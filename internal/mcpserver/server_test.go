package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type spyCommandCall struct {
	Binary string
	Args   []string
}

type spyCommandRunner struct {
	mu      sync.Mutex
	calls   []spyCommandCall
	nextErr error
	nextRes *executor.Result
}

func (s *spyCommandRunner) Execute(_ context.Context, binary string, args []string, _ time.Duration) (*executor.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, spyCommandCall{Binary: binary, Args: append([]string(nil), args...)})
	if s.nextErr != nil {
		err := s.nextErr
		s.nextErr = nil
		res := s.nextRes
		s.nextRes = nil
		if res == nil {
			res = &executor.Result{Binary: binary, Args: args, ExitCode: -1, TimedOut: errors.Is(err, executor.ErrCommandTimeout)}
		}
		return res, err
	}
	if s.nextRes != nil {
		res := s.nextRes
		s.nextRes = nil
		return res, nil
	}
	return &executor.Result{
		Binary:   binary,
		Args:     args,
		ExitCode: 0,
		Stdout:   "ok",
		Stderr:   "",
		Duration: 12 * time.Millisecond,
	}, nil
}

type spyJournalReader struct {
	lines []string
}

func (j *spyJournalReader) Tail(_ context.Context, _ string, lines int) ([]string, error) {
	if lines < len(j.lines) {
		return j.lines[len(j.lines)-lines:], nil
	}
	return append([]string(nil), j.lines...), nil
}

type spyPropertyDriver struct {
	mu    sync.Mutex
	props map[string]reflex.UnitProperties
}

func newSpyPropDriver() *spyPropertyDriver {
	return &spyPropertyDriver{props: make(map[string]reflex.UnitProperties)}
}

func (d *spyPropertyDriver) GetProperties(_ context.Context, unit string) (reflex.UnitProperties, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.props[unit]; ok {
		return p, nil
	}
	return reflex.UnitProperties{MemoryHigh: "infinity", CPUQuota: "infinity", IOWeight: "100"}, nil
}

func (d *spyPropertyDriver) SetProperties(_ context.Context, unit string, props reflex.UnitProperties) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.props[unit] = props
	return nil
}

type spyUnitInspector struct {
	active bool
}

func (u *spyUnitInspector) IsActive(_ context.Context, _ string) (bool, string, error) {
	if u.active {
		return true, "active", nil
	}
	return false, "failed", nil
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+b.token)
	rt := b.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(clone)
}

type testMCPHarness struct {
	srv      *Server
	store    *incident.Store
	fs       *kernelfs.MemFS
	runner   *spyCommandRunner
	unitInsp *spyUnitInspector
	minter   *approval.Minter
	now      time.Time
}

func setupTestMCPHarness(t *testing.T) *testMCPHarness {
	t.Helper()
	tmpDir := t.TempDir()
	store, err := incident.NewStore(filepath.Join(tmpDir, "mcp_test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpu memory io pids\n")
	mfs.SetFile("/sys/fs/cgroup/memory.reclaim", "")
	mfs.SetFile("/proc/meminfo", "MemTotal:        2097152 kB\nMemFree:          524288 kB\nMemAvailable:    1048576 kB\n")
	mfs.SetFile("/proc/loadavg", "0.42 0.35 0.28 1/120 4512\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=2.10 avg60=1.50 avg300=0.90 total=1000\nfull avg10=0.40 avg60=0.20 avg300=0.10 total=200\n")

	// Seed beberapa cgroup untuk pengujian top cgroup & process_tree
	apiCg := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	mfs.SetFile(apiCg+"/memory.current", "314572800\n") // 300 MiB
	mfs.SetFile(apiCg+"/memory.max", "536870912\n")
	mfs.SetFile(apiCg+"/memory.high", "419430400\n")
	mfs.SetFile(apiCg+"/memory.events", "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0\n")
	mfs.SetFile(apiCg+"/memory.pressure", "some avg10=3.50 avg60=2.00 avg300=1.00 total=50\nfull avg10=0.50 avg60=0.10 avg300=0.05 total=10\n")
	mfs.SetFile(apiCg+"/memory.reclaim", "")
	mfs.SetFile(apiCg+"/cgroup.procs", "1\n1200\n")

	workerCg := "/sys/fs/cgroup/franken.slice/worker.service"
	mfs.SetFile(workerCg+"/memory.current", "104857600\n") // 100 MiB
	mfs.SetFile(workerCg+"/memory.max", "max\n")
	mfs.SetFile(workerCg+"/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	mfs.SetFile(workerCg+"/memory.pressure", "some avg10=1.00 avg60=0.50 avg300=0.20 total=5\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	// Seed proses /proc untuk process_tree & zombie_report
	mfs.SetFile("/proc/1/stat", "1 (systemd) S 0 1 1 0 -1 4194560 0 0 0 0\n")
	mfs.SetFile("/proc/1/cmdline", "/sbin/init\x00--system\x00")
	mfs.SetFile("/proc/1/status", "Name:\tsystemd\nVmRSS:\t   12000 kB\n")

	mfs.SetFile("/proc/1200/stat", "1200 (node) S 1 1200 1200 0 -1 4194560 0 0 0 0\n")
	mfs.SetFile("/proc/1200/cmdline", "node\x00server.js\x00--token=supersecrettoken123456\x00")
	mfs.SetFile("/proc/1200/status", "Name:\tnode\nVmRSS:\t  280000 kB\n")

	mfs.SetFile("/proc/1205/stat", "1205 (sh zombie) Z 1200 1200 1200 0 -1 4194560 0 0 0 0\n")

	now := time.Date(2026, 11, 13, 9, 30, 0, 0, time.UTC)
	clockFn := func() time.Time { return now }

	kp, err := approval.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	minter, _ := approval.NewMinter(kp.PrivateKey, clockFn)
	verifier, _ := approval.NewVerifier(kp.PublicKey, store, clockFn)

	runner := &spyCommandRunner{}
	propDriver := newSpyPropDriver()
	admDriver := reflex.NewFSAdmissionDriver(filepath.Join(tmpDir, "run-franken"))
	reflexEng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    propDriver,
		AdmissionDriver:   admDriver,
		HostMemTotalBytes: 2 * 1024 * 1024 * 1024,
		Clock:             clockFn,
	})
	if err != nil {
		t.Fatalf("reflex.NewEngine: %v", err)
	}

	unitInsp := &spyUnitInspector{active: true}
	journalSpy := &spyJournalReader{
		lines: []string{
			"2026-11-13T09:29:50Z haunted-api error: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sigtest123456 from 192.168.10.22",
			"2026-11-13T09:29:55Z haunted-api fatal: JavaScript heap out of memory contacting postgres://admin:secretpass@10.0.0.5:5432/prod",
		},
	}

	srv, err := New(Config{
		NodeName:          "pi01",
		Version:           "0.2.0",
		Store:             store,
		Catalog:           cat,
		Reflex:            reflexEng,
		Verifier:          verifier,
		Runner:            runner,
		FS:                mfs,
		CgroupRoot:        "/sys/fs/cgroup",
		ProcRoot:          "/proc",
		JournalReader:     journalSpy,
		UnitInspector:     unitInsp,
		BearerToken:       "sentinel-secret-bearer-token-99",
		HeartbeatInterval: 40 * time.Millisecond,
		Clock:             clockFn,
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	// Seed satu insiden awal beserta evidence terredaksi
	ctx := context.Background()
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID:       "INC-20261113-0930-pi01",
		Node:     "pi01",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P2",
		State:    incident.StateDetected,
	}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	_ = store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
		ID:         "ev-seed1",
		IncidentID: "INC-20261113-0930-pi01",
		Kind:       "journal",
		RawData:    "raw line from 10.1.2.3 Bearer secret_token_abcdefghijklmnop",
	})

	return &testMCPHarness{
		srv:      srv,
		store:    store,
		fs:       mfs,
		runner:   runner,
		unitInsp: unitInsp,
		minter:   minter,
		now:      now,
	}
}

func connectPipeMCPClient(t *testing.T, ctx context.Context, srv *Server) (*mcp.ClientSession, func()) {
	t.Helper()
	srvReader, clientWriter := io.Pipe()
	clientReader, srvWriter := io.Pipe()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.RunTransport(ctx, &mcp.IOTransport{Reader: srvReader, Writer: srvWriter})
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-mcp-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientReader, Writer: clientWriter}, nil)
	if err != nil {
		t.Fatalf("MCP IOTransport Connect failed: %v", err)
	}

	cleanup := func() {
		_ = session.Close()
		_ = clientWriter.Close()
		_ = clientReader.Close()
		_ = srvReader.Close()
		_ = srvWriter.Close()
		<-errCh
	}
	return session, cleanup
}

func decodeStructured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	if res == nil {
		t.Fatal("nil CallToolResult")
	}
	if res.IsError {
		var msg string
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				msg += tc.Text
			}
		}
		t.Fatalf("expected non-error tool result, got IsError=true: %s", msg)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal StructuredContent into %T: %v (raw=%s)", out, err, string(raw))
	}
	return out
}

func TestMCP_StdioAndAllReadTools(t *testing.T) {
	h := setupTestMCPHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Tambahkan sampel histori PSI ke ring buffer
	h.srv.PSIRing().Record("/franken.slice/haunted-api.service", PSIPoint{
		At:        h.now.Add(-30 * time.Second),
		SomeAvg10: 4.5,
		FullAvg10: 0.8,
	})

	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	// 1. Verifikasi seluruh 14 tool MCP terdaftar resmi beserta ReadOnlyHint
	toolsRes, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	gotTools := make(map[string]*mcp.Tool, len(toolsRes.Tools))
	for _, tl := range toolsRes.Tools {
		gotTools[tl.Name] = tl
	}
	expectedNames := []string{
		"node_snapshot", "incident_list", "incident_get", "incident_claim",
		"psi_history", "cgroup_top", "journal_tail", "process_tree", "zombie_report",
		"plan_submit", "action_execute", "action_rollback", "incident_transition", "verify_health",
	}
	for _, name := range expectedNames {
		if _, ok := gotTools[name]; !ok {
			t.Fatalf("missing expected MCP tool %q", name)
		}
	}
	if gotTools["node_snapshot"].Annotations == nil || !gotTools["node_snapshot"].Annotations.ReadOnlyHint {
		t.Errorf("node_snapshot must advertise ReadOnlyHint=true")
	}

	// 2. Uji node_snapshot
	snapRes, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "node_snapshot"})
	if err != nil {
		t.Fatalf("CallTool node_snapshot: %v", err)
	}
	snap := decodeStructured[NodeSnapshotOutput](t, snapRes)
	if !snap.CapabilityHealthy || snap.MemoryTotalBytes != 2097152*1024 || len(snap.TopCgroups) == 0 {
		t.Errorf("unexpected node_snapshot output: %+v", snap)
	}

	// 3. Uji psi_history & validasi batas > 10 menit
	psiRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "psi_history",
		Arguments: map[string]any{"cgroup": "/franken.slice/haunted-api.service", "minutes": 5},
	})
	if err != nil {
		t.Fatalf("CallTool psi_history: %v", err)
	}
	psiOut := decodeStructured[PSIHistoryOutput](t, psiRes)
	if len(psiOut.Points) != 1 || psiOut.Points[0].SomeAvg10 != 4.5 {
		t.Errorf("unexpected psi_history points: %+v", psiOut.Points)
	}
	badPSI, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "psi_history",
		Arguments: map[string]any{"minutes": 15},
	})
	if err != nil || !badPSI.IsError {
		t.Errorf("expected IsError=true when psi_history minutes > 10")
	}

	// 4. Uji cgroup_top terurut membesar->mengecil
	cgRes, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "cgroup_top", Arguments: map[string]any{"limit": 10}})
	if err != nil {
		t.Fatalf("CallTool cgroup_top: %v", err)
	}
	cgTop := decodeStructured[CgroupTopOutput](t, cgRes)
	if len(cgTop.Cgroups) != 2 || cgTop.Cgroups[0].MemoryCurrent < cgTop.Cgroups[1].MemoryCurrent {
		t.Errorf("unexpected cgroup_top ordering: %+v", cgTop.Cgroups)
	}

	// 5. Uji journal_tail menyensor JWT, IP, DB credentials dan menyimpan evidence_id
	jtRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "journal_tail",
		Arguments: map[string]any{
			"unit":        "haunted-api.service",
			"lines":       20,
			"incident_id": "INC-20261113-0930-pi01",
		},
	})
	if err != nil {
		t.Fatalf("CallTool journal_tail: %v", err)
	}
	jt := decodeStructured[JournalTailOutput](t, jtRes)
	joinedLog := strings.Join(jt.Lines, "\n")
	if !strings.HasPrefix(jt.EvidenceID, "ev-") {
		t.Errorf("expected ev-* EvidenceID, got %q", jt.EvidenceID)
	}
	if strings.Contains(joinedLog, "eyJhbG") || strings.Contains(joinedLog, "secretpass") || strings.Contains(joinedLog, "192.168.10.22") {
		t.Fatalf("unredacted secrets leaked in journal_tail: %s", joinedLog)
	}

	// 6. Uji process_tree + proteksi PID 1 + penolakan path traversal `..`
	ptRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "process_tree",
		Arguments: map[string]any{"cgroup": "/franken.slice/haunted-api.service"},
	})
	if err != nil {
		t.Fatalf("CallTool process_tree: %v", err)
	}
	pt := decodeStructured[ProcessTreeOutput](t, ptRes)
	if len(pt.Processes) != 2 || !pt.Processes[0].Protected || pt.Processes[1].Protected {
		t.Errorf("unexpected process_tree protection flags: %+v", pt.Processes)
	}
	if strings.Contains(pt.Processes[1].Cmdline, "supersecrettoken123456") {
		t.Errorf("token in process cmdline was not redacted: %s", pt.Processes[1].Cmdline)
	}

	travRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "process_tree",
		Arguments: map[string]any{"cgroup": "/../../etc"},
	})
	if err != nil || !travRes.IsError {
		t.Errorf("expected traversal cgroup path to fail with IsError=true")
	}

	// 7. Uji zombie_report
	zRes, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "zombie_report"})
	if err != nil {
		t.Fatalf("CallTool zombie_report: %v", err)
	}
	rawZ, _ := json.Marshal(zRes.StructuredContent)
	if !strings.Contains(string(rawZ), `"total_zombies":1`) {
		t.Errorf("expected 1 zombie in report, got: %s", string(rawZ))
	}

	// 8. Uji incident_claim atomik (mencegah double claim)
	c1Res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "incident_claim",
		Arguments: map[string]any{"claimer": "franken-sentry"},
	})
	if err != nil {
		t.Fatalf("CallTool incident_claim 1: %v", err)
	}
	c1 := decodeStructured[IncidentClaimOutput](t, c1Res)
	if !c1.Claimed || c1.Incident == nil || c1.Incident.State != incident.StateTriaging {
		t.Fatalf("expected incident claimed to TRIAGING, got %+v", c1)
	}

	c2Res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "incident_claim",
		Arguments: map[string]any{"claimer": "duplicate-sentry"},
	})
	if err != nil {
		t.Fatalf("CallTool incident_claim 2: %v", err)
	}
	c2 := decodeStructured[IncidentClaimOutput](t, c2Res)
	if c2.Claimed {
		t.Fatalf("expected second claim to return claimed=false")
	}

	// 9. Uji incident_list & incident_get (pastikan RawData mentah tidak pernah terbaca)
	listRes, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "incident_list", Arguments: map[string]any{"state": "TRIAGING"}})
	if err != nil {
		t.Fatalf("CallTool incident_list: %v", err)
	}
	incList := decodeStructured[IncidentListOutput](t, listRes)
	if incList.Count != 1 {
		t.Errorf("expected 1 TRIAGING incident, got %+v", incList)
	}

	getRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "incident_get",
		Arguments: map[string]any{"incident_id": "INC-20261113-0930-pi01"},
	})
	if err != nil {
		t.Fatalf("CallTool incident_get: %v", err)
	}
	rawGetBytes, _ := json.Marshal(getRes.StructuredContent)
	if strings.Contains(string(rawGetBytes), "secret_token_abcdefghijklmnop") || strings.Contains(string(rawGetBytes), `"raw_data"`) {
		t.Fatalf("raw unredacted evidence leaked via incident_get: %s", string(rawGetBytes))
	}
}

func TestMCP_WriteToolsPolicyTokenAndVerification(t *testing.T) {
	h := setupTestMCPHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Seed insiden tambahan untuk pengujian revisi gagal > 2x -> ESCALATED
	_ = h.store.CreateIncident(ctx, &incident.Incident{
		ID: "INC-20261113-0931-pi01", Node: "pi01", Cgroup: "/franken.slice/haunted-api.service", Severity: "P2", State: incident.StateTriaging,
	})

	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	// 1. Uji plan_submit gagal 3 kali (melanggar L3 + target terlindungi) -> otomatis ESCALATED
	badPlan := policy.Plan{
		IncidentID:         "INC-20261113-0931-pi01",
		SuspectedRootCause: "Trying forbidden actions on protected unit",
		HumanFollowUp:      []string{},
		Options: []policy.PlanOption{{
			ID:    "A",
			Label: "Bad L3",
			Steps: []policy.PlanStep{{
				ID:             "s1",
				Action:         "raw_shell",
				Params:         map[string]any{"unit": "sshd.service"},
				EvidenceIDs:    []string{"ev-seed1"},
				ExpectedEffect: "bad",
			}},
		}},
	}
	for attempt := 1; attempt <= 3; attempt++ {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "plan_submit",
			Arguments: map[string]any{"incident_id": "INC-20261113-0931-pi01", "plan": badPlan},
		})
		if err != nil {
			t.Fatalf("plan_submit bad attempt %d: %v", attempt, err)
		}
		out := decodeStructured[PlanSubmitOutput](t, res)
		if out.Valid {
			t.Fatalf("expected invalid plan rejected on attempt %d", attempt)
		}
		if attempt == 3 && (!out.Escalated || out.State != string(incident.StateEscalated)) {
			t.Fatalf("expected auto-escalation on 3rd failed plan submission, got %+v", out)
		}
	}

	// 2. Ajukan plan sah pada INC-20261113-0930-pi01 (L1 throttle + L2 unit_restart)
	validPlan := policy.Plan{
		IncidentID:         "INC-20261113-0930-pi01",
		SuspectedRootCause: "Node API memory leak exceeding baseline",
		HumanFollowUp:      []string{"Inspect cache eviction policy"},
		Options: []policy.PlanOption{{
			ID:    "A",
			Label: "Restart haunted-api cleanly",
			Steps: []policy.PlanStep{
				{
					ID:             "step-l1",
					Action:         "cgroup_throttle",
					Params:         map[string]any{"unit": "haunted-api.service", "memory_high": "350M", "ttl_seconds": 120},
					EvidenceIDs:    []string{"ev-seed1"},
					ExpectedEffect: "Slow RSS allocation safely",
				},
				{
					ID:             "step-l2",
					Action:         "unit_restart",
					Params:         map[string]any{"unit": "haunted-api.service"},
					EvidenceIDs:    []string{"ev-seed1"},
					ExpectedEffect: "Reset leaked worker heap",
				},
			},
		}},
	}
	pRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "plan_submit",
		Arguments: map[string]any{"incident_id": "INC-20261113-0930-pi01", "plan": validPlan},
	})
	if err != nil {
		t.Fatalf("plan_submit valid: %v", err)
	}
	pOut := decodeStructured[PlanSubmitOutput](t, pRes)
	if !pOut.Valid || pOut.State != string(incident.StatePlanned) {
		t.Fatalf("expected valid PLANNED submission, got %+v", pOut)
	}

	// Mint token Ed25519 asli yang terikat pada step-l2 (unit_restart)
	tokL2, _, err := h.minter.Mint(approval.MintRequest{
		IncidentID:     "INC-20261113-0930-pi01",
		PlanHash:       pOut.PlanHash,
		OptionID:       "A",
		ActionName:     "unit_restart",
		StepIDs:        []string{"step-l2"},
		ApproverSender: "+62811112222",
	})
	if err != nil {
		t.Fatalf("minter.Mint: %v", err)
	}

	// 3. Tolak L3 meski membawa token, tolak L2 tanpa token, dan tolak parameter yang dimodifikasi pasca-approval
	for _, tc := range []struct {
		name   string
		args   map[string]any
		wantSub string
	}{
		{
			name:   "l3_forbidden_even_with_token",
			args:   map[string]any{"incident_id": "INC-20261113-0930-pi01", "step_id": "step-l2", "action": "raw_shell", "params": map[string]any{}, "approval_token": tokL2},
			wantSub: "forbidden",
		},
		{
			name:   "l2_protected_unit_even_with_token",
			args:   map[string]any{"incident_id": "INC-20261113-0930-pi01", "step_id": "step-l2", "action": "unit_restart", "params": map[string]any{"unit": "sshd.service"}, "approval_token": tokL2},
			wantSub: "protected",
		},
		{
			name:   "l2_missing_token",
			args:   map[string]any{"incident_id": "INC-20261113-0930-pi01", "step_id": "step-l2", "action": "unit_restart", "params": map[string]any{"unit": "haunted-api.service"}},
			wantSub: "approval_token is required",
		},
		{
			name:   "l2_mutated_params",
			args:   map[string]any{"incident_id": "INC-20261113-0930-pi01", "step_id": "step-l2", "action": "unit_restart", "params": map[string]any{"unit": "other-unit.service"}, "approval_token": tokL2},
			wantSub: "differ from approved plan",
		},
	} {
		r, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: "action_execute", Arguments: tc.args})
		if callErr != nil || !r.IsError {
			t.Fatalf("%s: expected IsError=true, got err=%v res=%+v", tc.name, callErr, r)
		}
		txt := r.Content[0].(*mcp.TextContent).Text
		if !strings.Contains(strings.ToLower(txt), tc.wantSub) {
			t.Errorf("%s: expected error mentioning %q, got %q", tc.name, tc.wantSub, txt)
		}
	}

	// 4. Eksekusi langkah L1 (cgroup_throttle) tanpa token -> sukses
	l1Res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "action_execute",
		Arguments: map[string]any{
			"incident_id": "INC-20261113-0930-pi01",
			"step_id":     "step-l1",
			"action":      "cgroup_throttle",
			"params":      map[string]any{"unit": "haunted-api.service", "memory_high": "350M", "ttl_seconds": 120},
		},
	})
	if err != nil {
		t.Fatalf("CallTool action_execute L1: %v", err)
	}
	l1Out := decodeStructured[ActionExecuteOutput](t, l1Res)
	if !l1Out.Success || !strings.HasPrefix(l1Out.ReflexID, "RFX-") {
		t.Fatalf("expected L1 reflex executed, got %+v", l1Out)
	}

	// 5. Eksekusi langkah L2 sah dengan token Ed25519 -> memanggil systemctl restart tanpa shell
	l2Res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "action_execute",
		Arguments: map[string]any{
			"incident_id":    "INC-20261113-0930-pi01",
			"step_id":        "step-l2",
			"action":         "unit_restart",
			"params":         map[string]any{"unit": "haunted-api.service"},
			"approval_token": tokL2,
		},
	})
	if err != nil {
		t.Fatalf("CallTool action_execute L2: %v", err)
	}
	l2Out := decodeStructured[ActionExecuteOutput](t, l2Res)
	if !l2Out.Success || l2Out.Binary != "systemctl" || len(h.runner.calls) != 1 || h.runner.calls[0].Args[0] != "restart" {
		t.Fatalf("unexpected L2 execution result/calls: out=%+v calls=%+v", l2Out, h.runner.calls)
	}

	// Serangan replay memakai token L2 yang sama persis wajib ditolak oleh SQLite nonce verifier
	replayRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "action_execute",
		Arguments: map[string]any{
			"incident_id":    "INC-20261113-0930-pi01",
			"step_id":        "step-l2",
			"action":         "unit_restart",
			"params":         map[string]any{"unit": "haunted-api.service"},
			"approval_token": tokL2,
		},
	})
	if err != nil || !replayRes.IsError {
		t.Fatalf("expected replay attack rejected with IsError=true")
	}

	// 6. Uji transisi REMEDIATING -> VERIFYING, verify_health (dengan probe loopback) otomatis me-rollback refleks L1, lalu RESOLVED
	trRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "incident_transition",
		Arguments: map[string]any{"incident_id": "INC-20261113-0930-pi01", "to": "VERIFYING", "reason": "restart done"},
	})
	if err != nil {
		t.Fatalf("incident_transition VERIFYING: %v", err)
	}
	_ = decodeStructured[IncidentTransitionOutput](t, trRes)

	appHealthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer appHealthSrv.Close()

	vhRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "verify_health",
		Arguments: map[string]any{
			"incident_id":    "INC-20261113-0930-pi01",
			"unit":           "haunted-api.service",
			"window_seconds": 120,
			"probe_url":      appHealthSrv.URL,
		},
	})
	if err != nil {
		t.Fatalf("verify_health: %v", err)
	}
	vh := decodeStructured[VerifyHealthOutput](t, vhRes)
	if !vh.Healthy || vh.RolledBackReflexes != 1 {
		t.Fatalf("expected healthy verification + 1 auto-rolled-back reflex, got %+v", vh)
	}

	// Uji proteksi SSRF pada verify_health (alamat metadata cloud wajib ditolak)
	ssrfRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "verify_health",
		Arguments: map[string]any{
			"incident_id": "INC-20261113-0930-pi01",
			"probe_url":   "http://169.254.169.254/latest/meta-data",
		},
	})
	if err != nil {
		t.Fatalf("verify_health SSRF check: %v", err)
	}
	ssrfOut := decodeStructured[VerifyHealthOutput](t, ssrfRes)
	if ssrfOut.Healthy {
		t.Errorf("expected cloud metadata probe URL to fail SSRF check")
	}

	// 7. Uji timeout eksekutor pada insiden baru -> otomatis eskalasi ke ESCALATED
	_ = h.store.CreateIncident(ctx, &incident.Incident{
		ID: "INC-20261113-0935-pi01", Node: "pi01", Cgroup: "/franken.slice/haunted-api.service", Severity: "P1", State: incident.StatePlanned,
		PlanJSON: h.mustSamplePlanJSON(t, "INC-20261113-0935-pi01", "haunted-api.service"),
	})
	h.runner.nextErr = executor.ErrCommandTimeout
	var timeoutPlan policy.Plan
	_ = json.Unmarshal([]byte(h.mustSamplePlanJSON(t, "INC-20261113-0935-pi01", "haunted-api.service")), &timeoutPlan)
	tHash, _ := policy.ComputePlanHash(&timeoutPlan)
	tokTO, _, _ := h.minter.Mint(approval.MintRequest{
		IncidentID: "INC-20261113-0935-pi01", PlanHash: tHash, OptionID: "A", ActionName: "unit_restart", StepIDs: []string{"step-to"}, ApproverSender: "+62811112222",
	})
	toRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "action_execute",
		Arguments: map[string]any{
			"incident_id": "INC-20261113-0935-pi01", "step_id": "step-to", "action": "unit_restart",
			"params": map[string]any{"unit": "haunted-api.service"}, "approval_token": tokTO,
		},
	})
	if err != nil || !toRes.IsError {
		t.Fatalf("expected timeout failure returned as IsError=true")
	}
	escInc, _ := h.store.GetIncident(ctx, "INC-20261113-0935-pi01")
	if escInc.State != incident.StateEscalated {
		t.Errorf("expected timed-out action to escalate incident, got state %s", escInc.State)
	}
}

func (h *testMCPHarness) mustSamplePlanJSON(t *testing.T, incID, unit string) string {
	t.Helper()
	p := policy.Plan{
		IncidentID:         incID,
		SuspectedRootCause: "Worker runaway memory spike",
		HumanFollowUp:      []string{},
		Options: []policy.PlanOption{{
			ID: "A", Label: "Restart " + unit,
			Steps: []policy.PlanStep{{
				ID: "step-to", Action: "unit_restart", Params: map[string]any{"unit": unit},
				EvidenceIDs: []string{"ev-1"}, ExpectedEffect: "Recover memory",
			}},
		}},
	}
	b, err := policy.CanonicalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMCP_HTTPTransportBindSecurityAuthAndSSE(t *testing.T) {
	// 1. Uji validasi alamat bind aman (tolak wildcard/publik, izinkan Tailscale CGNAT & localhost)
	for _, bad := range []string{"", ":8080", "0.0.0.0:8080", "[::]:8080", "8.8.8.8:8080"} {
		if _, err := ValidateBindAddr(bad, false); !errors.Is(err, ErrUnsafeBindAddress) {
			t.Errorf("ValidateBindAddr(%q) expected ErrUnsafeBindAddress, got %v", bad, err)
		}
	}
	for _, good := range []string{"127.0.0.1:8080", "[::1]:8080", "100.88.12.5:8080", "[fd7a:115c:a1e0::1]:8080"} {
		if _, err := ValidateBindAddr(good, false); err != nil {
			t.Errorf("ValidateBindAddr(%q) unexpected error: %v", good, err)
		}
	}

	h := setupTestMCPHarness(t)
	handler, err := h.srv.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// 2. Uji GET /healthz unauthenticated -> 200 OK; degradasi PSI -> 503
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on /healthz, got %d", resp.StatusCode)
	}
	var hz HealthzResponse
	_ = json.NewDecoder(resp.Body).Decode(&hz)
	resp.Body.Close()
	if hz.Status != "ok" || len(hz.Capabilities) < 2 {
		t.Errorf("unexpected healthz payload: %+v", hz)
	}

	// 3. Uji autentikasi Bearer pada /mcp dan /v1/events (wajib 401 tanpa/salah token)
	unauthMCP, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST unauth /mcp: %v", err)
	}
	unauthMCP.Body.Close()
	if unauthMCP.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on unauthenticated /mcp, got %d", unauthMCP.StatusCode)
	}

	badReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/events", nil)
	badReq.Header.Set("Authorization", "Bearer wrong-token")
	badSSE, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatalf("GET bad auth /v1/events: %v", err)
	}
	badSSE.Body.Close()
	if badSSE.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on wrong-token /v1/events, got %d", badSSE.StatusCode)
	}

	// 4. Uji koneksi resmi MCP Go SDK StreamableClientTransport + Bearer auth over HTTP
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authClient := &http.Client{
		Transport: &bearerTransport{token: "sentinel-secret-bearer-token-99"},
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "streamable-test-client", Version: "1.0.0"}, nil)
	session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   ts.URL + "/mcp",
		HTTPClient: authClient,
	}, nil)
	if err != nil {
		t.Fatalf("StreamableClientTransport Connect failed: %v", err)
	}
	defer session.Close()

	listOut, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "incident_list"})
	if err != nil {
		t.Fatalf("Streamable HTTP CallTool incident_list: %v", err)
	}
	incidents := decodeStructured[IncidentListOutput](t, listOut)
	if incidents.Count != 1 {
		t.Errorf("expected 1 seeded incident over Streamable HTTP, got %d", incidents.Count)
	}

	// 5. Uji /v1/events SSE stream real-time + sensor payload + resume Last-Event-ID + heartbeat
	ev1 := h.srv.Broker().Publish(StreamEvent{
		Type:       "incident.opened",
		IncidentID: "INC-20261113-0940-pi01",
		Severity:   "P1",
		Summary:    "Alert from 10.20.30.40 with Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sigabcdef1234",
	})
	_ = h.srv.Broker().Publish(StreamEvent{
		Type:       "reflex.applied",
		IncidentID: "INC-20261113-0940-pi01",
		Summary:    "Reclaim executed",
	})

	sseCtx, sseCancel := context.WithTimeout(ctx, 2*time.Second)
	defer sseCancel()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, ts.URL+"/v1/events", nil)
	sseReq.Header.Set("Last-Event-ID", "1") // Resume setelah ev1 -> hanya ev2 lalu heartbeat yang diterima
	sseResp, err := authClient.Do(sseReq)
	if err != nil {
		t.Fatalf("GET /v1/events failed: %v", err)
	}
	defer sseResp.Body.Close()

	if ct := sseResp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream Content-Type, got %q", ct)
	}
	if strings.Contains(ev1.Summary, "10.20.30.40") || strings.Contains(ev1.Summary, "eyJhbG") {
		t.Fatalf("SSE event summary was not redacted before broadcast: %s", ev1.Summary)
	}

	scanner := bufio.NewScanner(sseResp.Body)
	var sawReflexApplied, sawHeartbeat, sawEv1Replay bool
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, `"type":"incident.opened"`) {
			sawEv1Replay = true
		}
		if strings.Contains(line, `"type":"reflex.applied"`) {
			sawReflexApplied = true
		}
		if strings.Contains(line, `"type":"heartbeat"`) {
			sawHeartbeat = true
		}
		if sawReflexApplied && sawHeartbeat {
			break
		}
	}
	if sawEv1Replay {
		t.Errorf("Last-Event-ID=1 should skip event 1 and only resume subsequent events")
	}
	if !sawReflexApplied || !sawHeartbeat {
		t.Errorf("expected resumed reflex.applied and heartbeat frames over SSE (reflex=%v hb=%v)", sawReflexApplied, sawHeartbeat)
	}
}

func TestMCP_HealthzDegraded503AndListenGuard(t *testing.T) {
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "degraded.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	cat, _ := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	// MemFS tanpa /proc/pressure/memory -> kapabilitas PSI tidak tersedia -> /healthz wajib 503
	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpu memory\n")

	srv, err := New(Config{
		NodeName:    "pi-degraded",
		Store:       store,
		Catalog:     cat,
		FS:          mfs,
		BearerToken: "test-bearer-123",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// ListenAndServe wajib menolak bind wildcard 0.0.0.0:0
	if err := srv.ListenAndServe(context.Background(), "0.0.0.0:8090"); !errors.Is(err, ErrUnsafeBindAddress) {
		t.Fatalf("expected ErrUnsafeBindAddress for 0.0.0.0, got: %v", err)
	}

	handler, _ := srv.HTTPHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable when PSI missing, got %d", resp.StatusCode)
	}

	// Uji graceful shutdown ListenAndServe di 127.0.0.1:0
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer listenCancel()
	if err := srv.ListenAndServe(listenCtx, "127.0.0.1:0"); err != nil {
		t.Errorf("ListenAndServe graceful shutdown failed: %v", err)
	}
}
