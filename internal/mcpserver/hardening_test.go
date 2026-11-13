package mcpserver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const scopedCgroup = "/franken.slice/haunted-api.service"

// newScopedIncident membuat insiden baru beserta satu evidence agar setiap kasus uji tidak terkena batas revisi plan.
func newScopedIncident(t *testing.T, h *testMCPHarness, id, cgroupRel string) string {
	t.Helper()
	ctx := context.Background()
	if err := h.store.CreateIncident(ctx, &incident.Incident{
		ID: id, Node: "pi01", Cgroup: cgroupRel, Severity: "P2", State: incident.StateDetected,
	}); err != nil {
		t.Fatalf("CreateIncident %s: %v", id, err)
	}
	evID := "ev-" + strings.ToLower(id[len(id)-9:])
	if err := h.store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
		ID: evID, IncidentID: id, Kind: "telemetry_sample", RawData: `{"memory_current":1}`,
	}); err != nil {
		t.Fatalf("SaveEvidence %s: %v", evID, err)
	}
	return evID
}

func singleStepPlan(incID, action string, params map[string]any, evidence ...string) policy.Plan {
	return policy.Plan{
		IncidentID:         incID,
		SuspectedRootCause: "heap leak in request cache",
		HumanFollowUp:      []string{"bound the cache"},
		Options: []policy.PlanOption{{
			ID: "A", Label: "remediate",
			Steps: []policy.PlanStep{{
				ID: "s1", Action: action, Params: params, EvidenceIDs: evidence, ExpectedEffect: "memory pressure drops",
			}},
		}},
	}
}

func callPlanSubmit(t *testing.T, ctx context.Context, session *mcp.ClientSession, incID string, plan policy.Plan) PlanSubmitOutput {
	t.Helper()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "plan_submit",
		Arguments: map[string]any{"incident_id": incID, "plan": plan},
	})
	if err != nil {
		t.Fatalf("plan_submit transport error: %v", err)
	}
	return decodeStructured[PlanSubmitOutput](t, res)
}

func hasViolation(out PlanSubmitOutput, needle string) bool {
	for _, v := range out.Violations {
		if strings.Contains(strings.ToLower(v), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func TestPlanSubmit_RejectsEvidenceNotRecordedForIncident(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	otherEv := newScopedIncident(t, h, "INC-20261113-1010-pi01", "/franken.slice/worker.service")

	cases := []struct {
		name     string
		incID    string
		evidence string
		valid    bool
	}{
		{"unknown evidence id", "INC-20261113-1011-pi01", "ev-ghost-404", false},
		{"evidence of another incident", "INC-20261113-1012-pi01", otherEv, false},
		{"evidence recorded for this incident", "INC-20261113-1013-pi01", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ownEv := newScopedIncident(t, h, tc.incID, scopedCgroup)
			ev := tc.evidence
			if ev == "" {
				ev = ownEv
			}
			out := callPlanSubmit(t, ctx, session, tc.incID, singleStepPlan(tc.incID, "unit_restart", map[string]any{"unit": "haunted-api.service"}, ev))
			if out.Valid != tc.valid {
				t.Fatalf("Valid=%v, want %v (violations=%v)", out.Valid, tc.valid, out.Violations)
			}
			if !tc.valid && !hasViolation(out, "evidence_id") {
				t.Fatalf("expected an evidence_id violation, got %v", out.Violations)
			}
		})
	}
}

func TestPlanSubmit_RejectsTargetsOutsideIncidentCgroup(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	h.fs.SetFile("/proc/1200/cgroup", "0::"+scopedCgroup+"\n")
	h.fs.SetFile("/proc/1300/stat", "1300 (postgres) S 1 1300 1300 0 -1 4194560 0 0 0 0\n")
	h.fs.SetFile("/proc/1300/cmdline", "postgres\x00-D\x00/var/lib/postgresql\x00")
	h.fs.SetFile("/proc/1300/cgroup", "0::/system.slice/postgresql.service\n")
	h.fs.SetFile("/sys/fs/cgroup/system.slice/pm2-pi.service/memory.current", "1048576\n")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	cases := []struct {
		name   string
		cgroup string
		action string
		params map[string]any
		valid  bool
	}{
		{"unit_restart of another unit", scopedCgroup, "unit_restart", map[string]any{"unit": "nginx.service"}, false},
		{"unit_restart of the incident unit without suffix", scopedCgroup, "unit_restart", map[string]any{"unit": "haunted-api"}, true},
		{"pm2 app unrelated to incident unit", scopedCgroup, "pm2_reload", map[string]any{"app": "billing-api"}, false},
		{"pm2 app matching incident unit", scopedCgroup, "pm2_reload", map[string]any{"app": "haunted-api"}, true},
		{"pm2 app inside a PM2 daemon unit", "/system.slice/pm2-pi.service", "pm2_restart_instance", map[string]any{"app": "billing-api", "pm_id": 1}, true},
		{"process in another cgroup", scopedCgroup, "process_terminate", map[string]any{"pid": 1300}, false},
		{"process inside incident cgroup", scopedCgroup, "process_terminate", map[string]any{"pid": 1200}, true},
		{"process whose cgroup cannot be read", scopedCgroup, "process_terminate", map[string]any{"pid": 4444}, false},
		{"zombie parent in another cgroup", scopedCgroup, "zombie_reap", map[string]any{"parent_pid": 1300}, false},
		{"reclaim on another cgroup", scopedCgroup, "cgroup_reclaim", map[string]any{"cgroup": "/system.slice/postgresql.service", "bytes": 1024}, false},
		{"reclaim on the incident cgroup", scopedCgroup, "cgroup_reclaim", map[string]any{"cgroup": scopedCgroup, "bytes": 1024}, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			incID := fmt.Sprintf("INC-20261113-11%02d-pi01", i)
			ev := newScopedIncident(t, h, incID, tc.cgroup)
			out := callPlanSubmit(t, ctx, session, incID, singleStepPlan(incID, tc.action, tc.params, ev))
			if out.Valid != tc.valid {
				t.Fatalf("Valid=%v, want %v (violations=%v)", out.Valid, tc.valid, out.Violations)
			}
			if !tc.valid && !hasViolation(out, "incident") {
				t.Fatalf("expected an incident-scope violation, got %v", out.Violations)
			}
		})
	}
}

func TestActionExecute_RechecksPIDScopeBeforeConsumingToken(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	h.srv.cfg.ProcessAlive = func(context.Context, int) bool { return false }
	h.fs.SetFile("/proc/1200/cgroup", "0::"+scopedCgroup+"\n")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	incID := "INC-20261113-1200-pi01"
	ev := newScopedIncident(t, h, incID, scopedCgroup)
	planOut := callPlanSubmit(t, ctx, session, incID, singleStepPlan(incID, "process_terminate", map[string]any{"pid": 1200}, ev))
	if !planOut.Valid {
		t.Fatalf("expected in-scope plan to validate, got %v", planOut.Violations)
	}
	tok, _, err := h.minter.Mint(approval.MintRequest{
		IncidentID: incID, PlanHash: planOut.PlanHash, OptionID: "A",
		ActionName: "process_terminate", StepIDs: []string{"s1"}, ApproverSender: "+6281234567890",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	execArgs := map[string]any{
		"incident_id": incID, "step_id": "s1", "action": "process_terminate",
		"params": map[string]any{"pid": 1200}, "approval_token": tok,
	}

	// Proses berpindah cgroup (atau PID dipakai ulang) setelah plan disetujui
	h.fs.SetFile("/proc/1200/cgroup", "0::/system.slice/postgresql.service\n")
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "action_execute", Arguments: execArgs})
	if err != nil {
		t.Fatalf("action_execute transport error: %v", err)
	}
	if !res.IsError || !strings.Contains(toolErrorText(res), "outside incident cgroup") {
		t.Fatalf("expected out-of-scope rejection, got IsError=%v text=%q", res.IsError, toolErrorText(res))
	}
	h.runner.mu.Lock()
	for _, call := range h.runner.calls {
		if call.Binary == "kill" {
			h.runner.mu.Unlock()
			t.Fatalf("no signal may be sent to an out-of-scope pid, got runner call %+v", call)
		}
	}
	h.runner.mu.Unlock()

	// Token belum terpakai karena penolakan terjadi sebelum verifikasi nonce
	h.fs.SetFile("/proc/1200/cgroup", "0::"+scopedCgroup+"\n")
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "action_execute", Arguments: execArgs})
	if err != nil {
		t.Fatalf("action_execute transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected the unused token to work once the pid is back in scope, got %q", toolErrorText(res))
	}
}

func TestIncidentGet_ExposesCanonicalPlanHash(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	incID := "INC-20261113-1300-pi01"
	ev := newScopedIncident(t, h, incID, scopedCgroup)
	planOut := callPlanSubmit(t, ctx, session, incID, singleStepPlan(incID, "unit_restart", map[string]any{"unit": "haunted-api.service"}, ev))
	if !planOut.Valid {
		t.Fatalf("plan rejected: %v", planOut.Violations)
	}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "incident_get", Arguments: map[string]any{"incident_id": incID}})
	if err != nil {
		t.Fatalf("incident_get: %v", err)
	}
	got := decodeStructured[IncidentGetOutput](t, res)
	if got.PlanHash != planOut.PlanHash {
		t.Fatalf("incident_get plan_hash=%q, want %q", got.PlanHash, planOut.PlanHash)
	}
}

func TestJournalTail_OmitsEvidenceIDWhenNothingIsStored(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "journal_tail",
		Arguments: map[string]any{"unit": "haunted-api.service", "lines": 5},
	})
	if err != nil {
		t.Fatalf("journal_tail: %v", err)
	}
	out := decodeStructured[JournalTailOutput](t, res)
	if out.EvidenceID != "" {
		t.Fatalf("journal_tail without incident_id stores nothing, so it must not return a citable evidence_id (got %q)", out.EvidenceID)
	}
}

// runForwardVerification menjalankan verify_health dua kali (mulai, lalu setelah 125 detik) dengan titik memori sintetis.
func runForwardVerification(t *testing.T, ctx context.Context, h *testMCPHarness, session *mcp.ClientSession, incID, cgroupRel string, memMiB []float64) VerifyHealthOutput {
	t.Helper()
	args := map[string]any{"incident_id": incID, "window_seconds": 120, "auto_transition": true}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "verify_health", Arguments: args})
	if err != nil {
		t.Fatalf("verify_health start: %v", err)
	}
	if start := decodeStructured[VerifyHealthOutput](t, res); !start.Pending {
		t.Fatalf("expected PENDING_VERIFICATION at start, got %+v", start)
	}
	base := h.Now()
	step := 120.0 / float64(len(memMiB)-1)
	for i, mib := range memMiB {
		h.srv.PSIRing().Record(cgroupRel, PSIPoint{
			At:            base.Add(time.Duration((float64(i)*step + 1) * float64(time.Second))),
			SomeAvg10:     1.5,
			FullAvg10:     0.1,
			MemoryCurrent: uint64(mib * 1024 * 1024),
		})
	}
	h.AdvanceClock(125 * time.Second)
	res, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "verify_health", Arguments: args})
	if err != nil {
		t.Fatalf("verify_health finalize: %v", err)
	}
	return decodeStructured[VerifyHealthOutput](t, res)
}

func linearMiB(from, to float64, points int) []float64 {
	out := make([]float64, points)
	for i := range out {
		out[i] = from + (to-from)*float64(i)/float64(points-1)
	}
	return out
}

func TestVerifyHealth_AcceptsWarmupGrowthWithAmpleHeadroom(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	incID := "INC-20261113-1400-pi01"
	_ = h.store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi01", Cgroup: scopedCgroup, Severity: "P2", State: incident.StateVerifying})

	// Proses Node yang baru di-restart tumbuh +18% saat warm-up, tetapi headroom ke memory.max (512 MiB) masih lebar
	out := runForwardVerification(t, ctx, h, session, incID, scopedCgroup, linearMiB(200, 236, 9))
	if !out.Healthy || !out.Checks.MemoryStable || out.State != string(incident.StateResolved) {
		t.Fatalf("warm-up growth with ample headroom must verify healthy, got healthy=%v state=%s failures=%v checks=%+v", out.Healthy, out.State, out.FailureReasons, out.Checks)
	}
	if out.Checks.MemoryTTOSeconds == nil || *out.Checks.MemoryTTOSeconds < MinStableTTOSeconds {
		t.Fatalf("expected projected TTO above %.0fs to be reported, got %v", MinStableTTOSeconds, out.Checks.MemoryTTOSeconds)
	}
}

func TestVerifyHealth_FailsWhenTrendProjectsOOMSoon(t *testing.T) {
	cases := []struct {
		name   string
		cgroup string
		mem    []float64
	}{
		// memory.max 512 MiB: naik 0.75 MiB/s dengan sisa 42 MiB -> OOM sekitar satu menit lagi
		{"bounded cgroup", scopedCgroup, linearMiB(380, 470, 9)},
		// memory.max "max": batas jatuh ke MemTotal host (2 GiB) dikurangi 64 MiB
		{"unbounded cgroup uses host limit", "/franken.slice/worker.service", linearMiB(1700, 1900, 9)},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := setupTestMCPHarness(t)
			defer h.srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
			defer cleanup()

			incID := fmt.Sprintf("INC-20261113-15%02d-pi01", i)
			_ = h.store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi01", Cgroup: tc.cgroup, Severity: "P1", State: incident.StateVerifying})
			out := runForwardVerification(t, ctx, h, session, incID, tc.cgroup, tc.mem)
			if out.Healthy || out.Checks.MemoryStable || out.State != string(incident.StateEscalated) {
				t.Fatalf("a trend that reaches the limit within %.0fs must fail verification, got healthy=%v state=%s checks=%+v", MinStableTTOSeconds, out.Healthy, out.State, out.Checks)
			}
			if out.Checks.MemoryTTOSeconds == nil || *out.Checks.MemoryTTOSeconds >= MinStableTTOSeconds {
				t.Fatalf("expected a projected TTO below %.0fs, got %v", MinStableTTOSeconds, out.Checks.MemoryTTOSeconds)
			}
		})
	}
}

func TestVerifyHealth_FinalizeWritesPostmortemAndAnnouncesIt(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	h.srv.cfg.PostmortemDir = filepath.Join(t.TempDir(), "incidents")
	h.srv.cfg.AutoPostmortem = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	subID, events, _ := h.srv.Broker().Subscribe(0)
	defer h.srv.Broker().Unsubscribe(subID)

	incID := "INC-20261113-1600-pi01"
	_ = h.store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi01", Cgroup: scopedCgroup, Severity: "P2", State: incident.StateVerifying})
	out := runForwardVerification(t, ctx, h, session, incID, scopedCgroup, linearMiB(220, 222, 9))
	if out.State != string(incident.StateResolved) {
		t.Fatalf("expected RESOLVED, got %+v", out)
	}

	wantPath := filepath.Join(h.srv.cfg.PostmortemDir, incID, "postmortem.md")
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected postmortem written at %s: %v", wantPath, err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Type != "verification.completed" || ev.IncidentID != incID {
				continue
			}
			if ev.Data["postmortem_path"] != wantPath || ev.Data["status"] != "RESOLVED" {
				t.Fatalf("verification.completed data must carry status and postmortem_path, got %+v", ev.Data)
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for verification.completed")
		}
	}
}

// Publish dan Unsubscribe yang berjalan bersamaan tidak boleh memicu panic "send on closed channel".
func TestEventBroker_UnsubscribeDuringPublishDoesNotPanic(t *testing.T) {
	broker := NewEventBroker("pi01", 64, time.Hour)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					broker.Publish(StreamEvent{Type: "telemetry.sample"})
				}
			}
		}()
	}
	for i := 0; i < 20000; i++ {
		id, _, _ := broker.Subscribe(0)
		broker.Unsubscribe(id)
	}
	close(stop)
	wg.Wait()
}

func toolErrorText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// Alur nyata: action_execute meninggalkan insiden di REMEDIATING. Verifikasi forward wajib memindahkannya
// ke VERIFYING lalu RESOLVED; sebelumnya REMEDIATING -> RESOLVED ditolak state machine sehingga insiden menggantung.
func TestVerifyHealth_AfterL2ExecutionResolvesIncident(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	h.srv.cfg.PostmortemDir = filepath.Join(t.TempDir(), "incidents")
	h.srv.cfg.AutoPostmortem = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	incID := "INC-20261113-1700-pi01"
	ev := newScopedIncident(t, h, incID, scopedCgroup)
	planOut := callPlanSubmit(t, ctx, session, incID, singleStepPlan(incID, "unit_restart", map[string]any{"unit": "haunted-api.service"}, ev))
	if !planOut.Valid {
		t.Fatalf("plan rejected: %v", planOut.Violations)
	}
	tok, _, err := h.minter.Mint(approval.MintRequest{
		IncidentID: incID, PlanHash: planOut.PlanHash, OptionID: "A",
		ActionName: "unit_restart", StepIDs: []string{"s1"}, ApproverSender: "+6281234567890",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	execRes, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "action_execute", Arguments: map[string]any{
		"incident_id": incID, "step_id": "s1", "action": "unit_restart",
		"params": map[string]any{"unit": "haunted-api.service"}, "approval_token": tok,
	}})
	if err != nil || execRes.IsError {
		t.Fatalf("action_execute failed: err=%v text=%q", err, toolErrorText(execRes))
	}

	out := runForwardVerification(t, ctx, h, session, incID, scopedCgroup, linearMiB(180, 182, 9))
	if out.State != string(incident.StateResolved) || !out.Healthy {
		t.Fatalf("expected the executed incident to end RESOLVED, got state=%s healthy=%v failures=%v", out.State, out.Healthy, out.FailureReasons)
	}
	if _, err := os.Stat(filepath.Join(h.srv.cfg.PostmortemDir, incID, "postmortem.md")); err != nil {
		t.Fatalf("expected a postmortem for the resolved incident: %v", err)
	}
}
