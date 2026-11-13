package chaos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/postmortem"
	"github.com/FikFikk/franken-crew/internal/reflex"
	"github.com/FikFikk/franken-crew/internal/sentinel"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Scenario mendefinisikan kelas gangguan buatan yang disuntikkan oleh chaos suite.
type Scenario string

const (
	ScenarioMemoryLeak  Scenario = "memory_leak"
	ScenarioMemorySpike Scenario = "memory_spike"
	ScenarioForkStorm   Scenario = "fork_storm"
	ScenarioZombieStorm Scenario = "zombie_storm"
	ScenarioLogFlood    Scenario = "log_flood"

	// DefaultRuns menetapkan standar 20 eksekusi beruntun tanpa kegagalan (Task 12.3).
	DefaultRuns = 20
	// MaxAllowedReflexLatency menetapkan SLA L1 refleks <= 250 ms dari deteksi.
	MaxAllowedReflexLatency = 250 * time.Millisecond
)

// DefaultScenarios mengembalikan kelima skenario chaos yang dijalankan secara bergantian.
func DefaultScenarios() []Scenario {
	return []Scenario{
		ScenarioMemoryLeak,
		ScenarioMemorySpike,
		ScenarioForkStorm,
		ScenarioZombieStorm,
		ScenarioLogFlood,
	}
}

// Config menyimpan konfigurasi eksekusi rangkaian uji chaos.
type Config struct {
	Runs       int
	PolicyPath string
	OutputDir  string
	NodeName   string
	Approver   string
}

// RunResult mencatat hasil lengkap satu eksekusi chaos end-to-end.
type RunResult struct {
	RunNumber          int      `json:"run_number"`
	Scenario           Scenario `json:"scenario"`
	IncidentID         string   `json:"incident_id"`
	TriageClass        string   `json:"triage_class"`
	ReflexCount        int      `json:"reflex_count"`
	ReflexLatencyMs    float64  `json:"reflex_latency_ms"`
	L2Action           string   `json:"l2_action"`
	HealthPassed       bool     `json:"health_passed"`
	RolledBackReflexes int      `json:"rolled_back_reflexes"`
	FinalState         string   `json:"final_state"`
	PostmortemPath     string   `json:"postmortem_path"`
	Passed             bool     `json:"passed"`
	Error              string   `json:"error,omitempty"`
}

// SuiteReport merangkum keseluruhan hasil dari 20 atau lebih pengujian chaos beruntun.
type SuiteReport struct {
	Runs               int         `json:"runs"`
	Passed             int         `json:"passed"`
	Failed             int         `json:"failed"`
	MaxReflexLatencyMs float64     `json:"max_reflex_latency_ms"`
	AvgReflexLatencyMs float64     `json:"avg_reflex_latency_ms"`
	Results            []RunResult `json:"results"`
}

type chaosPropertyDriver struct {
	mu    sync.Mutex
	props map[string]reflex.UnitProperties
}

func newChaosPropertyDriver() *chaosPropertyDriver {
	return &chaosPropertyDriver{props: make(map[string]reflex.UnitProperties)}
}

func (d *chaosPropertyDriver) GetProperties(_ context.Context, unit string) (reflex.UnitProperties, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.props[unit]; ok {
		return p, nil
	}
	return reflex.UnitProperties{MemoryHigh: "infinity", CPUQuota: "infinity", IOWeight: "100"}, nil
}

func (d *chaosPropertyDriver) SetProperties(_ context.Context, unit string, props reflex.UnitProperties) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.props[unit] = props
	return nil
}

type chaosCommandRunner struct {
	mu    sync.Mutex
	calls []string
	fs    *kernelfs.MemFS
}

func (r *chaosCommandRunner) Execute(_ context.Context, binary string, args []string, _ time.Duration) (*executor.Result, error) {
	// Cegah penggunaan shell interpreter di jalur eksekusi simulasi sekalipun
	if binary == "sh" || binary == "bash" {
		return nil, fmt.Errorf("shell interpreter %q forbidden", binary)
	}
	r.mu.Lock()
	r.calls = append(r.calls, binary+" "+strings.Join(args, " "))
	r.mu.Unlock()
	// Simulasikan proses target keluar setelah menerima sinyal terminasi agar tidak memicu tunggu grace 10 detik
	if r.fs != nil && binary == "kill" && len(args) >= 2 && (args[0] == "-TERM" || args[0] == "-KILL") {
		r.fs.Remove("/proc/" + args[1] + "/stat")
	}
	return &executor.Result{
		Binary:   binary,
		Args:     append([]string(nil), args...),
		ExitCode: 0,
		Stdout:   "ok",
		Duration: 8 * time.Millisecond,
	}, nil
}

type chaosUnitInspector struct{}

func (u *chaosUnitInspector) IsActive(_ context.Context, _ string) (bool, string, error) {
	return true, "active", nil
}

type chaosJournalReader struct {
	mu    sync.Mutex
	lines []string
}

func (j *chaosJournalReader) SetLines(lines []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.lines = append([]string(nil), lines...)
}

func (j *chaosJournalReader) Tail(_ context.Context, _ string, limit int) ([]string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if limit > 0 && len(j.lines) > limit {
		return append([]string(nil), j.lines[len(j.lines)-limit:]...), nil
	}
	return append([]string(nil), j.lines...), nil
}

// RunSuite mengeksekusi simulasi gangguan secara beruntun end-to-end dari deteksi hingga postmortem.
func RunSuite(ctx context.Context, cfg Config) (*SuiteReport, error) {
	if cfg.Runs <= 0 {
		cfg.Runs = DefaultRuns
	}
	if strings.TrimSpace(cfg.NodeName) == "" {
		cfg.NodeName = "chaos-pi01"
	}
	if strings.TrimSpace(cfg.Approver) == "" {
		cfg.Approver = "+6281234567890"
	}
	if strings.TrimSpace(cfg.PolicyPath) == "" {
		cfg.PolicyPath = filepath.Join("policy", "actions.yaml")
	}

	tmpDir, err := os.MkdirTemp("", "franken-chaos-*")
	if err != nil {
		return nil, fmt.Errorf("create chaos temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	postmortemBase := strings.TrimSpace(cfg.OutputDir)
	if postmortemBase == "" {
		postmortemBase = filepath.Join(tmpDir, "incidents")
	}

	cat, err := policy.LoadCatalog(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load policy catalog %s: %w", cfg.PolicyPath, err)
	}

	store, err := incident.NewStore(filepath.Join(tmpDir, "chaos-sentinel.db"))
	if err != nil {
		return nil, fmt.Errorf("init chaos sqlite store: %w", err)
	}
	defer func() {
		_ = store.Close()
	}()

	mfs := seedBaseMemFS()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	var clockMu sync.Mutex
	clockFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	kp, err := approval.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate chaos ed25519 keys: %w", err)
	}
	minter, err := approval.NewMinter(kp.PrivateKey, clockFn)
	if err != nil {
		return nil, err
	}
	verifier, err := approval.NewVerifier(kp.PublicKey, store, clockFn)
	if err != nil {
		return nil, err
	}

	propDriver := newChaosPropertyDriver()
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
		return nil, fmt.Errorf("init reflex engine: %w", err)
	}

	journalReader := &chaosJournalReader{}
	mcpSrv, err := mcpserver.New(mcpserver.Config{
		NodeName:      cfg.NodeName,
		Version:       "chaos-test",
		Store:         store,
		Catalog:       cat,
		Reflex:        reflexEng,
		Verifier:      verifier,
		Runner:        &chaosCommandRunner{fs: mfs},
		FS:            mfs,
		CgroupRoot:    "/sys/fs/cgroup",
		ProcRoot:      "/proc",
		JournalReader: journalReader,
		UnitInspector: &chaosUnitInspector{},
		HTTPProber:    &mcpserver.LoopbackHTTPProber{},
		PostmortemDir: postmortemBase,
		Clock:         clockFn,
	})
	if err != nil {
		return nil, fmt.Errorf("init mcpserver: %w", err)
	}

	apiCg := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	daemon, err := sentinel.New(sentinel.Config{
		NodeName:    cfg.NodeName,
		FS:          mfs,
		CgroupRoot:  "/sys/fs/cgroup",
		ProcRoot:    "/proc",
		CgroupPaths: []string{apiCg},
		Store:       store,
		Catalog:     cat,
		Reflex:      reflexEng,
		MCPServer:   mcpSrv,
		Clock:       clockFn,
	})
	if err != nil {
		return nil, fmt.Errorf("init sentinel daemon: %w", err)
	}

	// Hubungkan client MCP lewat InMemoryTransports seperti alur Kiro Crew + wa-bridge
	srvTransport, cliTransport := mcp.NewInMemoryTransports()
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- mcpSrv.MCPServer().Run(runCtx, srvTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "chaos-runner", Version: "1.0.0"}, nil)
	session, err := client.Connect(runCtx, cliTransport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect in-memory mcp client: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	healthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthSrv.Close()

	scenarios := DefaultScenarios()
	report := &SuiteReport{
		Runs:    cfg.Runs,
		Results: make([]RunResult, 0, cfg.Runs),
	}
	var sumLatencyMs float64

	for idx := 0; idx < cfg.Runs; idx++ {
		scenario := scenarios[idx%len(scenarios)]
		res := executeSingleChaosRun(runCtx, idx+1, scenario, apiCg, mfs, journalReader, daemon, mcpSrv, store, minter, session, healthSrv.URL, cfg.Approver, clockFn, advanceClock)
		report.Results = append(report.Results, res)
		if res.ReflexLatencyMs > report.MaxReflexLatencyMs {
			report.MaxReflexLatencyMs = res.ReflexLatencyMs
		}
		sumLatencyMs += res.ReflexLatencyMs
		if res.Passed {
			report.Passed++
		} else {
			report.Failed++
		}

		// Pulihkan kondisi detector (25 tick 1 Hz untuk decay EWMA + 125s hysteresis + 6m debounce) agar run berikutnya independen
		setHealthyMetrics(mfs, apiCg, 160*1024*1024)
		for tick := 0; tick < 25; tick++ {
			advanceClock(1 * time.Second)
			_, _ = daemon.EvaluateOnce(runCtx, apiCg)
		}
		advanceClock(125 * time.Second)
		_, _ = daemon.EvaluateOnce(runCtx, apiCg)
		advanceClock(6 * time.Minute)
	}

	if cfg.Runs > 0 {
		report.AvgReflexLatencyMs = sumLatencyMs / float64(cfg.Runs)
	}
	return report, nil
}

func executeSingleChaosRun(
	ctx context.Context,
	runNum int,
	scenario Scenario,
	apiCg string,
	mfs *kernelfs.MemFS,
	journalReader *chaosJournalReader,
	daemon *sentinel.Daemon,
	mcpSrv *mcpserver.Server,
	store *incident.Store,
	minter *approval.Minter,
	session *mcp.ClientSession,
	healthURL string,
	approver string,
	clockFn func() time.Time,
	advanceClock func(time.Duration),
) RunResult {
	out := RunResult{RunNumber: runNum, Scenario: scenario}

	// Reset baseline tenang sebelum menyuntikkan tekanan chaos
	setHealthyMetrics(mfs, apiCg, 160*1024*1024)
	journalReader.SetLines(nil)
	if _, err := daemon.EvaluateOnce(ctx, apiCg); err != nil {
		out.Error = fmt.Sprintf("baseline evaluate failed: %v", err)
		return out
	}

	// Suntikkan gangguan sesuai skenario lalu ukur latensi deteksi -> refleks L1
	advanceClock(1 * time.Second)
	triageClass, l2Action, l2Params := injectChaosScenario(mfs, apiCg, journalReader, scenario, runNum)
	out.TriageClass = triageClass
	out.L2Action = l2Action

	t0 := time.Now()
	eval, err := daemon.EvaluateOnce(ctx, apiCg)
	reflexElapsed := time.Since(t0)
	out.ReflexLatencyMs = float64(reflexElapsed.Microseconds()) / 1000.0
	if err != nil {
		out.Error = fmt.Sprintf("chaos evaluate failed: %v", err)
		return out
	}
	if !eval.IncidentOpen || eval.IncidentID == "" {
		out.Error = fmt.Sprintf("expected open incident after injecting %s, got %+v", scenario, eval)
		return out
	}
	out.IncidentID = eval.IncidentID

	if reflexElapsed > MaxAllowedReflexLatency {
		out.Error = fmt.Sprintf("reflex latency %.2fms exceeded 250ms budget", out.ReflexLatencyMs)
		return out
	}

	// Pastikan refleks L1 tercatat di SQLite
	reflexes, err := store.GetReflexActionsByIncident(ctx, out.IncidentID)
	if err != nil {
		out.Error = fmt.Sprintf("list reflexes: %v", err)
		return out
	}
	out.ReflexCount = len(reflexes)
	if out.ReflexCount == 0 {
		out.Error = "expected >= 1 L1 reflex action persisted"
		return out
	}

	// 1. Sentry klaim insiden & tangkap journal terredaksi via MCP
	if _, err := callToolJSON[map[string]any](ctx, session, "incident_claim", map[string]any{
		"claimer": "franken-sentry",
	}); err != nil {
		out.Error = fmt.Sprintf("incident_claim failed: %v", err)
		return out
	}
	jtOut, err := callToolJSON[mcpserver.JournalTailOutput](ctx, session, "journal_tail", map[string]any{
		"unit":        "haunted-api.service",
		"lines":       20,
		"incident_id": out.IncidentID,
	})
	if err != nil {
		out.Error = fmt.Sprintf("journal_tail failed: %v", err)
		return out
	}
	if strings.Contains(strings.Join(jtOut.Lines, "\n"), "chaos_secret_jwt_payload") {
		out.Error = "SECURITY VIOLATION: unredacted secret found in journal_tail output"
		return out
	}
	evidenceID := jtOut.EvidenceID
	if evidenceID == "" {
		evidenceID = "ev-chaos-fallback"
	}

	// Simpan klasifikasi triage JSON seperti yang dilakukan Franken-Sentry
	triageBytes, _ := json.Marshal(postmortem.TriageSummary{
		Class:       triageClass,
		Confidence:  0.94,
		EvidenceIDs: []string{evidenceID},
		Summary:     fmt.Sprintf("Chaos %s isolated on %s", scenario, apiCg),
	})
	_ = store.SaveTriage(ctx, out.IncidentID, string(triageBytes))

	// 2. Architect mengirim remediation plan yang valid dan mendapatkan plan_hash kanonik
	plan := policy.Plan{
		IncidentID:         out.IncidentID,
		SuspectedRootCause: fmt.Sprintf("Simulated %s overload in chaos cycle %d", scenario, runNum),
		Options: []policy.PlanOption{{
			ID:    "A",
			Label: fmt.Sprintf("Remediate %s safely", scenario),
			Steps: []policy.PlanStep{{
				ID:             "step-chaos-1",
				Action:         l2Action,
				Params:         l2Params,
				EvidenceIDs:    []string{evidenceID},
				ExpectedEffect: fmt.Sprintf("Stabilize %s after chaos injection", apiCg),
			}},
		}},
		HumanFollowUp: []string{fmt.Sprintf("Review chaos remediation benchmark #%d (%s)", runNum, scenario)},
	}
	planOut, err := callToolJSON[mcpserver.PlanSubmitOutput](ctx, session, "plan_submit", map[string]any{
		"incident_id": out.IncidentID,
		"plan":        plan,
	})
	if err != nil || !planOut.Valid {
		out.Error = fmt.Sprintf("plan_submit rejected (%v): %+v", err, planOut.Violations)
		return out
	}

	// 3. Simulasikan vote manusia -> wa-bridge mint token Ed25519 -> Remediator eksekusi aksi L2
	_, _ = callToolJSON[mcpserver.IncidentTransitionOutput](ctx, session, "incident_transition", map[string]any{
		"incident_id": out.IncidentID,
		"to":          string(incident.StateWaitingApproval),
		"reason":      "WhatsApp poll dispatched",
		"actor":       "wa-bridge",
	})

	tok, _, err := minter.Mint(approval.MintRequest{
		IncidentID:     out.IncidentID,
		PlanHash:       planOut.PlanHash,
		OptionID:       "A",
		ActionName:     l2Action,
		StepIDs:        []string{"step-chaos-1"},
		ApproverSender: approver,
	})
	if err != nil {
		out.Error = fmt.Sprintf("mint approval token: %v", err)
		return out
	}

	execOut, err := callToolJSON[mcpserver.ActionExecuteOutput](ctx, session, "action_execute", map[string]any{
		"incident_id":    out.IncidentID,
		"step_id":        "step-chaos-1",
		"action":         l2Action,
		"params":         l2Params,
		"approval_token": tok,
	})
	if err != nil || !execOut.Success {
		out.Error = fmt.Sprintf("action_execute failed: err=%v out=%+v", err, execOut)
		return out
	}

	_, _ = callToolJSON[mcpserver.IncidentTransitionOutput](ctx, session, "incident_transition", map[string]any{
		"incident_id": out.IncidentID,
		"to":          string(incident.StateVerifying),
		"reason":      "L2 action completed; starting 120s health verification",
		"actor":       "franken-remediator",
	})

	// 4. Majukan waktu pasca eksekusi L2 (10s) lalu rekam 120 detik telemetri pulih ke PSIRing
	// agar sampel lonjakan pra-remediasi keluar dari jendela [now-120s, now]
	advanceClock(10 * time.Second)
	setHealthyMetrics(mfs, apiCg, 155*1024*1024)
	for step := 0; step <= 8; step++ {
		if step > 0 {
			advanceClock(15 * time.Second)
		}
		mcpSrv.PSIRing().Record("/franken.slice/haunted-api.service", mcpserver.PSIPoint{
			At:            clockFn(),
			SomeAvg10:     1.2,
			FullAvg10:     0.1,
			MemoryCurrent: 155 * 1024 * 1024,
		})
	}

	vhOut, err := callToolJSON[mcpserver.VerifyHealthOutput](ctx, session, "verify_health", map[string]any{
		"incident_id":             out.IncidentID,
		"unit":                    "haunted-api.service",
		"window_seconds":          120,
		"probe_url":               healthURL,
		"require_window_coverage": true,
		"auto_transition":         true,
	})
	if err != nil || !vhOut.Healthy {
		out.Error = fmt.Sprintf("verify_health failed: err=%v reasons=%v", err, vhOut.FailureReasons)
		return out
	}
	out.HealthPassed = vhOut.Healthy
	out.RolledBackReflexes = vhOut.RolledBackReflexes
	out.FinalState = vhOut.State
	if vhOut.State != string(incident.StateResolved) {
		out.Error = fmt.Sprintf("expected final state RESOLVED, got %s", vhOut.State)
		return out
	}
	if vhOut.RolledBackReflexes != out.ReflexCount {
		out.Error = fmt.Sprintf("expected %d reflexes rolled back, got %d", out.ReflexCount, vhOut.RolledBackReflexes)
		return out
	}

	// 5. Hasilkan laporan postmortem markdown terredaksi secara otomatis
	pmOut, err := callToolJSON[mcpserver.PostmortemGenerateOutput](ctx, session, "postmortem_generate", map[string]any{
		"incident_id": out.IncidentID,
		"author":      "franken-remediator",
		"notes":       fmt.Sprintf("Automated chaos test run #%d (%s) recovered cleanly.", runNum, scenario),
	})
	if err != nil {
		out.Error = fmt.Sprintf("postmortem_generate failed: %v", err)
		return out
	}
	if strings.Contains(pmOut.Markdown, "chaos_secret_jwt_payload") {
		out.Error = "SECURITY VIOLATION: secret leaked into generated postmortem"
		return out
	}
	out.PostmortemPath = pmOut.FilePath
	out.Passed = true
	return out
}

func injectChaosScenario(mfs *kernelfs.MemFS, apiCg string, journalReader *chaosJournalReader, scenario Scenario, runNum int) (string, string, map[string]any) {
	// Reset /proc zombie terlebih dahulu agar tidak tercampur antar skenario
	mfs.SetFile("/proc/1305/stat", "1305 (worker) S 1200 1200 1200 0 -1 4194560 0 0 0 0\n")

	switch scenario {
	case ScenarioMemoryLeak:
		// TTO < 30s dan memory.current naik tajam dari 160 MiB -> 490 MiB
		mfs.SetFile(apiCg+"/memory.current", "490000000\n")
		mfs.SetFile(apiCg+"/memory.events", fmt.Sprintf("low 0\nhigh %d\nmax 0\noom 0\noom_kill 0\n", runNum))
		mfs.SetFile(apiCg+"/memory.pressure", "some avg10=28.50 avg60=14.00 avg300=4.00 total=5000\nfull avg10=3.20 avg60=1.20 avg300=0.40 total=800\n")
		journalReader.SetLines([]string{
			"2026-11-13T12:00:01Z haunted-api FATAL: JavaScript heap out of memory Authorization: Bearer chaos_secret_jwt_payload",
		})
		return "heap_leak", "pm2_reload", map[string]any{"app": "haunted-api"}

	case ScenarioMemorySpike:
		mfs.SetFile(apiCg+"/memory.current", "440000000\n")
		mfs.SetFile(apiCg+"/memory.events", fmt.Sprintf("low 0\nhigh %d\nmax %d\noom 0\noom_kill 0\n", runNum, runNum))
		mfs.SetFile(apiCg+"/memory.pressure", "some avg10=36.00 avg60=12.00 avg300=3.00 total=7000\nfull avg10=7.50 avg60=2.10 avg300=0.60 total=1500\n")
		journalReader.SetLines([]string{
			"2026-11-13T12:00:01Z haunted-api WARN: request burst triggered memory high threshold from 10.99.88.77",
		})
		return "traffic_spike", "unit_restart", map[string]any{"unit": "haunted-api.service"}

	case ScenarioForkStorm:
		mfs.SetFile(apiCg+"/memory.current", "470000000\n")
		mfs.SetFile(apiCg+"/memory.events", fmt.Sprintf("low 0\nhigh %d\nmax %d\noom 0\noom_kill 0\n", runNum, runNum))
		mfs.SetFile(apiCg+"/memory.pressure", "some avg10=32.00 avg60=15.00 avg300=5.00 total=6200\nfull avg10=5.40 avg60=2.00 avg300=0.50 total=1200\n")
		mfs.SetFile("/proc/1305/stat", "1305 (worker) S 1200 1200 1200 0 -1 4194560 0 0 0 0\n")
		journalReader.SetLines([]string{
			"2026-11-13T12:00:01Z haunted-api ERROR: PM2 worker fork storm / restart loop detected",
		})
		return "fork_storm", "process_terminate", map[string]any{"pid": 1305}

	case ScenarioZombieStorm:
		mfs.SetFile(apiCg+"/memory.current", "430000000\n")
		mfs.SetFile(apiCg+"/memory.events", fmt.Sprintf("low 0\nhigh %d\nmax %d\noom 0\noom_kill 0\n", runNum, runNum))
		mfs.SetFile(apiCg+"/memory.pressure", "some avg10=27.00 avg60=11.00 avg300=3.00 total=4500\nfull avg10=2.50 avg60=0.90 avg300=0.20 total=600\n")
		mfs.SetFile("/proc/1305/stat", "1305 (zombie-child) Z 1200 1200 1200 0 -1 4194560 0 0 0 0\n")
		journalReader.SetLines([]string{
			"2026-11-13T12:00:01Z haunted-api WARN: accumulated unreaped child zombie processes under ppid 1200",
		})
		return "zombie_accumulation", "zombie_reap", map[string]any{"parent_pid": 1200}

	default: // ScenarioLogFlood
		mfs.SetFile(apiCg+"/memory.current", "450000000\n")
		mfs.SetFile(apiCg+"/memory.events", fmt.Sprintf("low 0\nhigh %d\nmax %d\noom 0\noom_kill 0\n", runNum, runNum))
		mfs.SetFile(apiCg+"/memory.pressure", "some avg10=29.00 avg60=13.00 avg300=4.00 total=5100\nfull avg10=6.10 avg60=2.40 avg300=0.70 total=1100\n")
		journalReader.SetLines([]string{
			"2026-11-13T12:00:01Z haunted-api ERROR: ENOMEM during log flood postgres://admin:chaos_secret_jwt_payload@10.0.0.9:5432/db",
		})
		return "log_flood", "unit_restart", map[string]any{"unit": "haunted-api.service"}
	}
}

func setHealthyMetrics(mfs *kernelfs.MemFS, apiCg string, memBytes uint64) {
	mfs.SetFile(apiCg+"/memory.current", fmt.Sprintf("%d\n", memBytes))
	mfs.SetFile(apiCg+"/memory.pressure", "some avg10=1.20 avg60=0.90 avg300=0.50 total=100\nfull avg10=0.10 avg60=0.05 avg300=0.01 total=10\n")
}

func seedBaseMemFS() *kernelfs.MemFS {
	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpu memory io pids\n")
	mfs.SetFile("/sys/fs/cgroup/memory.reclaim", "")
	mfs.SetFile("/proc/meminfo", "MemTotal:        2097152 kB\nMemFree:          524288 kB\nMemAvailable:    1048576 kB\n")
	mfs.SetFile("/proc/loadavg", "0.35 0.30 0.25 1/90 1200\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=1.10 avg60=0.80 avg300=0.40 total=100\nfull avg10=0.10 avg60=0.05 avg300=0.02 total=10\n")

	apiCg := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	mfs.SetFile(apiCg+"/memory.current", "160000000\n")
	mfs.SetFile(apiCg+"/memory.max", "536870912\n")
	mfs.SetFile(apiCg+"/memory.high", "450000000\n")
	mfs.SetFile(apiCg+"/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	mfs.SetFile(apiCg+"/memory.pressure", "some avg10=1.20 avg60=0.90 avg300=0.50 total=100\nfull avg10=0.10 avg60=0.05 avg300=0.01 total=10\n")
	mfs.SetFile(apiCg+"/memory.reclaim", "")
	mfs.SetFile(apiCg+"/cgroup.procs", "1200\n1305\n")

	mfs.SetFile("/proc/1/stat", "1 (systemd) S 0 1 1 0 -1 4194560 0 0 0 0\n")
	mfs.SetFile("/proc/1/status", "Name:\tsystemd\nVmRSS:\t   10000 kB\n")
	mfs.SetFile("/proc/1200/stat", "1200 (node) S 1 1200 1200 0 -1 4194560 0 0 0 0\n")
	mfs.SetFile("/proc/1200/cmdline", "node\x00server.js\x00")
	mfs.SetFile("/proc/1200/status", "Name:\tnode\nVmRSS:\t  150000 kB\n")
	mfs.SetFile("/proc/1305/stat", "1305 (worker) S 1200 1200 1200 0 -1 4194560 0 0 0 0\n")
	mfs.SetFile("/proc/1305/status", "Name:\tworker\nVmRSS:\t   20000 kB\n")
	return mfs
}

func callToolJSON[T any](ctx context.Context, session *mcp.ClientSession, name string, args map[string]any) (T, error) {
	var zero T
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		return zero, err
	}
	if res == nil {
		return zero, errors.New("empty tool result")
	}
	if res.IsError {
		raw, _ := json.Marshal(res.Content)
		return zero, fmt.Errorf("tool %s error: %s", name, string(raw))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return zero, err
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return zero, fmt.Errorf("decode %s output: %w", name, err)
	}
	return out, nil
}
