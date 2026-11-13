package sentinel

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/detector"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/psi"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

type spyPropDriver struct {
	mu      sync.Mutex
	current map[string]reflex.UnitProperties
	calls   []string
}

func newSpyPropDriver() *spyPropDriver {
	return &spyPropDriver{current: make(map[string]reflex.UnitProperties)}
}

func (s *spyPropDriver) GetProperties(_ context.Context, unit string) (reflex.UnitProperties, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.current[unit]; ok {
		return p, nil
	}
	return reflex.UnitProperties{MemoryHigh: "infinity"}, nil
}

func (s *spyPropDriver) SetProperties(_ context.Context, unit string, props reflex.UnitProperties) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current[unit] = props
	s.calls = append(s.calls, unit+":"+props.MemoryHigh)
	return nil
}

func (s *spyPropDriver) Calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

type mockPSIPoller struct {
	mu       sync.Mutex
	triggers map[string]func()
}

func (m *mockPSIPoller) Watch(ctx context.Context, pressurePath string, _ psi.TriggerSpec, onEvent func()) error {
	m.mu.Lock()
	if m.triggers == nil {
		m.triggers = make(map[string]func())
	}
	m.triggers[pressurePath] = onEvent
	m.mu.Unlock()
	<-ctx.Done()
	return nil
}

type mockInotify struct{}

func (m *mockInotify) Watch(ctx context.Context, _ string, _ func()) error {
	<-ctx.Done()
	return nil
}

func loadTestCatalog(t *testing.T) *policy.Catalog {
	t.Helper()
	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	return cat
}

func setupHealthyMemFS() *kernelfs.MemFS {
	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "memory cpu io pids\n")
	mfs.SetFile("/proc/meminfo", "MemTotal:        4194304 kB\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=1.20 avg60=0.80 avg300=0.20 total=100\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	cg := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	mfs.SetFile(cg+"/memory.current", "209715200\n") // 200 MiB
	mfs.SetFile(cg+"/memory.max", "524288000\n")     // 500 MiB
	mfs.SetFile(cg+"/memory.reclaim", "0\n")
	mfs.SetFile(cg+"/memory.stat", "anon 180000000\nfile 29715200\n")
	mfs.SetFile(cg+"/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	mfs.SetFile(cg+"/memory.pressure", "some avg10=2.00 avg60=1.00 avg300=0.50 total=200\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	return mfs
}

func TestDaemon_FailsFastWithoutCgroupOrPSI(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	cat := loadTestCatalog(t)
	eng, err := reflex.NewEngine(reflex.EngineConfig{Store: store, FS: mfs, Catalog: cat})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	mcpSrv, err := mcpserver.New(mcpserver.Config{
		NodeName: "pi-test",
		Store:    store,
		Catalog:  cat,
		Reflex:   eng,
		FS:       mfs,
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	daemon, err := New(Config{
		NodeName:  "pi-test",
		FS:        mfs,
		Store:     store,
		Catalog:   cat,
		Reflex:    eng,
		MCPServer: mcpSrv,
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}

	if runErr := daemon.Run(context.Background()); runErr == nil || !strings.Contains(runErr.Error(), "probe failed") {
		t.Fatalf("expected fail-fast probe error on missing cgroup v2 / PSI, got %v", runErr)
	}
}

func TestDaemon_EndToEndLeakDetectionReflexAndSSE(t *testing.T) {
	mfs := setupHealthyMemFS()
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	cat := loadTestCatalog(t)
	propDrv := newSpyPropDriver()
	eng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    propDrv,
		AdmissionDriver:   reflex.NewFSAdmissionDriver(t.TempDir()),
		HostMemTotalBytes: 4 * 1024 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	mcpSrv, err := mcpserver.New(mcpserver.Config{
		NodeName: "pi-e2e",
		Store:    store,
		Catalog:  cat,
		Reflex:   eng,
		FS:       mfs,
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	baseNow := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	curNow := baseNow
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return curNow
	}

	journalLogs := `{"MESSAGE":"FATAL ERROR: JavaScript heap out of memory connecting to postgres://app:TopSecretPass99@10.0.0.8:5432/prod","_SYSTEMD_UNIT":"haunted-api.service","_COMM":"node","_PID":"5512"}` + "\n"

	daemon, err := New(Config{
		NodeName:         "pi-e2e",
		FS:               mfs,
		Store:            store,
		Catalog:          cat,
		Reflex:           eng,
		MCPServer:        mcpSrv,
		PSIPoller:        &mockPSIPoller{},
		InotifyPoller:    &mockInotify{},
		JournalStream:    strings.NewReader(journalLogs),
		SampleInterval:   40 * time.Millisecond,
		RollbackInterval: 40 * time.Millisecond,
		Clock:            clock,
		Detector: detector.NewDetector(detector.Config{
			NodeName:          "pi-e2e",
			HostMemTotalBytes: 4 * 1024 * 1024 * 1024,
		}),
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}

	cgPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"

	// 1. Sampel baseline T0 (200 MiB)
	eval1, err := daemon.EvaluateOnce(context.Background(), cgPath)
	if err != nil {
		t.Fatalf("baseline EvaluateOnce: %v", err)
	}
	if eval1.IncidentOpen {
		t.Fatalf("expected no incident on initial sample")
	}

	// 2. Majukan clock +1 detik dan lonjakkan memori ke 490 MiB (limit 500 MiB -> TTO < 30s -> P1)
	mu.Lock()
	curNow = baseNow.Add(1 * time.Second)
	mu.Unlock()
	mfs.SetFile(cgPath+"/memory.current", "490000000\n")
	mfs.SetFile(cgPath+"/memory.pressure", "some avg10=42.50 avg60=18.00 avg300=4.00 total=900\nfull avg10=8.10 avg60=2.00 avg300=0.40 total=150\n")

	eval2, err := daemon.EvaluateOnce(context.Background(), cgPath)
	if err != nil {
		t.Fatalf("pressure EvaluateOnce: %v", err)
	}
	if !eval2.IncidentOpen || eval2.Severity != detector.SeverityP1 {
		t.Fatalf("expected P1 open incident, got open=%v severity=%s", eval2.IncidentOpen, eval2.Severity)
	}

	// Verifikasi SQLite insiden berpindah ke REFLEX_APPLIED dan kedua refleks L1 berjalan
	inc, err := store.GetIncident(context.Background(), eval2.IncidentID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if inc.State != incident.StateReflexApplied {
		t.Errorf("expected state REFLEX_APPLIED, got %s", inc.State)
	}

	reclaimRaw, err := mfs.ReadFile(cgPath + "/memory.reclaim")
	if err != nil || strings.TrimSpace(string(reclaimRaw)) == "0" || strings.TrimSpace(string(reclaimRaw)) == "" {
		t.Errorf("expected memory.reclaim write on leak cgroup, got %q (err=%v)", string(reclaimRaw), err)
	}
	if len(propDrv.Calls()) == 0 {
		t.Errorf("expected cgroup_throttle SetProperties call for haunted-api.service")
	}

	// Verifikasi PSIRingBuffer merekam seri PSI cgroup target
	pts := mcpSrv.PSIRing().Query("/franken.slice/haunted-api.service", 5, clock())
	if len(pts) < 2 {
		t.Errorf("expected >= 2 PSI ring points, got %d", len(pts))
	}

	// 3. Jalankan daemon Run singkat untuk memverifikasi journal stream redaction + host PSI polling + clean shutdown
	runCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := daemon.Run(runCtx); err != nil {
		t.Fatalf("daemon.Run failed: %v", err)
	}

	evidences, err := store.GetEvidenceByIncident(context.Background(), inc.ID)
	if err != nil {
		t.Fatalf("GetEvidenceByIncident: %v", err)
	}
	var foundRedactedJournal bool
	for _, ev := range evidences {
		if ev.Kind == "journal_pattern" {
			foundRedactedJournal = true
			if strings.Contains(ev.RedactedData, "TopSecretPass99") {
				t.Errorf("journal evidence leaked raw DB password: %s", ev.RedactedData)
			}
		}
	}
	if !foundRedactedJournal {
		t.Errorf("expected journal_pattern evidence saved to incident %s", inc.ID)
	}
}

func TestDaemon_SkipsReflexForProtectedUnits(t *testing.T) {
	mfs := setupHealthyMemFS()
	sshdCg := "/sys/fs/cgroup/system.slice/sshd.service"
	mfs.SetFile(sshdCg+"/memory.current", "209715200\n")
	mfs.SetFile(sshdCg+"/memory.max", "524288000\n")
	mfs.SetFile(sshdCg+"/memory.reclaim", "0\n")
	mfs.SetFile(sshdCg+"/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	mfs.SetFile(sshdCg+"/memory.pressure", "some avg10=1.00 avg60=0.50 avg300=0.10 total=10\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	store, err := incident.NewStore(filepath.Join(t.TempDir(), "sentinel.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	cat := loadTestCatalog(t)
	propDrv := newSpyPropDriver()
	eng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:          store,
		FS:             mfs,
		Catalog:        cat,
		PropertyDriver: propDrv,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	mcpSrv, err := mcpserver.New(mcpserver.Config{NodeName: "pi-prot", Store: store, Catalog: cat, Reflex: eng, FS: mfs})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	base := time.Date(2026, 11, 13, 11, 0, 0, 0, time.UTC)
	now := base
	daemon, err := New(Config{
		NodeName:    "pi-prot",
		FS:          mfs,
		Store:       store,
		Catalog:     cat,
		Reflex:      eng,
		MCPServer:   mcpSrv,
		CgroupPaths: []string{sshdCg},
		Clock:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}

	_, _ = daemon.EvaluateOnce(context.Background(), sshdCg)
	now = base.Add(1 * time.Second)
	mfs.SetFile(sshdCg+"/memory.current", "490000000\n")

	eval, err := daemon.EvaluateOnce(context.Background(), sshdCg)
	if err != nil {
		t.Fatalf("EvaluateOnce: %v", err)
	}
	if !eval.IncidentOpen {
		t.Fatalf("expected protected target telemetry to still open alert incident")
	}

	// Invariant P1: tidak boleh memodifikasi cgroup atau unit yang dilindungi
	reclaimRaw, _ := mfs.ReadFile(sshdCg + "/memory.reclaim")
	if strings.TrimSpace(string(reclaimRaw)) != "0" {
		t.Errorf("protected unit sshd.service had memory.reclaim mutated: %q", string(reclaimRaw))
	}
	if len(propDrv.Calls()) > 0 {
		t.Errorf("protected unit sshd.service was throttled: %v", propDrv.Calls())
	}
}
