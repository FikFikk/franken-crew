package chaos

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/detector"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
	"github.com/FikFikk/franken-crew/internal/sentinel"
)

func TestChaosSuite_20ConsecutiveGreenRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	outDir := filepath.Join(t.TempDir(), "chaos-incidents")
	report, err := RunSuite(ctx, Config{
		Runs:       DefaultRuns,
		PolicyPath: filepath.Join("..", "..", "policy", "actions.yaml"),
		OutputDir:  outDir,
		NodeName:   "chaos-node01",
		Approver:   "+6281234567890",
	})
	if err != nil {
		t.Fatalf("RunSuite failed: %v", err)
	}

	if report.Runs != 20 || report.Passed != 20 || report.Failed != 0 {
		for _, r := range report.Results {
			if !r.Passed {
				t.Logf("run #%d (%s) FAILED: %s", r.RunNumber, r.Scenario, r.Error)
			}
		}
		t.Fatalf("expected 20/20 consecutive green chaos runs, got %d/%d (failed=%d)", report.Passed, report.Runs, report.Failed)
	}

	if report.MaxReflexLatencyMs > 250.0 {
		t.Errorf("expected max L1 reflex latency <= 250ms, got %.2fms", report.MaxReflexLatencyMs)
	}

	// Pastikan setiap run menghasilkan postmortem.md yang tersimpan dan status RESOLVED
	seenScenarios := make(map[Scenario]int)
	for _, r := range report.Results {
		seenScenarios[r.Scenario]++
		if r.FinalState != string(incident.StateResolved) {
			t.Errorf("run #%d final state = %s, want RESOLVED", r.RunNumber, r.FinalState)
		}
		if _, statErr := os.Stat(r.PostmortemPath); statErr != nil {
			t.Errorf("run #%d postmortem file missing %q: %v", r.RunNumber, r.PostmortemPath, statErr)
		}
	}
	if len(seenScenarios) != 5 {
		t.Errorf("expected all 5 chaos scenarios covered, got %d", len(seenScenarios))
	}
}

func BenchmarkSentinelEvalAndReflexFootprint(b *testing.B) {
	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		b.Fatalf("LoadCatalog: %v", err)
	}
	store, err := incident.NewStore(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	mfs := seedBaseMemFS()
	apiCg := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	propDriver := newChaosPropertyDriver()
	admDriver := reflex.NewFSAdmissionDriver(filepath.Join(b.TempDir(), "adm"))
	reflexEng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    propDriver,
		AdmissionDriver:   admDriver,
		HostMemTotalBytes: 2 * 1024 * 1024 * 1024,
	})
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	mcpSrv, err := mcpserver.New(mcpserver.Config{
		NodeName: "bench-node",
		Store:    store,
		Catalog:  cat,
		Reflex:   reflexEng,
		FS:       mfs,
	})
	if err != nil {
		b.Fatalf("mcpserver.New: %v", err)
	}
	det := detector.NewDetector(detector.Config{
		NodeName:          "bench-node",
		HostMemTotalBytes: 2 * 1024 * 1024 * 1024,
	})
	daemon, err := sentinel.New(sentinel.Config{
		NodeName:    "bench-node",
		FS:          mfs,
		CgroupRoot:  kernelfs.DefaultCgroupRoot,
		ProcRoot:    kernelfs.DefaultProcRoot,
		CgroupPaths: []string{apiCg},
		Store:       store,
		Catalog:     cat,
		Detector:    det,
		Reflex:      reflexEng,
		MCPServer:   mcpSrv,
	})
	if err != nil {
		b.Fatalf("sentinel.New: %v", err)
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := daemon.EvaluateOnce(ctx, apiCg); err != nil {
			b.Fatalf("EvaluateOnce: %v", err)
		}
	}
}
