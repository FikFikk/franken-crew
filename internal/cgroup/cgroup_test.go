package cgroup

import (
	"context"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

// mockInotifyPoller menyimulasikan pemicuan event modifikasi berkas untuk pengujian unit.
type mockInotifyPoller struct {
	fn func(ctx context.Context, targetPath string, onChange func()) error
}

func (m *mockInotifyPoller) Watch(ctx context.Context, targetPath string, onChange func()) error {
	return m.fn(ctx, targetPath, onChange)
}

func TestEventsWatcher_DeltaComputationUnder100ms(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	eventsPath := "/sys/fs/cgroup/haunted-api.service/memory.events"
	mfs.SetFile(eventsPath, "low 0\nhigh 2\nmax 1\noom 0\noom_kill 0\n")

	poller := &mockInotifyPoller{
		fn: func(ctx context.Context, targetPath string, onChange func()) error {
			// Simulasikan kernel mengupdate counter max dan oom
			mfs.SetFile(targetPath, "low 0\nhigh 5\nmax 3\noom 1\noom_kill 0\n")
			onChange()
			<-ctx.Done()
			return nil
		},
	}

	watcher := NewEventsWatcher(EventsWatcherConfig{
		FS:     mfs,
		Poller: poller,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan EventsDelta, 2)
	start := time.Now()
	go func() {
		_ = watcher.WatchTarget(ctx, "/haunted-api.service", eventsPath, out)
	}()

	select {
	case delta := <-out:
		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			t.Errorf("expected delta event within 100ms, took %v", elapsed)
		}
		// Baseline awal: high 2, max 1, oom 0
		// Nilai baru: high 5, max 3, oom 1
		// Delta yang diharapkan: high 3, max 2, oom 1
		if delta.Delta.High != 3 || delta.Delta.Max != 2 || delta.Delta.OOM != 1 {
			t.Errorf("unexpected delta values: %+v", delta.Delta)
		}
		if delta.Current.High != 5 || delta.Current.Max != 3 || delta.Current.OOM != 1 {
			t.Errorf("unexpected current values: %+v", delta.Current)
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatalf("timed out waiting for EventsDelta")
	}
}

func TestSampler_SampleCgroup(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	cgPath := "/sys/fs/cgroup/franken.slice/worker.service"
	mfs.SetFile(cgPath+"/memory.current", "262144000\n") // 250 MiB
	mfs.SetFile(cgPath+"/memory.max", "524288000\n")     // 500 MiB
	mfs.SetFile(cgPath+"/memory.stat", "anon 200000000\nfile 60000000\nshmem 2144000\n")
	mfs.SetFile(cgPath+"/memory.events", "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0\n")
	mfs.SetFile(cgPath+"/memory.pressure", "some avg10=12.50 avg60=5.00 avg300=1.00 total=1000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	sampler := NewSampler(mfs, 100*time.Millisecond)

	sample, err := sampler.SampleCgroup(cgPath)
	if err != nil {
		t.Fatalf("unexpected error sampling cgroup: %v", err)
	}

	if sample.MemoryCurrent != 262144000 {
		t.Errorf("expected memory.current 262144000, got %d", sample.MemoryCurrent)
	}
	if sample.MemoryMax != 524288000 {
		t.Errorf("expected memory.max 524288000, got %d", sample.MemoryMax)
	}
	if sample.Stat["anon"] != 200000000 || sample.Stat["file"] != 60000000 {
		t.Errorf("unexpected memory.stat parsed: %+v", sample.Stat)
	}
	if sample.PSISomeAvg10 != 12.50 {
		t.Errorf("expected PSI some avg10 12.50, got %f", sample.PSISomeAvg10)
	}
	if sample.Events.High != 1 {
		t.Errorf("expected Events.High = 1, got %d", sample.Events.High)
	}
}

func TestZombie_ParseProcStatAndScanZombies(t *testing.T) {
	// 1. Uji parsing /proc/[pid]/stat dengan nama comm rumit (memuat spasi dan tanda kurung)
	rawStat := "2048 (worker (pool 1)) Z 1024 2048 1024 0 -1 4194304 120 0 0 0 0 0 0 0 20 0 1 0 100 0 0"
	stat, err := ParseProcStat(rawStat)
	if err != nil {
		t.Fatalf("failed parsing complex /proc stat: %v", err)
	}
	if stat.PID != 2048 || stat.Comm != "worker (pool 1)" || stat.State != "Z" || stat.PPID != 1024 {
		t.Errorf("unexpected parsed stat: %+v", stat)
	}

	// 2. Uji ScanZombies dengan MemFS
	mfs := kernelfs.NewMemFS()
	proc := "/proc"

	// Parent process PID 100 (node parent)
	mfs.SetFile("/proc/100/stat", "100 (node-cluster) S 1 100 100 0")
	mfs.SetFile("/proc/100/comm", "node-cluster\n")

	// Child zombie PID 101, PPID 100
	mfs.SetFile("/proc/101/stat", "101 (worker-leaked) Z 100 101 100 0")

	// Child zombie PID 102, PPID 100
	mfs.SetFile("/proc/102/stat", "102 (worker-leaked) Z 100 102 100 0")

	// Normal running process PID 200, PPID 1
	mfs.SetFile("/proc/200/stat", "200 (sshd) S 1 200 200 0")

	report, err := ScanZombies(mfs, proc)
	if err != nil {
		t.Fatalf("failed scanning zombies: %v", err)
	}

	if report.TotalZombies != 2 {
		t.Fatalf("expected 2 total zombies, got %d", report.TotalZombies)
	}
	if len(report.Groups) != 1 {
		t.Fatalf("expected 1 group for PPID 100, got %d", len(report.Groups))
	}

	grp := report.Groups[0]
	if grp.ParentPID != 100 || grp.ParentComm != "node-cluster" || grp.Count != 2 {
		t.Errorf("unexpected zombie group: %+v", grp)
	}
	if grp.ChildPIDs[0] != 101 || grp.ChildPIDs[1] != 102 {
		t.Errorf("unexpected child PIDs: %v", grp.ChildPIDs)
	}
}
