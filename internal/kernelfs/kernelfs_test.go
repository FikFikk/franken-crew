package kernelfs

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestProbe_SuccessFullCapabilities(t *testing.T) {
	// Siapkan fixture sistem berkas dengan dukungan penuh cgroup v2, PSI, dan memory.reclaim
	mfs := NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory pids\n")
	mfs.SetFile("/sys/fs/cgroup/system.slice/memory.reclaim", "")
	mfs.SetFile("/proc/pressure/memory", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	caps, err := Probe(mfs, DefaultCgroupRoot, DefaultProcRoot)
	if err != nil {
		t.Fatalf("expected Probe to succeed, got error: %v", err)
	}
	if !caps.CgroupV2 {
		t.Errorf("expected CgroupV2 to be true")
	}
	if !caps.PSI {
		t.Errorf("expected PSI to be true")
	}
	if !caps.MemoryReclaim {
		t.Errorf("expected MemoryReclaim to be true")
	}
}

func TestProbe_MissingPSI_RefusesStartWithHint(t *testing.T) {
	// Simulasikan sistem dengan cgroup v2 aktif namun PSI tidak diaktifkan di kernel
	mfs := NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")

	_, err := Probe(mfs, DefaultCgroupRoot, DefaultProcRoot)
	if err == nil {
		t.Fatalf("expected error when PSI is missing, got nil")
	}
	if !errors.Is(err, ErrPSIMissing) {
		t.Fatalf("expected ErrPSIMissing, got: %v", err)
	}
	if !strings.Contains(err.Error(), "psi=1") {
		t.Errorf("expected remediation hint 'psi=1' in error message, got: %v", err)
	}
}

func TestProbe_MissingCgroupV2_RefusesStart(t *testing.T) {
	// Simulasikan sistem tanpa hierarki unified cgroup v2
	mfs := NewMemFS()
	mfs.SetFile("/proc/pressure/memory", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	_, err := Probe(mfs, DefaultCgroupRoot, DefaultProcRoot)
	if err == nil {
		t.Fatalf("expected error when cgroup v2 is missing, got nil")
	}
	if !errors.Is(err, ErrCgroupV2Missing) {
		t.Fatalf("expected ErrCgroupV2Missing, got: %v", err)
	}
}

func TestProbe_WithoutMemoryReclaim_StillStarts(t *testing.T) {
	// Simulasikan kernel < 5.19 yang memiliki cgroup v2 dan PSI tetapi belum memiliki berkas memory.reclaim
	mfs := NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=0.10 avg60=0.05 avg300=0.01 total=120\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	caps, err := Probe(mfs, DefaultCgroupRoot, DefaultProcRoot)
	if err != nil {
		t.Fatalf("expected Probe to succeed without memory.reclaim, got: %v", err)
	}
	if caps.MemoryReclaim {
		t.Errorf("expected MemoryReclaim to be false on pre-5.19 kernel fixture")
	}
}

func TestTriggerReclaim_WritesBytesAndHandlesErrors(t *testing.T) {
	mfs := NewMemFS()
	cgroupPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	reclaimFile := cgroupPath + "/memory.reclaim"
	mfs.SetFile(reclaimFile, "")

	// Uji kegagalan jika jumlah byte yang diminta adalah 0
	if err := TriggerReclaim(mfs, cgroupPath, 0); !errors.Is(err, ErrReclaimUnsupported) {
		t.Fatalf("expected ErrReclaimUnsupported for 0 bytes, got: %v", err)
	}

	// Uji penulisan 64 MiB ke memory.reclaim
	const targetBytes = 64 * 1024 * 1024
	if err := TriggerReclaim(mfs, cgroupPath, targetBytes); err != nil {
		t.Fatalf("unexpected error triggering reclaim: %v", err)
	}

	written, err := mfs.ReadFile(reclaimFile)
	if err != nil {
		t.Fatalf("failed reading reclaim file back: %v", err)
	}
	if strings.TrimSpace(string(written)) != "67108864" {
		t.Errorf("expected '67108864' written to memory.reclaim, got %q", string(written))
	}
}

func TestReadHelpers_Uint64AndKeyValueAndMemTotal(t *testing.T) {
	mfs := NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/app.service/memory.current", "104857600\n")
	mfs.SetFile("/sys/fs/cgroup/app.service/memory.max", "max\n")
	mfs.SetFile("/sys/fs/cgroup/app.service/memory.events", "low 0\nhigh 4\nmax 1\noom 1\noom_kill 0\n")
	mfs.SetFile("/proc/meminfo", "MemTotal:        2097152 kB\nMemFree:          524288 kB\n")

	// Uji pembacaan nilai numerik memory.current
	cur, isMax, err := ReadUint64(mfs, "/sys/fs/cgroup/app.service/memory.current")
	if err != nil || isMax || cur != 104857600 {
		t.Fatalf("unexpected ReadUint64 result: cur=%d isMax=%v err=%v", cur, isMax, err)
	}

	// Uji pembacaan nilai literal "max" pada memory.max
	_, isMax, err = ReadUint64(mfs, "/sys/fs/cgroup/app.service/memory.max")
	if err != nil || !isMax {
		t.Fatalf("expected isMax=true on 'max', got isMax=%v err=%v", isMax, err)
	}

	// Uji pembacaan peta key-value pada memory.events
	events, err := ReadKeyValueUint64(mfs, "/sys/fs/cgroup/app.service/memory.events")
	if err != nil {
		t.Fatalf("unexpected error reading memory.events: %v", err)
	}
	if events["high"] != 4 || events["max"] != 1 || events["oom_kill"] != 0 {
		t.Errorf("unexpected memory.events values: %+v", events)
	}

	// Uji pembacaan MemTotal dari /proc/meminfo
	memTotal, err := ReadMemTotalBytes(mfs, "/proc")
	if err != nil {
		t.Fatalf("unexpected error reading MemTotal: %v", err)
	}
	const expectedBytes = 2097152 * 1024
	if memTotal != expectedBytes {
		t.Errorf("expected MemTotal=%d, got %d", expectedBytes, memTotal)
	}

	// Uji penghapusan cgroup simulasi
	mfs.Remove("/sys/fs/cgroup/app.service/memory.current")
	if _, err := mfs.Stat("/sys/fs/cgroup/app.service/memory.current"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected ErrNotExist after Remove, got %v", err)
	}
}

