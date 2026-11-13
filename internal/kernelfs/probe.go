package kernelfs

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// DefaultCgroupRoot adalah lokasi mount standar hierarki unified cgroup v2 di Linux.
	DefaultCgroupRoot = "/sys/fs/cgroup"
	// DefaultProcRoot adalah lokasi mount standar procfs di Linux.
	DefaultProcRoot = "/proc"
)

var (
	// ErrCgroupV2Missing dikembalikan ketika hierarki cgroup v2 tidak ditemukan pada sistem.
	ErrCgroupV2Missing = errors.New("cgroup v2 unified hierarchy is unavailable; boot with systemd.unified_cgroup_hierarchy=1")
	// ErrPSIMissing dikembalikan ketika Pressure Stall Information (PSI) tidak aktif pada kernel.
	ErrPSIMissing = errors.New("kernel PSI (Pressure Stall Information) is unavailable; enable with psi=1 kernel parameter")
	// ErrReclaimUnsupported dikembalikan ketika fitur memory.reclaim tidak didukung atau argumen tidak valid.
	ErrReclaimUnsupported = errors.New("proactive memory.reclaim is unsupported or invalid")
)

// Capabilities menyimpan hasil deteksi fitur kernel pada saat startup Sentinel.
type Capabilities struct {
	CgroupV2      bool
	PSI           bool
	MemoryReclaim bool
	CgroupRoot    string
	ProcRoot      string
}

// Probe memeriksa ketersediaan cgroup v2, PSI, dan fitur memory.reclaim pada sistem.
// Sesuai Requirement 1.4, fungsi ini menolak startup dan menyertakan petunjuk parameter kernel `psi=1` jika PSI tidak tersedia.
func Probe(fsys FS, cgroupRoot, procRoot string) (Capabilities, error) {
	if fsys == nil {
		return Capabilities{}, errors.New("kernelfs: nil FS provided to Probe")
	}
	if cgroupRoot == "" {
		cgroupRoot = DefaultCgroupRoot
	}
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}

	caps := Capabilities{
		CgroupRoot: cgroupRoot,
		ProcRoot:   procRoot,
	}

	// 1. Pastikan cgroup v2 aktif dengan memeriksa keberadaan berkas cgroup.controllers di root cgroup.
	controllersPath := JoinPath(cgroupRoot, "cgroup.controllers")
	controllersRaw, err := fsys.ReadFile(controllersPath)
	if err != nil {
		return caps, fmt.Errorf("%w (failed reading %s: %v)", ErrCgroupV2Missing, controllersPath, err)
	}
	if !containsMemoryController(string(controllersRaw)) {
		// Beberapa root cgroup mendaftarkan memory controller secara implisit jika sudah diaktifkan di subtree,
		// namun kita pastikan setidaknya berkas cgroup.procs atau memory.pressure ada di cgroupRoot.
		if _, statErr := fsys.Stat(JoinPath(cgroupRoot, "cgroup.procs")); statErr != nil {
			return caps, fmt.Errorf("%w (memory controller and cgroup.procs missing in %s)", ErrCgroupV2Missing, cgroupRoot)
		}
	}
	caps.CgroupV2 = true

	// 2. Pastikan PSI (Pressure Stall Information) tersedia dan mengeluarkan metrik "some".
	psiPath := JoinPath(procRoot, "pressure/memory")
	psiRaw, err := fsys.ReadFile(psiPath)
	if err != nil || !strings.Contains(string(psiRaw), "some ") {
		if err != nil {
			return caps, fmt.Errorf("%w (failed reading %s: %v)", ErrPSIMissing, psiPath, err)
		}
		return caps, fmt.Errorf("%w (unexpected format in %s)", ErrPSIMissing, psiPath)
	}
	caps.PSI = true

	// 3. Periksa ketersediaan memory.reclaim (diperkenalkan pada Linux kernel 5.19+).
	caps.MemoryReclaim = detectMemoryReclaim(fsys, cgroupRoot)

	return caps, nil
}

// containsMemoryController memeriksa apakah daftar controller memuat kata "memory".
func containsMemoryController(controllers string) bool {
	for _, field := range strings.Fields(controllers) {
		if field == "memory" {
			return true
		}
	}
	return false
}

// detectMemoryReclaim memeriksa keberadaan berkas memory.reclaim di root cgroup atau sub-slice langsung.
func detectMemoryReclaim(fsys FS, cgroupRoot string) bool {
	if _, err := fsys.Stat(JoinPath(cgroupRoot, "memory.reclaim")); err == nil {
		return true
	}

	entries, err := fsys.ReadDir(cgroupRoot)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := JoinPath(cgroupRoot, entry.Name(), "memory.reclaim")
		if _, err := fsys.Stat(candidate); err == nil {
			return true
		}
	}
	return false
}

// TriggerReclaim memicu reklamasi memori proaktif pada cgroup target sebesar jumlah byte tertentu.
func TriggerReclaim(fsys FS, cgroupPath string, reclaimBytes uint64) error {
	if reclaimBytes == 0 {
		return fmt.Errorf("%w: reclaimBytes must be greater than zero", ErrReclaimUnsupported)
	}
	reclaimFile := JoinPath(cgroupPath, "memory.reclaim")
	payload := []byte(fmt.Sprintf("%d\n", reclaimBytes))
	if err := fsys.WriteFile(reclaimFile, payload); err != nil {
		return fmt.Errorf("reclaim %d bytes on %s: %w", reclaimBytes, reclaimFile, err)
	}
	return nil
}
