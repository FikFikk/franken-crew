package cgroup

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

// ProcessStat merepresentasikan parsing dari berkas /proc/[pid]/stat.
type ProcessStat struct {
	PID   int    `json:"pid"`
	Comm  string `json:"comm"`
	State string `json:"state"`
	PPID  int    `json:"ppid"`
}

// ZombieGroup mengelompokkan anak proses zombie (state Z) berdasarkan Parent PID (PPID).
type ZombieGroup struct {
	ParentPID  int      `json:"parent_pid"`
	ParentComm string   `json:"parent_comm"`
	ChildPIDs  []int    `json:"child_pids"`
	Count      int      `json:"count"`
}

// ZombieReport merepresentasikan laporan komprehensif temuan proses zombie di sistem.
type ZombieReport struct {
	TotalZombies int           `json:"total_zombies"`
	Groups       []ZombieGroup `json:"groups"`
	ScannedAt    time.Time     `json:"scanned_at"`
}

// ParseProcStat mem-parsing teks /proc/[pid]/stat secara aman terhadap nama comm yang memuat spasi atau tanda kurung.
func ParseProcStat(content string) (ProcessStat, error) {
	trimmed := strings.TrimSpace(content)
	openIdx := strings.Index(trimmed, "(")
	closeIdx := strings.LastIndex(trimmed, ")")

	if openIdx == -1 || closeIdx == -1 || closeIdx <= openIdx {
		return ProcessStat{}, fmt.Errorf("malformed /proc stat format: %q", trimmed)
	}

	pidStr := strings.TrimSpace(trimmed[:openIdx])
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return ProcessStat{}, fmt.Errorf("parse pid %q: %w", pidStr, err)
	}

	comm := trimmed[openIdx+1 : closeIdx]
	after := strings.Fields(trimmed[closeIdx+1:])
	if len(after) < 2 {
		return ProcessStat{}, fmt.Errorf("not enough fields after comm in /proc stat: %q", trimmed)
	}

	state := after[0]
	ppid, err := strconv.Atoi(after[1])
	if err != nil {
		return ProcessStat{}, fmt.Errorf("parse ppid %q: %w", after[1], err)
	}

	return ProcessStat{
		PID:   pid,
		Comm:  comm,
		State: state,
		PPID:  ppid,
	}, nil
}

// ScanZombies memindai seluruh direktori proses numerik di /proc dan mengelompokkan proses berstatus 'Z' berdasarkan PPID.
func ScanZombies(fsys kernelfs.FS, procRoot string) (ZombieReport, error) {
	if procRoot == "" {
		procRoot = kernelfs.DefaultProcRoot
	}

	entries, err := fsys.ReadDir(procRoot)
	if err != nil {
		return ZombieReport{}, fmt.Errorf("read proc root %s: %w", procRoot, err)
	}

	// Kumpulkan seluruh data proses untuk memudahkan resolusi ParentComm
	processMap := make(map[int]ProcessStat)
	var zombies []ProcessStat

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Hanya periksa direktori yang berupa angka PID
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		statPath := kernelfs.JoinPath(procRoot, entry.Name(), "stat")
		raw, err := fsys.ReadFile(statPath)
		if err != nil {
			continue
		}

		stat, err := ParseProcStat(string(raw))
		if err != nil {
			continue
		}

		processMap[pid] = stat
		if stat.State == "Z" {
			zombies = append(zombies, stat)
		}
	}

	// Kelompokkan proses zombie berdasarkan PPID
	groupMap := make(map[int][]int)
	for _, z := range zombies {
		groupMap[z.PPID] = append(groupMap[z.PPID], z.PID)
	}

	var groups []ZombieGroup
	for ppid, childPIDs := range groupMap {
		sort.Ints(childPIDs)
		parentComm := "unknown"
		if parentStat, ok := processMap[ppid]; ok {
			parentComm = parentStat.Comm
		} else {
			// Coba baca langsung /proc/[ppid]/comm jika ada
			commPath := kernelfs.JoinPath(procRoot, strconv.Itoa(ppid), "comm")
			if commBytes, err := fsys.ReadFile(commPath); err == nil {
				parentComm = strings.TrimSpace(string(commBytes))
			}
		}

		groups = append(groups, ZombieGroup{
			ParentPID:  ppid,
			ParentComm: parentComm,
			ChildPIDs:  childPIDs,
			Count:      len(childPIDs),
		})
	}

	// Urutkan grup berdasarkan jumlah anak zombie terbanyak
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count == groups[j].Count {
			return groups[i].ParentPID < groups[j].ParentPID
		}
		return groups[i].Count > groups[j].Count
	})

	return ZombieReport{
		TotalZombies: len(zombies),
		Groups:       groups,
		ScannedAt:    time.Now(),
	}, nil
}
