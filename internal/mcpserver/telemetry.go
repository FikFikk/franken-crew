package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/psi"
	"github.com/FikFikk/franken-crew/internal/redact"
)

const (
	// DefaultPSIRingCapacity menyimpan 10 menit sampel 1 Hz (600 titik per cgroup/host).
	DefaultPSIRingCapacity = 600
	// maxCgroupWalkDepth membatasi kedalaman pemindaian subtree cgroup agar hemat CPU/memori.
	maxCgroupWalkDepth = 4
)

var (
	// validSystemdUnitRegex mencegah flag injection saat meneruskan nama unit ke journalctl/systemctl.
	validSystemdUnitRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._:-]*$`)
	// ErrInvalidCgroupPath dikembalikan jika parameter path cgroup mencoba traversal keluar cgroupRoot.
	ErrInvalidCgroupPath = errors.New("mcpserver: invalid or out-of-bounds cgroup path")
	// ErrInvalidProbeURL dikembalikan jika URL HTTP health probe tidak mengarah ke loopback lokal.
	ErrInvalidProbeURL = errors.New("mcpserver: http health probe URL must target localhost or loopback address")
)

// PSIPoint merepresentasikan satu titik sampel metrik tekanan PSI dan pemakaian RAM cgroup pada seri waktu.
type PSIPoint struct {
	At            time.Time `json:"at"`
	SomeAvg10     float64   `json:"some_avg10"`
	SomeAvg60     float64   `json:"some_avg60"`
	SomeAvg300    float64   `json:"some_avg300"`
	FullAvg10     float64   `json:"full_avg10"`
	FullAvg60     float64   `json:"full_avg60"`
	FullAvg300    float64   `json:"full_avg300"`
	MemoryCurrent uint64    `json:"memory_current_bytes,omitempty"`
	// Nomor urut internal monolitik untuk membedakan titik pra vs pasca remediasi saat clock identik
	seq uint64
}

// PSIRingBuffer menyimpan histori metrik PSI berkapasitas tetap di memori untuk tool `psi_history` dan `verify_health`.
type PSIRingBuffer struct {
	mu     sync.RWMutex
	maxLen int
	seq    uint64
	series map[string][]PSIPoint
}

// NewPSIRingBuffer membuat ring buffer PSI baru.
func NewPSIRingBuffer(maxPerKey int) *PSIRingBuffer {
	if maxPerKey <= 0 {
		maxPerKey = DefaultPSIRingCapacity
	}
	return &PSIRingBuffer{
		maxLen: maxPerKey,
		series: make(map[string][]PSIPoint),
	}
}

func normalizePSIKey(cgroupName string) string {
	trimmed := strings.TrimSpace(strings.ReplaceAll(cgroupName, "\\", "/"))
	if trimmed == "" || trimmed == "/" || strings.EqualFold(trimmed, "host") {
		return "host"
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(trimmed, "/"))
	return cleaned
}

// CurrentSeq mengembalikan nomor urut sampel PSI terakhir untuk menandai batas observasi forward.
func (rb *PSIRingBuffer) CurrentSeq() uint64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.seq
}

// Record menambahkan satu titik sampel PSI untuk key cgroup atau "host".
func (rb *PSIRingBuffer) Record(cgroupKey string, pt PSIPoint) {
	if pt.At.IsZero() {
		pt.At = time.Now().UTC()
	}
	key := normalizePSIKey(cgroupKey)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.seq++
	pt.seq = rb.seq

	buf := append(rb.series[key], pt)
	if len(buf) > rb.maxLen {
		trim := len(buf) - rb.maxLen
		buf = append([]PSIPoint(nil), buf[trim:]...)
	}
	rb.series[key] = buf
}

// Query mengambil seri titik PSI dalam rentang menit terakhir.
func (rb *PSIRingBuffer) Query(cgroupKey string, minutes int, now time.Time) []PSIPoint {
	if minutes <= 0 {
		minutes = 10
	}
	if minutes > 10 {
		minutes = 10
	}
	cutoff := now.Add(-time.Duration(minutes) * time.Minute)
	key := normalizePSIKey(cgroupKey)

	rb.mu.RLock()
	defer rb.mu.RUnlock()

	src := rb.series[key]
	if len(src) == 0 {
		return nil
	}
	var out []PSIPoint
	for _, pt := range src {
		if !pt.At.Before(cutoff) {
			out = append(out, pt)
		}
	}
	return out
}

// CommandRunner mengabstraksikan eksekusi biner allowlist tanpa shell milik `executor.Executor`.
type CommandRunner interface {
	Execute(ctx context.Context, binary string, args []string, timeout time.Duration) (*executor.Result, error)
}

// JournalReader membaca potongan log systemd journald untuk unit tertentu.
type JournalReader interface {
	Tail(ctx context.Context, unit string, lines int) ([]string, error)
}

// ExecJournalReader membaca log unit menggunakan perintah `journalctl` argumen tetap tanpa shell.
type ExecJournalReader struct {
	Timeout time.Duration
}

// Tail menjalankan `journalctl --unit=<unit> --lines=<lines> --no-pager --output=short-iso`.
func (r *ExecJournalReader) Tail(ctx context.Context, unit string, lines int) ([]string, error) {
	if !validSystemdUnitRegex.MatchString(unit) {
		return nil, fmt.Errorf("invalid systemd unit name %q", unit)
	}
	if lines <= 0 {
		lines = 50
	}
	if lines > 200 {
		lines = 200
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "journalctl",
		"--unit="+unit,
		"--lines="+strconv.Itoa(lines),
		"--no-pager",
		"--output=short-iso",
	)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("journalctl tail for %s: %w (stderr=%s)", unit, err, redact.String(errBuf.String()))
	}

	rawLines := strings.Split(strings.TrimRight(outBuf.String(), "\r\n"), "\n")
	var result []string
	for _, line := range rawLines {
		if strings.TrimSpace(line) != "" {
			result = append(result, line)
		}
	}
	return result, nil
}

// UnitInspector memeriksa status aktif systemd unit untuk `verify_health`.
type UnitInspector interface {
	IsActive(ctx context.Context, unit string) (active bool, state string, err error)
}

// RunnerUnitInspector memeriksa status unit via `systemctl is-active`.
type RunnerUnitInspector struct {
	Runner CommandRunner
}

// IsActive menjalankan `systemctl is-active <unit>` melalui safe fixed-argv runner.
func (u *RunnerUnitInspector) IsActive(ctx context.Context, unit string) (bool, string, error) {
	if !validSystemdUnitRegex.MatchString(unit) {
		return false, "invalid", fmt.Errorf("invalid unit name %q", unit)
	}
	res, err := u.Runner.Execute(ctx, "systemctl", []string{"is-active", unit}, 5*time.Second)
	if err != nil {
		return false, "error", err
	}
	state := strings.TrimSpace(res.Stdout)
	if state == "" {
		state = strings.TrimSpace(res.Stderr)
	}
	return res.ExitCode == 0 && state == "active", state, nil
}

// HTTPProber menjalankan healthcheck HTTP ke endpoint aplikasi lokal.
type HTTPProber interface {
	Probe(ctx context.Context, rawURL string) (statusCode int, err error)
}

// LoopbackHTTPProber hanya mengizinkan health probe menuju loopback lokal untuk mencegah SSRF.
type LoopbackHTTPProber struct {
	Client *http.Client
}

// ValidateLoopbackProbeURL memvalidasi bahwa URL health probe hanya menuju loopback lokal (anti-SSRF).
func ValidateLoopbackProbeURL(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("%w: invalid scheme", ErrInvalidProbeURL)
	}
	host := u.Hostname()
	if !strings.EqualFold(host, "localhost") {
		addr, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !addr.IsLoopback() {
			return "", fmt.Errorf("%w: host %q is not loopback", ErrInvalidProbeURL, host)
		}
	}
	return u.String(), nil
}

// Probe memeriksa kode status HTTP 2xx-3xx pada URL loopback lokal.
func (p *LoopbackHTTPProber) Probe(ctx context.Context, rawURL string) (int, error) {
	safeURL, err := ValidateLoopbackProbeURL(rawURL)
	if err != nil {
		return 0, err
	}

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, safeURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// CgroupMemoryStat merepresentasikan ringkasan penggunaan memori dan PSI satu cgroup.
type CgroupMemoryStat struct {
	Cgroup         string  `json:"cgroup"`
	MemoryCurrent  uint64  `json:"memory_current_bytes"`
	MemoryMax      uint64  `json:"memory_max_bytes"`
	MemoryHigh     uint64  `json:"memory_high_bytes"`
	PSISomeAvg10   float64 `json:"psi_some_avg10"`
	PSIFullAvg10   float64 `json:"psi_full_avg10"`
	OOMCount       uint64  `json:"oom_count"`
	OOMKillCount   uint64  `json:"oom_kill_count"`
}

// ProcessNode merepresentasikan informasi satu proses dalam hierarki cgroup yang sudah disensor.
type ProcessNode struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	Comm      string `json:"comm"`
	State     string `json:"state"`
	RSSBytes  uint64 `json:"rss_bytes"`
	Cmdline   string `json:"cmdline,omitempty"`
	Protected bool   `json:"protected"`
}

// resolveSafeCgroupDir memastikan cgroupPath relatif selalu berada di dalam cgroupRoot.
func resolveSafeCgroupDir(cgroupRoot, cgroupRel string) (string, string, error) {
	cleanRel := strings.ReplaceAll(strings.TrimSpace(cgroupRel), "\\", "/")
	if cleanRel == "" || cleanRel == "/" {
		return kernelfs.JoinPath(cgroupRoot), "/", nil
	}
	for _, seg := range strings.Split(cleanRel, "/") {
		if seg == ".." {
			return "", "", fmt.Errorf("%w: traversal segment '..' rejected", ErrInvalidCgroupPath)
		}
	}
	normRel := path.Clean("/" + strings.TrimPrefix(cleanRel, "/"))
	trimmed := strings.TrimPrefix(normRel, "/")
	fullPath := kernelfs.JoinPath(cgroupRoot, trimmed)
	return fullPath, normRel, nil
}

// readHostMemInfo mem-parsing MemTotal, MemAvailable, dan MemFree (dalam byte) dari `/proc/meminfo`.
func readHostMemInfo(fsys kernelfs.FS, procRoot string) (total, available, free uint64, err error) {
	meminfoPath := kernelfs.JoinPath(procRoot, "meminfo")
	raw, err := fsys.ReadFile(meminfoPath)
	if err != nil {
		return 0, 0, 0, err
	}
	var hasAvail bool
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		bytesVal := kb * 1024
		switch fields[0] {
		case "MemTotal:":
			total = bytesVal
		case "MemAvailable:":
			available = bytesVal
			hasAvail = true
		case "MemFree:":
			free = bytesVal
		}
	}
	if !hasAvail {
		available = free
	}
	if total == 0 {
		return 0, 0, 0, errors.New("MemTotal missing in /proc/meminfo")
	}
	return total, available, free, nil
}

// collectTopCgroups memindai subtree cgroup v2 dan mengurutkan berdasarkan `memory.current` terbesar.
func collectTopCgroups(fsys kernelfs.FS, cgroupRoot string, limit int) ([]CgroupMemoryStat, error) {
	if limit <= 0 {
		limit = 10
	}

	var stats []CgroupMemoryStat
	var walk func(absDir, relPath string, depth int)
	walk = func(absDir, relPath string, depth int) {
		if depth > maxCgroupWalkDepth {
			return
		}
		if relPath != "/" {
			cur, isMax, err := kernelfs.ReadUint64(fsys, kernelfs.JoinPath(absDir, "memory.current"))
			if err == nil && !isMax {
				maxB, maxIsMax, _ := kernelfs.ReadUint64(fsys, kernelfs.JoinPath(absDir, "memory.max"))
				if maxIsMax {
					maxB = 0
				}
				highB, highIsMax, _ := kernelfs.ReadUint64(fsys, kernelfs.JoinPath(absDir, "memory.high"))
				if highIsMax {
					highB = 0
				}
				ev, _ := cgroup.ReadMemoryEvents(fsys, kernelfs.JoinPath(absDir, "memory.events"))
				psiM, psiErr := psi.ReadMetrics(fsys, kernelfs.JoinPath(absDir, "memory.pressure"))
				var some10, full10 float64
				if psiErr == nil {
					some10 = psiM.Some.Avg10
					full10 = psiM.Full.Avg10
				}
				stats = append(stats, CgroupMemoryStat{
					Cgroup:        relPath,
					MemoryCurrent: cur,
					MemoryMax:     maxB,
					MemoryHigh:    highB,
					PSISomeAvg10:  some10,
					PSIFullAvg10:  full10,
					OOMCount:      ev.OOM,
					OOMKillCount:  ev.OOMKill,
				})
			}
		}

		entries, err := fsys.ReadDir(absDir)
		if err != nil {
			return
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			childRel := path.Join(relPath, ent.Name())
			walk(kernelfs.JoinPath(absDir, ent.Name()), childRel, depth+1)
		}
	}

	walk(kernelfs.JoinPath(cgroupRoot), "/", 0)

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].MemoryCurrent == stats[j].MemoryCurrent {
			return stats[i].Cgroup < stats[j].Cgroup
		}
		return stats[i].MemoryCurrent > stats[j].MemoryCurrent
	})

	if len(stats) > limit {
		stats = stats[:limit]
	}
	return stats, nil
}

// collectCgroupPIDs membaca seluruh PID dari `cgroup.procs` target beserta sub-cgroup anaknya.
func collectCgroupPIDs(fsys kernelfs.FS, absDir string) ([]int, error) {
	pidSet := make(map[int]bool)

	var scanDir func(dir string, depth int) error
	scanDir = func(dir string, depth int) error {
		if depth > maxCgroupWalkDepth {
			return nil
		}
		if raw, err := fsys.ReadFile(kernelfs.JoinPath(dir, "cgroup.procs")); err == nil {
			for _, tok := range strings.Fields(string(raw)) {
				if pid, pErr := strconv.Atoi(tok); pErr == nil && pid > 0 {
					pidSet[pid] = true
				}
			}
		}
		entries, err := fsys.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			if ent.IsDir() {
				_ = scanDir(kernelfs.JoinPath(dir, ent.Name()), depth+1)
			}
		}
		return nil
	}

	if err := scanDir(absDir, 0); err != nil && len(pidSet) == 0 {
		return nil, err
	}

	pids := make([]int, 0, len(pidSet))
	for pid := range pidSet {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

// collectProcessTree membaca detail stat, cmdline terredaksi, dan RSS proses dalam suatu cgroup.
func collectProcessTree(fsys kernelfs.FS, procRoot, absCgroupDir string, cat *policy.Catalog) ([]ProcessNode, error) {
	pids, err := collectCgroupPIDs(fsys, absCgroupDir)
	if err != nil {
		return nil, fmt.Errorf("read cgroup pids on %s: %w", absCgroupDir, err)
	}

	nodes := make([]ProcessNode, 0, len(pids))
	for _, pid := range pids {
		pidStr := strconv.Itoa(pid)
		rawStat, err := fsys.ReadFile(kernelfs.JoinPath(procRoot, pidStr, "stat"))
		if err != nil {
			continue
		}
		st, err := cgroup.ParseProcStat(string(rawStat))
		if err != nil {
			continue
		}

		var cmdline string
		if rawCmd, err := fsys.ReadFile(kernelfs.JoinPath(procRoot, pidStr, "cmdline")); err == nil {
			cleaned := strings.TrimSpace(strings.ReplaceAll(string(rawCmd), "\x00", " "))
			cmdline = redact.String(cleaned)
		}

		rssBytes := readProcVmRSS(fsys, procRoot, pidStr)
		protected := false
		if cat != nil {
			protected = cat.IsProtectedPID(st.PID)
		}

		nodes = append(nodes, ProcessNode{
			PID:       st.PID,
			PPID:      st.PPID,
			Comm:      st.Comm,
			State:     st.State,
			RSSBytes:  rssBytes,
			Cmdline:   cmdline,
			Protected: protected,
		})
	}
	return nodes, nil
}

func readProcVmRSS(fsys kernelfs.FS, procRoot, pidStr string) uint64 {
	raw, err := fsys.ReadFile(kernelfs.JoinPath(procRoot, pidStr, "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

