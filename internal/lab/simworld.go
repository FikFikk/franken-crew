package lab

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

const (
	mebibyte       = 1024 * 1024
	simCgroupRoot  = "/sys/fs/cgroup"
	simProcRoot    = "/proc"
	simHostTotalKB = 3883788 // MemTotal Raspberry Pi 4 Model B 4 GB
	pageSize       = 4096
)

var (
	psiDecay10  = math.Exp(-1.0 / 10)
	psiDecay60  = math.Exp(-1.0 / 60)
	psiDecay300 = math.Exp(-1.0 / 300)
)

// simClock adalah jam simulasi yang hanya maju saat skenario memanggil Advance.
type simClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *simClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *simClock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return c.now
}

// lockedReader membungkus aliran ChaCha8 deterministik agar aman dibaca dari goroutine handler MCP.
type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (l *lockedReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

// deterministicStream menghasilkan aliran byte ChaCha8 yang sama pada setiap run untuk label yang sama.
func deterministicStream(label string) io.Reader {
	seed := sha256.Sum256([]byte("frankencrew-lab/" + label))
	return &lockedReader{r: rand.NewChaCha8(seed)}
}

// workload memodelkan perilaku memori dan stall satu cgroup per detik simulasi beserta reaksinya terhadap aksi.
type workload interface {
	step(c *simCgroup, now time.Time)
	onReclaim(c *simCgroup, now time.Time, bytes float64)
	onCommand(c *simCgroup, now time.Time, binary string, args []string)
}

// idleWorkload menahan memori datar dengan stall rendah.
type idleWorkload struct{}

func (idleWorkload) step(c *simCgroup, _ time.Time) {
	c.someStall, c.fullStall = 0.3, 0.02
}
func (idleWorkload) onReclaim(*simCgroup, time.Time, float64)          {}
func (idleWorkload) onCommand(*simCgroup, time.Time, string, []string) {}

// simCgroup adalah satu cgroup leaf .service dalam fixture beserta state PSI yang diturunkan dari stall.
type simCgroup struct {
	unit     string
	path     string
	maxBytes uint64
	mem      float64
	high     uint64

	someStall, fullStall    float64
	some10, some60, some300 float64
	full10, full60, full300 float64
	someTotal, fullTotal    float64
	highEvents              uint64

	model workload
}

// simWorld menulis telemetri cgroup ke MemFS setiap detik dan meneruskan efek refleks/aksi ke model beban kerja.
type simWorld struct {
	mfs     *kernelfs.MemFS
	cgroups []*simCgroup
	byUnit  map[string]*simCgroup
	byPath  map[string]*simCgroup

	reclaimMu      sync.Mutex
	pendingReclaim map[string]uint64
}

func newSimWorld(mfs *kernelfs.MemFS) *simWorld {
	w := &simWorld{mfs: mfs, byUnit: map[string]*simCgroup{}, byPath: map[string]*simCgroup{}, pendingReclaim: map[string]uint64{}}
	// Write hook dipanggil saat MemFS terkunci: cukup antrekan permintaan reclaim, efeknya diterapkan pada detik berikutnya
	mfs.SetWriteHook(func(p string, data []byte) error {
		if strings.HasSuffix(p, "/memory.reclaim") {
			if n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
				w.reclaimMu.Lock()
				w.pendingReclaim[path.Dir(p)] += n
				w.reclaimMu.Unlock()
			}
		}
		return nil
	})
	return w
}

func (w *simWorld) addCgroup(unit, slice string, maxBytes uint64, memBytes float64) *simCgroup {
	c := &simCgroup{unit: unit, path: kernelfs.JoinPath(simCgroupRoot, slice, unit), maxBytes: maxBytes, mem: memBytes, model: idleWorkload{}}
	c.some10, c.some60, c.some300 = 0.3, 0.3, 0.3
	c.full10, c.full60, c.full300 = 0.02, 0.02, 0.02
	w.cgroups = append(w.cgroups, c)
	w.byUnit[unit] = c
	w.byPath[c.path] = c
	w.mfs.SetFile(c.path+"/memory.max", fmt.Sprintf("%d\n", maxBytes))
	w.mfs.SetFile(c.path+"/memory.high", "max\n")
	w.mfs.SetFile(c.path+"/memory.reclaim", "")
	w.write(c)
	return c
}

// step memajukan seluruh cgroup satu detik: reclaim tertunda, model beban kerja, PSI EMA, lalu berkas kernel.
func (w *simWorld) step(now time.Time) {
	w.reclaimMu.Lock()
	pending := w.pendingReclaim
	w.pendingReclaim = map[string]uint64{}
	w.reclaimMu.Unlock()

	for _, c := range w.cgroups {
		if n := pending[c.path]; n > 0 {
			c.mem = math.Max(c.mem-float64(n), 32*mebibyte)
			c.model.onReclaim(c, now, float64(n))
		}
		c.model.step(c, now)
		if c.high > 0 && c.mem > float64(c.high) {
			c.highEvents++
		}
		c.some10 = c.some10*psiDecay10 + c.someStall*(1-psiDecay10)
		c.some60 = c.some60*psiDecay60 + c.someStall*(1-psiDecay60)
		c.some300 = c.some300*psiDecay300 + c.someStall*(1-psiDecay300)
		c.full10 = c.full10*psiDecay10 + c.fullStall*(1-psiDecay10)
		c.full60 = c.full60*psiDecay60 + c.fullStall*(1-psiDecay60)
		c.full300 = c.full300*psiDecay300 + c.fullStall*(1-psiDecay300)
		c.someTotal += c.someStall * 1e4
		c.fullTotal += c.fullStall * 1e4
		w.write(c)
	}
	w.writeHost()
}

func (w *simWorld) write(c *simCgroup) {
	cur := uint64(c.mem) / pageSize * pageSize
	anon := uint64(float64(cur)*0.86) / pageSize * pageSize
	file := uint64(float64(cur)*0.11) / pageSize * pageSize
	w.mfs.SetFile(c.path+"/memory.current", fmt.Sprintf("%d\n", cur))
	w.mfs.SetFile(c.path+"/memory.stat", fmt.Sprintf("anon %d\nfile %d\nkernel %d\nsock 0\nshmem 0\n", anon, file, cur-anon-file))
	w.mfs.SetFile(c.path+"/memory.events", fmt.Sprintf("low 0\nhigh %d\nmax 0\noom 0\noom_kill 0\n", c.highEvents))
	w.mfs.SetFile(c.path+"/memory.pressure", fmt.Sprintf(
		"some avg10=%.2f avg60=%.2f avg300=%.2f total=%d\nfull avg10=%.2f avg60=%.2f avg300=%.2f total=%d\n",
		c.some10, c.some60, c.some300, uint64(c.someTotal), c.full10, c.full60, c.full300, uint64(c.fullTotal)))
}

func (w *simWorld) writeHost() {
	var some, full, used float64
	for _, c := range w.cgroups {
		some = math.Max(some, c.some10*0.7)
		full = math.Max(full, c.full10*0.7)
		used += c.mem
	}
	// Sistem dasar (kernel, journald, Sentinel, bridge) memakai sekitar 1.1 GiB pada Pi 4 GB
	used += 1100 * mebibyte
	availKB := uint64(math.Max(float64(simHostTotalKB)*1024-used, 256*mebibyte) / 1024)
	w.mfs.SetFile(kernelfs.JoinPath(simProcRoot, "meminfo"), fmt.Sprintf(
		"MemTotal:        %d kB\nMemFree:          %d kB\nMemAvailable:    %d kB\n", simHostTotalKB, availKB/2, availKB))
	w.mfs.SetFile(kernelfs.JoinPath(simProcRoot, "pressure/memory"), fmt.Sprintf(
		"some avg10=%.2f avg60=%.2f avg300=%.2f total=0\nfull avg10=%.2f avg60=%.2f avg300=%.2f total=0\n", some, some, some, full, full, full))
}

// onCommand meneruskan perintah runner palsu ke cgroup pemilik unit/aplikasi/pid.
func (w *simWorld) onCommand(now time.Time, binary string, args []string) {
	target := ""
	switch {
	case binary == "systemd-run":
		// systemd-run ... -- pm2 <verb> <app> [id]
		for i, a := range args {
			if a == "--" && i+3 < len(args) {
				target = args[i+3] + ".service"
			}
		}
	case binary == "systemctl" && len(args) >= 2:
		target = args[1]
	case binary == "kill" && len(args) >= 2:
		pid, _ := strconv.Atoi(args[1])
		target = w.unitOfPID(pid)
	}
	if c := w.byUnit[target]; c != nil {
		c.model.onCommand(c, now, binary, args)
	}
}

func (w *simWorld) unitOfPID(pid int) string {
	raw, err := w.mfs.ReadFile(kernelfs.JoinPath(simProcRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	return path.Base(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0::")))
}

// setProc menulis entri /proc/<pid> lengkap beserta keanggotaan cgroup v2-nya.
func setProc(mfs *kernelfs.MemFS, pid, ppid int, comm, state, cmdline, cgroupRel string, rssKB int) {
	base := kernelfs.JoinPath(simProcRoot, strconv.Itoa(pid))
	mfs.SetFile(base+"/stat", fmt.Sprintf("%d (%s) %s %d %d %d 0 -1 4194560 0 0 0 0\n", pid, comm, state, ppid, ppid, ppid))
	mfs.SetFile(base+"/status", fmt.Sprintf("Name:\t%s\nState:\t%s\nVmRSS:\t%8d kB\n", comm, state, rssKB))
	mfs.SetFile(base+"/cgroup", "0::"+cgroupRel+"\n")
	if cmdline != "" {
		mfs.SetFile(base+"/cmdline", strings.ReplaceAll(cmdline, " ", "\x00")+"\x00")
	}
}

func removeProc(mfs *kernelfs.MemFS, pid int) {
	base := kernelfs.JoinPath(simProcRoot, strconv.Itoa(pid))
	for _, f := range []string{"stat", "status", "cgroup", "cmdline"} {
		mfs.Remove(base + "/" + f)
	}
	mfs.Remove(base)
}

// simPropertyDriver menggantikan `systemctl set-property --runtime` dan mencerminkan MemoryHigh ke fixture.
type simPropertyDriver struct {
	mu    sync.Mutex
	world *simWorld
	props map[string]reflex.UnitProperties
}

func (d *simPropertyDriver) GetProperties(_ context.Context, unit string) (reflex.UnitProperties, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.props[unit]; ok {
		return p, nil
	}
	return reflex.UnitProperties{MemoryHigh: "infinity", CPUQuota: "", IOWeight: "100"}, nil
}

func (d *simPropertyDriver) SetProperties(_ context.Context, unit string, props reflex.UnitProperties) error {
	d.mu.Lock()
	cur := d.props[unit]
	if props.MemoryHigh != "" {
		cur.MemoryHigh = props.MemoryHigh
	}
	d.props[unit] = cur
	d.mu.Unlock()

	if c := d.world.byUnit[unit]; c != nil && props.MemoryHigh != "" {
		high, err := strconv.ParseUint(props.MemoryHigh, 10, 64)
		if err != nil {
			high = 0 // "infinity" atau "max"
		}
		c.high = high
		val := "max\n"
		if high > 0 {
			val = fmt.Sprintf("%d\n", high)
		}
		d.world.mfs.SetFile(c.path+"/memory.high", val)
	}
	return nil
}

// simRunner adalah runner perintah palsu (systemd-run/pm2/systemctl/kill) yang meneruskan efeknya ke model.
type simRunner struct {
	mu    sync.Mutex
	world *simWorld
	clock *simClock
	calls []string
}

func (r *simRunner) Execute(_ context.Context, binary string, args []string, _ time.Duration) (*executor.Result, error) {
	if binary == "sh" || binary == "bash" {
		return nil, fmt.Errorf("shell interpreter %q forbidden", binary)
	}
	r.mu.Lock()
	r.calls = append(r.calls, binary+" "+strings.Join(args, " "))
	r.mu.Unlock()
	r.world.onCommand(r.clock.Now(), binary, args)
	return &executor.Result{Binary: binary, Args: append([]string(nil), args...), ExitCode: 0, Stdout: "ok"}, nil
}

// simJournal menyajikan baris journal palsu per unit.
type simJournal struct {
	mu    sync.Mutex
	lines map[string][]string
}

func (j *simJournal) Set(unit string, lines []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.lines[unit] = append([]string(nil), lines...)
}

func (j *simJournal) Tail(_ context.Context, unit string, n int) ([]string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	lines := j.lines[unit]
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return append([]string(nil), lines...), nil
}

type simUnitInspector struct{}

func (simUnitInspector) IsActive(context.Context, string) (bool, string, error) {
	return true, "active", nil
}

type simProber struct{}

func (simProber) Probe(context.Context, string) (int, error) { return 200, nil }

// journalLine menyusun baris journalctl --output=short-iso pada node simulasi.
func journalLine(at time.Time, proc string, msg string) string {
	return at.UTC().Format("2006-01-02T15:04:05-0700") + " " + SimulationNode + " " + proc + ": " + msg
}

// ramp bernilai 0..1 secara linear dari start hingga start+dur.
func ramp(now, start time.Time, dur time.Duration) float64 {
	if now.Before(start) {
		return 0
	}
	return math.Min(1, now.Sub(start).Seconds()/dur.Seconds())
}

// jitter memberi variasi kecil yang deterministik agar kurva tidak tampak sintetis lurus.
func jitter(now time.Time, scale float64) float64 {
	s := float64(now.Unix() % 997)
	return scale * (0.6*math.Sin(s*0.73) + 0.4*math.Sin(s*1.91))
}

// sortedKeys mengembalikan kunci map terurut agar iterasi fixture selalu deterministik.
func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
