package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/psi"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

const (
	hauntedAPICgroup = "/sys/fs/cgroup/franken.slice/haunted-api.service"
	hauntedAPIRel    = "/franken.slice/haunted-api.service"
	lateCgroup       = "/sys/fs/cgroup/franken.slice/late.service"
	lateRel          = "/franken.slice/late.service"
	doomedCgroup     = "/sys/fs/cgroup/system.slice/doomed.service"
	doomedRel        = "/system.slice/doomed.service"

	rediscoveryTestInterval = 20 * time.Millisecond
	rediscoveryWaitTimeout  = time.Second
)

// watchTracker mencatat watcher palsu yang sedang memblokir per path beserta callback pemicunya,
// sehingga test dapat memicu event dan memastikan watcher benar-benar berhenti saat context dibatalkan.
type watchTracker struct {
	mu       sync.Mutex
	active   map[string]int
	handlers map[string]func()
}

func (w *watchTracker) block(ctx context.Context, path string, onEvent func()) error {
	w.mu.Lock()
	if w.active == nil {
		w.active = make(map[string]int)
		w.handlers = make(map[string]func())
	}
	w.active[path]++
	w.handlers[path] = onEvent
	w.mu.Unlock()

	<-ctx.Done()

	w.mu.Lock()
	w.active[path]--
	if w.active[path] <= 0 {
		delete(w.active, path)
		delete(w.handlers, path)
	}
	w.mu.Unlock()
	return nil
}

func (w *watchTracker) isActive(path string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.active[path] > 0
}

func (w *watchTracker) activeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := 0
	for _, n := range w.active {
		total += n
	}
	return total
}

// fire memanggil callback watcher aktif pada path (di luar lock) seolah kernel mengirim notifikasi.
func (w *watchTracker) fire(path string) bool {
	w.mu.Lock()
	fn := w.handlers[path]
	w.mu.Unlock()
	if fn == nil {
		return false
	}
	fn()
	return true
}

// trackingPSIPoller mengimplementasikan psi.TriggerPoller di atas watchTracker.
type trackingPSIPoller struct{ watchTracker }

func (p *trackingPSIPoller) Watch(ctx context.Context, pressurePath string, _ psi.TriggerSpec, onEvent func()) error {
	return p.block(ctx, pressurePath, onEvent)
}

// trackingInotifyPoller mengimplementasikan cgroup.InotifyPoller di atas watchTracker.
type trackingInotifyPoller struct{ watchTracker }

func (p *trackingInotifyPoller) Watch(ctx context.Context, targetPath string, onChange func()) error {
	return p.block(ctx, targetPath, onChange)
}

// newSentinelTestDeps membangun store SQLite sementara, katalog kebijakan, mesin refleks, dan MCP server di atas MemFS.
// Driver properti dan admission selalu palsu/sementara agar test tidak pernah menyentuh systemctl atau /run host.
func newSentinelTestDeps(t *testing.T, mfs *kernelfs.MemFS) (*incident.Store, *policy.Catalog, *reflex.Engine, *mcpserver.Server) {
	t.Helper()
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "sentinel_rediscover.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cat := loadTestCatalog(t)
	eng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:           store,
		FS:              mfs,
		Catalog:         cat,
		PropertyDriver:  newSpyPropDriver(),
		AdmissionDriver: reflex.NewFSAdmissionDriver(t.TempDir()),
	})
	if err != nil {
		t.Fatalf("reflex.NewEngine: %v", err)
	}

	srv, err := mcpserver.New(mcpserver.Config{
		NodeName: "pi-rediscover",
		Store:    store,
		Catalog:  cat,
		Reflex:   eng,
		FS:       mfs,
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}
	t.Cleanup(srv.Close)
	return store, cat, eng, srv
}

// rediscoveryHarness merangkai daemon Sentinel dengan MemFS, poller palsu yang dapat dilacak, clock tetap,
// dan interval pendek agar rediscovery target dapat diuji tanpa menunggu lama.
type rediscoveryHarness struct {
	daemon  *Daemon
	store   *incident.Store
	srv     *mcpserver.Server
	psi     *trackingPSIPoller
	inotify *trackingInotifyPoller
	now     time.Time

	eventsMu sync.Mutex
	events   []mcpserver.StreamEvent

	stopOnce sync.Once
	cancel   context.CancelFunc
	runErr   chan error
}

func newRediscoveryHarness(t *testing.T, mfs *kernelfs.MemFS, cgroupPaths []string, sampleInterval time.Duration) *rediscoveryHarness {
	t.Helper()
	store, cat, eng, srv := newSentinelTestDeps(t, mfs)
	h := &rediscoveryHarness{
		store:   store,
		srv:     srv,
		psi:     &trackingPSIPoller{},
		inotify: &trackingInotifyPoller{},
		now:     time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC),
	}
	d, err := New(Config{
		NodeName:           "pi-rediscover",
		FS:                 mfs,
		CgroupRoot:         "/sys/fs/cgroup",
		ProcRoot:           "/proc",
		CgroupPaths:        cgroupPaths,
		PSIPoller:          h.psi,
		InotifyPoller:      h.inotify,
		SampleInterval:     sampleInterval,
		RollbackInterval:   50 * time.Millisecond,
		RediscoverInterval: rediscoveryTestInterval,
		// Harness ini menghitung setiap evaluasi lewat titik ring di bawah jam beku, jadi throttle ring 500 ms
		// (yang diuji terpisah di TestDaemon_ThrottlesFastPathRingWrites) dimatikan di sini.
		RingWriteInterval: -1,
		Store:             store,
		Catalog:           cat,
		Reflex:            eng,
		MCPServer:         srv,
		Clock:             func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}
	h.daemon = d

	// Satu langganan SSE seumur test, dikuras goroutine terpisah. Unsubscribe baru dilakukan setelah Run
	// berhenti (cleanup LIFO) karena Unsubscribe yang bersamaan dengan Publish dapat memicu send on closed channel.
	subID, ch, _ := srv.Broker().Subscribe(0)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for ev := range ch {
			h.eventsMu.Lock()
			h.events = append(h.events, ev)
			h.eventsMu.Unlock()
		}
	}()
	t.Cleanup(func() {
		srv.Broker().Unsubscribe(subID)
		<-drained
	})
	return h
}

// start menjalankan daemon.Run di goroutine terpisah; penghentian dijamin lewat t.Cleanup bila test gagal lebih awal.
func (h *rediscoveryHarness) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.runErr = make(chan error, 1)
	go func() { h.runErr <- h.daemon.Run(ctx) }()
	t.Cleanup(func() { h.stop(t) })
}

// stop membatalkan context Run lalu memastikan Run kembali bersih tanpa watcher yang tertinggal.
func (h *rediscoveryHarness) stop(t *testing.T) {
	t.Helper()
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case err := <-h.runErr:
			if err != nil {
				t.Errorf("daemon.Run returned error on shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("daemon.Run did not return within 2s after context cancel")
			return
		}
		if n := h.psi.activeCount(); n != 0 {
			t.Errorf("%d PSI watchers still running after Run returned (goroutine leak)", n)
		}
		if n := h.inotify.activeCount(); n != 0 {
			t.Errorf("%d memory.events watchers still running after Run returned (goroutine leak)", n)
		}
	})
}

// evaluatedPoints menghitung titik ring PSI hasil EvaluateOnce (yang selalu membawa memory.current) untuk cgroup relatif.
func (h *rediscoveryHarness) evaluatedPoints(rel string) int {
	n := 0
	for _, pt := range h.srv.PSIRing().Query(rel, 10, h.now) {
		if pt.MemoryCurrent > 0 {
			n++
		}
	}
	return n
}

// hasTargetEvent memeriksa event SSE yang sudah diterima untuk tipe eventType dengan data cgroup == rel.
func (h *rediscoveryHarness) hasTargetEvent(eventType, rel string) bool {
	h.eventsMu.Lock()
	defer h.eventsMu.Unlock()
	for _, ev := range h.events {
		if ev.Type == eventType && ev.Data["cgroup"] == rel {
			return true
		}
	}
	return false
}

// auditCount menghitung baris audit tingkat daemon (incident_id kosong) bertipe eventType dengan payload cgroup == cg.
func (h *rediscoveryHarness) auditCount(t *testing.T, eventType, cg string) int {
	t.Helper()
	entries, err := h.store.GetAuditTrail(context.Background(), "")
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.EventType != eventType {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(e.PayloadJSON), &payload); err != nil {
			t.Fatalf("audit %s payload is not valid JSON: %q (%v)", eventType, e.PayloadJSON, err)
		}
		if payload["cgroup"] == cg {
			n++
		}
	}
	return n
}

// eventually melakukan polling kondisi hingga terpenuhi atau batas waktu habis; kegagalan dicatat lewat t.Errorf.
func eventually(t *testing.T, what string, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(rediscoveryWaitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Errorf("timed out after %v waiting for %s", rediscoveryWaitTimeout, what)
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// mustEventually sama seperti eventually namun menghentikan test karena langkah berikutnya bergantung pada kondisi ini.
func mustEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	if !eventually(t, what, cond) {
		t.FailNow()
	}
}

// setLeafServiceCgroup membuat fixture leaf cgroup service lengkap. memory.current ditulis terakhir agar discovery
// tidak melihat cgroup setengah jadi (di kernel, seluruh berkas antarmuka muncul bersamaan saat mkdir).
func setLeafServiceCgroup(mfs *kernelfs.MemFS, cgPath string, currentBytes uint64) {
	mfs.SetFile(cgPath+"/memory.max", "524288000\n")
	mfs.SetFile(cgPath+"/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	mfs.SetFile(cgPath+"/memory.pressure", "some avg10=0.50 avg60=0.20 avg300=0.10 total=50\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	mfs.SetFile(cgPath+"/memory.current", fmt.Sprintf("%d\n", currentBytes))
}

// removeLeafServiceCgroup menghapus seluruh berkas fixture beserta direktorinya, menyimulasikan rmdir cgroup oleh systemd.
func removeLeafServiceCgroup(mfs *kernelfs.MemFS, cgPath string) {
	for _, name := range []string{"memory.current", "memory.max", "memory.events", "memory.pressure"} {
		mfs.Remove(cgPath + "/" + name)
	}
	mfs.Remove(cgPath)
}

func TestNew_RediscoverIntervalDefaultsWhenNotPositive(t *testing.T) {
	mfs := seedBaseHostFS()
	store, cat, eng, srv := newSentinelTestDeps(t, mfs)

	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "zero uses default", in: 0, want: 10 * time.Second},
		{name: "negative uses default", in: -5 * time.Second, want: 10 * time.Second},
		{name: "positive is kept", in: 25 * time.Millisecond, want: 25 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(Config{
				FS:                 mfs,
				Store:              store,
				Catalog:            cat,
				Reflex:             eng,
				MCPServer:          srv,
				RediscoverInterval: tc.in,
			})
			if err != nil {
				t.Fatalf("sentinel.New: %v", err)
			}
			if d.cfg.RediscoverInterval != tc.want {
				t.Fatalf("RediscoverInterval = %v, want %v", d.cfg.RediscoverInterval, tc.want)
			}
		})
	}
}

func TestDaemon_RunMonitorsServiceCgroupCreatedAfterStartup(t *testing.T) {
	mfs := seedBaseHostFS()
	setLeafServiceCgroup(mfs, hauntedAPICgroup, 209715200)

	h := newRediscoveryHarness(t, mfs, nil, rediscoveryTestInterval)
	h.start(t)
	mustEventually(t, "initial target haunted-api.service to be sampled", func() bool {
		return h.evaluatedPoints(hauntedAPIRel) > 0
	})

	// Workload baru muncul setelah Sentinel berjalan (seperti systemd-run pada chaos/haunted_workload.sh)
	setLeafServiceCgroup(mfs, lateCgroup, 52428800)

	eventually(t, "PSI watcher on late.service memory.pressure", func() bool {
		return h.psi.isActive(lateCgroup + "/memory.pressure")
	})
	eventually(t, "memory.events watcher on late.service", func() bool {
		return h.inotify.isActive(lateCgroup + "/memory.events")
	})
	eventually(t, "telemetry.target_added SSE event for late.service", func() bool {
		return h.hasTargetEvent("telemetry.target_added", lateRel)
	})
	eventually(t, "TARGET_ADDED audit row for late.service", func() bool {
		return h.auditCount(t, "TARGET_ADDED", lateRel) == 1
	})
	eventually(t, "sampling loop to record late.service in the PSI ring", func() bool {
		return h.evaluatedPoints(lateRel) >= 2
	})

	// Target lama tetap dipantau setelah target baru ditambahkan
	if !h.psi.isActive(hauntedAPICgroup + "/memory.pressure") {
		t.Errorf("PSI watcher of initial target haunted-api.service stopped after a new target was added")
	}

	h.stop(t)
}

func TestDaemon_RunStopsMonitoringCgroupWhoseDirectoryIsRemoved(t *testing.T) {
	mfs := seedBaseHostFS()
	setLeafServiceCgroup(mfs, hauntedAPICgroup, 209715200)
	setLeafServiceCgroup(mfs, doomedCgroup, 104857600)

	h := newRediscoveryHarness(t, mfs, nil, rediscoveryTestInterval)
	h.start(t)
	mustEventually(t, "both initial targets watched and sampled", func() bool {
		return h.psi.isActive(doomedCgroup+"/memory.pressure") &&
			h.inotify.isActive(doomedCgroup+"/memory.events") &&
			h.psi.isActive(hauntedAPICgroup+"/memory.pressure") &&
			h.evaluatedPoints(doomedRel) > 0 &&
			h.evaluatedPoints(hauntedAPIRel) > 0
	})

	// systemd menghapus direktori cgroup saat unit berhenti
	removeLeafServiceCgroup(mfs, doomedCgroup)

	eventually(t, "PSI watcher of removed doomed.service to be cancelled", func() bool {
		return !h.psi.isActive(doomedCgroup + "/memory.pressure")
	})
	eventually(t, "memory.events watcher of removed doomed.service to be cancelled", func() bool {
		return !h.inotify.isActive(doomedCgroup + "/memory.events")
	})
	eventually(t, "telemetry.target_removed SSE event for doomed.service", func() bool {
		return h.hasTargetEvent("telemetry.target_removed", doomedRel)
	})
	eventually(t, "TARGET_REMOVED audit row for doomed.service", func() bool {
		return h.auditCount(t, "TARGET_REMOVED", doomedRel) == 1
	})

	// Beri jeda dua tick agar iterasi sampling yang sedang berjalan selesai, lalu pastikan cgroup hilang tidak lagi disampel
	time.Sleep(2 * rediscoveryTestInterval)
	errorsBefore := h.auditCount(t, "SAMPLE_ERROR", doomedCgroup)
	survivorBefore := h.evaluatedPoints(hauntedAPIRel)
	time.Sleep(150 * time.Millisecond)
	if errorsAfter := h.auditCount(t, "SAMPLE_ERROR", doomedCgroup); errorsAfter != errorsBefore {
		t.Errorf("removed doomed.service is still sampled: SAMPLE_ERROR rows grew from %d to %d", errorsBefore, errorsAfter)
	}
	if survivorAfter := h.evaluatedPoints(hauntedAPIRel); survivorAfter <= survivorBefore {
		t.Errorf("surviving target haunted-api.service stopped being sampled (%d -> %d points)", survivorBefore, survivorAfter)
	}
	if !h.psi.isActive(hauntedAPICgroup+"/memory.pressure") || !h.inotify.isActive(hauntedAPICgroup+"/memory.events") {
		t.Errorf("watchers of surviving target haunted-api.service were cancelled")
	}

	// Target awal diumumkan saat startup sehingga konsumen SSE mengetahui set target lengkap
	for _, rel := range []string{hauntedAPIRel, doomedRel} {
		if !h.hasTargetEvent("telemetry.target_added", rel) {
			t.Errorf("missing telemetry.target_added SSE event for initial target %s", rel)
		}
	}

	h.stop(t)
}

func TestDaemon_RunRoutesFastSignalsToCgroupAddedAfterStartup(t *testing.T) {
	mfs := seedBaseHostFS()
	setLeafServiceCgroup(mfs, hauntedAPICgroup, 209715200)

	// Interval sampling sangat panjang: hanya baseline startup yang berjalan, sehingga setiap evaluasi
	// tambahan pasti berasal dari jalur cepat PSI atau memory.events.
	h := newRediscoveryHarness(t, mfs, nil, time.Hour)
	h.start(t)
	mustEventually(t, "startup baseline sample of haunted-api.service", func() bool {
		return h.evaluatedPoints(hauntedAPIRel) == 1
	})

	setLeafServiceCgroup(mfs, lateCgroup, 52428800)
	latePressure := lateCgroup + "/memory.pressure"
	mustEventually(t, "PSI watcher on late.service memory.pressure", func() bool {
		return h.psi.isActive(latePressure)
	})
	if got := h.evaluatedPoints(lateRel); got != 0 {
		t.Fatalf("late.service evaluated %d times before any fast signal, want 0", got)
	}

	// Event PSI milik target baru harus dievaluasi terhadap snapshot set target terkini
	h.psi.fire(latePressure)
	eventually(t, "late.service evaluation after its own PSI event", func() bool {
		return h.evaluatedPoints(lateRel) == 1
	})

	// Event PSI host tetap disebar ke seluruh target terkini, termasuk target yang baru ditemukan
	if !h.psi.fire("/proc/pressure/memory") {
		t.Fatalf("host PSI watcher on /proc/pressure/memory is not running")
	}
	eventually(t, "host PSI fan-out to late.service", func() bool {
		return h.evaluatedPoints(lateRel) == 2
	})
	eventually(t, "host PSI fan-out to haunted-api.service", func() bool {
		return h.evaluatedPoints(hauntedAPIRel) == 2
	})

	// Delta memory.events pada target baru juga memicu evaluasi jalur cepat
	mfs.SetFile(lateCgroup+"/memory.events", "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0\n")
	if !h.inotify.fire(lateCgroup + "/memory.events") {
		t.Fatalf("memory.events watcher on late.service is not running")
	}
	eventually(t, "late.service evaluation after memory.events delta", func() bool {
		return h.evaluatedPoints(lateRel) == 3
	})

	h.stop(t)
}

func TestDaemon_RunActivatesConfiguredCgroupPathOnceMemoryCurrentExists(t *testing.T) {
	mfs := seedBaseHostFS()
	// Leaf service lain di system.slice tidak boleh ikut dipantau ketika CgroupPaths dikonfigurasi eksplisit
	decoyCgroup := "/sys/fs/cgroup/system.slice/worker.service"
	setLeafServiceCgroup(mfs, decoyCgroup, 104857600)

	h := newRediscoveryHarness(t, mfs, []string{lateRel}, rediscoveryTestInterval)
	h.start(t)

	// Beberapa tick rediscovery dan sampling berlalu selagi cgroup yang dikonfigurasi belum ada
	time.Sleep(5 * rediscoveryTestInterval)
	if n := h.auditCount(t, "SAMPLE_ERROR", lateCgroup); n != 0 {
		t.Errorf("configured path sampled before its memory.current existed: %d SAMPLE_ERROR rows, want 0", n)
	}
	if h.hasTargetEvent("telemetry.target_added", lateRel) {
		t.Errorf("configured path announced as target before its memory.current existed")
	}

	setLeafServiceCgroup(mfs, lateCgroup, 52428800)

	eventually(t, "memory.events watcher on configured late.service", func() bool {
		return h.inotify.isActive(lateCgroup + "/memory.events")
	})
	eventually(t, "PSI watcher on configured late.service", func() bool {
		return h.psi.isActive(lateCgroup + "/memory.pressure")
	})
	eventually(t, "telemetry.target_added SSE event for configured late.service", func() bool {
		return h.hasTargetEvent("telemetry.target_added", lateRel)
	})
	eventually(t, "configured late.service to be sampled", func() bool {
		return h.evaluatedPoints(lateRel) >= 1
	})

	if h.psi.isActive(decoyCgroup+"/memory.pressure") || h.hasTargetEvent("telemetry.target_added", "/system.slice/worker.service") {
		t.Errorf("auto-discovered worker.service was monitored even though CgroupPaths is configured")
	}

	h.stop(t)
}

func TestDaemon_VanishedTargetClosesOpenIncidentAndDetectsSubsequentLeak(t *testing.T) {
	mfs := seedBaseHostFS()
	chaosCG := "/sys/fs/cgroup/franken.slice/franken-chaos-workload.service"
	chaosRel := "/franken.slice/franken-chaos-workload.service"

	// Gunakan jam yang bisa dimajukan deterministik untuk kedua fase kebocoran
	var clockMu sync.Mutex
	curNow := time.Date(2026, 11, 14, 4, 29, 0, 0, time.UTC)
	advance := func(d time.Duration) {
		clockMu.Lock()
		curNow = curNow.Add(d)
		clockMu.Unlock()
	}
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curNow
	}

	store, cat, eng, srv := newSentinelTestDeps(t, mfs)
	psiPoller := &trackingPSIPoller{}
	inoPoller := &trackingInotifyPoller{}
	d, err := New(Config{
		NodeName:           "ip-test",
		FS:                 mfs,
		CgroupRoot:         "/sys/fs/cgroup",
		ProcRoot:           "/proc",
		PSIPoller:          psiPoller,
		InotifyPoller:      inoPoller,
		SampleInterval:     20 * time.Millisecond,
		RollbackInterval:   50 * time.Millisecond,
		RediscoverInterval: 20 * time.Millisecond,
		RingWriteInterval:  -1,
		Store:              store,
		Catalog:            cat,
		Reflex:             eng,
		MCPServer:          srv,
		Clock:              nowFn,
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}

	setLeafServiceCgroup(mfs, chaosCG, 20*1024*1024)
	mfs.SetFile(chaosCG+"/memory.max", "209715200\n") // 200 MiB

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()
	defer func() {
		cancel()
		<-runErr
	}()

	// 1. Picu insiden P1 pertama (REFLEX_APPLIED) melalui kenaikan cepat TTO < 30 detik
	mustEventually(t, "initial baseline on chaos workload", func() bool {
		return len(srv.PSIRing().Query(chaosRel, 5, nowFn())) >= 1
	})
	advance(2 * time.Second)
	mfs.SetFile(chaosCG+"/memory.current", "190000000\n")
	mfs.SetFile(chaosCG+"/memory.pressure", "some avg10=40.00 avg60=12.00 avg300=2.00 total=500\nfull avg10=6.00 avg60=1.50 avg300=0.30 total=80\n")

	var firstID string
	mustEventually(t, "first REFLEX_APPLIED incident on chaos workload", func() bool {
		open, listErr := store.ListOpenIncidents(context.Background())
		if listErr != nil || len(open) != 1 {
			return false
		}
		firstID = open[0].ID
		return open[0].Cgroup == chaosRel && open[0].State == incident.StateReflexApplied
	})

	// 2. Unit transien selesai: systemd menghapus direktori cgroup sebelum hysteresis 120 detik sempat berjalan
	advance(5 * time.Second)
	removeLeafServiceCgroup(mfs, chaosCG)

	mustEventually(t, "vanished transient unit incident auto-resolved", func() bool {
		inc, getErr := store.GetIncident(context.Background(), firstID)
		return getErr == nil && inc.State == incident.StateResolved && inc.ClosedAt != nil
	})

	// 3. Jalankan ulang unit transien dengan nama yang sama -> insiden kedua WAJIB terdeteksi (tidak tertelan)
	advance(15 * time.Second)
	setLeafServiceCgroup(mfs, chaosCG, 20*1024*1024)
	mfs.SetFile(chaosCG+"/memory.max", "209715200\n")

	mustEventually(t, "second chaos workload discovered", func() bool {
		return psiPoller.isActive(chaosCG + "/memory.pressure")
	})
	advance(2 * time.Second)
	mfs.SetFile(chaosCG+"/memory.current", "192000000\n")
	mfs.SetFile(chaosCG+"/memory.pressure", "some avg10=38.00 avg60=10.00 avg300=2.00 total=600\nfull avg10=7.00 avg60=2.00 avg300=0.40 total=90\n")

	mustEventually(t, "second fresh incident opened on recreated chaos workload", func() bool {
		open, listErr := store.ListOpenIncidents(context.Background())
		return listErr == nil && len(open) == 1 && open[0].ID != firstID && open[0].Cgroup == chaosRel
	})
}

func TestDaemon_StartupReconcilesVanishedAndLiveOpenIncidents(t *testing.T) {
	mfs := seedBaseHostFS()
	liveCG := "/sys/fs/cgroup/system.slice/haunted-api.service"
	liveRel := "/system.slice/haunted-api.service"
	vanishedRel := "/franken.slice/franken-chaos-workload.service"
	setLeafServiceCgroup(mfs, liveCG, 150*1024*1024)
	mfs.SetFile(liveCG+"/memory.max", "209715200\n")

	store, cat, eng, srv := newSentinelTestDeps(t, mfs)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 14, 1, 27, 14, 0, time.UTC)

	// Tanamkan 2 insiden sebelum restart: satu unitnya sudah hilang (macet REFLEX_APPLIED), satu masih hidup
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID: "INC-STALE-VANISHED", Node: "ip-startup", Cgroup: vanishedRel, Severity: "P1", State: incident.StateReflexApplied, OpenedAt: t0,
	}); err != nil {
		t.Fatalf("seed vanished incident: %v", err)
	}
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID: "INC-STALE-LIVE", Node: "ip-startup", Cgroup: liveRel, Severity: "P2", State: incident.StateDetected, OpenedAt: t0.Add(time.Minute),
	}); err != nil {
		t.Fatalf("seed live incident: %v", err)
	}

	d, err := New(Config{
		NodeName:           "ip-startup",
		FS:                 mfs,
		PSIPoller:          &trackingPSIPoller{},
		InotifyPoller:      &trackingInotifyPoller{},
		SampleInterval:     20 * time.Millisecond,
		RediscoverInterval: 50 * time.Millisecond,
		RingWriteInterval:  -1,
		Store:              store,
		Catalog:            cat,
		Reflex:             eng,
		MCPServer:          srv,
		Clock:              func() time.Time { return t0.Add(2 * time.Minute) },
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, 180*time.Millisecond)
	defer cancel()
	if runErr := d.Run(runCtx); runErr != nil {
		t.Fatalf("daemon.Run: %v", runErr)
	}

	vanished, _ := store.GetIncident(ctx, "INC-STALE-VANISHED")
	if vanished.State != incident.StateResolved || vanished.ClosedAt == nil {
		t.Errorf("expected stale vanished incident closed on startup (RESOLVED), got state=%s closed=%v", vanished.State, vanished.ClosedAt)
	}

	// Target hidup tidak boleh membuka insiden duplikat baru meski sempat tertekan
	list, _ := store.ListIncidents(ctx, "", 20)
	if len(list) != 2 {
		t.Errorf("expected strictly the 2 seeded incidents without duplicate for live target, got %d (%+v)", len(list), list)
	}
}

func TestDaemon_SingleProcessOOMOnVanishedCgroupCapturedViaDeltaAndJournal(t *testing.T) {
	mfs := seedBaseHostFS()
	store, cat, eng, srv := newSentinelTestDeps(t, mfs)

	curNow := time.Date(2026, 11, 14, 4, 33, 26, 0, time.UTC)
	journalPayloads := strings.Join([]string{
		`{"_SYSTEMD_UNIT":"init.scope","_COMM":"systemd","_PID":"1","UNIT":"franken-chaos-workload.service","MESSAGE":"franken-chaos-workload.service: The kernel OOM killer killed some processes in this unit.","__REALTIME_TIMESTAMP":"1794630806000000"}`,
		`{"_SYSTEMD_UNIT":"init.scope","_COMM":"systemd","_PID":"1","UNIT":"franken-chaos-workload.service","MESSAGE":"franken-chaos-workload.service: Failed with result 'oom-kill'.","__REALTIME_TIMESTAMP":"1794630806001000"}`,
	}, "\n") + "\n"

	d, err := New(Config{
		NodeName:           "ip-oom",
		FS:                 mfs,
		PSIPoller:          &trackingPSIPoller{},
		InotifyPoller:      &trackingInotifyPoller{},
		JournalStream:      strings.NewReader(journalPayloads),
		SampleInterval:     time.Hour,
		RediscoverInterval: time.Hour,
		RingWriteInterval:  -1,
		Store:              store,
		Catalog:            cat,
		Reflex:             eng,
		MCPServer:          srv,
		Clock:              func() time.Time { return curNow },
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}

	subID, evCh, _ := srv.Broker().Subscribe(0)
	defer srv.Broker().Unsubscribe(subID)

	// 1. Uji jalur journal saat unit OOM dan cgroup transien sudah telanjur dihapus systemd:
	// Dua baris log OOM beruntun harus dideduplikasi menjadi SATU insiden POST_OOM berstatus akhir ESCALATED.
	runCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if runErr := d.Run(runCtx); runErr != nil {
		t.Fatalf("daemon.Run: %v", runErr)
	}

	allIncs, _ := store.ListIncidents(context.Background(), "", 10)
	if len(allIncs) != 1 {
		t.Fatalf("expected 1 deduped POST_OOM incident from systemd OOM journal burst, got %d (%+v)", len(allIncs), allIncs)
	}
	if allIncs[0].Severity != "POST_OOM" || allIncs[0].State != incident.StateEscalated || allIncs[0].ClosedAt == nil {
		t.Fatalf("expected POST_OOM/ESCALATED/closed incident from vanished unit OOM, got %+v", allIncs[0])
	}

	// 2. Uji jalur EventsDelta fallback saat memory.events mengirim delta OOMKill lalu direktori lenyap sebelum SampleCgroup
	d.handleEventsDelta(context.Background(), cgroup.EventsDelta{
		Cgroup:  "/franken.slice/fast-oom-worker.service",
		Current: cgroup.MemoryEvents{Max: 1, OOM: 1, OOMKill: 1},
		Delta:   cgroup.MemoryEvents{Max: 1, OOM: 1, OOMKill: 1},
		At:      curNow.Add(15 * time.Second),
	})

	allAfterDelta, _ := store.ListIncidents(context.Background(), "", 10)
	if len(allAfterDelta) != 2 {
		t.Fatalf("expected second POST_OOM incident from vanished cgroup EventsDelta fallback, got %d (%+v)", len(allAfterDelta), allAfterDelta)
	}

	// Pastikan minimal dua event incident.opened ber-severity POST_OOM terkirim lewat SSE untuk WA bridge
	openedPOSTOOM := 0
	for {
		select {
		case ev := <-evCh:
			if ev.Type == "incident.opened" && ev.Severity == "POST_OOM" {
				openedPOSTOOM++
			}
		default:
			goto doneDrain
		}
	}
doneDrain:
	if openedPOSTOOM != 2 {
		t.Errorf("expected 2 SSE incident.opened POST_OOM alerts, got %d", openedPOSTOOM)
	}
}

type daemonBlockingReclaimFS struct {
	*kernelfs.MemFS
	mu      sync.Mutex
	release chan struct{}
	calls   int
}

func (f *daemonBlockingReclaimFS) WriteFile(filePath string, data []byte) error {
	if strings.HasSuffix(filePath, "memory.reclaim") {
		f.mu.Lock()
		f.calls++
		ch := f.release
		f.mu.Unlock()
		<-ch
		return nil
	}
	return f.MemFS.WriteFile(filePath, data)
}

func TestDaemon_BlockedReclaimDoesNotDeadlockThrottleOrVanishedClose(t *testing.T) {
	mfs := seedBaseHostFS()
	mfs.SetFile("/proc/meminfo", "MemTotal:       1048576 kB\nMemFree:         524288 kB\n")
	cgPath := "/sys/fs/cgroup/franken.slice/franken-chaos-workload.service"
	rel := "/franken.slice/franken-chaos-workload.service"
	mfs.SetFile(cgPath+"/memory.current", "130000000\n")
	mfs.SetFile(cgPath+"/memory.max", "167772160\n") // 160 MiB
	mfs.SetFile(cgPath+"/memory.pressure", "some avg10=35.00 avg60=10.00 avg300=1.00 total=100\nfull avg10=8.00 avg60=2.00 avg300=0.50 total=20\n")
	mfs.SetFile(cgPath+"/memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")

	release := make(chan struct{})
	var closeOnce sync.Once
	defer closeOnce.Do(func() { close(release) })
	bfs := &daemonBlockingReclaimFS{MemFS: mfs, release: release}

	store, err := incident.NewStore(filepath.Join(t.TempDir(), "blocked_reclaim.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	spyProp := newSpyPropDriver()
	t0 := time.Date(2026, 11, 14, 14, 30, 0, 0, time.UTC)
	curNow := t0
	eng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                bfs,
		Catalog:           cat,
		PropertyDriver:    spyProp,
		AdmissionDriver:   reflex.NewFSAdmissionDriver(t.TempDir()),
		HostMemTotalBytes: 1024 * 1024 * 1024,
		ReclaimTimeout:    25 * time.Millisecond,
		Clock:             func() time.Time { return curNow },
	})
	if err != nil {
		t.Fatalf("reflex.NewEngine: %v", err)
	}

	srv, err := mcpserver.New(mcpserver.Config{
		NodeName: "ip-172-31-45-195",
		Store:    store,
		Catalog:  cat,
		Reflex:   eng,
		FS:       bfs,
		Clock:    func() time.Time { return curNow },
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	d, err := New(Config{
		NodeName:           "ip-172-31-45-195",
		FS:                 bfs,
		PSIPoller:          &trackingPSIPoller{},
		InotifyPoller:      &trackingInotifyPoller{},
		SampleInterval:     time.Hour,
		RediscoverInterval: 20 * time.Millisecond,
		RingWriteInterval:  -1,
		Store:              store,
		Catalog:            cat,
		Reflex:             eng,
		MCPServer:          srv,
		Clock:              func() time.Time { return curNow },
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}

	watchCtx, watchCancel := context.WithCancel(context.Background())
	var watchWG sync.WaitGroup
	defer func() {
		watchCancel()
		watchWG.Wait()
	}()

	ctx := context.Background()
	sinks := targetWatchSinks{
		wg:       &watchWG,
		psiCh:    make(chan psi.PressureEvent, 8),
		eventsCh: make(chan cgroup.EventsDelta, 8),
	}
	d.reconcileTargets(watchCtx, sinks)

	// Picu kebocoran cepat hingga P1 walau memory.reclaim memblokir di kernel
	for i, cur := range []uint64{130000000, 145000000, 158000000} {
		curNow = t0.Add(time.Duration(i) * time.Second)
		mfs.SetFile(cgPath+"/memory.current", fmt.Sprintf("%d\n", cur))
		if _, evalErr := d.EvaluateOnce(ctx, cgPath); evalErr != nil {
			t.Fatalf("EvaluateOnce[%d]: %v", i, evalErr)
		}
	}

	// P1 harus membuka insiden, ApplyReclaim timeout tanpa hang, ApplyThrottle berjalan, dan state menjadi REFLEX_APPLIED
	incs, err := store.ListIncidents(ctx, "", 10)
	if err != nil || len(incs) != 1 {
		t.Fatalf("expected 1 open P1 incident after blocked reclaim, got %d (err=%v)", len(incs), err)
	}
	inc1 := incs[0]
	if inc1.State != incident.StateReflexApplied {
		t.Fatalf("expected incident %s to reach REFLEX_APPLIED via ApplyThrottle despite stalled reclaim, got %s", inc1.ID, inc1.State)
	}
	if count, cErr := store.CountAuditByEvent(ctx, inc1.ID, "REFLEX_RECLAIM_SKIPPED"); cErr != nil || count < 1 {
		t.Fatalf("expected at least 1 REFLEX_RECLAIM_SKIPPED audit entry, got %d (err=%v)", count, cErr)
	}

	// Unit transien berhenti dan direktori cgroup hilang -> evalMu tidak boleh deadlock saat rediscovery menutup insiden
	mfs.Remove(cgPath + "/memory.current")
	mfs.Remove(cgPath)
	d.reconcileTargets(watchCtx, sinks)

	closedInc, err := store.GetIncident(ctx, inc1.ID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if closedInc.State != incident.StateResolved || closedInc.ClosedAt == nil {
		t.Fatalf("expected %s auto-resolved immediately after target vanished, got state=%s closedAt=%v", inc1.ID, closedInc.State, closedInc.ClosedAt)
	}

	// Chaos uji kedua pada nama unit yang sama & menit yang sama segera mengalami OOM -> wajib tercatat POST_OOM/ESCALATED
	curNow = curNow.Add(5 * time.Second)
	d.handleEventsDelta(ctx, cgroup.EventsDelta{
		Cgroup:  cgPath,
		Current: cgroup.MemoryEvents{Max: 1, OOM: 1, OOMKill: 1},
		Delta:   cgroup.MemoryEvents{Max: 1, OOM: 1, OOMKill: 1},
		At:      curNow,
	})

	incsAfter, err := store.ListIncidents(ctx, "", 10)
	if err != nil || len(incsAfter) != 2 {
		t.Fatalf("expected second chaos workload OOM to create new incident in %s (got %d: %+v, err=%v)", rel, len(incsAfter), incsAfter, err)
	}
	var foundOOM bool
	for _, candidate := range incsAfter {
		if candidate.ID != inc1.ID && candidate.Severity == "POST_OOM" && candidate.State == incident.StateEscalated {
			foundOOM = true
		}
	}
	if !foundOOM {
		t.Fatalf("expected second incident to be POST_OOM/ESCALATED, got %+v", incsAfter)
	}
}
