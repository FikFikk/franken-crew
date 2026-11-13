package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
		Store:              store,
		Catalog:            cat,
		Reflex:             eng,
		MCPServer:          srv,
		Clock:              func() time.Time { return h.now },
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
