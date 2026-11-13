package sentinel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/detector"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/journal"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/psi"
	"github.com/FikFikk/franken-crew/internal/redact"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

const (
	defaultSampleInterval     = 1 * time.Second
	defaultRollbackInterval   = 1 * time.Second
	defaultRediscoverInterval = 10 * time.Second
	maxDiscoveredCgroups      = 32
	// defaultRingWriteInterval mencegah banjir inotify (~100/detik saat throttling memory.high) mengusir
	// ring 600 titik yang dirancang menampung ~10 menit histori.
	defaultRingWriteInterval = 500 * time.Millisecond
)

// Config menyimpan seluruh dependensi dan parameter runtime untuk daemon Sentinel.
type Config struct {
	NodeName         string
	FS               kernelfs.FS
	CgroupRoot       string
	ProcRoot         string
	CgroupPaths      []string
	PSIPoller        psi.TriggerPoller
	InotifyPoller    cgroup.InotifyPoller
	JournalStream    io.Reader
	JournalUnits     []string
	SampleInterval   time.Duration
	RollbackInterval time.Duration
	Store            *incident.Store
	Catalog          *policy.Catalog
	Detector         *detector.Detector
	Reflex           *reflex.Engine
	MCPServer        *mcpserver.Server
	HTTPAddr         string
	Clock            func() time.Time
	// RediscoverInterval mengatur seberapa sering set target cgroup dipindai ulang (default 10 detik).
	RediscoverInterval time.Duration
	// RingWriteInterval adalah jarak minimum antar titik ring PSI per kunci cgroup yang ditulis daemon
	// (default 500 ms); nilai negatif menonaktifkan throttle.
	RingWriteInterval time.Duration
	// Monotonic opsional menggantikan time.Now (yang membawa bacaan monotonik) untuk mengukur latensi refleks.
	Monotonic func() time.Time
	// IDSource opsional menyediakan byte ID evidence daemon (simulasi deterministik); nil memakai crypto/rand.
	IDSource io.Reader
}

// Daemon mengorkestrasi seluruh pipeline Sentinel: startup probe, kolektor telemetri,
// detektor TTO EWMA, refleks L1 ber-TTL, penyimpanan SQLite, serta server MCP/SSE.
type Daemon struct {
	cfg           Config
	sampler       *cgroup.Sampler
	psiWatcher    *psi.Watcher
	eventsWatcher *cgroup.EventsWatcher
	evalMu        sync.Mutex
	openByCgroup  map[string]string
	lastSeverity  map[string]detector.Severity
	// Set target hidup: targetOrder menyimpan path absolut sesuai urutan discovery, targetCancel
	// menyimpan pembatal context watcher per target. Keduanya selalu berisi kunci yang sama.
	targetsMu    sync.Mutex
	targetOrder  []string
	targetCancel map[string]context.CancelFunc
	// ringLast menyimpan waktu titik ring terakhir per kunci cgroup untuk throttle RingWriteInterval
	ringMu   sync.Mutex
	ringLast map[string]time.Time
	idMu     sync.Mutex
}

// Jenis pemicu refleks L1 yang dicatat pada event reflex.applied dan audit REFLEX_LATENCY.
const (
	reflexTriggerPSI          = "psi"
	reflexTriggerMemoryEvents = "memory_events"
	reflexTriggerSample       = "sample"
)

// reflexTrigger menyimpan jenis sinyal yang memulai evaluasi beserta instan monotoniknya.
type reflexTrigger struct {
	kind string
	at   time.Time
}

// targetWatchSinks menyatukan WaitGroup milik Run dan channel fast-path yang dipakai watcher per target.
type targetWatchSinks struct {
	wg       *sync.WaitGroup
	psiCh    chan<- psi.PressureEvent
	eventsCh chan<- cgroup.EventsDelta
}

// New membangun instance Sentinel Daemon setelah memvalidasi dependensi inti.
func New(cfg Config) (*Daemon, error) {
	if cfg.Store == nil {
		return nil, errors.New("sentinel: incident store is required")
	}
	if cfg.Catalog == nil {
		return nil, errors.New("sentinel: policy catalog is required")
	}
	if cfg.Reflex == nil {
		return nil, errors.New("sentinel: reflex engine is required")
	}
	if cfg.MCPServer == nil {
		return nil, errors.New("sentinel: mcp server is required")
	}
	if cfg.FS == nil {
		cfg.FS = kernelfs.NewOSFS()
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = kernelfs.DefaultCgroupRoot
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = kernelfs.DefaultProcRoot
	}
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = defaultSampleInterval
	}
	if cfg.RollbackInterval <= 0 {
		cfg.RollbackInterval = defaultRollbackInterval
	}
	if cfg.RediscoverInterval <= 0 {
		cfg.RediscoverInterval = defaultRediscoverInterval
	}
	if cfg.RingWriteInterval == 0 {
		cfg.RingWriteInterval = defaultRingWriteInterval
	}
	if cfg.Monotonic == nil {
		// time.Now membawa bacaan jam monotonik sehingga Sub() kebal terhadap lompatan jam dinding
		cfg.Monotonic = time.Now
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.NodeName == "" {
		cfg.NodeName = "node01"
	}

	if cfg.Detector == nil {
		hostMem, _ := kernelfs.ReadMemTotalBytes(cfg.FS, cfg.ProcRoot)
		cfg.Detector = detector.NewDetector(detector.Config{
			NodeName:          cfg.NodeName,
			HostMemTotalBytes: hostMem,
		})
	}

	psiWatcher := psi.NewWatcher(psi.WatcherConfig{
		FS:     cfg.FS,
		Poller: cfg.PSIPoller,
		OnDegradedAlert: func(cg string, reason error) {
			cfg.MCPServer.Broker().Publish(mcpserver.StreamEvent{
				Type:    "telemetry.degraded",
				Summary: fmt.Sprintf("PSI trigger unsupported on %s (%v); polling at 1 Hz", cg, reason),
			})
		},
	})

	eventsWatcher := cgroup.NewEventsWatcher(cgroup.EventsWatcherConfig{
		FS:     cfg.FS,
		Poller: cfg.InotifyPoller,
	})

	return &Daemon{
		cfg:           cfg,
		sampler:       cgroup.NewSampler(cfg.FS, cfg.SampleInterval),
		psiWatcher:    psiWatcher,
		eventsWatcher: eventsWatcher,
		openByCgroup:  make(map[string]string),
		lastSeverity:  make(map[string]detector.Severity),
		targetCancel:  make(map[string]context.CancelFunc),
		ringLast:      make(map[string]time.Time),
	}, nil
}

// Run menjalankan startup fail-fast probe lalu mengaktifkan seluruh worker Sentinel hingga ctx selesai.
func (d *Daemon) Run(ctx context.Context) error {
	caps, err := kernelfs.Probe(d.cfg.FS, d.cfg.CgroupRoot, d.cfg.ProcRoot)
	if err != nil {
		return fmt.Errorf("sentinel startup capability probe failed: %w", err)
	}
	if !caps.CgroupV2 || !caps.PSI {
		return fmt.Errorf("sentinel startup capability probe failed: cgroup_v2=%t psi=%t", caps.CgroupV2, caps.PSI)
	}

	_ = d.cfg.Store.RecordAudit(ctx, "", "sentinel", "DAEMON_STARTED",
		fmt.Sprintf(`{"node":%q,"cgroup_v2":%t,"psi":%t,"memory_reclaim":%t}`, d.cfg.NodeName, caps.CgroupV2, caps.PSI, caps.MemoryReclaim))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	// Hanya scheduler refleks dan HTTP server yang mengirim error fatal; watcher per target cukup mencatat audit
	errCh := make(chan error, 4)

	psiEvents := make(chan psi.PressureEvent, 64)
	evDeltas := make(chan cgroup.EventsDelta, 64)
	sinks := targetWatchSinks{wg: &wg, psiCh: psiEvents, eventsCh: evDeltas}

	// Bentuk set target awal (beserta watcher fast-path per target) sebelum sampler membaca baseline,
	// lalu kosongkan set saat Run selesai agar daemon dapat dijalankan ulang dengan bersih.
	d.reconcileTargets(runCtx, sinks)
	defer d.stopAllTargets()

	// 1. Jalankan scheduler rollback TTL refleks L1 (termasuk sweep saldo TTL pasca-restart)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if runErr := d.cfg.Reflex.RunScheduler(runCtx, d.cfg.RollbackInterval); runErr != nil && runCtx.Err() == nil {
			errCh <- fmt.Errorf("reflex rollback scheduler: %w", runErr)
		}
	}()

	// 2. Jalankan sampler periodik 1 Hz untuk seluruh cgroup target hidup dan PSI host
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runSamplingLoop(runCtx)
	}()

	// 3. Pindai ulang target cgroup secara berkala agar workload yang muncul atau hilang setelah startup ikut terkelola
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runRediscoveryLoop(runCtx, sinks)
	}()

	// Pasang PSI watcher pada tingkat host (/proc/pressure/memory)
	hostPressure := kernelfs.JoinPath(d.cfg.ProcRoot, "pressure/memory")
	if _, statErr := d.cfg.FS.Stat(hostPressure); statErr == nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if wErr := d.psiWatcher.WatchTarget(runCtx, "host", hostPressure, psiEvents); wErr != nil && runCtx.Err() == nil {
				_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "HOST_PSI_WATCH_WARN", fmt.Sprintf(`{"error":%q}`, wErr.Error()))
			}
		}()
	}

	// 4. Konsumsi event fast-path PSI dan delta memory.events untuk reaksi sub-100ms
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.consumeFastSignals(runCtx, psiEvents, evDeltas)
	}()

	// 5. Alirkan event pola OOM/ENOMEM/heap/PM2 dari systemd journal jika dikonfigurasi
	journalCh := make(chan journal.JournalEvent, 32)
	if d.cfg.JournalStream != nil || len(d.cfg.JournalUnits) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var jErr error
			if d.cfg.JournalStream != nil {
				jErr = journal.Stream(runCtx, d.cfg.JournalStream, journalCh)
			} else {
				jErr = journal.StartJournalctlStream(runCtx, d.cfg.JournalUnits, journalCh)
			}
			if jErr != nil && runCtx.Err() == nil {
				_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "JOURNAL_STREAM_WARN", fmt.Sprintf(`{"error":%q}`, jErr.Error()))
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			d.consumeJournalEvents(runCtx, journalCh)
		}()
	}

	// 6. Jalankan HTTP MCP & SSE server jika HTTPAddr diisi
	if d.cfg.HTTPAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if srvErr := d.cfg.MCPServer.ListenAndServe(runCtx, d.cfg.HTTPAddr); srvErr != nil && runCtx.Err() == nil {
				errCh <- fmt.Errorf("mcp http server: %w", srvErr)
			}
		}()
	}

	var firstErr error
	doneWait := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneWait)
	}()

	select {
	case <-ctx.Done():
		cancel()
		<-doneWait
	case err := <-errCh:
		firstErr = err
		cancel()
		<-doneWait
	case <-doneWait:
	}

	return firstErr
}

// EvaluateOnce mengambil sampel satu cgroup lalu mengevaluasi TTO, state machine SQLite, dan refleks L1.
// Instan pemicu "sample" diambil tepat saat pembacaan sampel dimulai.
func (d *Daemon) EvaluateOnce(ctx context.Context, cgPath string) (detector.Evaluation, error) {
	return d.evaluate(ctx, cgPath, d.newTrigger(reflexTriggerSample))
}

// newTrigger mencatat instan monotonik saat sinyal diterima atau sampel mulai dibaca.
func (d *Daemon) newTrigger(kind string) reflexTrigger {
	return reflexTrigger{kind: kind, at: d.cfg.Monotonic()}
}

// reflexLatencyMS menghitung latensi pemicu -> refleks dalam milidetik (presisi mikrodetik) dari jam monotonik,
// bukan dari jam injeksi cfg.Clock.
func (d *Daemon) reflexLatencyMS(trig reflexTrigger) float64 {
	elapsed := d.cfg.Monotonic().Sub(trig.at)
	if elapsed < 0 {
		elapsed = 0
	}
	return float64(elapsed.Microseconds()) / 1000.0
}

// recordRing menulis titik ring PSI milik daemon dengan throttle per kunci cgroup (RingWriteInterval).
// Keputusan memakai jam daemon agar konsisten untuk jalur cepat maupun sampling 1 Hz.
func (d *Daemon) recordRing(key string, pt mcpserver.PSIPoint) {
	if d.cfg.RingWriteInterval > 0 {
		norm := ringThrottleKey(key)
		now := d.cfg.Clock().UTC()
		d.ringMu.Lock()
		if last, ok := d.ringLast[norm]; ok {
			// Jam yang mundur (mis. koreksi NTP) tidak boleh membungkam ring selama selisihnya
			if elapsed := now.Sub(last); elapsed >= 0 && elapsed < d.cfg.RingWriteInterval {
				d.ringMu.Unlock()
				return
			}
		}
		d.ringLast[norm] = now
		d.ringMu.Unlock()
	}
	d.cfg.MCPServer.PSIRing().Record(key, pt)
}

// ringThrottleKey menormalkan kunci ring seperti PSIRingBuffer ("host" atau path cgroup bersih).
func ringThrottleKey(key string) string {
	trimmed := strings.TrimSpace(strings.ReplaceAll(key, "\\", "/"))
	if trimmed == "" || trimmed == "/" || strings.EqualFold(trimmed, "host") {
		return "host"
	}
	return path.Clean("/" + strings.TrimPrefix(trimmed, "/"))
}

// evaluate adalah varian internal EvaluateOnce yang membawa pemicu refleks ke jalur reflex.
func (d *Daemon) evaluate(ctx context.Context, cgPath string, trig reflexTrigger) (detector.Evaluation, error) {
	sample, err := d.sampler.SampleCgroup(cgPath)
	if err != nil {
		return detector.Evaluation{}, err
	}

	rel := d.relativeCgroup(cgPath)
	now := d.cfg.Clock().UTC()
	if now.IsZero() && !sample.At.IsZero() {
		now = sample.At.UTC()
	}
	// Seragamkan stempel sampel dengan jam daemon agar evidence, ring, dan detektor memakai waktu yang sama
	sample.At = now

	d.recordRing(rel, mcpserver.PSIPoint{
		At:            now,
		SomeAvg10:     sample.PSISomeAvg10,
		FullAvg10:     sample.PSIFullAvg10,
		MemoryCurrent: sample.MemoryCurrent,
	})

	detSample := detector.Sample{
		Cgroup:        rel,
		MemoryCurrent: sample.MemoryCurrent,
		MemoryMax:     sample.MemoryMax,
		PSISomeAvg10:  sample.PSISomeAvg10,
		PSIFullAvg10:  sample.PSIFullAvg10,
		Events: detector.MemoryEvents{
			Low:     sample.Events.Low,
			High:    sample.Events.High,
			Max:     sample.Events.Max,
			OOM:     sample.Events.OOM,
			OOMKill: sample.Events.OOMKill,
		},
		At: now,
	}

	eval := d.cfg.Detector.Evaluate(detSample)
	if err := d.reconcileEvaluation(ctx, cgPath, rel, sample, eval, trig); err != nil {
		return eval, err
	}
	return eval, nil
}

func (d *Daemon) runSamplingLoop(ctx context.Context) {
	// Lakukan pembacaan baseline awal segera saat startup tanpa menunggu tick pertama
	d.sampleAllTargets(ctx, d.snapshotTargets())

	ticker := time.NewTicker(d.cfg.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Ambil snapshot set target hidup pada setiap tick agar target hasil rediscovery ikut disampel
			d.sampleAllTargets(ctx, d.snapshotTargets())
		}
	}
}

// runRediscoveryLoop memindai ulang target cgroup setiap RediscoverInterval hingga ctx selesai.
func (d *Daemon) runRediscoveryLoop(ctx context.Context, sinks targetWatchSinks) {
	ticker := time.NewTicker(d.cfg.RediscoverInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.reconcileTargets(ctx, sinks)
		}
	}
}

// reconcileTargets menyelaraskan set target hidup dengan hasil resolveTargetCgroups: target baru dinyalakan
// watcher-nya di bawah context anak, target yang tidak lagi diinginkan dibatalkan watcher-nya.
func (d *Daemon) reconcileTargets(ctx context.Context, sinks targetWatchSinks) {
	if ctx.Err() != nil {
		return
	}
	desired := d.resolveTargetCgroups()

	d.targetsMu.Lock()
	wanted := make(map[string]bool, len(desired))
	order := make([]string, 0, len(desired))
	var added, removed []string
	for _, cgPath := range desired {
		if wanted[cgPath] {
			continue
		}
		wanted[cgPath] = true
		order = append(order, cgPath)
		if _, exists := d.targetCancel[cgPath]; !exists {
			d.targetCancel[cgPath] = d.startTargetWatchers(ctx, sinks, cgPath)
			added = append(added, cgPath)
		}
	}
	for _, cgPath := range d.targetOrder {
		if wanted[cgPath] {
			continue
		}
		d.targetCancel[cgPath]()
		delete(d.targetCancel, cgPath)
		removed = append(removed, cgPath)
	}
	d.targetOrder = order
	d.targetsMu.Unlock()

	// Siarkan perubahan di luar lock agar sampler dan konsumen fast-path tidak tertahan oleh I/O SSE/SQLite
	broker := d.cfg.MCPServer.Broker()
	for _, cgPath := range added {
		rel := d.relativeCgroup(cgPath)
		broker.Publish(mcpserver.StreamEvent{
			Type:    "telemetry.target_added",
			Summary: fmt.Sprintf("Monitoring new cgroup target %s", rel),
			Data:    map[string]any{"cgroup": rel},
		})
		_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "TARGET_ADDED", fmt.Sprintf(`{"cgroup":%q}`, rel))
	}
	for _, cgPath := range removed {
		rel := d.relativeCgroup(cgPath)
		broker.Publish(mcpserver.StreamEvent{
			Type:    "telemetry.target_removed",
			Summary: fmt.Sprintf("Stopped monitoring cgroup target %s (no longer discovered)", rel),
			Data:    map[string]any{"cgroup": rel},
		})
		_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "TARGET_REMOVED", fmt.Sprintf(`{"cgroup":%q}`, rel))
	}
}

// startTargetWatchers menyalakan PSI watcher dan (bila memory.events ada) events watcher untuk satu target
// di bawah context anak yang dapat dibatalkan. Setiap goroutine dilacak oleh WaitGroup milik Run.
func (d *Daemon) startTargetWatchers(ctx context.Context, sinks targetWatchSinks, cgPath string) context.CancelFunc {
	targetCtx, cancel := context.WithCancel(ctx)
	rel := d.relativeCgroup(cgPath)
	pressureFile := kernelfs.JoinPath(cgPath, "memory.pressure")
	eventsFile := kernelfs.JoinPath(cgPath, "memory.events")

	sinks.wg.Add(1)
	go func() {
		defer sinks.wg.Done()
		if wErr := d.psiWatcher.WatchTarget(targetCtx, rel, pressureFile, sinks.psiCh); wErr != nil && targetCtx.Err() == nil {
			_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "PSI_WATCH_WARN", fmt.Sprintf(`{"cgroup":%q,"error":%q}`, rel, wErr.Error()))
		}
	}()

	if _, statErr := d.cfg.FS.Stat(eventsFile); statErr == nil {
		sinks.wg.Add(1)
		go func() {
			defer sinks.wg.Done()
			if wErr := d.eventsWatcher.WatchTarget(targetCtx, rel, eventsFile, sinks.eventsCh); wErr != nil && targetCtx.Err() == nil {
				_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "EVENTS_WATCH_WARN", fmt.Sprintf(`{"cgroup":%q,"error":%q}`, rel, wErr.Error()))
			}
		}()
	}
	return cancel
}

// stopAllTargets membatalkan seluruh watcher per target dan mengosongkan set target hidup.
func (d *Daemon) stopAllTargets() {
	d.targetsMu.Lock()
	defer d.targetsMu.Unlock()
	for _, cancel := range d.targetCancel {
		cancel()
	}
	clear(d.targetCancel)
	d.targetOrder = nil
}

// snapshotTargets mengembalikan salinan path absolut target hidup sesuai urutan discovery.
func (d *Daemon) snapshotTargets() []string {
	d.targetsMu.Lock()
	defer d.targetsMu.Unlock()
	return slices.Clone(d.targetOrder)
}

func (d *Daemon) sampleAllTargets(ctx context.Context, targets []string) {
	now := d.cfg.Clock().UTC()
	hostPressurePath := kernelfs.JoinPath(d.cfg.ProcRoot, "pressure/memory")
	if m, err := psi.ReadMetrics(d.cfg.FS, hostPressurePath); err == nil {
		d.recordRing("host", mcpserver.PSIPoint{
			At:         now,
			SomeAvg10:  m.Some.Avg10,
			SomeAvg60:  m.Some.Avg60,
			SomeAvg300: m.Some.Avg300,
			FullAvg10:  m.Full.Avg10,
			FullAvg60:  m.Full.Avg60,
			FullAvg300: m.Full.Avg300,
		})
	}

	for _, cgPath := range targets {
		if ctx.Err() != nil {
			return
		}
		if _, err := d.EvaluateOnce(ctx, cgPath); err != nil {
			_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "SAMPLE_ERROR",
				fmt.Sprintf(`{"cgroup":%q,"error":%q}`, cgPath, err.Error()))
		}
	}
}

// consumeFastSignals mengevaluasi event PSI dan delta memory.events terhadap snapshot set target hidup
// yang diambil per event; event PSI host disebar ke seluruh target terkini.
func (d *Daemon) consumeFastSignals(ctx context.Context, psiCh <-chan psi.PressureEvent, evCh <-chan cgroup.EventsDelta) {
	for {
		select {
		case <-ctx.Done():
			return
		case pev := <-psiCh:
			d.handlePSIEvent(ctx, pev)
		case dev := <-evCh:
			d.handleEventsDelta(ctx, dev)
		}
	}
}

// handlePSIEvent memproses satu wakeup trigger PSI: evaluasi target yang cocok lalu titik ring PSI.
// Evaluasi berjalan lebih dulu agar titik lengkap (dengan memory.current) yang mengisi slot throttle cgroup;
// titik PSI-only berikutnya pada kunci yang sama otomatis tersaring oleh throttle.
func (d *Daemon) handlePSIEvent(ctx context.Context, pev psi.PressureEvent) {
	trig := d.newTrigger(reflexTriggerPSI)
	for _, cgPath := range d.matchTargetsForRel(d.snapshotTargets(), pev.Cgroup) {
		_, _ = d.evaluate(ctx, cgPath, trig)
	}
	d.recordRing(pev.Cgroup, mcpserver.PSIPoint{
		At:         pev.At,
		SomeAvg10:  pev.Metrics.Some.Avg10,
		SomeAvg60:  pev.Metrics.Some.Avg60,
		SomeAvg300: pev.Metrics.Some.Avg300,
		FullAvg10:  pev.Metrics.Full.Avg10,
		FullAvg60:  pev.Metrics.Full.Avg60,
		FullAvg300: pev.Metrics.Full.Avg300,
	})
}

// handleEventsDelta memproses satu delta memory.events (inotify) dengan mengevaluasi target yang cocok.
func (d *Daemon) handleEventsDelta(ctx context.Context, dev cgroup.EventsDelta) {
	trig := d.newTrigger(reflexTriggerMemoryEvents)
	for _, cgPath := range d.matchTargetsForRel(d.snapshotTargets(), dev.Cgroup) {
		_, _ = d.evaluate(ctx, cgPath, trig)
	}
}

func (d *Daemon) consumeJournalEvents(ctx context.Context, ch <-chan journal.JournalEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case jev := <-ch:
			rawBytes, _ := json.Marshal(jev)
			redacted := redact.String(string(rawBytes))
			redactedMsg := redact.String(jev.Message)

			d.cfg.MCPServer.Broker().Publish(mcpserver.StreamEvent{
				Type:    "journal.pattern",
				Summary: fmt.Sprintf("[%s] %s on %s", jev.Category, redactedMsg, jev.Unit),
				Data: map[string]any{
					"category": jev.Category,
					"unit":     jev.Unit,
					"pid":      jev.PID,
					"comm":     jev.Comm,
				},
			})

			incidentID := d.findOpenIncidentForUnit(jev.Unit)
			if incidentID != "" {
				_ = d.cfg.Store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
					ID:           d.newID("EVD"),
					IncidentID:   incidentID,
					Kind:         "journal_pattern",
					RawData:      redacted,
					RedactedData: redacted,
					CapturedAt:   d.cfg.Clock().UTC(),
				})
			}
		}
	}
}

func (d *Daemon) reconcileEvaluation(ctx context.Context, cgPath, rel string, sample cgroup.Sample, eval detector.Evaluation, trig reflexTrigger) error {
	d.evalMu.Lock()
	defer d.evalMu.Unlock()

	broker := d.cfg.MCPServer.Broker()

	if eval.IncidentClosed && eval.IncidentID != "" {
		return d.closeIncidentOnRecovery(ctx, rel, eval, broker)
	}

	if !eval.IncidentOpen || eval.IncidentID == "" {
		return nil
	}

	incID := eval.IncidentID
	if existingID, ok := d.openByCgroup[rel]; ok && existingID != "" {
		if existingInc, gErr := d.cfg.Store.GetIncident(ctx, existingID); gErr == nil && !isTerminalState(existingInc.State) {
			incID = existingID
		} else {
			delete(d.openByCgroup, rel)
			delete(d.lastSeverity, rel)
		}
	}

	inc, getErr := d.cfg.Store.GetIncident(ctx, incID)
	if getErr != nil {
		// Insiden baru atau ID lama sudah terminal saat debounce reopening
		if errors.Is(getErr, incident.ErrIncidentNotFound) {
			inc = &incident.Incident{
				ID:         incID,
				Node:       d.cfg.NodeName,
				Cgroup:     rel,
				Severity:   string(eval.Severity),
				State:      incident.StateDetected,
				TTOSeconds: eval.TTOSeconds,
				OpenedAt:   d.cfg.Clock().UTC(),
			}
			if err := d.cfg.Store.CreateIncident(ctx, inc); err != nil {
				return fmt.Errorf("create incident %s: %w", incID, err)
			}

			d.openByCgroup[rel] = incID
			d.lastSeverity[rel] = eval.Severity

			samplePayload, _ := json.Marshal(sample)
			redactedSample := redact.String(string(samplePayload))
			_ = d.cfg.Store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
				ID:           d.newID("EVD"),
				IncidentID:   incID,
				Kind:         "telemetry_sample",
				RawData:      redactedSample,
				RedactedData: redactedSample,
				CapturedAt:   d.cfg.Clock().UTC(),
			})

			broker.Publish(mcpserver.StreamEvent{
				Type:       "incident.opened",
				IncidentID: incID,
				Severity:   string(eval.Severity),
				State:      string(incident.StateDetected),
				Summary:    fmt.Sprintf("%s pressure/leak detected on %s", eval.Severity, rel),
				Data: map[string]any{
					"cgroup":          rel,
					"memory_current":  sample.MemoryCurrent,
					"memory_max":      eval.LimitBytes,
					"psi_some_avg10":  sample.PSISomeAvg10,
					"psi_full_avg10":  sample.PSIFullAvg10,
					"slope_bytes_sec": eval.SlopeBytesPerS,
				},
			})

			return d.maybeApplyReflex(ctx, inc, cgPath, rel, eval, broker, trig)
		}
		return getErr
	}

	// Jika detector me-reopen ID lama yang sudah terminal di SQLite, buat sufiks ID baru agar audit trail tetap valid
	if isTerminalState(inc.State) && eval.Reopened {
		reopenID := fmt.Sprintf("%s-R%d", incID, d.cfg.Clock().UTC().Unix()%10000)
		newInc := &incident.Incident{
			ID:         reopenID,
			Node:       d.cfg.NodeName,
			Cgroup:     rel,
			Severity:   string(eval.Severity),
			State:      incident.StateDetected,
			TTOSeconds: eval.TTOSeconds,
			OpenedAt:   d.cfg.Clock().UTC(),
		}
		if err := d.cfg.Store.CreateIncident(ctx, newInc); err != nil {
			return fmt.Errorf("create reopened incident %s: %w", reopenID, err)
		}
		d.openByCgroup[rel] = reopenID
		d.lastSeverity[rel] = eval.Severity

		broker.Publish(mcpserver.StreamEvent{
			Type:       "incident.opened",
			IncidentID: reopenID,
			Severity:   string(eval.Severity),
			State:      string(incident.StateDetected),
			Summary:    fmt.Sprintf("%s reopened pressure on %s", eval.Severity, rel),
		})
		return d.maybeApplyReflex(ctx, newInc, cgPath, rel, eval, broker, trig)
	}

	d.openByCgroup[rel] = inc.ID

	// Cek apakah severity meningkat (misalnya P2 -> P1 atau POST_OOM) untuk memicu refleks tambahan
	prevSev := d.lastSeverity[rel]
	if eval.Severity.Rank() > prevSev.Rank() {
		d.lastSeverity[rel] = eval.Severity
		broker.Publish(mcpserver.StreamEvent{
			Type:       "incident.escalated_severity",
			IncidentID: inc.ID,
			Severity:   string(eval.Severity),
			State:      string(inc.State),
			Summary:    fmt.Sprintf("Severity increased from %s to %s on %s", prevSev, eval.Severity, rel),
		})
		return d.maybeApplyReflex(ctx, inc, cgPath, rel, eval, broker, trig)
	}

	return nil
}

func (d *Daemon) maybeApplyReflex(ctx context.Context, inc *incident.Incident, cgPath, rel string, eval detector.Evaluation, broker *mcpserver.EventBroker, trig reflexTrigger) error {
	if d.cfg.Catalog.IsProtectedUnit(rel) || d.cfg.Catalog.IsProtectedUnit(path.Base(rel)) || !d.isEligibleReflexTarget(cgPath, rel) {
		return nil
	}

	// Aksi L1 otomatis dipicu untuk P2, P1, atau POST_OOM
	if eval.Severity.Rank() < detector.SeverityP2.Rank() {
		return nil
	}

	applied := false
	// 1. Coba memory.reclaim proaktif 10%
	if act, err := d.cfg.Reflex.ApplyReclaim(ctx, reflex.ReclaimRequest{
		IncidentID: inc.ID,
		CgroupPath: cgPath,
		TTLSeconds: reflex.DefaultTTLSeconds,
	}); err == nil {
		applied = true
		latencyMS := d.reflexLatencyMS(trig)
		d.recordReflexLatency(ctx, inc.ID, act, latencyMS, trig)
		broker.Publish(mcpserver.StreamEvent{
			Type:       "reflex.applied",
			IncidentID: inc.ID,
			Severity:   string(eval.Severity),
			State:      string(inc.State),
			Summary:    fmt.Sprintf("Applied L1 cgroup_reclaim (%s) on %s", act.ID, rel),
			Data: map[string]any{
				"reflex_id":   act.ID,
				"action":      act.Action,
				"target":      act.Target,
				"ttl_seconds": act.TTLSeconds,
				"latency_ms":  latencyMS,
				"trigger":     trig.kind,
			},
		})
	}

	// 2. Untuk P1/POST_OOM pada unit systemd non-terlindungi, terapkan memory throttle MemoryHigh +5%
	if eval.Severity.Rank() >= detector.SeverityP1.Rank() {
		if unitName := unitNameFromCgroup(rel); unitName != "" && !d.cfg.Catalog.IsProtectedUnit(unitName) {
			if act, err := d.cfg.Reflex.ApplyThrottle(ctx, reflex.ThrottleRequest{
				IncidentID: inc.ID,
				Unit:       unitName,
				CgroupPath: cgPath,
				TTLSeconds: reflex.DefaultTTLSeconds,
			}); err == nil {
				applied = true
				latencyMS := d.reflexLatencyMS(trig)
				d.recordReflexLatency(ctx, inc.ID, act, latencyMS, trig)
				broker.Publish(mcpserver.StreamEvent{
					Type:       "reflex.applied",
					IncidentID: inc.ID,
					Severity:   string(eval.Severity),
					State:      string(inc.State),
					Summary:    fmt.Sprintf("Applied L1 cgroup_throttle (%s) on %s", act.ID, unitName),
					Data: map[string]any{
						"reflex_id":   act.ID,
						"action":      act.Action,
						"target":      act.Target,
						"ttl_seconds": act.TTLSeconds,
						"latency_ms":  latencyMS,
						"trigger":     trig.kind,
					},
				})
			}
		}
	}

	if applied && inc.State == incident.StateDetected {
		if err := d.cfg.Store.TransitionState(ctx, inc.ID, incident.StateReflexApplied, "sentinel", "L1 reflex applied"); err == nil {
			broker.Publish(mcpserver.StreamEvent{
				Type:       "incident.updated",
				IncidentID: inc.ID,
				Severity:   string(eval.Severity),
				State:      string(incident.StateReflexApplied),
				Summary:    fmt.Sprintf("Incident %s transitioned to REFLEX_APPLIED", inc.ID),
			})
		}
	}

	return nil
}

// recordReflexLatency mencatat audit REFLEX_LATENCY {reflex_id, action, latency_ms, trigger} untuk refleks daemon.
func (d *Daemon) recordReflexLatency(ctx context.Context, incidentID string, act *incident.ReflexAction, latencyMS float64, trig reflexTrigger) {
	payload, err := json.Marshal(struct {
		ReflexID  string  `json:"reflex_id"`
		Action    string  `json:"action"`
		LatencyMS float64 `json:"latency_ms"`
		Trigger   string  `json:"trigger"`
	}{ReflexID: act.ID, Action: act.Action, LatencyMS: latencyMS, Trigger: trig.kind})
	if err != nil {
		return
	}
	_ = d.cfg.Store.RecordAudit(ctx, incidentID, "sentinel", "REFLEX_LATENCY", string(payload))
}

func (d *Daemon) closeIncidentOnRecovery(ctx context.Context, rel string, eval detector.Evaluation, broker *mcpserver.EventBroker) error {
	incID := eval.IncidentID
	if mappedID, ok := d.openByCgroup[rel]; ok && mappedID != "" {
		incID = mappedID
	}

	delete(d.openByCgroup, rel)
	delete(d.lastSeverity, rel)

	inc, err := d.cfg.Store.GetIncident(ctx, incID)
	if err != nil {
		if errors.Is(err, incident.ErrIncidentNotFound) {
			return nil
		}
		return err
	}
	if isTerminalState(inc.State) {
		return nil
	}

	// Patuhi state machine ketat sebelum menuju RESOLVED
	if inc.State == incident.StateDetected || inc.State == incident.StateReflexApplied || inc.State == incident.StateTriaging {
		if tErr := d.cfg.Store.TransitionState(ctx, incID, incident.StateVerifying, "sentinel", "120s hysteresis half-threshold healthy"); tErr != nil {
			return tErr
		}
		inc.State = incident.StateVerifying
	}

	if inc.State == incident.StateVerifying {
		if tErr := d.cfg.Store.TransitionState(ctx, incID, incident.StateResolved, "sentinel", "auto-resolved after 120s sustained recovery"); tErr != nil {
			return tErr
		}
		// Simpan seri PSI/memori insiden sekali saat ditutup oleh hysteresis pemulihan
		_, _ = d.cfg.MCPServer.SnapshotTelemetrySeries(ctx, incID)
		broker.Publish(mcpserver.StreamEvent{
			Type:       "incident.updated",
			IncidentID: incID,
			State:      string(incident.StateResolved),
			Summary:    fmt.Sprintf("Incident %s auto-resolved after 120s recovery on %s", incID, rel),
		})
	}
	return nil
}

func (d *Daemon) resolveTargetCgroups() []string {
	if len(d.cfg.CgroupPaths) > 0 {
		configured := false
		out := make([]string, 0, len(d.cfg.CgroupPaths))
		for _, p := range d.cfg.CgroupPaths {
			trimmed := strings.TrimSpace(p)
			if trimmed == "" {
				continue
			}
			configured = true
			if !strings.HasPrefix(trimmed, "/") {
				trimmed = kernelfs.JoinPath(d.cfg.CgroupRoot, trimmed)
			} else if !strings.HasPrefix(trimmed, d.cfg.CgroupRoot) {
				trimmed = kernelfs.JoinPath(d.cfg.CgroupRoot, trimmed)
			}
			// Path eksplisit baru dianggap aktif setelah memory.current tersedia; path yang muncul belakangan
			// akan ditangkap oleh tick rediscovery berikutnya.
			if _, statErr := d.cfg.FS.Stat(kernelfs.JoinPath(trimmed, "memory.current")); statErr != nil {
				continue
			}
			out = append(out, trimmed)
		}
		// Bila operator mengonfigurasi path eksplisit, jangan pernah fallback ke auto-discovery
		// walaupun belum ada satu pun path yang aktif.
		if configured {
			return out
		}
	}

	// Temukan sub-cgroup layanan leaf (.service) hanya di dalam franken.slice dan system.slice;
	// jangan pernah memindai root cgroup, init.scope, user.slice, atau root slice itu sendiri.
	var discovered []string
	for _, sub := range []string{"franken.slice", "system.slice"} {
		dir := kernelfs.JoinPath(d.cfg.CgroupRoot, sub)
		d.walkLeafServiceCgroups(dir, 0, &discovered)
		if len(discovered) >= maxDiscoveredCgroups {
			break
		}
	}
	return discovered
}

// walkLeafServiceCgroups menelusuri hierarki slice secara terbatas untuk mengumpulkan hanya leaf cgroup *.service.
func (d *Daemon) walkLeafServiceCgroups(dir string, depth int, discovered *[]string) {
	if depth > 4 || len(*discovered) >= maxDiscoveredCgroups {
		return
	}
	entries, err := d.cfg.FS.ReadDir(dir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if len(*discovered) >= maxDiscoveredCgroups {
			return
		}
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if isDisallowedCgroupNode(name) || d.cfg.Catalog.IsProtectedUnit(name) {
			continue
		}
		candidate := kernelfs.JoinPath(dir, name)
		if strings.HasSuffix(name, ".slice") {
			// Telusuri isi sub-slice (kecuali user.slice yang sudah disaring) tanpa memasukkan slice-nya ke target.
			d.walkLeafServiceCgroups(candidate, depth+1, discovered)
			continue
		}
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		if !d.isLeafCgroupDir(candidate) {
			continue
		}
		if _, statErr := d.cfg.FS.Stat(kernelfs.JoinPath(candidate, "memory.current")); statErr == nil {
			if !slices.Contains(*discovered, candidate) {
				*discovered = append(*discovered, candidate)
			}
		}
	}
}

// isDisallowedCgroupNode memblokir root/system slice, init.scope, user.slice, dan scope sesi admin dari target refleks.
func isDisallowedCgroupNode(name string) bool {
	if name == "" || name == "." || name == ".." || name == "init.scope" || name == "user.slice" {
		return true
	}
	if strings.HasPrefix(name, "user-") && strings.HasSuffix(name, ".slice") {
		return true
	}
	return strings.HasSuffix(name, ".scope")
}

// isLeafCgroupDir memastikan direktori cgroup tidak memiliki sub-cgroup anak sehingga refleks tidak mengenai induk/OS.
func (d *Daemon) isLeafCgroupDir(cgPath string) bool {
	if d.cfg.FS == nil {
		return true
	}
	entries, err := d.cfg.FS.ReadDir(cgPath)
	if err != nil {
		return true
	}
	for _, ent := range entries {
		if ent.IsDir() {
			return false
		}
	}
	return true
}

// isEligibleReflexTarget memverifikasi bahwa target refleks adalah leaf .service cgroup dan bukan slice/scope/root.
func (d *Daemon) isEligibleReflexTarget(cgPath, rel string) bool {
	trimmed := strings.Trim(strings.TrimSpace(rel), "/")
	if trimmed == "" || trimmed == "." {
		return false
	}
	segments := strings.Split(trimmed, "/")
	for _, seg := range segments {
		if isDisallowedCgroupNode(seg) {
			return false
		}
	}
	leaf := segments[len(segments)-1]
	if strings.HasSuffix(leaf, ".slice") || !strings.HasSuffix(leaf, ".service") {
		return false
	}
	return d.isLeafCgroupDir(cgPath)
}

func (d *Daemon) relativeCgroup(cgPath string) string {
	cleanRoot := filepath.ToSlash(path.Clean(d.cfg.CgroupRoot))
	cleanPath := filepath.ToSlash(path.Clean(cgPath))
	if cleanPath == cleanRoot {
		return "/"
	}
	rel := strings.TrimPrefix(cleanPath, cleanRoot)
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return rel
}

func (d *Daemon) matchTargetsForRel(targets []string, rel string) []string {
	if rel == "host" {
		return targets
	}
	var matched []string
	for _, cg := range targets {
		if d.relativeCgroup(cg) == rel {
			matched = append(matched, cg)
		}
	}
	return matched
}

func (d *Daemon) findOpenIncidentForUnit(unit string) string {
	trimmedUnit := strings.TrimSpace(unit)
	if trimmedUnit == "" {
		return ""
	}
	normalizedUnit := strings.TrimSuffix(trimmedUnit, ".service")

	d.evalMu.Lock()
	defer d.evalMu.Unlock()

	for rel, id := range d.openByCgroup {
		base := path.Base(strings.TrimSuffix(rel, "/"))
		if base == trimmedUnit || strings.TrimSuffix(base, ".service") == normalizedUnit {
			return id
		}
	}
	return ""
}

func unitNameFromCgroup(rel string) string {
	base := path.Base(strings.TrimSuffix(rel, "/"))
	if strings.HasSuffix(base, ".service") {
		return base
	}
	return ""
}

func isTerminalState(st incident.State) bool {
	return st == incident.StateResolved ||
		st == incident.StateEscalated ||
		st == incident.StateDismissed ||
		st == incident.StateExpired
}

// newID membuat ID evidence daemon dari cfg.IDSource bila dikonfigurasi (simulasi deterministik), selain itu crypto/rand.
func (d *Daemon) newID(prefix string) string {
	var b [6]byte
	d.idMu.Lock()
	src := d.cfg.IDSource
	ok := src != nil
	if ok {
		_, err := io.ReadFull(src, b[:])
		ok = err == nil
	}
	d.idMu.Unlock()
	if !ok {
		_, _ = rand.Read(b[:])
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b[:]))
}
