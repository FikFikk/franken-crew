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
	defaultSampleInterval   = 1 * time.Second
	defaultRollbackInterval = 1 * time.Second
	maxDiscoveredCgroups    = 32
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

	targets := d.resolveTargetCgroups()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, len(targets)*2+4)

	// 1. Jalankan scheduler rollback TTL refleks L1 (termasuk sweep saldo TTL pasca-restart)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if runErr := d.cfg.Reflex.RunScheduler(runCtx, d.cfg.RollbackInterval); runErr != nil && runCtx.Err() == nil {
			errCh <- fmt.Errorf("reflex rollback scheduler: %w", runErr)
		}
	}()

	// 2. Jalankan sampler periodik 1 Hz untuk seluruh cgroup target dan PSI host
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runSamplingLoop(runCtx, targets)
	}()

	// 3. Jalankan fast-path PSI watcher + memory.events inotify watcher per target cgroup
	psiEvents := make(chan psi.PressureEvent, 64)
	evDeltas := make(chan cgroup.EventsDelta, 64)

	for _, cgPath := range targets {
		rel := d.relativeCgroup(cgPath)
		pressureFile := kernelfs.JoinPath(cgPath, "memory.pressure")
		eventsFile := kernelfs.JoinPath(cgPath, "memory.events")

		wg.Add(1)
		go func(targetRel, pPath string) {
			defer wg.Done()
			if wErr := d.psiWatcher.WatchTarget(runCtx, targetRel, pPath, psiEvents); wErr != nil && runCtx.Err() == nil {
				_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "PSI_WATCH_WARN", fmt.Sprintf(`{"cgroup":%q,"error":%q}`, targetRel, wErr.Error()))
			}
		}(rel, pressureFile)

		if _, statErr := d.cfg.FS.Stat(eventsFile); statErr == nil {
			wg.Add(1)
			go func(targetRel, ePath string) {
				defer wg.Done()
				if wErr := d.eventsWatcher.WatchTarget(runCtx, targetRel, ePath, evDeltas); wErr != nil && runCtx.Err() == nil {
					_ = d.cfg.Store.RecordAudit(context.Background(), "", "sentinel", "EVENTS_WATCH_WARN", fmt.Sprintf(`{"cgroup":%q,"error":%q}`, targetRel, wErr.Error()))
				}
			}(rel, eventsFile)
		}
	}

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
		d.consumeFastSignals(runCtx, targets, psiEvents, evDeltas)
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
func (d *Daemon) EvaluateOnce(ctx context.Context, cgPath string) (detector.Evaluation, error) {
	sample, err := d.sampler.SampleCgroup(cgPath)
	if err != nil {
		return detector.Evaluation{}, err
	}

	rel := d.relativeCgroup(cgPath)
	now := d.cfg.Clock().UTC()
	if now.IsZero() && !sample.At.IsZero() {
		now = sample.At.UTC()
	}

	d.cfg.MCPServer.PSIRing().Record(rel, mcpserver.PSIPoint{
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
	if err := d.reconcileEvaluation(ctx, cgPath, rel, sample, eval); err != nil {
		return eval, err
	}
	return eval, nil
}

func (d *Daemon) runSamplingLoop(ctx context.Context, targets []string) {
	// Lakukan pembacaan baseline awal segera saat startup tanpa menunggu tick pertama
	d.sampleAllTargets(ctx, targets)

	ticker := time.NewTicker(d.cfg.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.sampleAllTargets(ctx, targets)
		}
	}
}

func (d *Daemon) sampleAllTargets(ctx context.Context, targets []string) {
	now := d.cfg.Clock().UTC()
	hostPressurePath := kernelfs.JoinPath(d.cfg.ProcRoot, "pressure/memory")
	if m, err := psi.ReadMetrics(d.cfg.FS, hostPressurePath); err == nil {
		d.cfg.MCPServer.PSIRing().Record("host", mcpserver.PSIPoint{
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

func (d *Daemon) consumeFastSignals(ctx context.Context, targets []string, psiCh <-chan psi.PressureEvent, evCh <-chan cgroup.EventsDelta) {
	for {
		select {
		case <-ctx.Done():
			return
		case pev := <-psiCh:
			d.cfg.MCPServer.PSIRing().Record(pev.Cgroup, mcpserver.PSIPoint{
				At:         pev.At,
				SomeAvg10:  pev.Metrics.Some.Avg10,
				SomeAvg60:  pev.Metrics.Some.Avg60,
				SomeAvg300: pev.Metrics.Some.Avg300,
				FullAvg10:  pev.Metrics.Full.Avg10,
				FullAvg60:  pev.Metrics.Full.Avg60,
				FullAvg300: pev.Metrics.Full.Avg300,
			})
			for _, cgPath := range d.matchTargetsForRel(targets, pev.Cgroup) {
				_, _ = d.EvaluateOnce(ctx, cgPath)
			}
		case dev := <-evCh:
			for _, cgPath := range d.matchTargetsForRel(targets, dev.Cgroup) {
				_, _ = d.EvaluateOnce(ctx, cgPath)
			}
		}
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

			d.cfg.MCPServer.Broker().Publish(mcpserver.StreamEvent{
				Type:    "journal.pattern",
				Summary: fmt.Sprintf("[%s] %s on %s", jev.Category, jev.Message, jev.Unit),
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
					ID:           newSentinelID("EVD"),
					IncidentID:   incidentID,
					Kind:         "journal_pattern",
					RawData:      string(rawBytes),
					RedactedData: redacted,
					CapturedAt:   d.cfg.Clock().UTC(),
				})
			}
		}
	}
}

func (d *Daemon) reconcileEvaluation(ctx context.Context, cgPath, rel string, sample cgroup.Sample, eval detector.Evaluation) error {
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
			_ = d.cfg.Store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
				ID:         newSentinelID("EVD"),
				IncidentID: incID,
				Kind:       "telemetry_sample",
				RawData:    string(samplePayload),
				CapturedAt: d.cfg.Clock().UTC(),
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

			return d.maybeApplyReflex(ctx, inc, cgPath, rel, eval, broker)
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
		return d.maybeApplyReflex(ctx, newInc, cgPath, rel, eval, broker)
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
		return d.maybeApplyReflex(ctx, inc, cgPath, rel, eval, broker)
	}

	return nil
}

func (d *Daemon) maybeApplyReflex(ctx context.Context, inc *incident.Incident, cgPath, rel string, eval detector.Evaluation, broker *mcpserver.EventBroker) error {
	if d.cfg.Catalog.IsProtectedUnit(rel) || d.cfg.Catalog.IsProtectedUnit(path.Base(rel)) {
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
		out := make([]string, 0, len(d.cfg.CgroupPaths))
		for _, p := range d.cfg.CgroupPaths {
			trimmed := strings.TrimSpace(p)
			if trimmed == "" {
				continue
			}
			if !strings.HasPrefix(trimmed, "/") {
				trimmed = kernelfs.JoinPath(d.cfg.CgroupRoot, trimmed)
			} else if !strings.HasPrefix(trimmed, d.cfg.CgroupRoot) {
				trimmed = kernelfs.JoinPath(d.cfg.CgroupRoot, trimmed)
			}
			out = append(out, trimmed)
		}
		if len(out) > 0 {
			return out
		}
	}

	// Temukan sub-cgroup layanan di franken.slice, system.slice, atau langsung di bawah cgroupRoot
	var discovered []string
	for _, sub := range []string{"franken.slice", "system.slice", ""} {
		dir := d.cfg.CgroupRoot
		if sub != "" {
			dir = kernelfs.JoinPath(d.cfg.CgroupRoot, sub)
		}
		entries, err := d.cfg.FS.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() {
				continue
			}
			name := ent.Name()
			if d.cfg.Catalog.IsProtectedUnit(name) {
				continue
			}
			candidate := kernelfs.JoinPath(dir, name)
			if _, statErr := d.cfg.FS.Stat(kernelfs.JoinPath(candidate, "memory.current")); statErr == nil {
				if !slices.Contains(discovered, candidate) {
					discovered = append(discovered, candidate)
				}
			}
			if len(discovered) >= maxDiscoveredCgroups {
				return discovered
			}
		}
	}

	if len(discovered) == 0 {
		if _, err := d.cfg.FS.Stat(kernelfs.JoinPath(d.cfg.CgroupRoot, "memory.current")); err == nil {
			discovered = append(discovered, d.cfg.CgroupRoot)
		}
	}
	return discovered
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
	d.evalMu.Lock()
	defer d.evalMu.Unlock()

	if unit != "" {
		for rel, id := range d.openByCgroup {
			if strings.Contains(rel, unit) {
				return id
			}
		}
	}
	for _, id := range d.openByCgroup {
		return id
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

func newSentinelID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b[:]))
}
