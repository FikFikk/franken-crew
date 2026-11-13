package mcpserver

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/incident"
)

// defaultVerifyPollInterval menentukan jeda default polling metrik untuk background worker verifikasi.
const defaultVerifyPollInterval = 5 * time.Second

// verifySpec menyimpan parameter evaluasi jendela pemulihan forward pasca remediasi L2.
type verifySpec struct {
	incidentID          string
	absCgDir            string
	normCg              string
	unit                string
	probeURL            string
	windowSec           int
	windowDur           time.Duration
	baselineAt          time.Time
	baselineSeq         uint64
	hasBaselineOOM      bool
	baselineOOMKill     uint64
	explicitBaselineOOM *uint64
	requireCoverage     bool
	autoTransition      bool
	generation          uint64
}

// verifyState melacak siklus hidup jendela verifikasi forward per insiden agar worker dan caller sinkron.
type verifyState struct {
	finMu           sync.Mutex
	generation      uint64
	startedAt       time.Time
	baselineSeq     uint64
	hasBaselineOOM  bool
	baselineOOMKill uint64
	workerStarted   bool
	workerCancel    context.CancelFunc
	completed       bool
	result          *VerifyHealthOutput
}

// verifyCoordinator mengelola state observasi forward serta siklus hidup goroutine verifikasi.
type verifyCoordinator struct {
	mu      sync.Mutex
	states  map[string]*verifyState
	rootCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func newVerifyCoordinator() *verifyCoordinator {
	ctx, cancel := context.WithCancel(context.Background())
	return &verifyCoordinator{
		states:  make(map[string]*verifyState),
		rootCtx: ctx,
		cancel:  cancel,
	}
}

// Close menghentikan seluruh worker verifikasi aktif dan menunggu seluruh goroutine berhenti.
func (vc *verifyCoordinator) Close() {
	if vc == nil {
		return
	}
	vc.cancel()
	vc.wg.Wait()
}

// RecordL2Execution menetapkan baseline waktu forward baru segera setelah aksi L2 berhasil dieksekusi.
func (vc *verifyCoordinator) RecordL2Execution(incID string, executedAt time.Time, baselineSeq uint64, hasOOM bool, baselineOOM uint64) {
	if vc == nil || incID == "" {
		return
	}
	vc.mu.Lock()
	defer vc.mu.Unlock()

	var nextGen uint64 = 1
	if prev, ok := vc.states[incID]; ok {
		nextGen = prev.generation + 1
		if prev.workerCancel != nil {
			prev.workerCancel()
		}
	}

	vc.states[incID] = &verifyState{
		generation:      nextGen,
		startedAt:       executedAt,
		baselineSeq:     baselineSeq,
		hasBaselineOOM:  hasOOM,
		baselineOOMKill: baselineOOM,
	}
}

func (vc *verifyCoordinator) getOrInitState(incID string, now time.Time, baselineSeq uint64, baselineOOM uint64) *verifyState {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	if st, ok := vc.states[incID]; ok {
		return st
	}
	st := &verifyState{
		generation:      1,
		startedAt:       now,
		baselineSeq:     baselineSeq,
		hasBaselineOOM:  true,
		baselineOOMKill: baselineOOM,
	}
	vc.states[incID] = st
	return st
}

// cloneVerifyOutput menyalin output verifikasi secara aman agar tidak terjadi data race pada slice/Checks.
func cloneVerifyOutput(out *VerifyHealthOutput) VerifyHealthOutput {
	cp := *out
	if len(out.FailureReasons) > 0 {
		cp.FailureReasons = append([]string(nil), out.FailureReasons...)
	}
	if out.Checks.UnitActive != nil {
		val := *out.Checks.UnitActive
		cp.Checks.UnitActive = &val
	}
	return cp
}

// startVerifyWorker meluncurkan goroutine latar untuk mensampling metrik forward hingga jendela selesai.
func (s *Server) startVerifyWorker(st *verifyState, spec verifySpec) {
	s.verifyCoord.mu.Lock()
	if st.workerStarted || st.completed {
		s.verifyCoord.mu.Unlock()
		return
	}
	// Pastikan insiden tidak memiliki worker versi lama yang masih berjalan
	if s.verifyCoord.rootCtx.Err() != nil {
		s.verifyCoord.mu.Unlock()
		return
	}
	jobCtx, jobCancel := context.WithCancel(s.verifyCoord.rootCtx)
	st.workerStarted = true
	st.workerCancel = jobCancel
	s.verifyCoord.wg.Add(1)
	s.verifyCoord.mu.Unlock()

	pollInterval := s.cfg.VerifyPollInterval
	if pollInterval <= 0 {
		pollInterval = defaultVerifyPollInterval
	}

	go func() {
		defer s.verifyCoord.wg.Done()
		defer jobCancel()

		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-jobCtx.Done():
				return
			case <-ticker.C:
				now := s.cfg.Clock().UTC()
				// Rekam sampel cgroup & PSI forward agar kurva pemulihan terbentuk walau tanpa panggilan manual
				if s.cfg.FS != nil && spec.absCgDir != "" {
					sampler := cgroup.NewSampler(s.cfg.FS, 1*time.Second)
					if snap, err := sampler.SampleCgroup(spec.absCgDir); err == nil {
						s.psiRing.Record(spec.normCg, PSIPoint{
							At:            now,
							SomeAvg10:     snap.PSISomeAvg10,
							FullAvg10:     snap.PSIFullAvg10,
							MemoryCurrent: snap.MemoryCurrent,
						})
					}
				}

				if now.Sub(spec.baselineAt) >= spec.windowDur {
					// Berikan timeout memadai agar transisi SQLite, rollback, dan HTTP probe selesai bersih
					evalCtx, evalCancel := context.WithTimeout(jobCtx, 15*time.Second)
					_, _ = s.finalizeForwardVerification(evalCtx, st, spec, now)
					evalCancel()
					return
				}
			}
		}
	}()
}

// finalizeForwardVerification mengevaluasi seluruh sampel pasca-baseline [baselineAt .. evalNow] dan mengeksekusi transisi akhir.
func (s *Server) finalizeForwardVerification(ctx context.Context, st *verifyState, spec verifySpec, evalNow time.Time) (VerifyHealthOutput, error) {
	st.finMu.Lock()
	defer st.finMu.Unlock()

	if st.completed && st.result != nil {
		return cloneVerifyOutput(st.result), nil
	}

	inc, err := s.cfg.Store.GetIncident(ctx, spec.incidentID)
	if err != nil {
		return VerifyHealthOutput{}, err
	}

	sampler := cgroup.NewSampler(s.cfg.FS, 1*time.Second)
	sample, err := sampler.SampleCgroup(spec.absCgDir)
	if err != nil {
		return VerifyHealthOutput{}, fmt.Errorf("sample cgroup health on %s: %w", spec.absCgDir, err)
	}

	var failures []string
	psiStable := true
	memStable := true

	if sample.PSISomeAvg10 >= HealthPSIHalfSomeMax {
		psiStable = false
		failures = append(failures, fmt.Sprintf("live psi_some_avg10=%.2f >= %.1f", sample.PSISomeAvg10, HealthPSIHalfSomeMax))
	}
	if sample.PSIFullAvg10 >= HealthPSIHalfFullMax {
		psiStable = false
		failures = append(failures, fmt.Sprintf("live psi_full_avg10=%.2f >= %.1f", sample.PSIFullAvg10, HealthPSIHalfFullMax))
	}
	if sample.MemoryMax > 0 && sample.MemoryCurrent > 0 {
		utilPct := (float64(sample.MemoryCurrent) / float64(sample.MemoryMax)) * 100.0
		if utilPct >= MaxCgroupMemoryUtilizationPct {
			memStable = false
			failures = append(failures, fmt.Sprintf("live memory utilization=%.1f%% >= %.1f%% of memory.max", utilPct, MaxCgroupMemoryUtilizationPct))
		}
	}

	if spec.explicitBaselineOOM != nil {
		if sample.Events.OOMKill > *spec.explicitBaselineOOM {
			memStable = false
			failures = append(failures, fmt.Sprintf("new oom_kill detected (%d > baseline %d)", sample.Events.OOMKill, *spec.explicitBaselineOOM))
		}
	} else if spec.hasBaselineOOM && sample.Events.OOMKill > spec.baselineOOMKill {
		memStable = false
		failures = append(failures, fmt.Sprintf("new oom_kill detected post-remediation (%d > baseline %d)", sample.Events.OOMKill, spec.baselineOOMKill))
	}

	// Kumpulkan metrik HANYA dari jendela observasi forward (>= baselineAt) agar lonjakan lama terisolasi
	details, fwdFailures, fwdPSIStable, fwdMemStable := s.collectForwardPSIDetails(spec, sample, evalNow)
	if !fwdPSIStable {
		psiStable = false
	}
	if !fwdMemStable {
		memStable = false
	}
	failures = append(failures, fwdFailures...)
	details.PSIStable = psiStable
	details.MemoryStable = memStable

	if unit := strings.TrimSpace(spec.unit); unit != "" {
		details.UnitChecked = unit
		if s.cfg.UnitInspector == nil {
			failures = append(failures, "unit inspector unavailable")
		} else {
			active, stateStr, uErr := s.cfg.UnitInspector.IsActive(ctx, unit)
			details.UnitActive = &active
			if uErr != nil || !active {
				failures = append(failures, fmt.Sprintf("unit %s not active (state=%s, err=%v)", unit, stateStr, uErr))
			}
		}
	}

	if probeURL := strings.TrimSpace(spec.probeURL); probeURL != "" {
		details.ProbeURLChecked = probeURL
		if s.cfg.HTTPProber == nil {
			failures = append(failures, "http prober unavailable")
		} else {
			code, pErr := s.cfg.HTTPProber.Probe(ctx, probeURL)
			details.ProbeStatusCode = code
			if pErr != nil || code < 200 || code >= 400 {
				failures = append(failures, fmt.Sprintf("http probe %s unhealthy (status=%d, err=%v)", probeURL, code, pErr))
			}
		}
	}

	healthy := len(failures) == 0
	rolledBack := 0
	if s.cfg.Reflex != nil && (healthy || spec.autoTransition) {
		// Rollback seluruh refleks L1 saat verifikasi lulus maupun saat auto-transition gagal
		rbCount, rbErr := s.cfg.Reflex.RollbackIncident(ctx, spec.incidentID)
		rolledBack = rbCount
		if rbErr != nil {
			failures = append(failures, "reflex rollback warning: "+rbErr.Error())
		}
		if rolledBack > 0 {
			s.broker.Publish(StreamEvent{
				Type:       "reflex.rolled_back",
				IncidentID: spec.incidentID,
				Severity:   inc.Severity,
				State:      string(inc.State),
				Summary:    fmt.Sprintf("Auto-rolled back %d L1 reflex action(s) during health verification (healthy=%t)", rolledBack, healthy),
			})
		}
	}

	healthy = len(failures) == 0
	finalState := inc.State
	if spec.autoTransition {
		targetState := incident.StateEscalated
		reason := "verify_health failed: " + strings.Join(failures, "; ")
		if healthy {
			targetState = incident.StateResolved
			reason = fmt.Sprintf("verify_health passed over %ds forward window (psi_some=%.2f, psi_full=%.2f)", spec.windowSec, sample.PSISomeAvg10, sample.PSIFullAvg10)
		}
		if incident.CanTransition(inc.State, targetState) {
			if trErr := s.cfg.Store.TransitionState(ctx, spec.incidentID, targetState, "sentinel", reason); trErr == nil {
				finalState = targetState
				s.broker.Publish(StreamEvent{
					Type:       "incident.updated",
					IncidentID: spec.incidentID,
					Severity:   inc.Severity,
					State:      string(finalState),
					Summary:    reason,
				})
			}
		}
	}

	statusStr := "FAILED"
	summaryMsg := "forward health verification failed: " + strings.Join(failures, "; ")
	if healthy {
		statusStr = "RESOLVED"
		summaryMsg = fmt.Sprintf("forward health verification stabilized over %ds window", spec.windowSec)
	}

	_ = s.cfg.Store.RecordAudit(ctx, spec.incidentID, "sentinel", "HEALTH_VERIFIED",
		fmt.Sprintf(`{"status":%q,"healthy":%t,"state":%q,"rolled_back":%d,"psi_some_avg10":%.2f,"psi_full_avg10":%.2f,"mem_growth_pct":%.2f,"oom_kill":%d}`,
			statusStr, healthy, string(finalState), rolledBack, sample.PSISomeAvg10, sample.PSIFullAvg10, details.MemoryGrowthPct, sample.Events.OOMKill))

	s.broker.Publish(StreamEvent{
		Type:       "verification.completed",
		IncidentID: spec.incidentID,
		Severity:   inc.Severity,
		State:      string(finalState),
		Summary:    summaryMsg,
		Data:       map[string]any{"status": statusStr, "healthy": healthy, "rolled_back": rolledBack},
	})

	elapsedSec := int64(evalNow.Sub(spec.baselineAt).Seconds())
	if elapsedSec < 0 {
		elapsedSec = 0
	}

	out := VerifyHealthOutput{
		IncidentID:           spec.incidentID,
		Status:               statusStr,
		Pending:              false,
		Healthy:              healthy,
		State:                string(finalState),
		Message:              summaryMsg,
		ObservationStartedAt: spec.baselineAt.Format(time.RFC3339),
		ObservationEndsAt:    spec.baselineAt.Add(spec.windowDur).Format(time.RFC3339),
		ElapsedSeconds:       elapsedSec,
		RemainingSeconds:     0,
		FailureReasons:       failures,
		RolledBackReflexes:   rolledBack,
		Checks:               details,
	}

	st.completed = true
	cp := cloneVerifyOutput(&out)
	st.result = &cp
	if st.workerCancel != nil {
		st.workerCancel()
	}

	return out, nil
}

// collectForwardPSIDetails hanya mengagregasi titik PSI sejak baselineAt ke depan (mengabaikan metrik pra-remediasi).
func (s *Server) collectForwardPSIDetails(spec verifySpec, sample cgroup.Sample, evalNow time.Time) (HealthChecksDetail, []string, bool, bool) {
	lookbackMinutes := int(math.Ceil(evalNow.Sub(spec.baselineAt).Minutes())) + 1
	if lookbackMinutes < 2 {
		lookbackMinutes = 2
	}
	if lookbackMinutes > 60 {
		lookbackMinutes = 60
	}

	var (
		windowSamples int
		firstAt       time.Time
		lastAt        time.Time
		memStart      uint64
		memEnd        uint64
		memMin        uint64
		memPeak       uint64
		memSamples    int
		failures      []string
		psiStable     = true
		memStable     = true
	)

	for _, pt := range s.psiRing.Query(spec.normCg, lookbackMinutes, evalNow) {
		// Filter ketat: tolak seluruh titik sebelum baselineAt atau yang tercatat sebelum baselineSeq pada timestamp sama
		if pt.At.Before(spec.baselineAt) {
			continue
		}
		if spec.baselineSeq > 0 && pt.seq > 0 && pt.seq <= spec.baselineSeq {
			continue
		}
		windowSamples++
		if firstAt.IsZero() || pt.At.Before(firstAt) {
			firstAt = pt.At
		}
		if lastAt.IsZero() || pt.At.After(lastAt) {
			lastAt = pt.At
		}
		if pt.SomeAvg10 >= HealthPSIHalfSomeMax && psiStable {
			psiStable = false
			failures = append(failures, fmt.Sprintf("window psi_some_avg10=%.2f exceeded %.1f at %s", pt.SomeAvg10, HealthPSIHalfSomeMax, pt.At.Format(time.RFC3339)))
		}
		if pt.FullAvg10 >= HealthPSIHalfFullMax && psiStable {
			psiStable = false
			failures = append(failures, fmt.Sprintf("window psi_full_avg10=%.2f exceeded %.1f at %s", pt.FullAvg10, HealthPSIHalfFullMax, pt.At.Format(time.RFC3339)))
		}
		if pt.MemoryCurrent > 0 {
			if memSamples == 0 {
				memStart = pt.MemoryCurrent
				memMin = pt.MemoryCurrent
				memPeak = pt.MemoryCurrent
			} else {
				if pt.MemoryCurrent < memMin {
					memMin = pt.MemoryCurrent
				}
				if pt.MemoryCurrent > memPeak {
					memPeak = pt.MemoryCurrent
				}
			}
			memEnd = pt.MemoryCurrent
			memSamples++
		}
	}

	var spanDur time.Duration
	if !firstAt.IsZero() && !lastAt.IsZero() && !lastAt.Before(firstAt) {
		spanDur = lastAt.Sub(firstAt)
	}
	spanSec := int64(math.Round(spanDur.Seconds()))

	var memGrowthPct float64
	if memSamples >= 2 && memStart > 0 {
		memGrowthPct = (float64(memEnd) - float64(memStart)) / float64(memStart) * 100.0
		// Tolak kelulusan bila RAM masih terus menanjak > 15% dibanding baseline jendela pemulihan
		if memGrowthPct > MaxVerifyMemoryGrowthPct && memEnd >= (memPeak*90)/100 {
			memStable = false
			failures = append(failures, fmt.Sprintf("memory unstable during %ds forward window: grew %.1f%% (%d -> %d bytes)", spec.windowSec, memGrowthPct, memStart, memEnd))
		}
	}

	if spec.requireCoverage {
		minRequiredDur := time.Duration(float64(spec.windowDur) * 0.8)
		if windowSamples < 2 || spanDur < minRequiredDur {
			failures = append(failures, fmt.Sprintf("insufficient forward verification window coverage: samples=%d span=%ds (need >= %ds)", windowSamples, spanSec, int64(minRequiredDur.Seconds())))
		}
	}

	details := HealthChecksDetail{
		PSISomeAvg10:      sample.PSISomeAvg10,
		PSIFullAvg10:      sample.PSIFullAvg10,
		PSIStable:         psiStable,
		MemoryCurrent:     sample.MemoryCurrent,
		MemoryMinBytes:    memMin,
		MemoryPeakBytes:   memPeak,
		MemoryStartBytes:  memStart,
		MemoryEndBytes:    memEnd,
		MemoryGrowthPct:   math.Round(memGrowthPct*100) / 100,
		MemoryStable:      memStable,
		OOMKillCount:      sample.Events.OOMKill,
		WindowSamples:     windowSamples,
		WindowSpanSeconds: spanSec,
	}
	return details, failures, psiStable, memStable
}
