package reflex

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/policy"
)

const (
	// MaxReflexPerIncident membatasi jumlah aksi refleks L1 per insiden (Requirement 3.3).
	MaxReflexPerIncident = 3
	// MaxTTLSeconds adalah batas keras masa berlaku aksi refleks (15 menit = 900 detik).
	MaxTTLSeconds = 900
	// DefaultTTLSeconds adalah TTL bawaan aksi refleks jika tidak ditentukan (120 detik).
	DefaultTTLSeconds = 120
	// MaxReclaimRatio membatasi reklamasi proaktif maksimal 25% dari memory.current.
	MaxReclaimRatio = 0.25
	// DefaultReclaimRatio adalah rasio reklamasi proaktif bawaan (10% dari memory.current).
	DefaultReclaimRatio = 0.10
	// MaxHostRAMRatio membatasi MemoryHigh agar tidak melebihi 95% total RAM host.
	MaxHostRAMRatio = 0.95
	// DefaultHeadroomPercent menambahkan kelonggaran 5% di atas pemakaian saat ini untuk MemoryHigh.
	DefaultHeadroomRatio = 1.05
	// DefaultRollbackMaxAttempts membatasi jumlah percobaan ulang rollback sebelum dieskalasi menjadi FAILED_ROLLBACK.
	DefaultRollbackMaxAttempts = 5
	// DefaultRollbackInitialBackoff adalah jeda awal exponential backoff sebelum percobaan ulang rollback pertama.
	DefaultRollbackInitialBackoff = 2 * time.Second
	// DefaultRollbackMaxBackoff adalah jeda maksimal antar percobaan ulang rollback otomatis.
	DefaultRollbackMaxBackoff = 60 * time.Second
)

var (
	// ErrMaxReflexReached dikembalikan jika insiden sudah memiliki 3 aksi refleks L1.
	ErrMaxReflexReached = errors.New("reflex: maximum 3 L1 actions per incident reached")
	// ErrRollbackEscalated dikembalikan jika rollback gagal berulang kali melewati batas maksimal retry dan telah dieskalasi.
	ErrRollbackEscalated = errors.New("reflex: rollback failed after max retries and was escalated")
	// ErrProtectedTarget dikembalikan jika target aksi termasuk unit atau aplikasi yang dilindungi.
	ErrProtectedTarget = errors.New("reflex: target unit or app is protected")
	// ErrInvalidTTL dikembalikan jika TTL bernilai negatif atau melebihi batas maksimal 15 menit (900 detik).
	ErrInvalidTTL = errors.New("reflex: ttl_seconds must be between 1 and 900")
	// ErrMemoryHighBelowUsage dikembalikan jika nilai MemoryHigh lebih rendah dari memory.current saat ini.
	ErrMemoryHighBelowUsage = errors.New("reflex: MemoryHigh must be >= current memory usage")
	// ErrMemoryHighAboveHostCap dikembalikan jika nilai MemoryHigh melebihi 95% kapasitas RAM host.
	ErrMemoryHighAboveHostCap = errors.New("reflex: MemoryHigh exceeds 95% of host RAM")
	// ErrReclaimExceedsCap dikembalikan jika ukuran reklamasi melebihi 25% dari memory.current.
	ErrReclaimExceedsCap = errors.New("reflex: reclaim bytes exceeds 25% of current memory usage")
	// ErrInvalidAppName dikembalikan jika nama aplikasi untuk admission_close tidak valid.
	ErrInvalidAppName = errors.New("reflex: invalid application name for admission control")
	// ErrUnknownReflexAction dikembalikan jika nama aksi refleks tidak dikenali saat rollback.
	ErrUnknownReflexAction = errors.New("reflex: unknown reflex action type")
)

// EngineConfig menyimpan dependensi dan batasan operasional untuk Reflex Engine.
type EngineConfig struct {
	Store                  *incident.Store
	FS                     kernelfs.FS
	Catalog                *policy.Catalog
	PropertyDriver         UnitPropertyDriver
	AdmissionDriver        AdmissionDriver
	HostMemTotalBytes      uint64
	Clock                  func() time.Time
	RollbackMaxAttempts    int
	RollbackInitialBackoff time.Duration
	RollbackMaxBackoff     time.Duration
	OnRollbackEscalated    func(action incident.ReflexAction, err error)
}

// Engine menjalankan aksi refleks L1 secara deterministik dan mengelola jadwal rollback TTL.
type Engine struct {
	store                  *incident.Store
	fs                     kernelfs.FS
	catalog                *policy.Catalog
	propDriver             UnitPropertyDriver
	admDriver              AdmissionDriver
	hostMemTotal           uint64
	clock                  func() time.Time
	rollbackMaxAttempts    int
	rollbackInitialBackoff time.Duration
	rollbackMaxBackoff     time.Duration
	onRollbackEscalated    func(action incident.ReflexAction, err error)
	applyMu                sync.Mutex
	rollbackMu             sync.Mutex
}

// ReclaimRequest memuat parameter untuk aksi refleks `cgroup_reclaim`.
type ReclaimRequest struct {
	IncidentID string
	CgroupPath string
	Bytes      uint64 // Opsional: jika 0, dihitung otomatis 10% dari memory.current
	TTLSeconds int    // Opsional: default 120 detik
}

// ThrottleRequest memuat parameter untuk aksi refleks `cgroup_throttle`.
type ThrottleRequest struct {
	IncidentID      string
	Unit            string
	CgroupPath      string
	MemoryHighBytes uint64 // Opsional: jika 0, dihitung otomatis memory.current + 5%
	CPUQuota        string // Opsional: contoh "50%" untuk membatasi CPU sementara
	IOWeight        string // Opsional: contoh "50" untuk menurunkan prioritas IO sementara
	TTLSeconds      int    // Opsional: default 120 detik
}

// AdmissionRequest memuat parameter untuk aksi refleks `admission_close`.
type AdmissionRequest struct {
	IncidentID string
	App        string
	TTLSeconds int // Opsional: default 120 detik
}

// reflexParamsPayload menyimpan metadata dan nilai awal sebelum aksi diterapkan agar rollback bertahan lintas restart.
type reflexParamsPayload struct {
	CgroupPath         string `json:"cgroup_path,omitempty"`
	ReclaimBytes       uint64 `json:"reclaim_bytes,omitempty"`
	MemoryCurrent      uint64 `json:"memory_current,omitempty"`
	AppliedMemoryHigh  uint64 `json:"applied_memory_high,omitempty"`
	PreviousMemoryHigh string `json:"previous_memory_high,omitempty"`
	AppliedCPUQuota    string `json:"applied_cpu_quota,omitempty"`
	PreviousCPUQuota   string `json:"previous_cpu_quota,omitempty"`
	AppliedIOWeight    string `json:"applied_io_weight,omitempty"`
	PreviousIOWeight   string `json:"previous_io_weight,omitempty"`
	PreviousAdmission  string `json:"previous_admission,omitempty"`
	RollbackAttempts   int    `json:"rollback_attempts,omitempty"`
	NextRetryAt        string `json:"next_retry_at,omitempty"`
	LastRollbackError  string `json:"last_rollback_error,omitempty"`
	RollbackExpired    bool   `json:"rollback_expired,omitempty"`
}

// NewEngine membuat instance Reflex Engine baru dengan nilai default yang aman.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("reflex: incident store is required")
	}
	fsys := cfg.FS
	if fsys == nil {
		fsys = kernelfs.NewOSFS()
	}
	propDrv := cfg.PropertyDriver
	if propDrv == nil {
		propDrv = NewExecutorPropertyDriver(nil, 5*time.Second)
	}
	admDrv := cfg.AdmissionDriver
	if admDrv == nil {
		admDrv = NewFSAdmissionDriver(DefaultAdmissionDir)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	maxAttempts := cfg.RollbackMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultRollbackMaxAttempts
	}
	initBackoff := cfg.RollbackInitialBackoff
	if initBackoff <= 0 {
		initBackoff = DefaultRollbackInitialBackoff
	}
	maxBackoff := cfg.RollbackMaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = DefaultRollbackMaxBackoff
	}
	if maxBackoff < initBackoff {
		maxBackoff = initBackoff
	}

	return &Engine{
		store:                  cfg.Store,
		fs:                     fsys,
		catalog:                cfg.Catalog,
		propDriver:             propDrv,
		admDriver:              admDrv,
		hostMemTotal:           cfg.HostMemTotalBytes,
		clock:                  clock,
		rollbackMaxAttempts:    maxAttempts,
		rollbackInitialBackoff: initBackoff,
		rollbackMaxBackoff:     maxBackoff,
		onRollbackEscalated:    cfg.OnRollbackEscalated,
	}, nil
}

// validateCommon memeriksa aturan batas jumlah refleks (maks 3 per insiden), perlindungan target, dan validitas TTL.
func (e *Engine) validateCommon(ctx context.Context, incidentID, target string, ttlSeconds int) (int, error) {
	if incidentID == "" {
		return 0, errors.New("reflex: incident_id is required")
	}
	if e.catalog != nil && e.catalog.IsProtectedUnit(target) {
		return 0, fmt.Errorf("%w: %s", ErrProtectedTarget, target)
	}

	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 || ttlSeconds > MaxTTLSeconds {
		return 0, fmt.Errorf("%w: got %d", ErrInvalidTTL, ttlSeconds)
	}

	count, err := e.store.CountReflexActionsByIncident(ctx, incidentID)
	if err != nil {
		return 0, fmt.Errorf("check reflex quota: %w", err)
	}
	if count >= MaxReflexPerIncident {
		return 0, fmt.Errorf("%w: incident %s already has %d actions", ErrMaxReflexReached, incidentID, count)
	}

	return ttlSeconds, nil
}

// ApplyReclaim menerapkan aksi L1 `cgroup_reclaim` dengan membatasi reklamasi maksimal 25% dari pemakaian saat ini.
func (e *Engine) ApplyReclaim(ctx context.Context, req ReclaimRequest) (*incident.ReflexAction, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	ttl, err := e.validateCommon(ctx, req.IncidentID, req.CgroupPath, req.TTLSeconds)
	if err != nil {
		return nil, err
	}

	currentBytes, isMax, err := kernelfs.ReadUint64(e.fs, kernelfs.JoinPath(req.CgroupPath, "memory.current"))
	if err != nil {
		return nil, fmt.Errorf("read memory.current for reclaim: %w", err)
	}
	if isMax {
		return nil, errors.New("reflex: memory.current unexpectedly returned 'max'")
	}

	maxAllowed := uint64(float64(currentBytes) * MaxReclaimRatio)
	reclaimBytes := req.Bytes
	if reclaimBytes == 0 {
		reclaimBytes = uint64(float64(currentBytes) * DefaultReclaimRatio)
		if reclaimBytes == 0 && maxAllowed > 0 {
			reclaimBytes = maxAllowed
		}
	}

	if reclaimBytes == 0 || reclaimBytes > maxAllowed {
		return nil, fmt.Errorf("%w: requested=%d max_allowed(25%%)=%d", ErrReclaimExceedsCap, reclaimBytes, maxAllowed)
	}

	if err := kernelfs.TriggerReclaim(e.fs, req.CgroupPath, reclaimBytes); err != nil {
		return nil, err
	}

	payloadBytes, _ := json.Marshal(reflexParamsPayload{
		CgroupPath:    req.CgroupPath,
		ReclaimBytes:  reclaimBytes,
		MemoryCurrent: currentBytes,
	})

	now := e.clock().UTC()
	action := &incident.ReflexAction{
		ID:         newReflexID(),
		IncidentID: req.IncidentID,
		Action:     "cgroup_reclaim",
		Target:     req.CgroupPath,
		ParamsJSON: string(payloadBytes),
		AppliedAt:  now,
		TTLSeconds: ttl,
		ExpiresAt:  now.Add(time.Duration(ttl) * time.Second),
		Status:     "APPLIED",
	}

	if err := e.store.SaveReflexAction(ctx, action); err != nil {
		return nil, err
	}
	return action, nil
}

// ApplyThrottle menerapkan aksi L1 `cgroup_throttle` dengan memvalidasi MemoryHigh >= memory.current dan <= 95% RAM host.
func (e *Engine) ApplyThrottle(ctx context.Context, req ThrottleRequest) (*incident.ReflexAction, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	if req.Unit == "" {
		return nil, errors.New("reflex: unit is required for cgroup_throttle")
	}

	ttl, err := e.validateCommon(ctx, req.IncidentID, req.Unit, req.TTLSeconds)
	if err != nil {
		return nil, err
	}

	// Baca pemakaian memori aktual cgroup untuk menegakkan Invariant P4
	currentBytes, isMax, err := kernelfs.ReadUint64(e.fs, kernelfs.JoinPath(req.CgroupPath, "memory.current"))
	if err != nil {
		return nil, fmt.Errorf("read memory.current for throttle: %w", err)
	}
	if isMax {
		return nil, errors.New("reflex: memory.current unexpectedly returned 'max'")
	}

	var hostCap uint64
	if e.hostMemTotal > 0 {
		hostCap = uint64(float64(e.hostMemTotal) * MaxHostRAMRatio)
	}

	targetHigh := req.MemoryHighBytes
	if targetHigh == 0 {
		// Hitung otomatis memory.current + 5% headroom agar tidak langsung memicu thrashing
		targetHigh = uint64(float64(currentBytes) * DefaultHeadroomRatio)
		if targetHigh < currentBytes {
			targetHigh = currentBytes
		}
		if hostCap > 0 && targetHigh > hostCap {
			if hostCap >= currentBytes {
				targetHigh = hostCap
			}
		}
	}

	// Penegakan mutlak Invariant P4: MemoryHigh tidak pernah boleh di bawah pemakaian saat ini
	if targetHigh < currentBytes {
		return nil, fmt.Errorf("%w: target=%d < current=%d", ErrMemoryHighBelowUsage, targetHigh, currentBytes)
	}
	if hostCap > 0 && targetHigh > hostCap {
		return nil, fmt.Errorf("%w: target=%d > host_cap_95pct=%d", ErrMemoryHighAboveHostCap, targetHigh, hostCap)
	}

	// Simpan properti awal sebelum mutasi agar dapat dikembalikan saat rollback
	prevProps, err := e.propDriver.GetProperties(ctx, req.Unit)
	if err != nil {
		return nil, fmt.Errorf("snapshot previous unit properties: %w", err)
	}
	if prevProps.MemoryHigh == "" {
		prevProps.MemoryHigh = "infinity"
	}

	// Jika ada aksi throttle aktif pada unit yang sama, warisi baseline awal sebelum intervensi refleks
	basePrevMemoryHigh := prevProps.MemoryHigh
	basePrevCPUQuota := ""
	if req.CPUQuota != "" {
		basePrevCPUQuota = normalizeUnsetCPUQuota(prevProps.CPUQuota)
	}
	basePrevIOWeight := restoreIOWeightPlaceholder(req.IOWeight, prevProps.IOWeight)
	if basePayload, found, bErr := e.findActiveBaseline(ctx, "cgroup_throttle", req.Unit); bErr == nil && found {
		if basePayload.PreviousMemoryHigh != "" {
			basePrevMemoryHigh = basePayload.PreviousMemoryHigh
		}
		if req.CPUQuota != "" && basePayload.AppliedCPUQuota != "" {
			basePrevCPUQuota = normalizeUnsetCPUQuota(basePayload.PreviousCPUQuota)
		}
		if req.IOWeight != "" && basePayload.PreviousIOWeight != "" {
			basePrevIOWeight = basePayload.PreviousIOWeight
		}
	}

	newProps := UnitProperties{
		MemoryHigh: strconv.FormatUint(targetHigh, 10),
		CPUQuota:   req.CPUQuota,
		IOWeight:   req.IOWeight,
	}

	if err := e.propDriver.SetProperties(ctx, req.Unit, newProps); err != nil {
		return nil, fmt.Errorf("apply cgroup throttle: %w", err)
	}

	payload := reflexParamsPayload{
		CgroupPath:         req.CgroupPath,
		MemoryCurrent:      currentBytes,
		AppliedMemoryHigh:  targetHigh,
		PreviousMemoryHigh: basePrevMemoryHigh,
		AppliedCPUQuota:    req.CPUQuota,
		PreviousCPUQuota:   basePrevCPUQuota,
		AppliedIOWeight:    req.IOWeight,
		PreviousIOWeight:   basePrevIOWeight,
	}
	payloadBytes, _ := json.Marshal(payload)

	now := e.clock().UTC()
	action := &incident.ReflexAction{
		ID:         newReflexID(),
		IncidentID: req.IncidentID,
		Action:     "cgroup_throttle",
		Target:     req.Unit,
		ParamsJSON: string(payloadBytes),
		AppliedAt:  now,
		TTLSeconds: ttl,
		ExpiresAt:  now.Add(time.Duration(ttl) * time.Second),
		Status:     "APPLIED",
	}

	if err := e.store.SaveReflexAction(ctx, action); err != nil {
		// Jika penyimpanan database gagal, segera kembalikan properti unit ke kondisi awal
		_ = e.propDriver.SetProperties(ctx, req.Unit, buildRevertProps(payload))
		return nil, err
	}
	return action, nil
}

// ApplyAdmissionClose menerapkan aksi L1 `admission_close` dengan menulis status penutupan ingress sementara.
func (e *Engine) ApplyAdmissionClose(ctx context.Context, req AdmissionRequest) (*incident.ReflexAction, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	if !validAppNameRegex.MatchString(req.App) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidAppName, req.App)
	}

	ttl, err := e.validateCommon(ctx, req.IncidentID, req.App, req.TTLSeconds)
	if err != nil {
		return nil, err
	}

	prevState, err := e.admDriver.ReadState(ctx, req.App)
	if err != nil {
		return nil, fmt.Errorf("read previous admission state: %w", err)
	}
	if prevState == "" {
		prevState = "open\n"
	}
	if basePayload, found, bErr := e.findActiveBaseline(ctx, "admission_close", req.App); bErr == nil && found && basePayload.PreviousAdmission != "" {
		// Warisi state admission awal sebelum refleks pertama menutup ingress
		prevState = basePayload.PreviousAdmission
	}

	now := e.clock().UTC()
	expiresAt := now.Add(time.Duration(ttl) * time.Second)
	closedContent := fmt.Sprintf("closed incident=%s expires=%s\n", req.IncidentID, expiresAt.Format(time.RFC3339))

	if err := e.admDriver.WriteState(ctx, req.App, closedContent); err != nil {
		return nil, err
	}

	payloadBytes, _ := json.Marshal(reflexParamsPayload{
		PreviousAdmission: prevState,
	})

	action := &incident.ReflexAction{
		ID:         newReflexID(),
		IncidentID: req.IncidentID,
		Action:     "admission_close",
		Target:     req.App,
		ParamsJSON: string(payloadBytes),
		AppliedAt:  now,
		TTLSeconds: ttl,
		ExpiresAt:  expiresAt,
		Status:     "APPLIED",
	}

	if err := e.store.SaveReflexAction(ctx, action); err != nil {
		_ = e.admDriver.WriteState(ctx, req.App, prevState)
		return nil, err
	}
	return action, nil
}

// Rollback mengembalikan satu aksi refleks L1 ke pengaturan awal secara aman dan menjamin eksekusi tepat satu kali.
func (e *Engine) Rollback(ctx context.Context, reflexID string, expired bool) (bool, error) {
	return e.rollbackWithPolicy(ctx, reflexID, expired, false)
}

func (e *Engine) rollbackWithPolicy(ctx context.Context, reflexID string, expired bool, respectBackoff bool) (bool, error) {
	e.rollbackMu.Lock()
	defer e.rollbackMu.Unlock()

	action, err := e.store.GetReflexAction(ctx, reflexID)
	if err != nil {
		return false, err
	}

	// Hanya aksi dengan status APPLIED yang berhak di-rollback atau dicoba ulang.
	if action.Status != "APPLIED" {
		return false, nil
	}

	var payload reflexParamsPayload
	if action.ParamsJSON != "" {
		if err := json.Unmarshal([]byte(action.ParamsJSON), &payload); err != nil {
			return false, fmt.Errorf("decode reflex params for %s: %w", reflexID, err)
		}
	}

	now := e.clock().UTC()
	if respectBackoff && payload.NextRetryAt != "" {
		nextRetry, parseErr := time.Parse(time.RFC3339Nano, payload.NextRetryAt)
		if parseErr == nil && now.Before(nextRetry) {
			return false, nil
		}
	}

	var rollbackErr error
	switch action.Action {
	case "cgroup_reclaim":
		// Memory reclaim bersifat one-shot kernel hint; tidak ada properti persisten untuk dikembalikan
		rollbackErr = nil
	case "cgroup_throttle":
		revertProps := buildRevertProps(payload)
		rollbackErr = e.propDriver.SetProperties(ctx, action.Target, revertProps)
	case "admission_close":
		prev := payload.PreviousAdmission
		if prev == "" {
			prev = "open\n"
		}
		rollbackErr = e.admDriver.WriteState(ctx, action.Target, prev)
	default:
		rollbackErr = fmt.Errorf("%w: %s", ErrUnknownReflexAction, action.Action)
	}

	if rollbackErr != nil {
		return false, e.handleRollbackFailure(ctx, *action, payload, expired, now, rollbackErr)
	}

	targetStatus := "ROLLED_BACK"
	if expired || payload.RollbackExpired {
		targetStatus = "EXPIRED_ROLLED_BACK"
	}

	changed, err := e.store.MarkReflexRolledBack(ctx, reflexID, targetStatus, now)
	if err != nil {
		return false, err
	}
	if changed {
		auditBytes, _ := json.Marshal(map[string]any{
			"reflex_id": reflexID,
			"action":    action.Action,
			"status":    targetStatus,
			"attempts":  payload.RollbackAttempts + 1,
		})
		_ = e.store.RecordAudit(ctx, action.IncidentID, "sentinel", "REFLEX_ROLLED_BACK", string(auditBytes))
	}
	return changed, nil
}

// handleRollbackFailure mencatat jadwal retry dengan exponential backoff sebelum eskalasi permanen ke FAILED_ROLLBACK.
func (e *Engine) handleRollbackFailure(ctx context.Context, action incident.ReflexAction, payload reflexParamsPayload, expired bool, now time.Time, rollbackErr error) error {
	payload.RollbackAttempts++
	payload.LastRollbackError = rollbackErr.Error()
	if expired {
		payload.RollbackExpired = true
	}

	if payload.RollbackAttempts < e.rollbackMaxAttempts {
		delay := e.computeRollbackBackoff(payload.RollbackAttempts)
		nextRetry := now.Add(delay)
		payload.NextRetryAt = nextRetry.Format(time.RFC3339Nano)
		if updatedJSON, err := json.Marshal(payload); err == nil {
			_ = e.store.UpdateReflexParams(ctx, action.ID, string(updatedJSON))
		}
		retryAudit, _ := json.Marshal(map[string]any{
			"reflex_id":     action.ID,
			"action":        action.Action,
			"attempt":       payload.RollbackAttempts,
			"max_attempts":  e.rollbackMaxAttempts,
			"next_retry_at": payload.NextRetryAt,
			"error":         rollbackErr.Error(),
		})
		_ = e.store.RecordAudit(ctx, action.IncidentID, "sentinel", "REFLEX_ROLLBACK_RETRY", string(retryAudit))
		return fmt.Errorf("rollback reflex %s (%s) attempt %d/%d failed, retry scheduled at %s: %w",
			action.ID, action.Action, payload.RollbackAttempts, e.rollbackMaxAttempts, payload.NextRetryAt, rollbackErr)
	}

	// Batas retry terlampaui: simpan payload akhir, tandai FAILED_ROLLBACK permanen, dan lakukan eskalasi.
	payload.NextRetryAt = ""
	if updatedJSON, err := json.Marshal(payload); err == nil {
		_ = e.store.UpdateReflexParams(ctx, action.ID, string(updatedJSON))
	}
	_ = e.store.UpdateReflexStatus(ctx, action.ID, "FAILED_ROLLBACK", &now)

	escalateAudit, _ := json.Marshal(map[string]any{
		"reflex_id":    action.ID,
		"action":       action.Action,
		"target":       action.Target,
		"attempts":     payload.RollbackAttempts,
		"max_attempts": e.rollbackMaxAttempts,
		"error":        rollbackErr.Error(),
	})
	_ = e.store.RecordAudit(ctx, action.IncidentID, "sentinel", "REFLEX_ROLLBACK_ESCALATED", string(escalateAudit))
	if e.onRollbackEscalated != nil {
		e.onRollbackEscalated(action, rollbackErr)
	}

	return fmt.Errorf("%w: rollback reflex %s (%s) failed after %d attempts: %w",
		ErrRollbackEscalated, action.ID, action.Action, payload.RollbackAttempts, rollbackErr)
}

func (e *Engine) computeRollbackBackoff(attempt int) time.Duration {
	if attempt <= 1 {
		return e.rollbackInitialBackoff
	}
	delay := e.rollbackInitialBackoff
	for i := 1; i < attempt; i++ {
		if delay >= e.rollbackMaxBackoff/2 {
			return e.rollbackMaxBackoff
		}
		delay *= 2
	}
	if delay > e.rollbackMaxBackoff {
		return e.rollbackMaxBackoff
	}
	return delay
}

// RollbackIncident me-rollback seluruh aksi refleks L1 yang masih aktif milik sebuah insiden.
func (e *Engine) RollbackIncident(ctx context.Context, incidentID string) (int, error) {
	actions, err := e.store.GetReflexActionsByIncident(ctx, incidentID)
	if err != nil {
		return 0, err
	}

	rolledBackCount := 0
	var firstErr error
	for _, act := range actions {
		if act.Status != "APPLIED" {
			continue
		}
		didRollback, rbErr := e.Rollback(ctx, act.ID, false)
		if rbErr != nil && firstErr == nil {
			firstErr = rbErr
		}
		if didRollback {
			rolledBackCount++
		}
	}
	return rolledBackCount, firstErr
}

// SweepExpired memeriksa SQLite untuk seluruh aksi APPLIED yang melewati batas TTL atau menunggu jadwal retry rollback.
func (e *Engine) SweepExpired(ctx context.Context) (int, error) {
	pending, err := e.store.GetPendingReflexActions(ctx)
	if err != nil {
		return 0, fmt.Errorf("sweep pending reflexes: %w", err)
	}

	now := e.clock().UTC()
	rolledBackCount := 0
	var firstErr error

	for _, act := range pending {
		var payload reflexParamsPayload
		if act.ParamsJSON != "" {
			_ = json.Unmarshal([]byte(act.ParamsJSON), &payload)
		}
		isExpired := !now.Before(act.ExpiresAt)
		isRetrying := payload.RollbackAttempts > 0
		if !isExpired && !isRetrying {
			continue
		}
		if payload.NextRetryAt != "" {
			nextRetry, parseErr := time.Parse(time.RFC3339Nano, payload.NextRetryAt)
			if parseErr == nil && now.Before(nextRetry) {
				continue
			}
		}
		didRollback, rbErr := e.rollbackWithPolicy(ctx, act.ID, isExpired || payload.RollbackExpired, true)
		if rbErr != nil && firstErr == nil {
			firstErr = rbErr
		}
		if didRollback {
			rolledBackCount++
		}
	}
	return rolledBackCount, firstErr
}

// RunScheduler menjalankan pembersihan TTL saat startup (pemulihan pasca restart) lalu melakukan sweep berkala.
func (e *Engine) RunScheduler(ctx context.Context, tickInterval time.Duration) error {
	if tickInterval <= 0 {
		tickInterval = 1 * time.Second
	}

	// Segera sweep saat startup untuk memulihkan deadline TTL yang terlewat saat Sentinel restart
	if _, err := e.SweepExpired(ctx); err != nil {
		_ = e.store.RecordAudit(ctx, "", "sentinel", "REFLEX_SWEEP_ERROR", fmt.Sprintf(`{"error":%q}`, err.Error()))
	}

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := e.SweepExpired(ctx); err != nil {
				_ = e.store.RecordAudit(ctx, "", "sentinel", "REFLEX_SWEEP_ERROR", fmt.Sprintf(`{"error":%q}`, err.Error()))
			}
		}
	}
}

func normalizeUnsetCPUQuota(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "infinity" || trimmed == "[not set]" {
		return ""
	}
	return trimmed
}

func restoreIOWeightPlaceholder(applied, previous string) string {
	if applied != "" && previous == "" {
		return "100"
	}
	return previous
}

func buildRevertProps(p reflexParamsPayload) UnitProperties {
	var props UnitProperties
	if p.AppliedMemoryHigh > 0 {
		memHigh := p.PreviousMemoryHigh
		if memHigh == "" {
			memHigh = "infinity"
		}
		props.MemoryHigh = memHigh
	}
	if p.AppliedCPUQuota != "" {
		prevQuota := normalizeUnsetCPUQuota(p.PreviousCPUQuota)
		if prevQuota == "" {
			// Reset ke kondisi unset via `CPUQuota=` karena systemctl menolak nilai "infinity" atau "[not set]".
			props.ResetCPUQuota = true
		} else {
			props.CPUQuota = prevQuota
		}
	}
	if p.AppliedIOWeight != "" {
		ioW := p.PreviousIOWeight
		if ioW == "" {
			ioW = "100"
		}
		props.IOWeight = ioW
	}
	return props
}

// findActiveBaseline mencari aksi APPLIED paling awal pada action+target yang sama untuk mewarisi baseline asli.
func (e *Engine) findActiveBaseline(ctx context.Context, actionName, target string) (reflexParamsPayload, bool, error) {
	pending, err := e.store.GetPendingReflexActions(ctx)
	if err != nil {
		return reflexParamsPayload{}, false, err
	}
	for _, act := range pending {
		if act.Action != actionName || act.Target != target || act.ParamsJSON == "" {
			continue
		}
		var payload reflexParamsPayload
		if err := json.Unmarshal([]byte(act.ParamsJSON), &payload); err == nil {
			return payload, true, nil
		}
	}
	return reflexParamsPayload{}, false, nil
}

func newReflexID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("RFX-%s", hex.EncodeToString(b[:]))
}
