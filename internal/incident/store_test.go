package incident

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStore_LifecycleAndTransitions(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "sentinel_test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	tto := 45.5
	inc := &Incident{
		ID:         "INC-20261112-0317-pi01",
		Node:       "pi01",
		Cgroup:     "/franken.slice/haunted-api.service",
		Severity:   "P2",
		State:      StateDetected,
		TTOSeconds: &tto,
	}

	// 1. Uji pembuatan insiden baru
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	fetched, err := store.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("failed to fetch incident: %v", err)
	}
	if fetched.State != StateDetected || fetched.Severity != "P2" {
		t.Errorf("unexpected incident data: %+v", fetched)
	}

	// 2. Uji transisi status yang valid: DETECTED -> REFLEX_APPLIED
	if err := store.TransitionState(ctx, inc.ID, StateReflexApplied, "sentinel", "cgroup_throttle applied"); err != nil {
		t.Fatalf("valid transition to REFLEX_APPLIED failed: %v", err)
	}

	// 3. Uji transisi status yang tidak valid: REFLEX_APPLIED -> RESOLVED (harus lewat VERIFYING)
	err = store.TransitionState(ctx, inc.ID, StateResolved, "sentinel", "illegal jump to resolved")
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition, got %v", err)
	}

	// 4. Lanjutkan siklus yang sah: REFLEX_APPLIED -> WAITING_APPROVAL -> REMEDIATING -> VERIFYING -> RESOLVED
	if err := store.TransitionState(ctx, inc.ID, StateWaitingApproval, "sentry", "waiting for developer poll"); err != nil {
		t.Fatalf("transition to WAITING_APPROVAL failed: %v", err)
	}
	if err := store.TransitionState(ctx, inc.ID, StateRemediating, "remediator", "pm2 reload executing"); err != nil {
		t.Fatalf("transition to REMEDIATING failed: %v", err)
	}
	if err := store.TransitionState(ctx, inc.ID, StateVerifying, "remediator", "waiting 120s green health"); err != nil {
		t.Fatalf("transition to VERIFYING failed: %v", err)
	}
	if err := store.TransitionState(ctx, inc.ID, StateResolved, "remediator", "health check passed"); err != nil {
		t.Fatalf("transition to RESOLVED failed: %v", err)
	}

	finalInc, err := store.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("failed to get resolved incident: %v", err)
	}
	if finalInc.State != StateResolved || finalInc.ClosedAt == nil {
		t.Errorf("expected incident to be closed with timestamp, got %+v", finalInc)
	}
}

func TestStore_EvidenceRedactionPipeline(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "evidence_test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inc := &Incident{
		ID:       "INC-EVID-001",
		Node:     "pi01",
		Cgroup:   "/app.service",
		Severity: "P1",
		State:    StateDetected,
	}
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("failed creating incident: %v", err)
	}

	rawLog := "Crash report: failed connecting to postgres://root:superSecretDBPass@10.0.0.12:5432/db with token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	snapshot := &EvidenceSnapshot{
		ID:         "EVID-001",
		IncidentID: inc.ID,
		Kind:       "journal_tail",
		RawData:    rawLog,
	}

	// Simpan snapshot bukti; sensor otomatis harus aktif
	if err := store.SaveEvidence(ctx, snapshot); err != nil {
		t.Fatalf("failed to save evidence: %v", err)
	}

	evList, err := store.GetEvidenceByIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("failed to get evidence: %v", err)
	}
	if len(evList) != 1 {
		t.Fatalf("expected 1 evidence item, got %d", len(evList))
	}

	redacted := evList[0].RedactedData
	if strings.Contains(redacted, "superSecretDBPass") {
		t.Errorf("raw database password was not redacted: %s", redacted)
	}
	if strings.Contains(redacted, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Errorf("JWT token was not redacted: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED_PASSWORD]") || !strings.Contains(redacted, "[REDACTED_JWT]") {
		t.Errorf("expected redacted markers in output: %s", redacted)
	}
}

func TestStore_NoncesAntiReplay(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nonces_test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	nonce := "random_unique_nonce_abc123"
	incidentID := "INC-NONCE-01"
	planHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Konsumsi pertama harus berhasil
	if err := store.ConsumeNonce(ctx, nonce, incidentID, planHash); err != nil {
		t.Fatalf("first nonce consumption should succeed: %v", err)
	}

	// Konsumsi kedua dengan nonce yang sama harus ditolak (replay attack prevention)
	err = store.ConsumeNonce(ctx, nonce, incidentID, planHash)
	if !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("expected ErrNonceReplayed on second attempt, got: %v", err)
	}
}

func TestStore_ReflexAndAuditTrail(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "reflex_audit_test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inc := &Incident{
		ID:       "INC-AUDIT-001",
		Node:     "pi01",
		Cgroup:   "/app.service",
		Severity: "P2",
		State:    StateDetected,
	}
	_ = store.CreateIncident(ctx, inc)

	// Simpan aksi refleks
	action := &ReflexAction{
		ID:         "REFLEX-001",
		IncidentID: inc.ID,
		Action:     "cgroup_throttle",
		Target:     "app.service",
		ParamsJSON: `{"memory_high":"500M"}`,
		TTLSeconds: 600,
	}
	if err := store.SaveReflexAction(ctx, action); err != nil {
		t.Fatalf("failed to save reflex action: %v", err)
	}

	// Perbarui status aksi refleks menjadi ROLLED_BACK
	now := time.Now().UTC()
	if err := store.UpdateReflexStatus(ctx, action.ID, "ROLLED_BACK", &now); err != nil {
		t.Fatalf("failed to update reflex status: %v", err)
	}

	// Periksa log audit trail
	trail, err := store.GetAuditTrail(ctx, inc.ID)
	if err != nil {
		t.Fatalf("failed to get audit trail: %v", err)
	}
	if len(trail) < 2 {
		t.Errorf("expected at least 2 audit entries, got %d", len(trail))
	}
}

func TestStore_ListClaimAndPlan(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "claim_test.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	_ = store.CreateIncident(ctx, &Incident{
		ID: "INC-1", Node: "pi01", Cgroup: "/a.service", Severity: "P2", State: StateDetected, OpenedAt: now.Add(-2 * time.Minute),
	})
	_ = store.CreateIncident(ctx, &Incident{
		ID: "INC-2", Node: "pi01", Cgroup: "/b.service", Severity: "P1", State: StateReflexApplied, OpenedAt: now.Add(-1 * time.Minute),
	})

	// Klaim otomatis terlama wajib mengembalikan INC-1 dan mengubah state menjadi TRIAGING
	claimed, err := store.ClaimIncident(ctx, "", "franken-sentry")
	if err != nil || claimed == nil || claimed.ID != "INC-1" || claimed.State != StateTriaging {
		t.Fatalf("expected INC-1 claimed in TRIAGING state, got %+v (err=%v)", claimed, err)
	}

	// Klaim ulang target yang sama harus mengembalikan nil agar tidak terjadi race condition
	doubleClaim, err := store.ClaimIncident(ctx, "INC-1", "other-worker")
	if err != nil || doubleClaim != nil {
		t.Fatalf("expected nil on duplicate claim, got %+v (err=%v)", doubleClaim, err)
	}

	list, err := store.ListIncidents(ctx, string(StateTriaging), 10)
	if err != nil || len(list) != 1 || list[0].ID != "INC-1" {
		t.Fatalf("unexpected filtered list: %+v (err=%v)", list, err)
	}

	if err := store.SavePlan(ctx, "INC-1", `{"incident_id":"INC-1"}`); err != nil {
		t.Fatalf("SavePlan failed: %v", err)
	}
	updated, _ := store.GetIncident(ctx, "INC-1")
	if updated.PlanJSON == "" {
		t.Fatal("expected PlanJSON persisted")
	}

	claimCount, err := store.CountAuditByEvent(ctx, "INC-1", "INCIDENT_CLAIMED")
	if err != nil || claimCount != 1 {
		t.Fatalf("expected 1 INCIDENT_CLAIMED audit entry, got %d (err=%v)", claimCount, err)
	}
}

func TestStore_TransitionState_AtomicConcurrency(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "concurrent_transition.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Uji pula persaingan dua koneksi DB terpisah (mis. Sentinel daemon & hook guard) pada berkas WAL yang sama
	store2, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore second conn: %v", err)
	}
	defer func() { _ = store2.Close() }()

	ctx := context.Background()
	incID := "INC-RACE-01"
	if err := store.CreateIncident(ctx, &Incident{
		ID:       incID,
		Node:     "pi01",
		Cgroup:   "/haunted-api.service",
		Severity: "P1",
		State:    StateDetected,
	}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	const workers = 16
	targets := []State{StateResolved, StateEscalated, StateDismissed}
	var startBarrier sync.WaitGroup
	startBarrier.Add(1)

	var wg sync.WaitGroup
	var winCount atomic.Int32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			startBarrier.Wait()

			targetStore := store
			if idx%2 == 1 {
				targetStore = store2
			}
			target := targets[idx%len(targets)]
			if trErr := targetStore.TransitionState(ctx, incID, target, "worker", "race test"); trErr == nil {
				winCount.Add(1)
			}
		}(i)
	}

	startBarrier.Done()
	wg.Wait()

	// Hanya tepat 1 goroutine yang boleh berhasil mentransisikan insiden dari DETECTED ke state terminal.
	if got := winCount.Load(); got != 1 {
		t.Fatalf("expected strictly 1 concurrent terminal transition winner, got %d", got)
	}

	finalInc, err := store.GetIncident(ctx, incID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if finalInc.State != StateResolved && finalInc.State != StateEscalated && finalInc.State != StateDismissed {
		t.Fatalf("unexpected final state after concurrent race: %s", finalInc.State)
	}

	// Pastikan audit STATE_TRANSITION juga tercipta tepat satu kali dalam transaksi pemenang
	trCount, err := store.CountAuditByEvent(ctx, incID, "STATE_TRANSITION")
	if err != nil || trCount != 1 {
		t.Fatalf("expected exactly 1 STATE_TRANSITION audit entry, got %d (err=%v)", trCount, err)
	}

	// Verifikasi penolakan transisi lanjutan pada state terminal tetap mengembalikan ErrInvalidTransition
	if err := store.TransitionState(ctx, incID, StateTriaging, "worker", "late regress"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition after terminal commit, got %v", err)
	}
}

