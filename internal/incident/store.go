package incident

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/redact"
	_ "modernc.org/sqlite"
)

// Store mengelola penyimpanan data persisten SQLite untuk insiden, bukti telemetri, dan audit.
type Store struct {
	db *sql.DB
}

const schemaDDL = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS incidents (
	id TEXT PRIMARY KEY,
	node TEXT NOT NULL,
	cgroup TEXT NOT NULL,
	severity TEXT NOT NULL,
	state TEXT NOT NULL,
	tto_seconds REAL,
	opened_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	closed_at DATETIME,
	triage_json TEXT,
	plan_json TEXT
);

CREATE TABLE IF NOT EXISTS evidence_snapshots (
	id TEXT PRIMARY KEY,
	incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
	kind TEXT NOT NULL,
	raw_data TEXT,
	redacted_data TEXT NOT NULL,
	captured_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS reflex_actions (
	id TEXT PRIMARY KEY,
	incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	params_json TEXT NOT NULL,
	applied_at DATETIME NOT NULL,
	ttl_seconds INTEGER NOT NULL,
	expires_at DATETIME NOT NULL,
	rolled_back_at DATETIME,
	status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_trail (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id TEXT,
	actor TEXT NOT NULL,
	event_type TEXT NOT NULL,
	payload_json TEXT NOT NULL,
	created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
	nonce TEXT PRIMARY KEY,
	bound_incident_id TEXT NOT NULL,
	bound_plan_hash TEXT NOT NULL,
	consumed_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence_snapshots(incident_id);
CREATE INDEX IF NOT EXISTS idx_reflex_incident ON reflex_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_trail(incident_id);
`

// NewStore membuka database SQLite dengan pragmas produksi dan menjalankan migrasi skema tabel.
func NewStore(dbPath string) (*Store, error) {
	dsn := dbPath
	if !strings.Contains(dsn, "?") {
		dsn += "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db %s: %w", dbPath, err)
	}

	// Batasi pool koneksi untuk SQLite file agar serialisasi write tetap aman
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx, schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init sqlite schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close menutup koneksi database SQLite.
func (s *Store) Close() error {
	return s.db.Close()
}

// CreateIncident mencatat insiden baru ke database.
func (s *Store) CreateIncident(ctx context.Context, inc *Incident) error {
	now := time.Now().UTC()
	if inc.OpenedAt.IsZero() {
		inc.OpenedAt = now
	}
	inc.UpdatedAt = now

	query := `
	INSERT INTO incidents (id, node, cgroup, severity, state, tto_seconds, opened_at, updated_at, closed_at, triage_json, plan_json)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err := s.db.ExecContext(ctx, query,
		inc.ID, inc.Node, inc.Cgroup, inc.Severity, string(inc.State),
		inc.TTOSeconds, inc.OpenedAt, inc.UpdatedAt, inc.ClosedAt,
		inc.TriageJSON, inc.PlanJSON,
	)
	if err != nil {
		return fmt.Errorf("insert incident %s: %w", inc.ID, err)
	}

	_ = s.RecordAudit(ctx, inc.ID, "sentinel", "INCIDENT_CREATED", fmt.Sprintf(`{"severity":"%s","cgroup":"%s"}`, inc.Severity, inc.Cgroup))
	return nil
}

// rowScanner mengabstraksikan sql.Row dan sql.Rows untuk menghindari duplikasi pemindaian kolom insiden.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanIncident(sc rowScanner) (Incident, error) {
	var inc Incident
	var stateStr string
	err := sc.Scan(
		&inc.ID, &inc.Node, &inc.Cgroup, &inc.Severity, &stateStr,
		&inc.TTOSeconds, &inc.OpenedAt, &inc.UpdatedAt, &inc.ClosedAt,
		&inc.TriageJSON, &inc.PlanJSON,
	)
	if err != nil {
		return Incident{}, err
	}
	inc.State = State(stateStr)
	return inc, nil
}

// GetIncident mengambil data insiden berdasarkan ID.
func (s *Store) GetIncident(ctx context.Context, id string) (*Incident, error) {
	query := `
	SELECT id, node, cgroup, severity, state, tto_seconds, opened_at, updated_at, closed_at, triage_json, plan_json
	FROM incidents WHERE id = ?;
	`
	inc, err := scanIncident(s.db.QueryRowContext(ctx, query, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIncidentNotFound
		}
		return nil, fmt.Errorf("query incident %s: %w", id, err)
	}
	return &inc, nil
}

// ListIncidents mengembalikan daftar insiden terbaru dengan filter status dan batas jumlah opsional.
func (s *Store) ListIncidents(ctx context.Context, stateFilter string, limit int) ([]Incident, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}

	var rows *sql.Rows
	var err error
	if stateFilter != "" {
		rows, err = s.db.QueryContext(ctx, `
		SELECT id, node, cgroup, severity, state, tto_seconds, opened_at, updated_at, closed_at, triage_json, plan_json
		FROM incidents WHERE state = ? ORDER BY opened_at DESC, id DESC LIMIT ?;
		`, stateFilter, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
		SELECT id, node, cgroup, severity, state, tto_seconds, opened_at, updated_at, closed_at, triage_json, plan_json
		FROM incidents ORDER BY opened_at DESC, id DESC LIMIT ?;
		`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var list []Incident
	for rows.Next() {
		inc, scanErr := scanIncident(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan incident row: %w", scanErr)
		}
		list = append(list, inc)
	}
	return list, rows.Err()
}

// ClaimIncident mengklaim insiden terbuka secara atomik menjadi TRIAGING untuk mencegah eksekusi ganda.
func (s *Store) ClaimIncident(ctx context.Context, incidentID, claimer string) (*Incident, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var inc Incident
	if incidentID != "" {
		inc, err = scanIncident(tx.QueryRowContext(ctx, `
		SELECT id, node, cgroup, severity, state, tto_seconds, opened_at, updated_at, closed_at, triage_json, plan_json
		FROM incidents WHERE id = ?;
		`, incidentID))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrIncidentNotFound
			}
			return nil, fmt.Errorf("query claim target %s: %w", incidentID, err)
		}
		if inc.State != StateDetected && inc.State != StateReflexApplied {
			return nil, nil
		}
	} else {
		inc, err = scanIncident(tx.QueryRowContext(ctx, `
		SELECT id, node, cgroup, severity, state, tto_seconds, opened_at, updated_at, closed_at, triage_json, plan_json
		FROM incidents
		WHERE state IN (?, ?)
		ORDER BY opened_at ASC, id ASC
		LIMIT 1;
		`, string(StateDetected), string(StateReflexApplied)))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return nil, fmt.Errorf("query oldest claimable incident: %w", err)
		}
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `
	UPDATE incidents SET state = ?, updated_at = ?
	WHERE id = ? AND state IN (?, ?);
	`, string(StateTriaging), now, inc.ID, string(StateDetected), string(StateReflexApplied))
	if err != nil {
		return nil, fmt.Errorf("update claimed incident %s: %w", inc.ID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("claim rows affected %s: %w", inc.ID, err)
	}
	if affected == 0 {
		return nil, nil
	}

	payload := fmt.Sprintf(`{"from":%q,"to":%q,"claimer":%q}`, inc.State, StateTriaging, claimer)
	if _, err := tx.ExecContext(ctx, `
	INSERT INTO audit_trail (incident_id, actor, event_type, payload_json, created_at)
	VALUES (?, ?, ?, ?, ?);
	`, inc.ID, claimer, "INCIDENT_CLAIMED", payload, now); err != nil {
		return nil, fmt.Errorf("audit claim %s: %w", inc.ID, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim %s: %w", inc.ID, err)
	}

	inc.State = StateTriaging
	inc.UpdatedAt = now
	return &inc, nil
}

// SaveTriage menyimpan payload JSON hasil klasifikasi triage agen Sentry pada rekaman insiden.
func (s *Store) SaveTriage(ctx context.Context, incidentID, triageJSON string) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
	UPDATE incidents SET triage_json = ?, updated_at = ? WHERE id = ?;
	`, triageJSON, now, incidentID)
	if err != nil {
		return fmt.Errorf("save triage for %s: %w", incidentID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("save triage rows affected %s: %w", incidentID, err)
	}
	if affected == 0 {
		return ErrIncidentNotFound
	}
	return nil
}

// SavePlan menyimpan payload JSON rencana mitigasi tervalidasi pada rekaman insiden.
func (s *Store) SavePlan(ctx context.Context, incidentID, planJSON string) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
	UPDATE incidents SET plan_json = ?, updated_at = ? WHERE id = ?;
	`, planJSON, now, incidentID)
	if err != nil {
		return fmt.Errorf("save plan for %s: %w", incidentID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("save plan rows affected %s: %w", incidentID, err)
	}
	if affected == 0 {
		return ErrIncidentNotFound
	}
	return nil
}

// CountAuditByEvent menghitung jumlah kemunculan tipe event audit tertentu pada satu insiden.
func (s *Store) CountAuditByEvent(ctx context.Context, incidentID, eventType string) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `
	SELECT COUNT(*) FROM audit_trail WHERE incident_id = ? AND event_type = ?;
	`, incidentID, eventType).Scan(&count); err != nil {
		return 0, fmt.Errorf("count audit %s/%s: %w", incidentID, eventType, err)
	}
	return count, nil
}

// TransitionState memindahkan status insiden secara atomik dalam satu transaksi SQL sesuai aturan state machine.
func (s *Store) TransitionState(ctx context.Context, id string, target State, actor, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transition tx for %s: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentRaw string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM incidents WHERE id = ?;`, id).Scan(&currentRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIncidentNotFound
		}
		return fmt.Errorf("query current state for %s: %w", id, err)
	}

	currentState := State(currentRaw)
	if !CanTransition(currentState, target) {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidTransition, currentState, target)
	}

	now := time.Now().UTC()
	var closedAt *time.Time
	if target == StateResolved || target == StateEscalated || target == StateDismissed || target == StateExpired {
		closedAt = &now
	}

	// Gunakan compare-and-swap (WHERE id = ? AND state = ?) agar transisi konkuren tidak saling menimpa.
	res, err := tx.ExecContext(ctx, `
	UPDATE incidents
	SET state = ?, updated_at = ?, closed_at = ?
	WHERE id = ? AND state = ?;
	`, string(target), now, closedAt, id, currentRaw)
	if err != nil {
		return fmt.Errorf("update incident state %s: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected transitioning %s to %s: %w", id, target, err)
	}
	if affected != 1 {
		return fmt.Errorf("%w: concurrent state conflict transitioning %s from %s to %s", ErrInvalidTransition, id, currentState, target)
	}

	auditPayload, err := json.Marshal(map[string]string{
		"from":   string(currentState),
		"to":     string(target),
		"reason": reason,
	})
	if err != nil {
		return fmt.Errorf("marshal state transition audit for %s: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `
	INSERT INTO audit_trail (incident_id, actor, event_type, payload_json, created_at)
	VALUES (?, ?, ?, ?, ?);
	`, id, actor, "STATE_TRANSITION", string(auditPayload), now); err != nil {
		return fmt.Errorf("insert state transition audit for %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state transition %s to %s: %w", id, target, err)
	}
	return nil
}

// SaveEvidence menyimpan snapshot bukti telemetri setelah menyensor informasi rahasia secara otomatis.
func (s *Store) SaveEvidence(ctx context.Context, snapshot *EvidenceSnapshot) error {
	if snapshot.CapturedAt.IsZero() {
		snapshot.CapturedAt = time.Now().UTC()
	}

	// Pastikan seluruh payload mentah maupun tersensor dibersihkan sebelum masuk ke SQLite
	snapshot.RawData = redact.String(snapshot.RawData)
	if snapshot.RedactedData == "" {
		snapshot.RedactedData = snapshot.RawData
	} else {
		snapshot.RedactedData = redact.String(snapshot.RedactedData)
	}

	query := `
	INSERT INTO evidence_snapshots (id, incident_id, kind, raw_data, redacted_data, captured_at)
	VALUES (?, ?, ?, ?, ?, ?);
	`
	_, err := s.db.ExecContext(ctx, query,
		snapshot.ID, snapshot.IncidentID, snapshot.Kind,
		snapshot.RawData, snapshot.RedactedData, snapshot.CapturedAt,
	)
	if err != nil {
		return fmt.Errorf("save evidence %s: %w", snapshot.ID, err)
	}
	return nil
}

// GetEvidenceByIncident mengambil seluruh daftar bukti yang tersimpan untuk sebuah insiden.
func (s *Store) GetEvidenceByIncident(ctx context.Context, incidentID string) ([]EvidenceSnapshot, error) {
	query := `
	SELECT id, incident_id, kind, raw_data, redacted_data, captured_at
	FROM evidence_snapshots WHERE incident_id = ? ORDER BY captured_at ASC;
	`
	rows, err := s.db.QueryContext(ctx, query, incidentID)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()

	var list []EvidenceSnapshot
	for rows.Next() {
		var e EvidenceSnapshot
		if err := rows.Scan(&e.ID, &e.IncidentID, &e.Kind, &e.RawData, &e.RedactedData, &e.CapturedAt); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		list = append(list, e)
	}
	return list, rows.Err()
}

// SaveReflexAction mencatat aksi refleks L1 ke database dengan masa kadaluarsa TTL.
func (s *Store) SaveReflexAction(ctx context.Context, action *ReflexAction) error {
	now := time.Now().UTC()
	if action.AppliedAt.IsZero() {
		action.AppliedAt = now
	}
	if action.ExpiresAt.IsZero() {
		action.ExpiresAt = action.AppliedAt.Add(time.Duration(action.TTLSeconds) * time.Second)
	}
	if action.Status == "" {
		action.Status = "APPLIED"
	}

	query := `
	INSERT INTO reflex_actions (id, incident_id, action, target, params_json, applied_at, ttl_seconds, expires_at, rolled_back_at, status)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`
	_, err := s.db.ExecContext(ctx, query,
		action.ID, action.IncidentID, action.Action, action.Target,
		action.ParamsJSON, action.AppliedAt, action.TTLSeconds,
		action.ExpiresAt, action.RolledBackAt, action.Status,
	)
	if err != nil {
		return fmt.Errorf("insert reflex action %s: %w", action.ID, err)
	}

	_ = s.RecordAudit(ctx, action.IncidentID, "sentinel", "REFLEX_APPLIED", fmt.Sprintf(`{"action":"%s","target":"%s"}`, action.Action, action.Target))
	return nil
}

// UpdateReflexStatus memperbarui status aksi refleks (misalnya saat di-rollback).
func (s *Store) UpdateReflexStatus(ctx context.Context, id, status string, rolledBackAt *time.Time) error {
	query := `
	UPDATE reflex_actions
	SET status = ?, rolled_back_at = ?
	WHERE id = ?;
	`
	_, err := s.db.ExecContext(ctx, query, status, rolledBackAt, id)
	if err != nil {
		return fmt.Errorf("update reflex status %s: %w", id, err)
	}
	return nil
}

// UpdateReflexParams memperbarui payload JSON metadata refleks (termasuk state retry rollback) selama berstatus APPLIED.
func (s *Store) UpdateReflexParams(ctx context.Context, id, paramsJSON string) error {
	query := `
	UPDATE reflex_actions
	SET params_json = ?
	WHERE id = ? AND status = 'APPLIED';
	`
	res, err := s.db.ExecContext(ctx, query, paramsJSON, id)
	if err != nil {
		return fmt.Errorf("update reflex params %s: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected updating reflex params %s: %w", id, err)
	}
	if affected == 0 {
		return fmt.Errorf("reflex action %s not found or no longer APPLIED", id)
	}
	return nil
}

// MarkReflexRolledBack menandai aksi refleks berstatus APPLIED menjadi rolled-back secara atomik agar rollback hanya berjalan tepat satu kali.
func (s *Store) MarkReflexRolledBack(ctx context.Context, id, newStatus string, rolledBackAt time.Time) (bool, error) {
	query := `
	UPDATE reflex_actions
	SET status = ?, rolled_back_at = ?
	WHERE id = ? AND status = 'APPLIED';
	`
	res, err := s.db.ExecContext(ctx, query, newStatus, rolledBackAt.UTC(), id)
	if err != nil {
		return false, fmt.Errorf("mark reflex %s rolled back: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check rows affected for reflex %s: %w", id, err)
	}
	return affected > 0, nil
}

// GetReflexAction mengambil satu data aksi refleks berdasarkan ID.
func (s *Store) GetReflexAction(ctx context.Context, id string) (*ReflexAction, error) {
	query := `
	SELECT id, incident_id, action, target, params_json, applied_at, ttl_seconds, expires_at, rolled_back_at, status
	FROM reflex_actions WHERE id = ?;
	`
	row := s.db.QueryRowContext(ctx, query, id)

	var a ReflexAction
	err := row.Scan(
		&a.ID, &a.IncidentID, &a.Action, &a.Target, &a.ParamsJSON,
		&a.AppliedAt, &a.TTLSeconds, &a.ExpiresAt, &a.RolledBackAt, &a.Status,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("reflex action %s not found: %w", id, err)
		}
		return nil, fmt.Errorf("query reflex action %s: %w", id, err)
	}
	return &a, nil
}

// GetReflexActionsByIncident mengambil seluruh aksi refleks yang terkait dengan suatu insiden.
func (s *Store) GetReflexActionsByIncident(ctx context.Context, incidentID string) ([]ReflexAction, error) {
	query := `
	SELECT id, incident_id, action, target, params_json, applied_at, ttl_seconds, expires_at, rolled_back_at, status
	FROM reflex_actions WHERE incident_id = ? ORDER BY applied_at ASC;
	`
	return s.queryReflexActions(ctx, query, incidentID)
}

// CountReflexActionsByIncident menghitung jumlah aksi refleks L1 yang telah tercatat untuk sebuah insiden.
func (s *Store) CountReflexActionsByIncident(ctx context.Context, incidentID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reflex_actions WHERE incident_id = ?;`, incidentID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count reflex actions for %s: %w", incidentID, err)
	}
	return count, nil
}

// GetPendingReflexActions mengambil seluruh aksi refleks yang masih aktif (APPLIED) terurut dari yang paling cepat kedaluwarsa.
func (s *Store) GetPendingReflexActions(ctx context.Context) ([]ReflexAction, error) {
	query := `
	SELECT id, incident_id, action, target, params_json, applied_at, ttl_seconds, expires_at, rolled_back_at, status
	FROM reflex_actions WHERE status = 'APPLIED' ORDER BY expires_at ASC;
	`
	return s.queryReflexActions(ctx, query)
}

// queryReflexActions mengeksekusi query daftar ReflexAction dan memindai baris hasilnya.
func (s *Store) queryReflexActions(ctx context.Context, query string, args ...any) ([]ReflexAction, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query reflex actions: %w", err)
	}
	defer rows.Close()

	var list []ReflexAction
	for rows.Next() {
		var a ReflexAction
		if err := rows.Scan(
			&a.ID, &a.IncidentID, &a.Action, &a.Target, &a.ParamsJSON,
			&a.AppliedAt, &a.TTLSeconds, &a.ExpiresAt, &a.RolledBackAt, &a.Status,
		); err != nil {
			return nil, fmt.Errorf("scan reflex action: %w", err)
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// RecordAudit menambahkan entri ke tabel log audit append-only.
func (s *Store) RecordAudit(ctx context.Context, incidentID, actor, eventType, payloadJSON string) error {
	query := `
	INSERT INTO audit_trail (incident_id, actor, event_type, payload_json, created_at)
	VALUES (?, ?, ?, ?, ?);
	`
	_, err := s.db.ExecContext(ctx, query, incidentID, actor, eventType, payloadJSON, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("insert audit: %w", err)
	}
	return nil
}

// GetAuditTrail mengambil rekam jejak audit untuk sebuah insiden.
func (s *Store) GetAuditTrail(ctx context.Context, incidentID string) ([]AuditEntry, error) {
	query := `
	SELECT id, incident_id, actor, event_type, payload_json, created_at
	FROM audit_trail WHERE incident_id = ? ORDER BY id ASC;
	`
	rows, err := s.db.QueryContext(ctx, query, incidentID)
	if err != nil {
		return nil, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()

	var list []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.IncidentID, &a.Actor, &a.EventType, &a.PayloadJSON, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// ConsumeNonce mencatat konsumsi nonce approval sekali-pakai; menggagalkan usaha replay attack.
func (s *Store) ConsumeNonce(ctx context.Context, nonce, incidentID, planHash string) error {
	query := `
	INSERT INTO nonces (nonce, bound_incident_id, bound_plan_hash, consumed_at)
	VALUES (?, ?, ?, ?);
	`
	_, err := s.db.ExecContext(ctx, query, nonce, incidentID, planHash, time.Now().UTC())
	if err != nil {
		// Pelanggaran UNIQUE constraint pada kolom primary key nonce
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "constraint failed") {
			return ErrNonceReplayed
		}
		return fmt.Errorf("insert nonce %s: %w", nonce, err)
	}

	_ = s.RecordAudit(ctx, incidentID, "approval-engine", "NONCE_CONSUMED", fmt.Sprintf(`{"nonce":"%s","plan_hash":"%s"}`, nonce, planHash))
	return nil
}

