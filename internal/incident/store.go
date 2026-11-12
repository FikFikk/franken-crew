package incident

import (
	"context"
	"database/sql"
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

// GetIncident mengambil data insiden berdasarkan ID.
func (s *Store) GetIncident(ctx context.Context, id string) (*Incident, error) {
	query := `
	SELECT id, node, cgroup, severity, state, tto_seconds, opened_at, updated_at, closed_at, triage_json, plan_json
	FROM incidents WHERE id = ?;
	`
	row := s.db.QueryRowContext(ctx, query, id)

	var inc Incident
	var stateStr string
	err := row.Scan(
		&inc.ID, &inc.Node, &inc.Cgroup, &inc.Severity, &stateStr,
		&inc.TTOSeconds, &inc.OpenedAt, &inc.UpdatedAt, &inc.ClosedAt,
		&inc.TriageJSON, &inc.PlanJSON,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIncidentNotFound
		}
		return nil, fmt.Errorf("query incident %s: %w", id, err)
	}
	inc.State = State(stateStr)
	return &inc, nil
}

// TransitionState mengubah status insiden secara aman dengan memeriksa aturan state machine.
func (s *Store) TransitionState(ctx context.Context, id string, target State, actor, reason string) error {
	inc, err := s.GetIncident(ctx, id)
	if err != nil {
		return err
	}

	if !CanTransition(inc.State, target) {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidTransition, inc.State, target)
	}

	now := time.Now().UTC()
	var closedAt *time.Time
	if target == StateResolved || target == StateEscalated || target == StateDismissed || target == StateExpired {
		closedAt = &now
	}

	query := `
	UPDATE incidents
	SET state = ?, updated_at = ?, closed_at = ?
	WHERE id = ?;
	`
	_, err = s.db.ExecContext(ctx, query, string(target), now, closedAt, id)
	if err != nil {
		return fmt.Errorf("update incident state %s: %w", id, err)
	}

	auditPayload := fmt.Sprintf(`{"from":"%s","to":"%s","reason":"%s"}`, inc.State, target, reason)
	_ = s.RecordAudit(ctx, id, actor, "STATE_TRANSITION", auditPayload)
	return nil
}

// SaveEvidence menyimpan snapshot bukti telemetri setelah menyensor informasi rahasia secara otomatis.
func (s *Store) SaveEvidence(ctx context.Context, snapshot *EvidenceSnapshot) error {
	if snapshot.CapturedAt.IsZero() {
		snapshot.CapturedAt = time.Now().UTC()
	}

	// Jalankan sensor otomatis jika data tersensor belum diisi
	if snapshot.RedactedData == "" {
		snapshot.RedactedData = redact.String(snapshot.RawData)
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
