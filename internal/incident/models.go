package incident

import (
	"errors"
	"time"
)

// State merepresentasikan status siklus hidup insiden.
type State string

const (
	StateDetected        State = "DETECTED"
	StateReflexApplied   State = "REFLEX_APPLIED"
	StateTriaging        State = "TRIAGING"
	StatePlanned         State = "PLANNED"
	StateWaitingApproval State = "WAITING_APPROVAL"
	StateRemediating     State = "REMEDIATING"
	StateVerifying       State = "VERIFYING"
	StateResolved        State = "RESOLVED"
	StateEscalated       State = "ESCALATED"
	StateDismissed       State = "DISMISSED"
	StateExpired         State = "EXPIRED"
)

// EvidenceKindTelemetrySeries adalah jenis evidence berisi seri telemetri insiden (PSI dan memory.current).
const EvidenceKindTelemetrySeries = "telemetry_series"

// TelemetrySeries adalah payload JSON evidence telemetry_series. Evidence melewati redact.String, dan pola
// telepon/IP di sana dapat merusak angka panjang atau bertitik, sehingga setiap angka disimpan sebagai integer:
// Points berisi [t_ms relatif opened_at, memory_kib, psi_some_x100, psi_full_x100] terurut menaik.
type TelemetrySeries struct {
	Cgroup     string     `json:"cgroup"`
	LimitBytes uint64     `json:"limit_bytes"`
	Points     [][4]int64 `json:"points"`
}

var (
	// ErrInvalidTransition terjadi ketika transisi status tidak diperbolehkan oleh state machine
	ErrInvalidTransition = errors.New("incident: invalid state transition")
	// ErrIncidentNotFound terjadi ketika ID insiden tidak ditemukan di database
	ErrIncidentNotFound = errors.New("incident: record not found")
	// ErrNonceReplayed terjadi jika nonce approval sudah pernah dipakai sebelumnya
	ErrNonceReplayed = errors.New("incident: approval nonce has already been consumed")
)

// Incident merepresentasikan entitas insiden utama di database.
type Incident struct {
	ID         string     `json:"id"`
	Node       string     `json:"node"`
	Cgroup     string     `json:"cgroup"`
	Severity   string     `json:"severity"`
	State      State      `json:"state"`
	TTOSeconds *float64   `json:"tto_seconds,omitempty"`
	OpenedAt   time.Time  `json:"opened_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	TriageJSON string     `json:"triage_json,omitempty"`
	PlanJSON   string     `json:"plan_json,omitempty"`
}

// EvidenceSnapshot merepresentasikan rekaman bukti telemetri yang telah disensor.
type EvidenceSnapshot struct {
	ID           string    `json:"id"`
	IncidentID   string    `json:"incident_id"`
	Kind         string    `json:"kind"`
	RawData      string    `json:"raw_data,omitempty"`
	RedactedData string    `json:"redacted_data"`
	CapturedAt   time.Time `json:"captured_at"`
}

// ReflexAction merepresentasikan aksi refleks L1 yang diterapkan dengan masa aktif TTL.
type ReflexAction struct {
	ID           string     `json:"id"`
	IncidentID   string     `json:"incident_id"`
	Action       string     `json:"action"`
	Target       string     `json:"target"`
	ParamsJSON   string     `json:"params_json"`
	AppliedAt    time.Time  `json:"applied_at"`
	TTLSeconds   int        `json:"ttl_seconds"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RolledBackAt *time.Time `json:"rolled_back_at,omitempty"`
	Status       string     `json:"status"`
}

// AuditEntry merepresentasikan catatan log audit append-only yang tidak dapat diubah.
type AuditEntry struct {
	ID          int64     `json:"id"`
	IncidentID  string    `json:"incident_id"`
	Actor       string    `json:"actor"`
	EventType   string    `json:"event_type"`
	PayloadJSON string    `json:"payload_json"`
	CreatedAt   time.Time `json:"created_at"`
}

// NonceRecord merepresentasikan status konsumsi token persetujuan approval.
type NonceRecord struct {
	Nonce           string    `json:"nonce"`
	BoundIncidentID string    `json:"bound_incident_id"`
	BoundPlanHash   string    `json:"bound_plan_hash"`
	ConsumedAt      time.Time `json:"consumed_at"`
}

// ValidTransitions mendefinisikan peta transisi status yang sah untuk menjaga state machine.
var ValidTransitions = map[State]map[State]bool{
	StateDetected: {
		StateReflexApplied:   true,
		StateTriaging:        true,
		StateWaitingApproval: true,
		StateVerifying:       true,
		StateEscalated:       true,
	},
	StateReflexApplied: {
		StateTriaging:        true,
		StatePlanned:         true,
		StateWaitingApproval: true,
		StateVerifying:       true,
		StateEscalated:       true,
	},
	StateTriaging: {
		StatePlanned:         true,
		StateEscalated:       true,
		StateWaitingApproval: true,
	},
	StatePlanned: {
		StateWaitingApproval: true,
		StateRemediating:     true,
		StateVerifying:       true,
		StateEscalated:       true,
	},
	StateWaitingApproval: {
		StateRemediating: true,
		StateDismissed:   true,
		StateExpired:     true,
		StateEscalated:   true,
	},
	StateRemediating: {
		StateVerifying: true,
		StateEscalated: true,
	},
	StateVerifying: {
		StateResolved:  true,
		StateEscalated: true,
	},
	// Terminal states tidak dapat berpindah lagi
	StateResolved:  {},
	StateEscalated: {},
	StateDismissed: {},
	StateExpired:   {},
}

// CanTransition memeriksa apakah perpindahan dari from ke to diperbolehkan.
func CanTransition(from, to State) bool {
	if allowed, ok := ValidTransitions[from]; ok {
		return allowed[to]
	}
	return false
}
