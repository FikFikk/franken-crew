// Package lab menyusun replay insiden publik (dashboard "Graveyard") dari data Sentinel asli: ekspor dari
// store SQLite, simulasi chaos in-process, serta server HTTP statis read-only beserta status live tersaring.
package lab

import "time"

// ReplaySchema adalah identitas versi kontrak JSON yang dibaca dashboard.
const ReplaySchema = "frankencrew.replay/v1"

// Jenis sumber replay.
const (
	SourceKindSimulation = "simulation"
	SourceKindRecording  = "recording"
)

// Lane linimasa replay.
const (
	LaneKernel   = "kernel"
	LaneSentinel = "sentinel"
	LaneCrew     = "crew"
	LaneHuman    = "human"
	LaneVerify   = "verify"
)

// Level event replay.
const (
	LevelInfo  = "info"
	LevelOK    = "ok"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Replay adalah dokumen akar yang dibaca dashboard.
type Replay struct {
	Schema      string           `json:"schema"`
	GeneratedAt time.Time        `json:"generated_at"`
	Source      ReplaySource     `json:"source"`
	Node        string           `json:"node"`
	Incidents   []ReplayIncident `json:"incidents"`
}

// ReplaySource menjelaskan asal data replay secara jujur.
type ReplaySource struct {
	Kind   string `json:"kind"` // "simulation" | "recording"
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// ReplayIncident adalah satu insiden lengkap: kurva, linimasa, poll, pesan, dan postmortem.
type ReplayIncident struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Scenario        string          `json:"scenario,omitempty"`
	Severity        string          `json:"severity"`
	Class           string          `json:"class,omitempty"`
	Confidence      *float64        `json:"confidence,omitempty"`
	TriageSummary   string          `json:"triage_summary,omitempty"`
	Cgroup          string          `json:"cgroup"`
	Unit            string          `json:"unit,omitempty"`
	State           string          `json:"state"`
	OpenedAt        time.Time       `json:"opened_at"`
	ClosedAt        *time.Time      `json:"closed_at,omitempty"`
	DurationS       float64         `json:"duration_s"`
	TTOSeconds      *float64        `json:"tto_seconds,omitempty"`
	ReflexLatencyMS *float64        `json:"reflex_latency_ms,omitempty"`
	ReflexTrigger   string          `json:"reflex_trigger,omitempty"`
	PlanHash        string          `json:"plan_hash,omitempty"`
	RootCause       string          `json:"root_cause,omitempty"`
	FollowUps       []string        `json:"follow_ups,omitempty"`
	Stats           ReplayStats     `json:"stats"`
	Series          *ReplaySeries   `json:"series,omitempty"`
	Events          []ReplayEvent   `json:"events"`
	Poll            *ReplayPoll     `json:"poll,omitempty"`
	Messages        []ReplayMessage `json:"messages"`
	Postmortem      string          `json:"postmortem_markdown,omitempty"`
}

// ReplayStats merangkum jumlah refleks, langkah L2, dan penolakan/blokir.
type ReplayStats struct {
	Reflexes      int `json:"reflexes"`
	L2Steps       int `json:"l2_steps"`
	Blocked       int `json:"blocked"`
	VerifyWindowS int `json:"verify_window_s,omitempty"`
}

// ReplaySeries adalah kurva memori/PSI: setiap titik [t_s relatif opened_at (negatif sebelum dibuka),
// memory_bytes, psi_some_avg10, psi_full_avg10], terurut menaik menurut t.
type ReplaySeries struct {
	LimitBytes uint64       `json:"limit_bytes"`
	Points     [][4]float64 `json:"points"`
}

// ReplayEvent adalah satu kejadian pada linimasa replay.
type ReplayEvent struct {
	T        float64   `json:"t"` // detik relatif opened_at, presisi milidetik
	At       time.Time `json:"at"`
	Lane     string    `json:"lane"` // kernel|sentinel|crew|human|verify
	Actor    string    `json:"actor"`
	Kind     string    `json:"kind"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
	Level    string    `json:"level"` // info|ok|warn|error
	Inferred bool      `json:"inferred,omitempty"`
}

// ReplayPoll merekonstruksi Native WhatsApp Poll persetujuan.
type ReplayPoll struct {
	T        float64  `json:"t"`
	Title    string   `json:"title"`
	Options  []string `json:"options"`
	Chosen   int      `json:"chosen"` // -1 bila tidak ada pilihan
	VotedT   *float64 `json:"voted_t,omitempty"`
	Approver string   `json:"approver,omitempty"`
}

// ReplayMessage adalah satu pesan WhatsApp yang direkonstruksi dalam format wa-bridge.
type ReplayMessage struct {
	T    float64 `json:"t"`
	From string  `json:"from"` // bot|operator
	Kind string  `json:"kind"` // alert|poll|vote|text|report
	Text string  `json:"text"`
}
