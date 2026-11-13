package lab

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/wabridge"
)

// Mode status /api/status.
const (
	StatusModeLive    = "live"
	StatusModeOffline = "offline"
	StatusModeReplay  = "replay"
)

const (
	// statusCacheTTL menahan hasil status selama 5 detik agar dashboard publik tidak membebani Sentinel.
	statusCacheTTL = 5 * time.Second
	// statusTimeout membatasi seluruh panggilan ke Sentinel per penyegaran status.
	statusTimeout = 3 * time.Second
	// statusIncidentLimit adalah jumlah insiden terbaru yang dibaca untuk hitungan open_incidents dan latest.
	statusIncidentLimit = 5
)

// StatusSource menyediakan ringkasan status live untuk endpoint /api/status.
type StatusSource interface {
	Status(ctx context.Context) LiveStatus
}

// LiveStatus adalah satu-satunya bentuk data live yang boleh keluar ke publik. Field pointer + omitempty
// memastikan mode replay/offline hanya membawa kunci yang memang diisi.
type LiveStatus struct {
	Mode          string        `json:"mode"`
	Node          string        `json:"node,omitempty"`
	UptimeS       *int64        `json:"uptime_s,omitempty"`
	PSI           *LivePSI      `json:"psi,omitempty"`
	MemoryUsedPct *float64      `json:"memory_used_pct,omitempty"`
	OpenIncidents *int          `json:"open_incidents,omitempty"`
	Latest        *LiveIncident `json:"latest,omitempty"`
	UpdatedAt     *time.Time    `json:"updated_at,omitempty"`
}

// LivePSI memuat PSI memori host avg10.
type LivePSI struct {
	SomeAvg10 float64 `json:"some_avg10"`
	FullAvg10 float64 `json:"full_avg10"`
}

// LiveIncident adalah ringkasan minimal insiden terbaru.
type LiveIncident struct {
	ID       string    `json:"id"`
	Severity string    `json:"severity"`
	State    string    `json:"state"`
	OpenedAt time.Time `json:"opened_at"`
}

// sentinelReader adalah subset wabridge.SentinelClient yang dipakai status live.
type sentinelReader interface {
	CheckHealthz(ctx context.Context) (*mcpserver.HealthzResponse, error)
	NodeSnapshot(ctx context.Context, topLimit int) (*mcpserver.NodeSnapshotOutput, error)
	IncidentList(ctx context.Context, state string, limit int) (*mcpserver.IncidentListOutput, error)
}

// SentinelStatusSource membaca /healthz, node_snapshot, dan incident_list (limit 5) dari Sentinel, menyaring
// hasilnya ke LiveStatus, lalu meng-cache-nya selama 5 detik. Galat apa pun menghasilkan mode offline tanpa
// detail galat agar dashboard publik tidak membocorkan alamat atau topologi internal.
type SentinelStatusSource struct {
	client  sentinelReader
	clock   func() time.Time
	ttl     time.Duration
	timeout time.Duration

	mu       sync.Mutex
	cached   LiveStatus
	cachedAt time.Time
	hasCache bool
}

// NewSentinelStatusSource membuat sumber status live dari client Sentinel milik wa-bridge.
func NewSentinelStatusSource(client *wabridge.SentinelClient) *SentinelStatusSource {
	var reader sentinelReader
	if client != nil {
		reader = client
	}
	return newSentinelStatusSource(reader, func() time.Time { return time.Now().UTC() })
}

func newSentinelStatusSource(client sentinelReader, clock func() time.Time) *SentinelStatusSource {
	return &SentinelStatusSource{client: client, clock: clock, ttl: statusCacheTTL, timeout: statusTimeout}
}

// Status mengembalikan status live dari cache (<= 5 detik) atau menyegarkannya dari Sentinel.
func (s *SentinelStatusSource) Status(ctx context.Context) LiveStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock().UTC()
	if s.hasCache {
		if age := now.Sub(s.cachedAt); age >= 0 && age < s.ttl {
			return s.cached.clone()
		}
	}
	st := s.fetch(ctx, now)
	s.cached, s.cachedAt, s.hasCache = st, now, true
	return st.clone()
}

func (s *SentinelStatusSource) fetch(ctx context.Context, now time.Time) LiveStatus {
	offline := LiveStatus{Mode: StatusModeOffline, UpdatedAt: &now}
	if s.client == nil {
		return offline
	}
	// Lepaskan dari pembatalan request agar klien yang menutup koneksi tidak membuat cache offline palsu
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.timeout)
	defer cancel()

	health, err := s.client.CheckHealthz(callCtx)
	if err != nil || health == nil {
		return offline
	}
	snap, err := s.client.NodeSnapshot(callCtx, 1)
	if err != nil || snap == nil {
		return offline
	}
	list, err := s.client.IncidentList(callCtx, "", statusIncidentLimit)
	if err != nil || list == nil {
		return offline
	}

	open := 0
	var latest *LiveIncident
	for _, inc := range list.Incidents {
		if !isTerminalStateName(inc.State) {
			open++
		}
		if latest == nil || inc.OpenedAt.After(latest.OpenedAt) {
			latest = &LiveIncident{ID: inc.ID, Severity: inc.Severity, State: inc.State, OpenedAt: inc.OpenedAt.UTC()}
		}
	}

	uptime := max(health.UptimeS, 0)
	pct := round(snap.MemoryUsedPct, 1)
	node := health.Node
	if node == "" {
		node = snap.Node
	}
	return LiveStatus{
		Mode:          StatusModeLive,
		Node:          node,
		UptimeS:       &uptime,
		PSI:           &LivePSI{SomeAvg10: round(snap.PSISomeAvg10, 2), FullAvg10: round(snap.PSIFullAvg10, 2)},
		MemoryUsedPct: &pct,
		OpenIncidents: &open,
		Latest:        latest,
		UpdatedAt:     &now,
	}
}

// clone menyalin LiveStatus beserta nilai pointer-nya agar cache tidak pernah berbagi memori dengan pemanggil.
func (st LiveStatus) clone() LiveStatus {
	out := st
	if st.UptimeS != nil {
		v := *st.UptimeS
		out.UptimeS = &v
	}
	if st.PSI != nil {
		v := *st.PSI
		out.PSI = &v
	}
	if st.MemoryUsedPct != nil {
		v := *st.MemoryUsedPct
		out.MemoryUsedPct = &v
	}
	if st.OpenIncidents != nil {
		v := *st.OpenIncidents
		out.OpenIncidents = &v
	}
	if st.Latest != nil {
		v := *st.Latest
		out.Latest = &v
	}
	if st.UpdatedAt != nil {
		v := *st.UpdatedAt
		out.UpdatedAt = &v
	}
	return out
}

func isTerminalStateName(state string) bool {
	switch state {
	case "RESOLVED", "ESCALATED", "DISMISSED", "EXPIRED":
		return true
	default:
		return false
	}
}

// round membulatkan x ke sejumlah digit desimal.
func round(x float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.Round(x*p) / p
}
