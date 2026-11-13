package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/incident"
)

const (
	// TelemetrySeriesKind adalah jenis evidence snapshot seri telemetri insiden.
	TelemetrySeriesKind = "telemetry_series"
	// MaxTelemetrySeriesPoints membatasi jumlah titik seri setelah downsampling merata.
	MaxTelemetrySeriesPoints = 400
	// telemetrySeriesLookback menyertakan 180 detik sebelum insiden dibuka agar kurva pra-insiden terlihat.
	telemetrySeriesLookback = 180 * time.Second
)

// TelemetrySeries adalah payload JSON evidence telemetry_series. Evidence melewati redact.String, dan pola
// telepon/IP di sana dapat merusak angka panjang atau bertitik, sehingga setiap angka disimpan sebagai integer:
// Points berisi [t_ms relatif opened_at, memory_kib, psi_some_x100, psi_full_x100] terurut menaik.
type TelemetrySeries struct {
	Cgroup     string     `json:"cgroup"`
	LimitBytes uint64     `json:"limit_bytes"`
	Points     [][4]int64 `json:"points"`
}

// SnapshotTelemetrySeries menyimpan satu evidence telemetry_series untuk insiden dari ring PSI cgroup insiden
// pada rentang [opened_at - 180 s, sekarang], di-downsample merata ke <= 400 titik. Snapshot hanya ditulis sekali:
// bila evidence sejenis sudah ada, fungsi mengembalikan false tanpa menulis apa pun.
func (s *Server) SnapshotTelemetrySeries(ctx context.Context, incidentID string) (bool, error) {
	// seriesMu menyerialkan pemeriksaan + penulisan agar dua jalur terminal yang bersamaan tidak menggandakan snapshot
	s.seriesMu.Lock()
	defer s.seriesMu.Unlock()

	inc, err := s.cfg.Store.GetIncident(ctx, incidentID)
	if err != nil {
		return false, err
	}
	evidence, err := s.cfg.Store.GetEvidenceByIncident(ctx, incidentID)
	if err != nil {
		return false, fmt.Errorf("load evidence for %s: %w", incidentID, err)
	}
	for _, ev := range evidence {
		if ev.Kind == TelemetrySeriesKind {
			return false, nil
		}
	}

	now := s.cfg.Clock().UTC()
	raw, err := json.Marshal(s.buildTelemetrySeries(inc, now))
	if err != nil {
		return false, fmt.Errorf("encode telemetry series for %s: %w", incidentID, err)
	}
	if err := s.cfg.Store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
		ID:           s.newEvidenceID(),
		IncidentID:   incidentID,
		Kind:         TelemetrySeriesKind,
		RedactedData: string(raw),
		CapturedAt:   now,
	}); err != nil {
		return false, err
	}
	return true, nil
}

// snapshotSeriesIfTerminal menyimpan snapshot seri secara best-effort setelah insiden mencapai status terminal.
func (s *Server) snapshotSeriesIfTerminal(ctx context.Context, incidentID string, state incident.State) {
	if isTerminalState(state) {
		_, _ = s.SnapshotTelemetrySeries(ctx, incidentID)
	}
}

// buildTelemetrySeries menyusun seri integer dari titik ring yang membawa memory.current.
func (s *Server) buildTelemetrySeries(inc *incident.Incident, now time.Time) TelemetrySeries {
	opened := inc.OpenedAt.UTC()
	window := s.psiRing.Window(inc.Cgroup, opened.Add(-telemetrySeriesLookback), now)

	// Titik PSI-only (tanpa memory.current) dilewati agar kurva memori tidak jatuh ke nol
	pts := make([]PSIPoint, 0, len(window))
	for _, pt := range window {
		if pt.MemoryCurrent > 0 {
			pts = append(pts, pt)
		}
	}
	sort.SliceStable(pts, func(i, j int) bool { return pts[i].At.Before(pts[j].At) })
	pts = downsampleEvenly(pts, MaxTelemetrySeriesPoints)

	points := make([][4]int64, 0, len(pts))
	for _, pt := range pts {
		points = append(points, [4]int64{
			pt.At.Sub(opened).Round(time.Millisecond).Milliseconds(),
			int64(pt.MemoryCurrent / 1024),
			int64(math.Round(pt.SomeAvg10 * 100)),
			int64(math.Round(pt.FullAvg10 * 100)),
		})
	}

	_, normCg, err := resolveSafeCgroupDir(s.cfg.CgroupRoot, inc.Cgroup)
	if err != nil {
		normCg = normalizePSIKey(inc.Cgroup)
	}
	return TelemetrySeries{
		Cgroup:     normCg,
		LimitBytes: s.incidentMemoryLimit(inc),
		Points:     points,
	}
}

// incidentMemoryLimit membaca memory.max cgroup insiden, atau MemTotal host - 64 MiB bila tak terbatas/hilang.
func (s *Server) incidentMemoryLimit(inc *incident.Incident) uint64 {
	if s.cfg.FS != nil {
		if absDir, _, err := resolveSafeCgroupDir(s.cfg.CgroupRoot, inc.Cgroup); err == nil {
			if sample, sErr := cgroup.NewSampler(s.cfg.FS, time.Second).SampleCgroup(absDir); sErr == nil {
				return s.memoryLimitFor(sample)
			}
		}
	}
	return s.memoryLimitFor(cgroup.Sample{})
}

// downsampleEvenly memilih maksimal limit titik dengan jarak indeks merata, selalu menyertakan titik pertama dan terakhir.
func downsampleEvenly(pts []PSIPoint, limit int) []PSIPoint {
	n := len(pts)
	if limit <= 0 || n <= limit {
		return pts
	}
	if limit == 1 {
		return pts[n-1:]
	}
	out := make([]PSIPoint, 0, limit)
	for i := 0; i < limit; i++ {
		idx := int(math.Round(float64(i) * float64(n-1) / float64(limit-1)))
		out = append(out, pts[idx])
	}
	return out
}
