package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/redact"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// seriesEvidence mengembalikan seluruh evidence telemetry_series milik insiden.
func seriesEvidence(t *testing.T, store *incident.Store, incID string) []incident.EvidenceSnapshot {
	t.Helper()
	all, err := store.GetEvidenceByIncident(context.Background(), incID)
	if err != nil {
		t.Fatalf("GetEvidenceByIncident: %v", err)
	}
	var out []incident.EvidenceSnapshot
	for _, ev := range all {
		if ev.Kind == TelemetrySeriesKind {
			out = append(out, ev)
		}
	}
	return out
}

// decodeIntegerSeries memastikan payload hanya berisi angka integer lalu mendekodenya.
func decodeIntegerSeries(t *testing.T, raw string) TelemetrySeries {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var generic map[string]any
	if err := dec.Decode(&generic); err != nil {
		t.Fatalf("series payload is not JSON: %v (%q)", err, raw)
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case json.Number:
			if strings.ContainsAny(x.String(), ".eE") {
				t.Fatalf("series payload must encode integers only, found %s", x)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(generic)
	var series TelemetrySeries
	if err := json.Unmarshal([]byte(raw), &series); err != nil {
		t.Fatalf("decode TelemetrySeries: %v", err)
	}
	return series
}

func TestTelemetrySeries_RoundTripsUnchangedThroughSaveEvidence(t *testing.T) {
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "series.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	if err := store.CreateIncident(ctx, &incident.Incident{ID: "INC-SERIES-RT", Node: "pi01", Cgroup: scopedCgroup, Severity: "P2", State: incident.StateResolved}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	for i, series := range []TelemetrySeries{
		{
			Cgroup:     scopedCgroup,
			LimitBytes: 536870912,
			Points: [][4]int64{
				{-180000, 180224, 42, 8},
				{-1, 253952, 1045, 210},
				{0, 254976, 1112, 236},
				{197000, 186368, 30, 0},
				{599999, 9999999, 10000, 10000},
			},
		},
		// Cgroup tanpa memory.max memakai MemTotal - 64 MiB (contoh host 8 GiB dan Raspberry Pi 4 GB)
		{Cgroup: "/system.slice/worker.service", LimitBytes: 8522825728, Points: [][4]int64{{-120000, 1740800, 0, 0}}},
		{Cgroup: "/system.slice/worker.service", LimitBytes: 3907289088, Points: [][4]int64{}},
	} {
		raw, err := json.Marshal(series)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if redact.String(string(raw)) != string(raw) {
			t.Fatalf("redaction alters the integer series encoding: %s -> %s", raw, redact.String(string(raw)))
		}
		evID := "ev-series-" + string(rune('a'+i))
		if err := store.SaveEvidence(ctx, &incident.EvidenceSnapshot{ID: evID, IncidentID: "INC-SERIES-RT", Kind: TelemetrySeriesKind, RedactedData: string(raw)}); err != nil {
			t.Fatalf("SaveEvidence: %v", err)
		}
		stored := seriesEvidence(t, store, "INC-SERIES-RT")
		var got string
		for _, ev := range stored {
			if ev.ID == evID {
				got = ev.RedactedData
			}
		}
		if got != string(raw) {
			t.Fatalf("stored series changed during SaveEvidence:\n got  %s\n want %s", got, raw)
		}
		back := decodeIntegerSeries(t, got)
		if back.LimitBytes != series.LimitBytes || len(back.Points) != len(series.Points) {
			t.Fatalf("decoded series differs: %+v vs %+v", back, series)
		}
	}
}

func TestVerifyFinalize_SavesTelemetrySeriesExactlyOnce(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	incID := "INC-20261113-1800-pi01"
	opened := h.Now().Add(-60 * time.Second)
	if err := h.store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi01", Cgroup: scopedCgroup, Severity: "P2", State: incident.StateVerifying, OpenedAt: opened}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	ring := h.srv.PSIRing()
	ring.Record(scopedCgroup, PSIPoint{At: opened.Add(-200 * time.Second), SomeAvg10: 0.5, MemoryCurrent: 170 << 20})                   // di luar jendela [-180s, now]
	ring.Record(scopedCgroup, PSIPoint{At: opened.Add(-170 * time.Second), SomeAvg10: 0.42, FullAvg10: 0.08, MemoryCurrent: 176 << 20}) // titik pertama
	ring.Record(scopedCgroup, PSIPoint{At: opened.Add(-30 * time.Second), SomeAvg10: 12.345, FullAvg10: 2.006, MemoryCurrent: 230 << 20})
	ring.Record(scopedCgroup, PSIPoint{At: opened.Add(-20 * time.Second), SomeAvg10: 13.1}) // titik PSI-only dilewati
	ring.Record(scopedCgroup, PSIPoint{At: opened.Add(10 * time.Second), SomeAvg10: 9.87, FullAvg10: 1.5, MemoryCurrent: 260 << 20})

	out := runForwardVerification(t, ctx, h, session, incID, scopedCgroup, linearMiB(220, 222, 9))
	if out.State != string(incident.StateResolved) {
		t.Fatalf("expected RESOLVED, got %+v", out)
	}

	stored := seriesEvidence(t, h.store, incID)
	if len(stored) != 1 {
		t.Fatalf("expected exactly one telemetry_series evidence after finalize, got %d", len(stored))
	}
	series := decodeIntegerSeries(t, stored[0].RedactedData)
	if series.Cgroup != scopedCgroup || series.LimitBytes != 536870912 {
		t.Fatalf("unexpected series header: cgroup=%q limit=%d", series.Cgroup, series.LimitBytes)
	}
	if len(series.Points) != 12 {
		t.Fatalf("expected 3 pre-verify points plus 9 forward points, got %d: %v", len(series.Points), series.Points)
	}
	if first := series.Points[0]; first != [4]int64{-170000, 176 * 1024, 42, 8} {
		t.Fatalf("first point must be relative to opened_at in ms with KiB and x100 PSI, got %v", first)
	}
	if p := series.Points[1]; p != [4]int64{-30000, 230 * 1024, 1235, 201} {
		t.Fatalf("PSI must be rounded to x100 integers, got %v", p)
	}
	for i := 1; i < len(series.Points); i++ {
		if series.Points[i][0] < series.Points[i-1][0] {
			t.Fatalf("series points must be ascending in time: %v", series.Points)
		}
	}

	// Jalur final kedua (cache verify_health dan pemanggilan ulang langsung) tidak boleh menggandakan snapshot
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "verify_health", Arguments: map[string]any{"incident_id": incID, "window_seconds": 120, "auto_transition": true}})
	if err != nil || res.IsError {
		t.Fatalf("cached verify_health: err=%v res=%+v", err, res)
	}
	if saved, err := h.srv.SnapshotTelemetrySeries(ctx, incID); err != nil || saved {
		t.Fatalf("second snapshot must be skipped, got saved=%v err=%v", saved, err)
	}
	if n := len(seriesEvidence(t, h.store, incID)); n != 1 {
		t.Fatalf("telemetry_series must be saved once, found %d", n)
	}
}

func TestSnapshotTelemetrySeries_DownsamplesEvenlyTo400Points(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx := context.Background()

	incID := "INC-20261113-1810-pi01"
	base := h.Now().Add(-10 * time.Minute)
	opened := base.Add(180 * time.Second)
	if err := h.store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi01", Cgroup: scopedCgroup, Severity: "P2", State: incident.StateResolved, OpenedAt: opened}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	for i := 0; i < DefaultPSIRingCapacity; i++ {
		h.srv.PSIRing().Record(scopedCgroup, PSIPoint{At: base.Add(time.Duration(i) * time.Second), SomeAvg10: float64(i%7) + 0.5, MemoryCurrent: uint64(200+i) << 20})
	}
	saved, err := h.srv.SnapshotTelemetrySeries(ctx, incID)
	if err != nil || !saved {
		t.Fatalf("SnapshotTelemetrySeries: saved=%v err=%v", saved, err)
	}
	series := decodeIntegerSeries(t, seriesEvidence(t, h.store, incID)[0].RedactedData)
	if len(series.Points) != MaxTelemetrySeriesPoints {
		t.Fatalf("expected %d points after downsampling, got %d", MaxTelemetrySeriesPoints, len(series.Points))
	}
	if series.Points[0][0] != -180000 || series.Points[len(series.Points)-1][0] != 419000 {
		t.Fatalf("downsampling must keep the first and last points, got %d .. %d", series.Points[0][0], series.Points[len(series.Points)-1][0])
	}
	for i := 1; i < len(series.Points); i++ {
		if series.Points[i][0] <= series.Points[i-1][0] {
			t.Fatalf("downsampled points must be strictly ascending: %v then %v", series.Points[i-1], series.Points[i])
		}
	}
}

func TestTerminalTransitions_SaveTelemetrySeries(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	record := func(incID string) {
		inc, err := h.store.GetIncident(ctx, incID)
		if err != nil {
			t.Fatalf("GetIncident: %v", err)
		}
		h.srv.PSIRing().Record(inc.Cgroup, PSIPoint{At: inc.OpenedAt.Add(time.Second), SomeAvg10: 3.2, FullAvg10: 0.4, MemoryCurrent: 300 << 20})
	}

	t.Run("incident_transition to a terminal state", func(t *testing.T) {
		incID := "INC-20261113-1820-pi01"
		_ = newScopedIncident(t, h, incID, scopedCgroup)
		record(incID)
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "incident_transition", Arguments: map[string]any{
			"incident_id": incID, "to": "ESCALATED", "reason": "architect escalation: low confidence", "actor": "franken-architect",
		}})
		if err != nil || res.IsError {
			t.Fatalf("incident_transition: err=%v res=%+v", err, res)
		}
		if n := len(seriesEvidence(t, h.store, incID)); n != 1 {
			t.Fatalf("expected one telemetry_series after terminal transition, got %d", n)
		}
	})

	t.Run("plan revision escalation", func(t *testing.T) {
		incID := "INC-20261113-1821-pi01"
		_ = newScopedIncident(t, h, incID, scopedCgroup)
		record(incID)
		bad := singleStepPlan(incID, "unit_restart", map[string]any{"unit": "sshd.service"}, "ev-ghost")
		var last PlanSubmitOutput
		for i := 0; i < MaxPlanRevisions+1; i++ {
			last = callPlanSubmit(t, ctx, session, incID, bad)
		}
		if !last.Escalated {
			t.Fatalf("expected escalation after %d rejected plans, got %+v", MaxPlanRevisions+1, last)
		}
		if n := len(seriesEvidence(t, h.store, incID)); n != 1 {
			t.Fatalf("expected one telemetry_series after plan revision escalation, got %d", n)
		}
	})

	t.Run("L2 failure escalation", func(t *testing.T) {
		incID := "INC-20261113-1822-pi01"
		ev := newScopedIncident(t, h, incID, scopedCgroup)
		record(incID)
		plan := singleStepPlan(incID, "unit_restart", map[string]any{"unit": "haunted-api.service"}, ev)
		planOut := callPlanSubmit(t, ctx, session, incID, plan)
		if !planOut.Valid {
			t.Fatalf("plan rejected: %v", planOut.Violations)
		}
		tok, _, err := h.minter.Mint(policyMint(incID, planOut.PlanHash, "unit_restart", "s1"))
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		h.runner.mu.Lock()
		h.runner.nextErr = errors.New("exit status 1")
		h.runner.nextRes = &executor.Result{Binary: "systemctl", ExitCode: 1, Stderr: "Job failed"}
		h.runner.mu.Unlock()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "action_execute", Arguments: map[string]any{
			"incident_id": incID, "step_id": "s1", "action": "unit_restart", "params": map[string]any{"unit": "haunted-api.service"}, "approval_token": tok,
		}})
		if err != nil || !res.IsError {
			t.Fatalf("expected failed L2 execution, got err=%v res=%+v", err, res)
		}
		if inc, _ := h.store.GetIncident(ctx, incID); inc.State != incident.StateEscalated {
			t.Fatalf("expected ESCALATED after L2 failure, got %s", inc.State)
		}
		if n := len(seriesEvidence(t, h.store, incID)); n != 1 {
			t.Fatalf("expected one telemetry_series after L2 failure escalation, got %d", n)
		}
	})
}

// policyMint menyusun MintRequest satu langkah untuk test eskalasi.
func policyMint(incID, planHash, action, stepID string) approval.MintRequest {
	return approval.MintRequest{
		IncidentID: incID, PlanHash: planHash, OptionID: "A", ActionName: action, StepIDs: []string{stepID}, ApproverSender: "lab-admin",
	}
}
