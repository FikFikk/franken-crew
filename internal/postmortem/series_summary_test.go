package postmortem

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
)

// Evidence telemetry_series berisi ratusan titik; postmortem wajib meringkasnya, bukan menempelkan angka mentah.
func TestGenerate_SummarizesTelemetrySeriesEvidence(t *testing.T) {
	t.Parallel()

	store, err := incident.NewStore(filepath.Join(t.TempDir(), "pm.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()

	opened := time.Date(2026, 11, 13, 3, 19, 0, 0, time.UTC)
	inc := &incident.Incident{
		ID: "INC-20261113-0319-pi01", Node: "pi01", Cgroup: "/franken.slice/haunted-api.service",
		Severity: "P2", State: incident.StateResolved, OpenedAt: opened,
	}
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	// 4 titik: memori puncak 300 MiB dari batas 512 MiB, PSI some puncak 41.5%, berakhir di 180 MiB
	series := incident.TelemetrySeries{
		Cgroup:     "/franken.slice/haunted-api.service",
		LimitBytes: 512 << 20,
		Points: [][4]int64{
			{-120000, 176 * 1024, 31, 2},
			{0, 290 * 1024, 4150, 480},
			{60000, 300 * 1024, 2000, 100},
			{190000, 180 * 1024, 40, 5},
		},
	}
	raw, _ := json.Marshal(series)
	if err := store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
		ID: "EVD-series-1", IncidentID: inc.ID, Kind: incident.EvidenceKindTelemetrySeries,
		RedactedData: string(raw), CapturedAt: opened.Add(190 * time.Second),
	}); err != nil {
		t.Fatalf("SaveEvidence: %v", err)
	}

	doc, err := Generate(ctx, store, Options{IncidentID: inc.ID, Clock: func() time.Time { return opened.Add(200 * time.Second) }})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	md := doc.Markdown

	if strings.Contains(md, `"points":[[`) {
		t.Fatalf("postmortem must summarize telemetry_series instead of dumping raw points:\n%s", md)
	}
	for _, want := range []string{
		"4 samples from T-120s to T+190s",
		"Peak memory:** 300.0 MiB of 512.0 MiB (59%)",
		"Peak PSI:** some avg10 41.5%, full avg10 4.8%",
		"Last sample:** 180.0 MiB, PSI some avg10 0.4%",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("postmortem missing %q in telemetry summary:\n%s", want, md)
		}
	}
}
