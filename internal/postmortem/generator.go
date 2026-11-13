package postmortem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/redact"
)

var validIncidentSlug = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$`)

// TriageSummary merepresentasikan ringkasan JSON klasifikasi insiden milik agen Franken-Sentry.
type TriageSummary struct {
	Class       string   `json:"class"`
	Confidence  float64  `json:"confidence"`
	EvidenceIDs []string `json:"evidence_ids"`
	Summary     string   `json:"summary"`
}

// Options mengatur parameter pembuatan laporan postmortem otomatis.
type Options struct {
	IncidentID string
	OutputDir  string
	Author     string
	Notes      string
	Clock      func() time.Time
}

// Document memuat hasil render markdown postmortem beserta metadata jalur berkas yang aman.
type Document struct {
	IncidentID   string    `json:"incident_id"`
	State        string    `json:"state"`
	FilePath     string    `json:"file_path,omitempty"`
	Markdown     string    `json:"markdown"`
	GeneratedAt  time.Time `json:"generated_at"`
	AuditEntries int       `json:"audit_entries"`
	EvidenceUsed int       `json:"evidence_used"`
}

// ValidateIncidentID memastikan ID insiden aman dijadikan nama subdirektori tanpa celah path traversal.
func ValidateIncidentID(id string) (string, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return "", errors.New("postmortem: incident_id is required")
	}
	if strings.Contains(trimmed, "..") || strings.ContainsAny(trimmed, `/\`) {
		return "", fmt.Errorf("postmortem: unsafe incident_id %q", trimmed)
	}
	if !validIncidentSlug.MatchString(trimmed) {
		return "", fmt.Errorf("postmortem: invalid incident_id format %q", trimmed)
	}
	return trimmed, nil
}

// Generate menyusun dokumen markdown postmortem terredaksi dari rekaman SQLite insiden terkait.
func Generate(ctx context.Context, store *incident.Store, opts Options) (*Document, error) {
	if store == nil {
		return nil, errors.New("postmortem: incident store is required")
	}
	incID, err := ValidateIncidentID(opts.IncidentID)
	if err != nil {
		return nil, err
	}

	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	now := clock().UTC()

	inc, err := store.GetIncident(ctx, incID)
	if err != nil {
		return nil, fmt.Errorf("load incident %s: %w", incID, err)
	}
	evidences, err := store.GetEvidenceByIncident(ctx, incID)
	if err != nil {
		return nil, fmt.Errorf("load evidence %s: %w", incID, err)
	}
	reflexes, err := store.GetReflexActionsByIncident(ctx, incID)
	if err != nil {
		return nil, fmt.Errorf("load reflexes %s: %w", incID, err)
	}
	audits, err := store.GetAuditTrail(ctx, incID)
	if err != nil {
		return nil, fmt.Errorf("load audit %s: %w", incID, err)
	}

	md := renderMarkdown(inc, evidences, reflexes, audits, opts, now)
	return &Document{
		IncidentID:   incID,
		State:        string(inc.State),
		Markdown:     md,
		GeneratedAt:  now,
		AuditEntries: len(audits),
		EvidenceUsed: len(evidences),
	}, nil
}

// GenerateAndWrite menyusun postmortem terredaksi, menyimpannya ke `<baseDir>/<incident_id>/postmortem.md`, dan mencatat audit.
func GenerateAndWrite(ctx context.Context, store *incident.Store, opts Options) (*Document, error) {
	doc, err := Generate(ctx, store, opts)
	if err != nil {
		return nil, err
	}

	outBase := strings.TrimSpace(opts.OutputDir)
	if outBase == "" {
		outBase = "incidents"
	}
	absBase, err := filepath.Abs(outBase)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory %q: %w", outBase, err)
	}

	targetDir := filepath.Join(absBase, doc.IncidentID)
	rel, err := filepath.Rel(absBase, targetDir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("postmortem: resolved output directory %q escapes base %q", targetDir, absBase)
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return nil, fmt.Errorf("create postmortem directory %s: %w", targetDir, err)
	}

	targetFile := filepath.Join(targetDir, "postmortem.md")
	if err := os.WriteFile(targetFile, []byte(doc.Markdown), 0o644); err != nil {
		return nil, fmt.Errorf("write postmortem file %s: %w", targetFile, err)
	}

	author := strings.TrimSpace(opts.Author)
	if author == "" {
		author = "franken-remediator"
	}
	payload, _ := json.Marshal(map[string]any{
		"file":          filepath.ToSlash(filepath.Join(filepath.Base(absBase), doc.IncidentID, "postmortem.md")),
		"state":         doc.State,
		"evidence_used": doc.EvidenceUsed,
		"audit_entries": doc.AuditEntries,
	})
	_ = store.RecordAudit(ctx, doc.IncidentID, author, "POSTMORTEM_GENERATED", redact.String(string(payload)))

	doc.FilePath = targetFile
	return doc, nil
}

type timelineItem struct {
	At      time.Time
	Actor   string
	Event   string
	Summary string
}

func renderMarkdown(
	inc *incident.Incident,
	evidences []incident.EvidenceSnapshot,
	reflexes []incident.ReflexAction,
	audits []incident.AuditEntry,
	opts Options,
	generatedAt time.Time,
) string {
	var triage TriageSummary
	hasTriage := false
	if strings.TrimSpace(inc.TriageJSON) != "" {
		if err := json.Unmarshal([]byte(inc.TriageJSON), &triage); err == nil {
			hasTriage = true
		}
	}

	var plan policy.Plan
	hasPlan := false
	if strings.TrimSpace(inc.PlanJSON) != "" {
		if err := json.Unmarshal([]byte(inc.PlanJSON), &plan); err == nil {
			hasPlan = true
		}
	}

	closedText := "open / ongoing"
	durationText := generatedAt.Sub(inc.OpenedAt.UTC()).Round(time.Second).String()
	if inc.ClosedAt != nil && !inc.ClosedAt.IsZero() {
		closedUTC := inc.ClosedAt.UTC()
		closedText = closedUTC.Format(time.RFC3339)
		durationText = closedUTC.Sub(inc.OpenedAt.UTC()).Round(time.Second).String()
	}

	ttoText := "N/A (non-positive slope)"
	if inc.TTOSeconds != nil {
		ttoText = fmt.Sprintf("%.1f s", *inc.TTOSeconds)
	}

	author := strings.TrimSpace(opts.Author)
	if author == "" {
		author = "franken-remediator"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Incident Postmortem: %s\n\n", inc.ID))
	b.WriteString(fmt.Sprintf("- **Generated At:** %s\n", generatedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- **Generated By:** %s\n", redact.String(author)))
	b.WriteString(fmt.Sprintf("- **Node:** `%s`\n", redact.String(inc.Node)))
	b.WriteString(fmt.Sprintf("- **Target Cgroup:** `%s`\n", redact.String(inc.Cgroup)))
	b.WriteString(fmt.Sprintf("- **Severity:** `%s`\n", redact.String(inc.Severity)))
	b.WriteString(fmt.Sprintf("- **Final State:** `%s`\n", inc.State))
	b.WriteString(fmt.Sprintf("- **Opened At:** %s\n", inc.OpenedAt.UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- **Closed At:** %s\n", closedText))
	b.WriteString(fmt.Sprintf("- **Duration:** %s\n", durationText))
	b.WriteString(fmt.Sprintf("- **Initial TTO Estimate:** %s\n\n", ttoText))

	b.WriteString("## Root Cause Analysis\n\n")
	if hasTriage {
		b.WriteString(fmt.Sprintf("- **Triage Class:** `%s` (confidence: `%.2f`)\n", redact.String(triage.Class), triage.Confidence))
		if strings.TrimSpace(triage.Summary) != "" {
			b.WriteString(fmt.Sprintf("- **Triage Summary:** %s\n", sanitizeSingleLine(triage.Summary)))
		}
	}
	if hasPlan && strings.TrimSpace(plan.SuspectedRootCause) != "" {
		b.WriteString(fmt.Sprintf("- **Suspected Root Cause:** %s\n", sanitizeSingleLine(plan.SuspectedRootCause)))
	} else if !hasTriage {
		b.WriteString("- **Suspected Root Cause:** Pending detailed root-cause diagnosis from Sentry/Architect triage.\n")
	}
	if strings.TrimSpace(opts.Notes) != "" {
		b.WriteString(fmt.Sprintf("- **Operator / Remediator Notes:** %s\n", sanitizeSingleLine(opts.Notes)))
	}
	b.WriteString("\n")

	b.WriteString("## Timeline (UTC)\n\n")
	b.WriteString("| Timestamp | Actor | Event | Summary |\n")
	b.WriteString("|---|---|---|---|\n")
	timeline := buildTimeline(inc, reflexes, audits)
	for _, item := range timeline {
		b.WriteString(fmt.Sprintf("| %s | `%s` | `%s` | %s |\n",
			item.At.UTC().Format(time.RFC3339),
			sanitizeTableCell(item.Actor),
			sanitizeTableCell(item.Event),
			sanitizeTableCell(item.Summary),
		))
	}
	b.WriteString("\n")

	b.WriteString("## Actions Taken\n\n")
	if len(reflexes) == 0 && !hasPlan {
		b.WriteString("No automated L1 reflexes or validated L2 remediation actions were recorded for this incident.\n\n")
	} else {
		if len(reflexes) > 0 {
			b.WriteString("### Level 1 Reflexes\n\n")
			b.WriteString("| Reflex ID | Action | Target | Status | TTL (s) | Rolled Back At |\n")
			b.WriteString("|---|---|---|---|---|---|\n")
			for _, r := range reflexes {
				rbAt := "—"
				if r.RolledBackAt != nil && !r.RolledBackAt.IsZero() {
					rbAt = r.RolledBackAt.UTC().Format(time.RFC3339)
				}
				b.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | %d | %s |\n",
					sanitizeTableCell(r.ID),
					sanitizeTableCell(r.Action),
					sanitizeTableCell(r.Target),
					sanitizeTableCell(r.Status),
					r.TTLSeconds,
					rbAt,
				))
			}
			b.WriteString("\n")
		}

		if hasPlan && len(plan.Options) > 0 {
			b.WriteString("### Planned Level 2 Remediation Steps\n\n")
			b.WriteString("| Option | Step ID | Action | Evidence IDs | Expected Effect |\n")
			b.WriteString("|---|---|---|---|---|\n")
			for _, opt := range plan.Options {
				for _, st := range opt.Steps {
					b.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | `%s` | %s |\n",
						sanitizeTableCell(opt.ID),
						sanitizeTableCell(st.ID),
						sanitizeTableCell(st.Action),
						sanitizeTableCell(strings.Join(st.EvidenceIDs, ", ")),
						sanitizeTableCell(st.ExpectedEffect),
					))
				}
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Redacted Evidence Snapshots\n\n")
	if len(evidences) == 0 {
		b.WriteString("No evidence snapshots were persisted.\n\n")
	} else {
		for _, ev := range evidences {
			// Seri telemetri berisi ratusan titik numerik: tampilkan ringkasannya, bukan angka mentah
			if ev.Kind == incident.EvidenceKindTelemetrySeries {
				if summary, ok := summarizeTelemetrySeries(ev.RedactedData); ok {
					b.WriteString(fmt.Sprintf("### `%s` (`%s`, captured %s)\n\n", ev.ID, sanitizeSingleLine(ev.Kind), ev.CapturedAt.UTC().Format(time.RFC3339)))
					b.WriteString(summary)
					b.WriteString("\n")
					continue
				}
			}
			// Gunakan hanya RedactedData dan jalankan redaksi ulang sebagai pertahanan berlapis
			safeBody := redact.String(strings.TrimSpace(ev.RedactedData))
			if safeBody == "" {
				safeBody = "(empty redacted payload)"
			}
			b.WriteString(fmt.Sprintf("### `%s` (`%s`, captured %s)\n\n", ev.ID, sanitizeSingleLine(ev.Kind), ev.CapturedAt.UTC().Format(time.RFC3339)))
			b.WriteString("```text\n")
			b.WriteString(safeBody)
			if !strings.HasSuffix(safeBody, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n\n")
		}
	}

	b.WriteString("## Follow-Up Action Items\n\n")
	if hasPlan && len(plan.HumanFollowUp) > 0 {
		for _, item := range plan.HumanFollowUp {
			if clean := sanitizeSingleLine(item); clean != "" {
				b.WriteString(fmt.Sprintf("- [ ] %s\n", clean))
			}
		}
	} else {
		b.WriteString("- [ ] Inspect application memory profile / cgroup ceiling to prevent recurrence.\n")
		b.WriteString("- [ ] Confirm post-remediation telemetry remains below PSI thresholds (`some_avg10 < 5.0`, `full_avg10 < 1.0`).\n")
	}

	return b.String()
}

func buildTimeline(inc *incident.Incident, reflexes []incident.ReflexAction, audits []incident.AuditEntry) []timelineItem {
	items := []timelineItem{
		{
			At:      inc.OpenedAt.UTC(),
			Actor:   "sentinel-detector",
			Event:   "INCIDENT_OPENED",
			Summary: fmt.Sprintf("Severity %s on %s", inc.Severity, inc.Cgroup),
		},
	}

	for _, r := range reflexes {
		items = append(items, timelineItem{
			At:      r.AppliedAt.UTC(),
			Actor:   "sentinel-reflex",
			Event:   "REFLEX_APPLIED",
			Summary: fmt.Sprintf("%s on %s (TTL %ds)", r.Action, r.Target, r.TTLSeconds),
		})
		if r.RolledBackAt != nil && !r.RolledBackAt.IsZero() {
			items = append(items, timelineItem{
				At:      r.RolledBackAt.UTC(),
				Actor:   "sentinel-reflex",
				Event:   "REFLEX_" + r.Status,
				Summary: fmt.Sprintf("%s restored on %s", r.Action, r.Target),
			})
		}
	}

	for _, a := range audits {
		items = append(items, timelineItem{
			At:      a.CreatedAt.UTC(),
			Actor:   a.Actor,
			Event:   a.EventType,
			Summary: a.PayloadJSON,
		})
	}

	if inc.ClosedAt != nil && !inc.ClosedAt.IsZero() {
		items = append(items, timelineItem{
			At:      inc.ClosedAt.UTC(),
			Actor:   "sentinel",
			Event:   "INCIDENT_" + string(inc.State),
			Summary: fmt.Sprintf("Incident reached terminal state %s", inc.State),
		})
	}

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].At.Before(items[j].At)
	})
	return items
}

func sanitizeSingleLine(s string) string {
	clean := redact.String(strings.TrimSpace(s))
	clean = strings.ReplaceAll(clean, "\r\n", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	return clean
}

func sanitizeTableCell(s string) string {
	clean := sanitizeSingleLine(s)
	clean = strings.ReplaceAll(clean, "|", "/")
	if len(clean) > 200 {
		clean = clean[:197] + "..."
	}
	if clean == "" {
		return "—"
	}
	return clean
}

// summarizeTelemetrySeries meringkas evidence telemetry_series menjadi poin markdown (rentang, puncak memori
// terhadap batas, puncak PSI, dan sampel terakhir). Payload yang tidak valid mengembalikan false agar
// pemanggil menampilkan teks tersensor apa adanya.
func summarizeTelemetrySeries(raw string) (string, bool) {
	var ts incident.TelemetrySeries
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &ts); err != nil || len(ts.Points) == 0 {
		return "", false
	}
	first, last := ts.Points[0], ts.Points[len(ts.Points)-1]
	var peakKiB, peakSome, peakFull int64
	for _, p := range ts.Points {
		peakKiB = max(peakKiB, p[1])
		peakSome = max(peakSome, p[2])
		peakFull = max(peakFull, p[3])
	}
	mib := func(kib int64) float64 { return float64(kib) / 1024 }
	offset := func(ms int64) string {
		if ms < 0 {
			return fmt.Sprintf("T-%ds", -ms/1000)
		}
		return fmt.Sprintf("T+%ds", ms/1000)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("- **Samples:** %d samples from %s to %s (T = incident opened)\n", len(ts.Points), offset(first[0]), offset(last[0])))
	if ts.LimitBytes > 0 {
		limitMiB := float64(ts.LimitBytes) / (1 << 20)
		b.WriteString(fmt.Sprintf("- **Peak memory:** %.1f MiB of %.1f MiB (%.0f%%)\n", mib(peakKiB), limitMiB, mib(peakKiB)/limitMiB*100))
	} else {
		b.WriteString(fmt.Sprintf("- **Peak memory:** %.1f MiB\n", mib(peakKiB)))
	}
	b.WriteString(fmt.Sprintf("- **Peak PSI:** some avg10 %.1f%%, full avg10 %.1f%%\n", float64(peakSome)/100, float64(peakFull)/100))
	b.WriteString(fmt.Sprintf("- **Last sample:** %.1f MiB, PSI some avg10 %.1f%%\n", mib(last[1]), float64(last[2])/100))
	b.WriteString("- The full series is available in the incident replay (`franken lab export`).\n")
	return b.String(), true
}
