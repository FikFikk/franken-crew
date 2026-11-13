package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/postmortem"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func callPlanSubmitWithTriage(t *testing.T, ctx context.Context, session *mcp.ClientSession, incID string, plan any, triage map[string]any) PlanSubmitOutput {
	t.Helper()
	args := map[string]any{"incident_id": incID, "plan": plan}
	if triage != nil {
		args["triage"] = triage
	}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "plan_submit", Arguments: args})
	if err != nil {
		t.Fatalf("plan_submit transport error: %v", err)
	}
	return decodeStructured[PlanSubmitOutput](t, res)
}

func TestPlanSubmit_RejectsInvalidTriage(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	otherEv := newScopedIncident(t, h, "INC-20261113-1700-pi01", "/franken.slice/worker.service")
	cases := []struct {
		name   string
		incID  string
		triage func(ownEv string) map[string]any
		needle string
	}{
		{
			name:   "class outside the fixed list",
			incID:  "INC-20261113-1701-pi01",
			triage: func(ev string) map[string]any { return triageArgs("memory_monster", 0.8, ev, "leak") },
			needle: "triage class",
		},
		{
			name:   "evidence never recorded",
			incID:  "INC-20261113-1702-pi01",
			triage: func(string) map[string]any { return triageArgs("heap_leak", 0.8, "ev-ghost-404", "leak") },
			needle: "triage evidence_id",
		},
		{
			name:   "evidence of another incident",
			incID:  "INC-20261113-1703-pi01",
			triage: func(string) map[string]any { return triageArgs("heap_leak", 0.8, otherEv, "leak") },
			needle: "triage evidence_id",
		},
		{
			name:   "confidence above one",
			incID:  "INC-20261113-1704-pi01",
			triage: func(ev string) map[string]any { return triageArgs("heap_leak", 1.4, ev, "leak") },
			needle: "triage confidence",
		},
		{
			name:   "confidence below zero",
			incID:  "INC-20261113-1705-pi01",
			triage: func(ev string) map[string]any { return triageArgs("heap_leak", -0.1, ev, "leak") },
			needle: "triage confidence",
		},
		{
			name:   "summary longer than 500 characters",
			incID:  "INC-20261113-1706-pi01",
			triage: func(ev string) map[string]any { return triageArgs("heap_leak", 0.8, ev, strings.Repeat("é", 501)) },
			needle: "triage summary",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := newScopedIncident(t, h, tc.incID, scopedCgroup)
			plan := singleStepPlan(tc.incID, "unit_restart", map[string]any{"unit": "haunted-api.service"}, ev)
			out := callPlanSubmitWithTriage(t, ctx, session, tc.incID, plan, tc.triage(ev))
			if out.Valid {
				t.Fatalf("invalid triage must make the submission invalid, got %+v", out)
			}
			if !hasViolation(out, tc.needle) {
				t.Fatalf("expected a %q violation, got %v", tc.needle, out.Violations)
			}
			inc, err := h.store.GetIncident(ctx, tc.incID)
			if err != nil {
				t.Fatalf("GetIncident: %v", err)
			}
			if inc.PlanJSON != "" || inc.TriageJSON != "" {
				t.Fatalf("rejected submission must not persist plan or triage: plan=%q triage=%q", inc.PlanJSON, inc.TriageJSON)
			}
			if n, _ := h.store.CountAuditByEvent(ctx, tc.incID, "PLAN_REJECTED"); n != 1 {
				t.Fatalf("triage violation must be audited as PLAN_REJECTED, got %d rows", n)
			}
		})
	}
}

func TestPlanSubmit_PersistsValidTriageForIncidentGetAndPostmortem(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	incID := "INC-20261113-1710-pi01"
	ev := newScopedIncident(t, h, incID, scopedCgroup)
	plan := singleStepPlan(incID, "pm2_reload", map[string]any{"app": "haunted-api"}, ev)
	out := callPlanSubmitWithTriage(t, ctx, session, incID, plan,
		triageArgs("heap_leak", 0.86, ev, "V8 heap grows ~2.2 MiB/s until heap limit; contact ops at +62 812-3456-7890"))
	if !out.Valid {
		t.Fatalf("valid triage must be accepted, got %v", out.Violations)
	}

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "incident_get", Arguments: map[string]any{"incident_id": incID}})
	if err != nil {
		t.Fatalf("incident_get: %v", err)
	}
	got := decodeStructured[IncidentGetOutput](t, res)
	var triage postmortem.TriageSummary
	if err := json.Unmarshal([]byte(got.Incident.TriageJSON), &triage); err != nil {
		t.Fatalf("incident_get triage_json must be JSON, got %q: %v", got.Incident.TriageJSON, err)
	}
	if triage.Class != "heap_leak" || triage.Confidence != 0.86 || len(triage.EvidenceIDs) != 1 || triage.EvidenceIDs[0] != ev {
		t.Fatalf("unexpected stored triage: %+v", triage)
	}
	if strings.Contains(got.Incident.TriageJSON, "812-3456-7890") || !strings.Contains(triage.Summary, "[REDACTED_PHONE]") {
		t.Fatalf("triage summary must be redacted, got %q", triage.Summary)
	}

	doc, err := postmortem.Generate(ctx, h.store, postmortem.Options{IncidentID: incID, Clock: h.Now})
	if err != nil {
		t.Fatalf("postmortem.Generate: %v", err)
	}
	if !strings.Contains(doc.Markdown, "**Triage Class:** `heap_leak` (confidence: `0.86`)") ||
		!strings.Contains(doc.Markdown, "**Triage Summary:** V8 heap grows") {
		t.Fatalf("postmortem must render the persisted triage, got:\n%s", doc.Markdown)
	}
}

func triageArgs(class string, confidence float64, evidenceID, summary string) map[string]any {
	return map[string]any{
		"class":        class,
		"confidence":   confidence,
		"evidence_ids": []string{evidenceID},
		"summary":      summary,
	}
}
