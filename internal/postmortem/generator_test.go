package postmortem

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
)

func TestGenerateAndWrite_RedactsSecretsAndWritesPostmortem(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	store, err := incident.NewStore(filepath.Join(tmp, "pm.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	triageBytes, _ := json.Marshal(TriageSummary{
		Class:       "heap_leak",
		Confidence:  0.92,
		EvidenceIDs: []string{"ev-1"},
		Summary:     "Node worker heap leaking while contacting postgres://admin:supersecret@10.20.30.40:5432/prod",
	})
	plan := policy.Plan{
		IncidentID:         "INC-20261113-1015-pi01",
		SuspectedRootCause: "Unbounded in-memory cache in haunted-api worker",
		Options: []policy.PlanOption{
			{
				ID:    "A",
				Label: "Restart haunted-api cleanly",
				Steps: []policy.PlanStep{
					{
						ID:             "step-1",
						Action:         "unit_restart",
						Params:         map[string]any{"unit": "haunted-api.service"},
						EvidenceIDs:    []string{"ev-1"},
						ExpectedEffect: "Reset leaked worker heap cleanly",
					},
				},
			},
		},
		HumanFollowUp: []string{
			"Add LRU cap to request cache",
			"Rotate token sk-antigravity-secret1234567890",
		},
	}
	planBytes, _ := json.Marshal(plan)

	tto := 22.5
	inc := &incident.Incident{
		ID:         "INC-20261113-1015-pi01",
		Node:       "pi01",
		Cgroup:     "/franken.slice/haunted-api.service",
		Severity:   "P1",
		State:      incident.StateTriaging,
		TTOSeconds: &tto,
		TriageJSON: string(triageBytes),
		PlanJSON:   string(planBytes),
	}
	if err := store.CreateIncident(ctx, inc); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	if err := store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
		ID:         "EV-TEST-1",
		IncidentID: inc.ID,
		Kind:       "journal",
		RawData:    "RAW SECRET postgres://dbuser:rawpassword@192.168.1.50:5432/app Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.secretSig99",
	}); err != nil {
		t.Fatalf("SaveEvidence: %v", err)
	}

	if err := store.SaveReflexAction(ctx, &incident.ReflexAction{
		ID:         "RFX-1",
		IncidentID: inc.ID,
		Action:     "cgroup_throttle",
		Target:     "haunted-api.service",
		ParamsJSON: `{"memory_high":"380M"}`,
		AppliedAt:  time.Date(2026, 11, 13, 10, 15, 1, 0, time.UTC),
		TTLSeconds: 120,
		ExpiresAt:  time.Date(2026, 11, 13, 10, 17, 1, 0, time.UTC),
		Status:     "APPLIED",
	}); err != nil {
		t.Fatalf("SaveReflexAction: %v", err)
	}
	if _, err := store.MarkReflexRolledBack(ctx, "RFX-1", "ROLLED_BACK", time.Date(2026, 11, 13, 10, 17, 5, 0, time.UTC)); err != nil {
		t.Fatalf("MarkReflexRolledBack: %v", err)
	}

	_ = store.TransitionState(ctx, inc.ID, incident.StatePlanned, "franken-architect", "plan validated")
	_ = store.TransitionState(ctx, inc.ID, incident.StateWaitingApproval, "franken-remediator", "poll sent")
	_ = store.TransitionState(ctx, inc.ID, incident.StateRemediating, "franken-remediator", "token verified")
	_ = store.TransitionState(ctx, inc.ID, incident.StateVerifying, "franken-remediator", "action completed")
	_ = store.TransitionState(ctx, inc.ID, incident.StateResolved, "franken-remediator", "healthy for 120s")

	doc, err := GenerateAndWrite(ctx, store, Options{
		IncidentID: inc.ID,
		OutputDir:  filepath.Join(tmp, "incidents"),
		Author:     "franken-remediator",
		Notes:      "Recovered via +6281234567890 approval without OOM.",
		Clock:      func() time.Time { return time.Date(2026, 11, 13, 10, 18, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("GenerateAndWrite: %v", err)
	}

	contentBytes, err := os.ReadFile(doc.FilePath)
	if err != nil {
		t.Fatalf("ReadFile postmortem: %v", err)
	}
	md := string(contentBytes)

	requiredHeadings := []string{
		"# Incident Postmortem: INC-20261113-1015-pi01",
		"## Root Cause Analysis",
		"## Timeline (UTC)",
		"## Actions Taken",
		"## Redacted Evidence Snapshots",
		"## Follow-Up Action Items",
		"`RESOLVED`",
		"`RFX-1`",
		"`unit_restart`",
	}
	for _, want := range requiredHeadings {
		if !strings.Contains(md, want) {
			t.Errorf("postmortem missing expected content %q\n%s", want, md)
		}
	}

	forbiddenLeaks := []string{
		"rawpassword",
		"supersecret",
		"192.168.1.50",
		"10.20.30.40",
		"secretSig99",
		"sk-antigravity-secret1234567890",
		"+6281234567890",
	}
	for _, leak := range forbiddenLeaks {
		if strings.Contains(md, leak) {
			t.Errorf("SECURITY VIOLATION: raw secret/PII leaked in postmortem: %q", leak)
		}
	}

	audits, err := store.GetAuditTrail(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	foundAudit := false
	for _, a := range audits {
		if a.EventType == "POSTMORTEM_GENERATED" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Errorf("expected POSTMORTEM_GENERATED audit entry")
	}
}

func TestValidateIncidentID_BlocksPathTraversal(t *testing.T) {
	t.Parallel()

	badIDs := []string{
		"",
		"../etc/passwd",
		`..\evil`,
		"INC/../../escape",
		".hidden",
	}
	for _, id := range badIDs {
		if _, err := ValidateIncidentID(id); err == nil {
			t.Errorf("expected path traversal ID %q to be rejected", id)
		}
	}
}
