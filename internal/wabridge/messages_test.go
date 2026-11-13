package wabridge

import (
	"strings"
	"testing"

	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
)

func TestBridgeMessageFormatsAreStable(t *testing.T) {
	hash := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	steps := []policy.PlanStep{{ID: "A1", Action: "pm2_reload", Params: map[string]any{"app": "haunted-api"}}}

	if got, want := FormatPollTitle("7F3A", "INC-20261113-0319-pi01-sim", hash),
		"[7F3A] INC-20261113-0319-pi01-sim (plan a1b2c3d4) — Choose action or reply APPROVE <OPT> 7F3A / ROLLBACK 7F3A / DISMISS 7F3A"; got != want {
		t.Errorf("FormatPollTitle = %q, want %q", got, want)
	}
	if got, want := FormatPollSentReason("APR-7F3A", hash), "WhatsApp approval poll APR-7F3A sent for plan a1b2c3d4"; got != want {
		t.Errorf("FormatPollSentReason = %q, want %q", got, want)
	}
	if got, want := FormatApprovalSummary("A", steps, "INC-1", hash, 1),
		"Approved option A (pm2_reload haunted-api) for INC-1 [plan a1b2c3d4]; 1 single-use Ed25519 step token(s) issued to Franken-Remediator."; got != want {
		t.Errorf("FormatApprovalSummary = %q, want %q", got, want)
	}

	report := FormatFinalReport(mcpserver.StreamEvent{
		IncidentID: "INC-1",
		State:      "ESCALATED",
		Data: map[string]any{
			"status":          "FAILED",
			"rolled_back":     1,
			"failure_reasons": "memory trend unstable",
			"postmortem_path": "incidents/INC-1/postmortem.md",
		},
	})
	if want := "[REPORT] *INC-1* ESCALATED (verification FAILED)\nL1 reflexes rolled back: 1\nReasons: memory trend unstable\nPostmortem: incidents/INC-1/postmortem.md"; report != want {
		t.Errorf("FormatFinalReport = %q, want %q", report, want)
	}

	alert := FormatCriticalAlertMessage("pi01-sim", mcpserver.StreamEvent{
		IncidentID: "INC-1", Severity: "p2", State: "DETECTED", Summary: "P2 pressure/leak detected on /franken.slice/haunted-api.service",
		Data: map[string]any{"cgroup": "/franken.slice/haunted-api.service"},
	})
	if want := "[P2] *INC-1* | DETECTED\nNode: `pi01-sim` | Target: `/franken.slice/haunted-api.service`\nP2 pressure/leak detected on /franken.slice/haunted-api.service"; alert != want {
		t.Errorf("FormatCriticalAlertMessage = %q, want %q", alert, want)
	}

	long := OutgoingText("call +62 812-3456-7890 " + strings.Repeat("x", 800))
	if len(long) != 700 || !strings.HasSuffix(long, "...") || strings.Contains(long, "812-3456") {
		t.Errorf("OutgoingText must redact then cap at 700 characters, got %d chars", len(long))
	}
}
