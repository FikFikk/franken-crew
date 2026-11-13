package wabridge

import (
	"fmt"
	"strings"

	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/redact"
)

// maxOutgoingTextLen membatasi panjang pesan WhatsApp keluar (steering: <= 700 karakter).
const maxOutgoingTextLen = 700

// OutgoingText mengembalikan teks persis seperti yang dikirim bridge: tersensor lalu dipotong ke 700 karakter.
func OutgoingText(text string) string {
	redacted := redact.String(text)
	if len(redacted) > maxOutgoingTextLen {
		redacted = redacted[:maxOutgoingTextLen-3] + "..."
	}
	return redacted
}

// FormatPollTitle menyusun judul Native WhatsApp Poll persetujuan beserta kode fallback teksnya.
func FormatPollTitle(shortCode, incidentID, planHash string) string {
	return fmt.Sprintf("[%s] %s (plan %s) — Choose action or reply APPROVE <OPT> %s / ROLLBACK %s / DISMISS %s",
		shortCode, incidentID, policy.ShortPlanHash(planHash), shortCode, shortCode, shortCode)
}

// FormatPollSentReason menyusun alasan transisi WAITING_APPROVAL yang dicatat bridge saat poll terkirim.
func FormatPollSentReason(approvalID, planHash string) string {
	return fmt.Sprintf("WhatsApp approval poll %s sent for plan %s", approvalID, policy.ShortPlanHash(planHash))
}

// FormatApprovalSummary menyusun pesan konfirmasi setelah vote disetujui dan token per langkah dicetak.
func FormatApprovalSummary(optionID string, steps []policy.PlanStep, incidentID, planHash string, tokens int) string {
	return fmt.Sprintf("Approved option %s (%s) for %s [plan %s]; %d single-use Ed25519 step token(s) issued to Franken-Remediator.",
		optionID, policy.FormatStepsSummary(steps), incidentID, policy.ShortPlanHash(planHash), tokens)
}

// FormatFinalReport menyusun laporan akhir dari event SSE verification.completed.
func FormatFinalReport(ev mcpserver.StreamEvent) string {
	status := extractAnyString(ev.Data, "status")
	lines := []string{fmt.Sprintf("[REPORT] *%s* %s (verification %s)", strings.TrimSpace(ev.IncidentID), ev.State, status)}
	if rolled, ok := ev.Data["rolled_back"]; ok {
		lines = append(lines, fmt.Sprintf("L1 reflexes rolled back: %v", rolled))
	}
	if reasons := extractAnyString(ev.Data, "failure_reasons"); reasons != "" {
		lines = append(lines, "Reasons: "+reasons)
	}
	if pm := extractAnyString(ev.Data, "postmortem_path"); pm != "" {
		lines = append(lines, "Postmortem: "+pm)
	}
	return strings.Join(lines, "\n")
}
