package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/FikFikk/franken-crew/internal/redact"
)

const (
	// PollOptionRollbackReflex adalah label opsi sekunder poll WhatsApp untuk me-rollback refleks L1.
	PollOptionRollbackReflex = "Rollback Reflex"
	// PollOptionDismiss adalah label opsi sekunder poll WhatsApp untuk menutup insiden tanpa aksi.
	PollOptionDismiss = "Dismiss"

	// maxPollOptionLabelLen membatasi panjang label opsi WhatsApp Poll agar tetap terbaca utuh beserta hash plan.
	maxPollOptionLabelLen = 96
)

// FormatOptionLabel menyusun label opsi poll langsung dari aksi & target plan Sentinel beserta 8 karakter hash plan.
// Fungsi ini menjadi sumber tunggal format label bagi wa-bridge dan replay dashboard sehingga teksnya identik.
func FormatOptionLabel(opt PlanOption, planHash string) string {
	hashTag := ShortPlanHash(planHash)
	prefix := fmt.Sprintf("%s: ", strings.TrimSpace(opt.ID))
	suffix := fmt.Sprintf(" [%s]", hashTag)
	body := redact.String(FormatStepsSummary(opt.Steps))
	if body == "" {
		body = redact.String(strings.TrimSpace(opt.Label))
	}
	maxBody := maxPollOptionLabelLen - len(prefix) - len(suffix)
	if maxBody > 3 && len(body) > maxBody {
		body = strings.TrimSpace(body[:maxBody-3]) + "..."
	}
	return prefix + body + suffix
}

// FormatStepsSummary meringkas langkah-langkah satu opsi menjadi "aksi target + aksi target".
func FormatStepsSummary(steps []PlanStep) string {
	if len(steps) == 0 {
		return ""
	}
	parts := make([]string, 0, len(steps))
	for _, st := range steps {
		parts = append(parts, FormatStepTarget(st))
	}
	return strings.Join(parts, " + ")
}

// FormatStepTarget menampilkan aksi satu langkah beserta target utamanya (unit, app PM2, pid, atau parameter pertama).
func FormatStepTarget(st PlanStep) string {
	action := strings.TrimSpace(st.Action)
	if len(st.Params) == 0 {
		return action
	}

	if unit, ok := st.Params["unit"].(string); ok && strings.TrimSpace(unit) != "" {
		return action + " " + strings.TrimSpace(unit)
	}
	if app, ok := st.Params["app"].(string); ok && strings.TrimSpace(app) != "" {
		// Tampilkan worker PM2 yang akan di-restart agar manusia tahu persis instans mana yang disetujui
		if pmID, ok := st.Params["pm_id"]; ok && pmID != nil {
			return fmt.Sprintf("%s %s pm_id=%v", action, strings.TrimSpace(app), pmID)
		}
		return action + " " + strings.TrimSpace(app)
	}
	if pidVal, ok := st.Params["pid"]; ok && pidVal != nil {
		return fmt.Sprintf("%s pid=%v", action, pidVal)
	}

	keys := make([]string, 0, len(st.Params))
	for k := range st.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		return fmt.Sprintf("%s %s=%v", action, keys[0], st.Params[keys[0]])
	}
	return action
}

// ShortPlanHash mengembalikan 8 karakter pertama plan_hash yang ditampilkan pada poll dan pesan WhatsApp.
func ShortPlanHash(h string) string {
	clean := strings.TrimSpace(h)
	if len(clean) > 8 {
		return clean[:8]
	}
	return clean
}

// PollOptionLabels mengembalikan label opsi plan sesuai urutan plan, diikuti "Rollback Reflex" dan "Dismiss".
func PollOptionLabels(plan *Plan, planHash string) []string {
	var labels []string
	if plan != nil {
		labels = make([]string, 0, len(plan.Options)+2)
		for _, opt := range plan.Options {
			labels = append(labels, FormatOptionLabel(opt, planHash))
		}
	}
	return append(labels, PollOptionRollbackReflex, PollOptionDismiss)
}
