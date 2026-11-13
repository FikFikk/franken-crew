package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/postmortem"
	"github.com/FikFikk/franken-crew/internal/redact"
	"github.com/FikFikk/franken-crew/internal/wabridge"
)

const (
	maxEventTitleRunes  = 60
	maxEventDetailRunes = 280
	// psiRisingThreshold menandai titik seri pertama sebelum insiden dibuka dengan PSI some avg10 >= 10.
	psiRisingThreshold = 10.0
	// defaultExportLimit adalah jumlah insiden terminal terbaru yang diekspor bila --incident tidak diisi.
	defaultExportLimit = 10

	// rebuiltNote dicantumkan pada source.detail: teks chat disusun ulang, bukan disalin dari WhatsApp.
	rebuiltNote = "Chat messages and the approval poll are rebuilt from the stored incident data in wa-bridge's message formats; file paths are shown relative to the postmortem directory, and all text is redacted."
)

var (
	approvalIDPattern     = regexp.MustCompile(`APR-[0-9A-Za-z]+`)
	forwardWindowPattern  = regexp.MustCompile(`(\d+)s forward window`)
	absPostmortemPattern  = regexp.MustCompile(`(?:/[^\s"'|/\\]+)+/([^\s"'|/\\]+/[^\s"'|/\\]+/postmortem\.md)`)
	pollSentReasonPrefix  = "WhatsApp approval poll "
	voteGrantedPrefix     = "WhatsApp approval granted for option "
	verifyWindowReason    = "forward health verification window started"
	verifyFailedReasonPfx = "verify_health failed: "
)

// BuildReplay menyusun replay hanya dari store SQLite: baris insiden, plan_json, triage_json, RedactedData evidence,
// baris refleks, audit trail, dan evidence telemetry_series. Postmortem dirender ulang dengan postmortem.Generate
// memakai jam deterministik = closed_at. Urutan insiden mengikuti incidentIDs.
func BuildReplay(ctx context.Context, store *incident.Store, incidentIDs []string, source ReplaySource, node string) (*Replay, error) {
	if store == nil {
		return nil, errors.New("lab: incident store is required")
	}
	if len(incidentIDs) == 0 {
		return nil, errors.New("lab: at least one incident id is required")
	}
	src, err := finalizeSource(source)
	if err != nil {
		return nil, err
	}

	rep := &Replay{
		Schema:      ReplaySchema,
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Source:      src,
		Node:        redact.String(strings.TrimSpace(node)),
		Incidents:   make([]ReplayIncident, 0, len(incidentIDs)),
	}
	for _, id := range incidentIDs {
		ri, nodeName, err := buildIncident(ctx, store, strings.TrimSpace(id))
		if err != nil {
			return nil, fmt.Errorf("build replay for %s: %w", id, err)
		}
		if rep.Node == "" {
			rep.Node = nodeName
		}
		rep.Incidents = append(rep.Incidents, *ri)
	}
	return rep, nil
}

// RecentTerminalIncidentIDs mengembalikan hingga limit insiden terminal terbaru, diurutkan kronologis (lama ke baru).
func RecentTerminalIncidentIDs(ctx context.Context, store *incident.Store, limit int) ([]string, error) {
	if limit <= 0 {
		limit = defaultExportLimit
	}
	list, err := store.ListIncidents(ctx, "", 200)
	if err != nil {
		return nil, err
	}
	var picked []incident.Incident
	for _, inc := range list {
		if isTerminalStateName(string(inc.State)) {
			picked = append(picked, inc)
			if len(picked) == limit {
				break
			}
		}
	}
	sort.SliceStable(picked, func(i, j int) bool { return picked[i].OpenedAt.Before(picked[j].OpenedAt) })
	ids := make([]string, 0, len(picked))
	for _, inc := range picked {
		ids = append(ids, inc.ID)
	}
	return ids, nil
}

// numericArrayPattern menangkap array angka hasil MarshalIndent; string JSON tidak pernah memuat newline mentah,
// sehingga pola ini tidak menyentuh isi teks.
var numericArrayPattern = regexp.MustCompile(`\[\n\s+-?[0-9][0-9.eE+-]*(?:,\n\s+-?[0-9][0-9.eE+-]*)*\n\s*\]`)

// MarshalReplay menghasilkan JSON ter-indentasi dengan array angka (titik seri) dipadatkan ke satu baris.
func MarshalReplay(r *Replay) ([]byte, error) {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	compact := numericArrayPattern.ReplaceAllFunc(raw, func(m []byte) []byte {
		out := make([]byte, 0, len(m))
		for _, c := range m {
			if c != '\n' && c != ' ' && c != '\t' {
				out = append(out, c)
			}
		}
		return out
	})
	return append(compact, '\n'), nil
}

func finalizeSource(src ReplaySource) (ReplaySource, error) {
	kind := strings.TrimSpace(src.Kind)
	if kind == "" {
		kind = SourceKindRecording
	}
	if kind != SourceKindRecording && kind != SourceKindSimulation {
		return ReplaySource{}, fmt.Errorf("lab: source kind must be %q or %q, got %q", SourceKindRecording, SourceKindSimulation, kind)
	}
	label := strings.TrimSpace(src.Label)
	if label == "" {
		label = "Sentinel recording"
		if kind == SourceKindSimulation {
			label = "Chaos simulation"
		}
	}
	detail := strings.TrimSpace(src.Detail)
	if !strings.Contains(detail, rebuiltNote) {
		detail = strings.TrimSpace(detail + " " + rebuiltNote)
	}
	return ReplaySource{Kind: kind, Label: redact.String(label), Detail: redact.String(detail)}, nil
}

// incidentReplay menampung data mentah satu insiden selama replay disusun.
type incidentReplay struct {
	inc      *incident.Incident
	opened   time.Time
	evidence []incident.EvidenceSnapshot
	reflexes []incident.ReflexAction
	audits   []incident.AuditEntry
	plan     *policy.Plan
	planHash string
	triage   *postmortem.TriageSummary
	series   *ReplaySeries

	events []ReplayEvent
	// metadata hasil pemetaan audit yang dipakai poll, pesan, dan statistik
	latency         map[string]latencyInfo
	firstLatency    *latencyInfo
	pollAt          *time.Time
	approvalID      string
	voteAt          *time.Time
	voteInferred    bool
	firstStepID     string
	approverHash    string
	dismissedAt     *time.Time
	expiredAt       *time.Time
	healthAt        *time.Time
	healthPayload   map[string]any
	failureReasons  []string
	postmortemAbs   string
	postmortemRel   string
	postmortemAt    *time.Time
	verifyWindowS   int
	l2Steps         int
	lastExecutedAt  *time.Time
	pendingReplay   bool
	hasPMGenerated  bool
	usedReflex      map[string]bool
	transitionCount int
}

type latencyInfo struct {
	ms      float64
	trigger string
}

func buildIncident(ctx context.Context, store *incident.Store, id string) (*ReplayIncident, string, error) {
	inc, err := store.GetIncident(ctx, id)
	if err != nil {
		return nil, "", err
	}
	evidence, err := store.GetEvidenceByIncident(ctx, id)
	if err != nil {
		return nil, "", err
	}
	reflexes, err := store.GetReflexActionsByIncident(ctx, id)
	if err != nil {
		return nil, "", err
	}
	audits, err := store.GetAuditTrail(ctx, id)
	if err != nil {
		return nil, "", err
	}

	b := &incidentReplay{
		inc:        inc,
		opened:     inc.OpenedAt.UTC(),
		evidence:   evidence,
		reflexes:   reflexes,
		audits:     audits,
		latency:    make(map[string]latencyInfo),
		usedReflex: make(map[string]bool),
	}
	if strings.TrimSpace(inc.PlanJSON) != "" {
		var plan policy.Plan
		if err := json.Unmarshal([]byte(inc.PlanJSON), &plan); err == nil {
			if h, hErr := policy.ComputePlanHash(&plan); hErr == nil {
				b.plan, b.planHash = &plan, h
			}
		}
	}
	if strings.TrimSpace(inc.TriageJSON) != "" {
		var tri postmortem.TriageSummary
		if err := json.Unmarshal([]byte(inc.TriageJSON), &tri); err == nil {
			b.triage = &tri
		}
	}
	b.series = decodeSeries(evidence)

	b.scanAudit()
	b.buildEvents()
	ri := b.assemble()

	md, err := b.renderPostmortem(ctx, store)
	if err != nil {
		return nil, "", err
	}
	ri.Postmortem = md
	return ri, redact.String(inc.Node), nil
}

// decodeSeries mengubah evidence telemetry_series (integer) menjadi seri replay (detik, byte, persen).
func decodeSeries(evidence []incident.EvidenceSnapshot) *ReplaySeries {
	for i := len(evidence) - 1; i >= 0; i-- {
		if evidence[i].Kind != mcpserver.TelemetrySeriesKind {
			continue
		}
		var ts mcpserver.TelemetrySeries
		if err := json.Unmarshal([]byte(evidence[i].RedactedData), &ts); err != nil {
			// Payload yang rusak (mis. tersentuh redaksi) tidak boleh menggagalkan ekspor seluruh insiden
			return nil
		}
		pts := make([][4]float64, 0, len(ts.Points))
		for _, p := range ts.Points {
			pts = append(pts, [4]float64{float64(p[0]) / 1000, float64(p[1] * 1024), float64(p[2]) / 100, float64(p[3]) / 100})
		}
		sort.SliceStable(pts, func(a, b int) bool { return pts[a][0] < pts[b][0] })
		return &ReplaySeries{LimitBytes: ts.LimitBytes, Points: pts}
	}
	return nil
}

// scanAudit mengumpulkan metadata lintas-baris (latensi refleks, poll, vote, verifikasi, postmortem) sebelum event disusun.
func (b *incidentReplay) scanAudit() {
	for _, a := range b.audits {
		p := parsePayload(a.PayloadJSON)
		at := a.CreatedAt.UTC()
		switch a.EventType {
		case "REFLEX_LATENCY":
			if ms, ok := num(p, "latency_ms"); ok {
				li := latencyInfo{ms: ms, trigger: str(p, "trigger")}
				b.latency[str(p, "reflex_id")] = li
				if b.firstLatency == nil {
					cp := li
					b.firstLatency = &cp
				}
			}
		case "ACTION_TOKEN_VERIFIED":
			if b.firstStepID == "" {
				b.firstStepID = str(p, "step_id")
				b.approverHash = str(p, "approver_hash")
			}
			if iat, ok := num(p, "issued_at"); ok && iat > 0 {
				t := time.Unix(int64(iat), 0).UTC()
				if b.voteAt == nil || t.Before(*b.voteAt) {
					b.voteAt = &t
				}
			}
		case "POSTMORTEM_GENERATED":
			b.hasPMGenerated = true
			if f := str(p, "file"); f != "" && b.postmortemRel == "" {
				b.postmortemRel = f
			}
		case "POSTMORTEM_WRITTEN":
			b.postmortemAbs = str(p, "path")
		case "STATE_TRANSITION":
			to, reason := str(p, "to"), str(p, "reason")
			if to == string(incident.StateEscalated) && strings.HasPrefix(reason, verifyFailedReasonPfx) {
				b.failureReasons = splitReasons(strings.TrimPrefix(reason, verifyFailedReasonPfx))
			}
			if m := forwardWindowPattern.FindStringSubmatch(reason); m != nil && b.verifyWindowS == 0 {
				b.verifyWindowS, _ = strconv.Atoi(m[1])
			}
			if to == string(incident.StateWaitingApproval) && a.Actor == "wa-bridge" && strings.HasPrefix(reason, voteGrantedPrefix) && b.voteAt == nil {
				t := at
				b.voteAt = &t
			}
		}
	}
	if b.postmortemAbs != "" && b.postmortemRel == "" {
		b.postmortemRel = relativePostmortemPath(b.postmortemAbs)
	}
}

// buildEvents memetakan setiap baris audit ke kosakata event replay, lalu menyisipkan event kernel dan crew turunan.
func (b *incidentReplay) buildEvents() {
	evidenceEvents := b.evidenceEvents()
	nextEvidence := 0
	for _, a := range b.audits {
		at := a.CreatedAt.UTC()
		// Sisipkan evidence yang direkam agen sebelum baris audit yang terjadi sesudahnya
		for nextEvidence < len(evidenceEvents) && evidenceEvents[nextEvidence].At.Before(at) {
			b.events = append(b.events, evidenceEvents[nextEvidence])
			nextEvidence++
		}
		b.mapAudit(a)
	}
	b.events = append(b.events, evidenceEvents[nextEvidence:]...)

	// Refleks yang tidak memiliki baris audit REFLEX_APPLIED tetap ditampilkan dari baris refleksnya
	for _, r := range b.reflexes {
		if !b.usedReflex[r.ID] {
			b.events = append(b.events, b.reflexAppliedEvent(r))
			b.usedReflex[r.ID] = true
		}
	}

	b.verdictBeforeOutcome()
	b.insertVote()
	b.insertKernelEvents()
	b.insertCrewEvents()
	sort.SliceStable(b.events, func(i, j int) bool { return b.events[i].T < b.events[j].T })
}

// verdictBeforeOutcome menampilkan vonis verifikasi sebelum transisi terminal yang dipicunya bila keduanya terjadi
// pada instan yang sama (worker verifikasi menulis transisi lebih dulu, lalu audit HEALTH_VERIFIED).
func (b *incidentReplay) verdictBeforeOutcome() {
	for i := 0; i+1 < len(b.events); i++ {
		cur, next := b.events[i], b.events[i+1]
		outcome := cur.Kind == "incident.resolved" || cur.Kind == "incident.escalated"
		verdict := next.Kind == "verify.passed" || next.Kind == "verify.failed"
		if outcome && verdict && cur.T == next.T {
			b.events[i], b.events[i+1] = next, cur
		}
	}
}

func (b *incidentReplay) mapAudit(a incident.AuditEntry) {
	p := parsePayload(a.PayloadJSON)
	at := a.CreatedAt.UTC()
	actor := mapActor(a.Actor)
	switch a.EventType {
	case "INCIDENT_CREATED":
		sev := strings.ToUpper(firstNonEmpty(str(p, "severity"), b.inc.Severity))
		detail := fmt.Sprintf("Detector opened %s on %s", b.inc.ID, b.inc.Cgroup)
		if b.inc.TTOSeconds != nil {
			detail += fmt.Sprintf("; projected time to OOM %.0f s", *b.inc.TTOSeconds)
		}
		b.add(at, LaneSentinel, "franken-sentinel", "incident.opened", sev+" incident opened", detail, severityLevel(sev), false)

	case "INCIDENT_CLAIMED":
		claimer := mapActor(firstNonEmpty(str(p, "claimer"), a.Actor))
		b.add(at, LaneCrew, claimer, "incident.claimed", "Claimed by "+claimer, str(p, "from")+" → "+str(p, "to"), LevelInfo, false)

	case "STATE_TRANSITION":
		b.mapTransition(at, actor, a.Actor, p)

	case "REFLEX_APPLIED":
		if r := b.matchReflex(str(p, "action"), str(p, "target")); r != nil {
			b.events = append(b.events, b.reflexAppliedEvent(*r))
		} else {
			b.add(at, LaneSentinel, "franken-sentinel", "reflex.applied", "L1 "+str(p, "action")+" applied", shortTarget(str(p, "target")), LevelOK, false)
		}

	case "REFLEX_LATENCY", "NONCE_CONSUMED":
		// Digabung ke reflex.applied dan token.verified agar satu kejadian tidak terhitung dua kali

	case "REFLEX_ROLLED_BACK":
		action, status := str(p, "action"), str(p, "status")
		detail := "Sentinel restored the previous setting (" + status + ")"
		if status == "EXPIRED_ROLLED_BACK" {
			detail = "TTL expired; Sentinel restored the previous setting"
			if action == "cgroup_reclaim" {
				detail = "TTL expired; reclaim is one-shot, so nothing needed restoring"
			}
		}
		if r := b.reflexByID(str(p, "reflex_id")); r != nil {
			detail = r.ID + ": " + detail
		}
		b.add(at, LaneSentinel, "franken-sentinel", "reflex.rolled_back", "L1 "+action+" rolled back", detail, LevelInfo, false)

	case "REFLEX_ROLLBACK_RETRY":
		b.add(at, LaneSentinel, "franken-sentinel", "state", "Reflex rollback retry scheduled", str(p, "action")+": "+str(p, "error"), LevelWarn, false)

	case "REFLEX_ROLLBACK_ESCALATED":
		b.add(at, LaneSentinel, "franken-sentinel", "state", "Reflex rollback failed", str(p, "action")+" on "+shortTarget(str(p, "target"))+": "+str(p, "error"), LevelError, false)

	case "PLAN_REJECTED":
		attempt, _ := num(p, "attempt")
		b.add(at, LaneSentinel, "franken-sentinel", "plan.rejected", fmt.Sprintf("Plan rejected by policy (attempt %d)", int(attempt)), strings.Join(strSlice(p, "violations"), "; "), LevelWarn, false)

	case "PLAN_ACCEPTED":
		hash := str(p, "plan_hash")
		detail := "plan " + policy.ShortPlanHash(hash)
		if b.plan != nil && hash == b.planHash {
			labels := make([]string, 0, len(b.plan.Options))
			for _, opt := range b.plan.Options {
				labels = append(labels, opt.ID+": "+policy.FormatStepsSummary(opt.Steps))
			}
			detail += "; options " + strings.Join(labels, " / ")
		}
		b.add(at, LaneCrew, "franken-architect", "plan.accepted", "Plan accepted by Sentinel", detail, LevelOK, false)

	case "ACTION_BLOCKED_L3", "ACTION_BLOCKED_PROTECTED", "ACTION_BLOCKED_SCOPE", "ACTION_REJECTED_UNKNOWN", "ACTION_PLAN_MISMATCH":
		reason := map[string]string{
			"ACTION_BLOCKED_L3":        "forbidden L3 action",
			"ACTION_BLOCKED_PROTECTED": "protected target",
			"ACTION_BLOCKED_SCOPE":     "outside incident scope",
			"ACTION_REJECTED_UNKNOWN":  "unknown action",
			"ACTION_PLAN_MISMATCH":     "not in the approved plan",
		}[a.EventType]
		b.add(at, LaneSentinel, "franken-sentinel", "action.blocked", "Blocked "+str(p, "action")+": "+reason, firstNonEmpty(str(p, "error"), "step "+str(p, "step_id")), LevelWarn, false)

	case "ACTION_REJECTED_NO_TOKEN":
		b.add(at, LaneSentinel, "franken-sentinel", "token.rejected", "Rejected "+str(p, "action")+": no approval token", "step "+str(p, "step_id"), LevelWarn, false)

	case "APPROVAL_REPLAY_REJECTED":
		b.pendingReplay = true
		b.add(at, LaneSentinel, "franken-sentinel", "token.replay_rejected", "Replayed step token rejected",
			fmt.Sprintf("Single-use nonce for %s was already consumed (plan %s)", str(p, "action"), policy.ShortPlanHash(str(p, "plan_hash"))), LevelWarn, false)

	case "ACTION_TOKEN_REJECTED":
		errText := str(p, "error")
		if isReplayError(errText) {
			if b.pendingReplay {
				b.pendingReplay = false
				return
			}
			b.add(at, LaneSentinel, "franken-sentinel", "token.replay_rejected", "Replayed step token rejected", errText, LevelWarn, false)
			return
		}
		b.add(at, LaneSentinel, "franken-sentinel", "token.rejected", "Approval token rejected ("+str(p, "step_id")+")", errText, LevelWarn, false)

	case "ACTION_TOKEN_VERIFIED":
		detail := "Ed25519 token for " + str(p, "action") + " verified and its nonce consumed"
		if h := str(p, "approver_hash"); h != "" {
			detail += "; approved by allowlisted admin " + policy.ShortPlanHash(h)
		}
		b.add(at, LaneCrew, "franken-remediator", "token.verified", "Step token verified ("+str(p, "step_id")+")", detail, LevelOK, false)

	case "ACTION_EXECUTED":
		b.l2Steps++
		t := at
		b.lastExecutedAt = &t
		exit, _ := num(p, "exit_code")
		detail := fmt.Sprintf("%s exited %d", str(p, "binary"), int(exit))
		if ms, ok := num(p, "duration_ms"); ok && ms > 0 {
			detail += fmt.Sprintf(" in %d ms", int(ms))
		}
		if v, ok := p["escalated_sigkill"].(bool); ok && v {
			detail += "; escalated to SIGKILL"
		}
		b.add(at, LaneCrew, "franken-remediator", "action.executed", "Executed "+str(p, "action")+" ("+str(p, "step_id")+")", detail, LevelOK, false)

	case "PROCESS_SIGKILL_ESCALATION":
		pid, _ := num(p, "pid")
		b.add(at, LaneCrew, "franken-remediator", "action.executed", fmt.Sprintf("SIGKILL after grace period (pid %d)", int(pid)), "step "+str(p, "step_id"), LevelWarn, false)

	case "ACTION_FAILED":
		exit, _ := num(p, "exit_code")
		b.add(at, LaneCrew, "franken-remediator", "action.failed", fmt.Sprintf("%s failed (exit %d)", str(p, "action"), int(exit)), str(p, "stderr"), LevelError, false)

	case "ACTION_TIMEOUT":
		b.add(at, LaneCrew, "franken-remediator", "action.failed", str(p, "action")+" timed out", str(p, "stderr"), LevelError, false)

	case "HEALTH_VERIFIED":
		t := at
		b.healthAt = &t
		b.healthPayload = p
		some, _ := num(p, "psi_some_avg10")
		full, _ := num(p, "psi_full_avg10")
		rolled, _ := num(p, "rolled_back")
		if healthy, _ := p["healthy"].(bool); healthy {
			b.add(at, LaneVerify, "franken-sentinel", "verify.passed", "Verification passed",
				fmt.Sprintf("PSI some %.2f / full %.2f at the end of the window; L1 reflexes rolled back: %d", some, full, int(rolled)), LevelOK, false)
		} else {
			detail := strings.Join(b.failureReasons, "; ")
			if detail == "" {
				detail = fmt.Sprintf("PSI some %.2f / full %.2f; L1 reflexes rolled back: %d", some, full, int(rolled))
			}
			b.add(at, LaneVerify, "franken-sentinel", "verify.failed", "Verification failed", detail, LevelError, false)
		}

	case "POSTMORTEM_GENERATED":
		t := at
		b.postmortemAt = &t
		ev, _ := num(p, "evidence_used")
		au, _ := num(p, "audit_entries")
		b.add(at, LaneVerify, actor, "postmortem.written", "Postmortem written",
			fmt.Sprintf("%s (%d evidence snapshots, %d audit rows)", b.postmortemPath(), int(ev), int(au)), LevelInfo, false)

	case "POSTMORTEM_WRITTEN":
		if !b.hasPMGenerated {
			t := at
			b.postmortemAt = &t
			b.add(at, LaneVerify, "franken-sentinel", "postmortem.written", "Postmortem written", b.postmortemPath(), LevelInfo, false)
		}

	case "POSTMORTEM_FAILED":
		b.add(at, LaneSentinel, "franken-sentinel", "state", "Postmortem generation failed", str(p, "error"), LevelError, false)

	case "PRE_TOOL_GUARD_ALLOW":
		b.add(at, LaneCrew, "kiro-guard", "guard.allow", "Guard allowed "+str(p, "tool"), str(p, "reason"), LevelInfo, false)

	case "PRE_TOOL_GUARD_BLOCK":
		b.add(at, LaneCrew, "kiro-guard", "guard.block", "Guard blocked "+str(p, "tool"), str(p, "reason"), LevelWarn, false)

	default:
		// Tipe audit lain (peringatan daemon dan sejenisnya) tetap tampil sebagai event state netral
		b.add(at, LaneSentinel, "franken-sentinel", "state", "Audit "+a.EventType, a.PayloadJSON, LevelInfo, false)
	}
}

func (b *incidentReplay) mapTransition(at time.Time, actor, rawActor string, p map[string]any) {
	from, to, reason := str(p, "from"), str(p, "to"), str(p, "reason")
	b.transitionCount++
	switch {
	case to == string(incident.StateWaitingApproval) && rawActor == "wa-bridge" && strings.HasPrefix(reason, pollSentReasonPrefix):
		if b.pollAt == nil {
			t := at
			b.pollAt = &t
			b.approvalID = approvalIDPattern.FindString(reason)
		}
		b.add(at, LaneHuman, "wa-bridge", "poll.sent", "Approval poll sent ("+firstNonEmpty(b.approvalID, "WhatsApp")+")", reason, LevelInfo, false)
	case to == string(incident.StateWaitingApproval) && rawActor == "wa-bridge" && strings.HasPrefix(reason, voteGrantedPrefix):
		opt := strings.TrimSpace(strings.TrimPrefix(reason, voteGrantedPrefix))
		b.add(at, LaneHuman, "operator", "vote.granted", "Operator approved option "+opt, b.voteDetail(), LevelOK, false)
	case to == string(incident.StateVerifying):
		title := "Verification window started"
		if !strings.Contains(reason, verifyWindowReason) {
			title = "Verification started"
			if strings.Contains(reason, "hysteresis") {
				title = "Recovery hysteresis satisfied"
			}
		}
		b.add(at, LaneVerify, "franken-sentinel", "verify.started", title, reason, LevelInfo, false)
	case to == string(incident.StateResolved):
		b.add(at, LaneVerify, "franken-sentinel", "incident.resolved", "Incident resolved", reason, LevelOK, false)
	case to == string(incident.StateEscalated):
		b.add(at, LaneVerify, "franken-sentinel", "incident.escalated", "Incident escalated to a human", reason, LevelError, false)
	case to == string(incident.StateDismissed) && rawActor == "wa-bridge":
		t := at
		b.dismissedAt = &t
		b.add(at, LaneHuman, "operator", "vote.dismissed", "Operator dismissed the incident", "", LevelInfo, false)
	case to == string(incident.StateExpired):
		t := at
		b.expiredAt = &t
		b.add(at, LaneHuman, "wa-bridge", "poll.expired", "Approval poll expired", reason, LevelWarn, false)
	default:
		b.add(at, LaneSentinel, actor, "state", "State "+from+" → "+to, reason, LevelInfo, false)
	}
}

// evidenceEvents menampilkan evidence yang direkam lewat tool agen (journal_tail) sebagai evidence.recorded.
func (b *incidentReplay) evidenceEvents() []ReplayEvent {
	firstPlan := time.Time{}
	for _, a := range b.audits {
		if a.EventType == "PLAN_ACCEPTED" || a.EventType == "PLAN_REJECTED" {
			firstPlan = a.CreatedAt.UTC()
			break
		}
	}
	var out []ReplayEvent
	for _, ev := range b.evidence {
		unit, ok := strings.CutPrefix(ev.Kind, "journal_tail:")
		if !ok {
			continue
		}
		// Evidence sebelum pengajuan plan pertama berasal dari triage Sentry; setelahnya dari Architect
		actor := "franken-sentry"
		if !firstPlan.IsZero() && ev.CapturedAt.After(firstPlan) {
			actor = "franken-architect"
		}
		lines := 0
		if body := strings.TrimSpace(ev.RedactedData); body != "" {
			lines = strings.Count(body, "\n") + 1
		}
		out = append(out, b.newEvent(ev.CapturedAt.UTC(), LaneCrew, actor, "evidence.recorded", "Journal evidence recorded",
			fmt.Sprintf("%s: %d redacted journal lines from %s", ev.ID, lines, unit), LevelInfo, false))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func (b *incidentReplay) matchReflex(action, target string) *incident.ReflexAction {
	for i := range b.reflexes {
		r := &b.reflexes[i]
		if !b.usedReflex[r.ID] && r.Action == action && r.Target == target {
			b.usedReflex[r.ID] = true
			return r
		}
	}
	return nil
}

func (b *incidentReplay) reflexByID(id string) *incident.ReflexAction {
	for i := range b.reflexes {
		if b.reflexes[i].ID == id {
			return &b.reflexes[i]
		}
	}
	return nil
}

func (b *incidentReplay) reflexAppliedEvent(r incident.ReflexAction) ReplayEvent {
	params := parsePayload(r.ParamsJSON)
	target := shortTarget(r.Target)
	var detail string
	switch r.Action {
	case "cgroup_reclaim":
		reclaim, _ := num(params, "reclaim_bytes")
		current, _ := num(params, "memory_current")
		detail = fmt.Sprintf("%s: reclaimed %s of %s via memory.reclaim; TTL %d s", r.ID, mib(reclaim), mib(current), r.TTLSeconds)
	case "cgroup_throttle":
		high, _ := num(params, "applied_memory_high")
		detail = fmt.Sprintf("%s: runtime MemoryHigh=%s on %s; TTL %d s", r.ID, mib(high), target, r.TTLSeconds)
	default:
		detail = fmt.Sprintf("%s: %s on %s; TTL %d s", r.ID, r.Action, target, r.TTLSeconds)
	}
	if li, ok := b.latency[r.ID]; ok {
		detail += fmt.Sprintf("; applied %.3f ms after the %s trigger", li.ms, triggerLabel(li.trigger))
	}
	return b.newEvent(r.AppliedAt.UTC(), LaneSentinel, "franken-sentinel", "reflex.applied", "L1 "+r.Action+" on "+target, detail, LevelOK, false)
}

// insertVote menambahkan vote.granted yang direkonstruksi dari iat token bila bridge tidak mencatat transisi vote.
func (b *incidentReplay) insertVote() {
	for _, ev := range b.events {
		if ev.Kind == "vote.granted" {
			return
		}
	}
	firstToken := -1
	for i, ev := range b.events {
		if ev.Kind == "token.verified" {
			firstToken = i
			break
		}
	}
	if firstToken < 0 {
		return
	}
	at := b.events[firstToken].At
	inferred := true
	if b.voteAt != nil {
		at, inferred = *b.voteAt, false
	}
	b.voteInferred = inferred
	if b.voteAt == nil {
		b.voteAt = &at
	}
	optID := b.chosenOptionID()
	title := "Operator approved the plan"
	if optID != "" {
		title = "Operator approved option " + optID
	}
	vote := b.newEvent(at, LaneHuman, "operator", "vote.granted", title, b.voteDetail(), LevelOK, inferred)
	b.events = slicesInsert(b.events, firstToken, vote)
}

func (b *incidentReplay) voteDetail() string {
	who := "allowlisted admin"
	if b.approverHash != "" {
		who += " " + policy.ShortPlanHash(b.approverHash)
	}
	if idx := b.chosenIndex(); idx >= 0 && b.plan != nil && idx < len(b.plan.Options) {
		return who + " chose " + policy.FormatOptionLabel(b.plan.Options[idx], b.planHash) + "; wa-bridge minted one Ed25519 token per step"
	}
	return who
}

// insertKernelEvents menurunkan psi.rising dari seri dan oom.kill dari severity POST_OOM.
func (b *incidentReplay) insertKernelEvents() {
	var front []ReplayEvent
	if b.series != nil {
		for _, pt := range b.series.Points {
			if pt[0] < 0 && pt[2] >= psiRisingThreshold {
				at := b.opened.Add(time.Duration(math.Round(pt[0]*1000)) * time.Millisecond)
				front = append(front, b.newEvent(at, LaneKernel, "kernel", "psi.rising", "PSI some avg10 crossed 10%",
					fmt.Sprintf("memory.pressure some avg10 %.2f%% / full avg10 %.2f%% with %s in use, %.0f s before the incident opened", pt[2], pt[3], mib(pt[1]), -pt[0]), LevelWarn, false))
				break
			}
		}
	}
	if strings.EqualFold(b.inc.Severity, "POST_OOM") {
		front = append(front, b.newEvent(b.opened, LaneKernel, "kernel", "oom.kill", "Kernel OOM kill in "+shortTarget(b.inc.Cgroup),
			"memory.events oom_kill increased; the detector classified the incident as POST_OOM", LevelError, false))
	}
	if len(front) > 0 {
		b.events = append(front, b.events...)
	}
}

// insertCrewEvents merekonstruksi fase dan spawn franken-conductor dari protokol TRIAGE/EXECUTE (selalu inferred).
func (b *incidentReplay) insertCrewEvents() {
	idx := func(kind string) int {
		for i, ev := range b.events {
			if ev.Kind == kind {
				return i
			}
		}
		return -1
	}
	conductor := func(at time.Time, kind, title, detail string) ReplayEvent {
		return b.newEvent(at, LaneCrew, "franken-conductor", kind, title, detail, LevelInfo, true)
	}
	inferredCrew := func(at time.Time, actor, kind, title, detail string) ReplayEvent {
		return b.newEvent(at, LaneCrew, actor, kind, title, detail, LevelInfo, true)
	}

	// EXECUTE: wa-bridge memicu fase EXECUTE setelah token dicetak
	if v := idx("vote.granted"); v >= 0 {
		at := b.events[v].At
		b.events = slicesInsert(b.events, v+1,
			conductor(at, "phase", "Crew phase EXECUTE", "wa-bridge webhook after the vote; reconstructed from the conductor protocol"),
			conductor(at, "spawn", "Spawned franken-remediator (EXECUTE)", "MODE=EXECUTE with the approval id; reconstructed from the conductor protocol"))
	}
	// verify_health yang dipanggil Remediator membuka jendela verifikasi forward
	for i, ev := range b.events {
		if ev.Kind == "verify.started" && strings.Contains(ev.Detail, verifyWindowReason) {
			b.events = slicesInsert(b.events, i, inferredCrew(ev.At, "franken-remediator", "verify.requested", "verify_health requested",
				"window_seconds=120, auto_transition=true; reconstructed from the remediator protocol"))
			break
		}
	}
	// REQUEST_APPROVAL: Remediator diminta mengirim poll setelah plan diterima
	if p := idx("poll.sent"); p >= 0 {
		at := b.events[p].At
		b.events = slicesInsert(b.events, p, inferredCrew(at, "franken-remediator", "approval.requested", "Approval requested via wa-bridge",
			"wa_request_approval with the stored plan_hash; reconstructed from the remediator protocol"))
		accepted := -1
		for i := p; i >= 0; i-- {
			if b.events[i].Kind == "plan.accepted" {
				accepted = i
				break
			}
		}
		if accepted >= 0 {
			b.events = slicesInsert(b.events, accepted+1, conductor(b.events[accepted].At, "spawn", "Spawned franken-remediator (REQUEST_APPROVAL)",
				"MODE=REQUEST_APPROVAL with the accepted plan_hash; reconstructed from the conductor protocol"))
		}
	}
	// TRIAGE: Architect di-spawn setelah aktivitas terakhir Sentry sebelum pengajuan plan pertama
	firstPlan := -1
	for i, ev := range b.events {
		if ev.Kind == "plan.accepted" || ev.Kind == "plan.rejected" {
			firstPlan = i
			break
		}
	}
	if firstPlan >= 0 {
		anchor := -1
		for i := firstPlan - 1; i >= 0; i-- {
			if b.events[i].Actor == "franken-sentry" {
				anchor = i
				break
			}
		}
		if anchor >= 0 {
			b.events = slicesInsert(b.events, anchor+1, conductor(b.events[anchor].At, "spawn", "Spawned franken-architect",
				"handed the Sentry triage JSON to the Architect; reconstructed from the conductor protocol"))
		} else {
			b.events = slicesInsert(b.events, firstPlan, conductor(b.events[firstPlan].At, "spawn", "Spawned franken-architect",
				"reconstructed from the conductor protocol"))
		}
	}
	// TRIAGE dipicu wa-bridge tepat setelah alert pertama untuk severity P1/P2/POST_OOM
	if o := idx("incident.opened"); o >= 0 && isAlertableSeverity(b.inc.Severity) {
		at := b.events[o].At
		add := []ReplayEvent{conductor(at, "phase", "Crew phase TRIAGE", "wa-bridge webhook after the first alert; reconstructed from the conductor protocol")}
		if idx("incident.claimed") >= 0 {
			add = append(add, conductor(at, "spawn", "Spawned franken-sentry", "claim and triage; reconstructed from the conductor protocol"))
		}
		b.events = slicesInsert(b.events, o+1, add...)
	}
}

// assemble menyusun ReplayIncident lengkap kecuali postmortem.
func (b *incidentReplay) assemble() *ReplayIncident {
	inc := b.inc
	ri := &ReplayIncident{
		ID:       inc.ID,
		Severity: inc.Severity,
		Cgroup:   inc.Cgroup,
		Unit:     unitOf(inc.Cgroup),
		State:    string(inc.State),
		OpenedAt: b.opened,
		Series:   b.series,
		Events:   b.events,
		Messages: []ReplayMessage{},
	}
	if ri.Events == nil {
		ri.Events = []ReplayEvent{}
	}
	end := b.endTime()
	if inc.ClosedAt != nil && !inc.ClosedAt.IsZero() {
		closed := inc.ClosedAt.UTC()
		ri.ClosedAt = &closed
	}
	ri.DurationS = msRound(end.Sub(b.opened).Seconds())
	if inc.TTOSeconds != nil {
		tto := math.Round(*inc.TTOSeconds*10) / 10
		ri.TTOSeconds = &tto
	}
	if b.firstLatency != nil {
		ms := b.firstLatency.ms
		ri.ReflexLatencyMS = &ms
		ri.ReflexTrigger = b.firstLatency.trigger
	}
	if b.triage != nil {
		ri.Class = redact.String(b.triage.Class)
		conf := b.triage.Confidence
		ri.Confidence = &conf
		ri.TriageSummary = clipRunes(oneLine(redact.String(b.triage.Summary)), 500)
	}
	if b.plan != nil {
		ri.PlanHash = b.planHash
		ri.RootCause = clipRunes(oneLine(redact.String(b.plan.SuspectedRootCause)), 500)
		for _, f := range b.plan.HumanFollowUp {
			if clean := clipRunes(oneLine(redact.String(f)), maxEventDetailRunes); clean != "" {
				ri.FollowUps = append(ri.FollowUps, clean)
			}
		}
	}
	ri.Title = b.title()

	ri.Stats = ReplayStats{Reflexes: len(b.reflexes), L2Steps: b.l2Steps, VerifyWindowS: b.verifyWindowS}
	for _, ev := range b.events {
		switch ev.Kind {
		case "plan.rejected", "action.blocked", "token.rejected", "token.replay_rejected", "guard.block":
			ri.Stats.Blocked++
		}
	}
	if ri.Stats.VerifyWindowS == 0 && b.healthAt != nil && b.lastExecutedAt != nil {
		ri.Stats.VerifyWindowS = int(math.Round(b.healthAt.Sub(*b.lastExecutedAt).Seconds()))
	}

	ri.Poll = b.buildPoll()
	ri.Messages = b.buildMessages(ri.Poll)
	return ri
}

func (b *incidentReplay) title() string {
	label := map[string]string{
		"heap_leak":           "Heap leak",
		"traffic_spike":       "Traffic spike",
		"fork_storm":          "Fork storm",
		"zombie_accumulation": "Zombie accumulation",
		"log_flood":           "Log flood",
		"swap_thrash":         "Swap thrash",
		"external":            "External memory pressure",
		"unknown":             "Memory pressure",
	}
	where := firstNonEmpty(unitOf(b.inc.Cgroup), b.inc.Cgroup)
	if b.triage != nil {
		if l, ok := label[b.triage.Class]; ok {
			return clipRunes(l+" on "+where, maxEventTitleRunes)
		}
	}
	return clipRunes(strings.ToUpper(b.inc.Severity)+" memory pressure on "+where, maxEventTitleRunes)
}

func (b *incidentReplay) chosenIndex() int {
	if b.plan == nil {
		return -1
	}
	if b.firstStepID != "" {
		for i, opt := range b.plan.Options {
			for _, st := range opt.Steps {
				if st.ID == b.firstStepID {
					return i
				}
			}
		}
	}
	if b.dismissedAt != nil {
		return len(b.plan.Options) + 1
	}
	return -1
}

func (b *incidentReplay) chosenOptionID() string {
	if idx := b.chosenIndex(); idx >= 0 && b.plan != nil && idx < len(b.plan.Options) {
		return b.plan.Options[idx].ID
	}
	return ""
}

// buildPoll merekonstruksi poll dengan label policy.PollOptionLabels dan format judul wa-bridge.
func (b *incidentReplay) buildPoll() *ReplayPoll {
	if b.pollAt == nil || b.plan == nil {
		return nil
	}
	shortCode := strings.TrimPrefix(b.approvalID, "APR-")
	poll := &ReplayPoll{
		T:       b.relT(*b.pollAt),
		Title:   redact.String(wabridge.FormatPollTitle(shortCode, b.inc.ID, b.planHash)),
		Options: policy.PollOptionLabels(b.plan, b.planHash),
		Chosen:  b.chosenIndex(),
	}
	if poll.Chosen >= len(poll.Options) {
		poll.Chosen = -1
	}
	switch {
	case b.voteAt != nil && poll.Chosen >= 0:
		vt := b.relT(*b.voteAt)
		poll.VotedT = &vt
	case b.dismissedAt != nil:
		vt := b.relT(*b.dismissedAt)
		poll.VotedT = &vt
	}
	if poll.VotedT != nil {
		poll.Approver = "allowlisted admin"
		if b.approverHash != "" {
			poll.Approver += " " + policy.ShortPlanHash(b.approverHash)
		}
	}
	return poll
}

// buildMessages menyusun ulang pesan WhatsApp dengan format persis milik wa-bridge.
func (b *incidentReplay) buildMessages(poll *ReplayPoll) []ReplayMessage {
	msgs := []ReplayMessage{}
	inc := b.inc
	if isAlertableSeverity(inc.Severity) {
		ev := mcpserver.StreamEvent{
			IncidentID: inc.ID,
			Severity:   inc.Severity,
			State:      string(incident.StateDetected),
			Summary:    fmt.Sprintf("%s pressure/leak detected on %s", inc.Severity, inc.Cgroup),
			Data:       map[string]any{"cgroup": inc.Cgroup},
		}
		if strings.Contains(inc.ID, "-R") && reopenSuffix.MatchString(inc.ID) {
			ev.Summary, ev.Data = fmt.Sprintf("%s reopened pressure on %s", inc.Severity, inc.Cgroup), nil
		}
		msgs = append(msgs, ReplayMessage{T: 0, From: "bot", Kind: "alert", Text: wabridge.OutgoingText(wabridge.FormatCriticalAlertMessage(inc.Node, ev))})
	}
	if poll != nil {
		msgs = append(msgs, ReplayMessage{T: poll.T, From: "bot", Kind: "poll", Text: poll.Title})
		if poll.VotedT != nil && poll.Chosen >= 0 && poll.Chosen < len(poll.Options) {
			msgs = append(msgs, ReplayMessage{T: *poll.VotedT, From: "operator", Kind: "vote", Text: poll.Options[poll.Chosen]})
			if idx := b.chosenIndex(); idx >= 0 && idx < len(b.plan.Options) {
				opt := b.plan.Options[idx]
				msgs = append(msgs, ReplayMessage{T: *poll.VotedT, From: "bot", Kind: "text",
					Text: wabridge.OutgoingText(wabridge.FormatApprovalSummary(opt.ID, opt.Steps, inc.ID, b.planHash, len(opt.Steps)))})
			}
		}
	}
	if b.dismissedAt != nil {
		if poll == nil || poll.Chosen < 0 {
			msgs = append(msgs, ReplayMessage{T: b.relT(*b.dismissedAt), From: "operator", Kind: "vote", Text: policy.PollOptionDismiss})
		}
		msgs = append(msgs, ReplayMessage{T: b.relT(*b.dismissedAt), From: "bot", Kind: "text",
			Text: wabridge.OutgoingText(fmt.Sprintf("Incident %s dismissed by operator.", inc.ID))})
	}
	if b.healthAt != nil {
		at := *b.healthAt
		if b.postmortemAt != nil && b.postmortemAt.After(at) {
			at = *b.postmortemAt
		}
		data := map[string]any{"status": str(b.healthPayload, "status")}
		if rolled, ok := num(b.healthPayload, "rolled_back"); ok {
			data["rolled_back"] = int(rolled)
		}
		if len(b.failureReasons) > 0 {
			data["failure_reasons"] = truncateReasonList(b.failureReasons, 3, 300)
		}
		if b.postmortemAbs != "" || b.postmortemRel != "" {
			data["postmortem_path"] = b.postmortemPath()
		}
		state := firstNonEmpty(str(b.healthPayload, "state"), string(inc.State))
		msgs = append(msgs, ReplayMessage{T: b.relT(at), From: "bot", Kind: "report",
			Text: wabridge.OutgoingText(wabridge.FormatFinalReport(mcpserver.StreamEvent{IncidentID: inc.ID, State: state, Data: data}))})
	}
	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].T < msgs[j].T })
	return msgs
}

// renderPostmortem merender ulang postmortem dengan jam = closed_at lalu menyamarkan path absolut berkas.
func (b *incidentReplay) renderPostmortem(ctx context.Context, store *incident.Store) (string, error) {
	end := b.endTime()
	notes := ""
	if b.healthPayload != nil {
		if healthy, _ := b.healthPayload["healthy"].(bool); healthy {
			if b.verifyWindowS > 0 {
				notes = fmt.Sprintf("forward health verification stabilized over %ds window", b.verifyWindowS)
			}
		} else if len(b.failureReasons) > 0 {
			notes = "forward health verification failed: " + strings.Join(b.failureReasons, "; ")
		}
	}
	doc, err := postmortem.Generate(ctx, store, postmortem.Options{
		IncidentID: b.inc.ID,
		Author:     "franken-sentinel",
		Notes:      notes,
		Clock:      func() time.Time { return end },
	})
	if err != nil {
		return "", fmt.Errorf("render postmortem: %w", err)
	}
	return b.relativizePaths(doc.Markdown), nil
}

// endTime adalah closed_at, atau waktu kejadian terakhir untuk insiden yang belum ditutup.
func (b *incidentReplay) endTime() time.Time {
	if b.inc.ClosedAt != nil && !b.inc.ClosedAt.IsZero() {
		return b.inc.ClosedAt.UTC()
	}
	end := b.inc.UpdatedAt.UTC()
	for _, a := range b.audits {
		if a.CreatedAt.After(end) {
			end = a.CreatedAt.UTC()
		}
	}
	return end
}

func (b *incidentReplay) postmortemPath() string {
	if b.postmortemRel != "" {
		return b.postmortemRel
	}
	return relativePostmortemPath(b.postmortemAbs)
}

func (b *incidentReplay) relativizePaths(s string) string {
	if b.postmortemAbs != "" {
		s = strings.ReplaceAll(s, b.postmortemAbs, b.postmortemPath())
	}
	return absPostmortemPattern.ReplaceAllString(s, "$1")
}

func (b *incidentReplay) relT(at time.Time) float64 {
	return msRound(at.UTC().Sub(b.opened).Seconds())
}

func (b *incidentReplay) newEvent(at time.Time, lane, actor, kind, title, detail, level string, inferred bool) ReplayEvent {
	at = at.UTC().Round(time.Millisecond)
	return ReplayEvent{
		T:        b.relT(at),
		At:       at,
		Lane:     lane,
		Actor:    actor,
		Kind:     kind,
		Title:    clipRunes(oneLine(redact.String(title)), maxEventTitleRunes),
		Detail:   b.relativizePaths(clipRunes(oneLine(redact.String(detail)), maxEventDetailRunes)),
		Level:    level,
		Inferred: inferred,
	}
}

func (b *incidentReplay) add(at time.Time, lane, actor, kind, title, detail, level string, inferred bool) {
	b.events = append(b.events, b.newEvent(at, lane, actor, kind, title, detail, level, inferred))
}

var reopenSuffix = regexp.MustCompile(`-R\d+$`)

// mapActor menerjemahkan aktor audit Sentinel ke daftar aktor replay yang tetap.
func mapActor(raw string) string {
	switch strings.TrimSpace(raw) {
	case "franken-sentry", "franken-architect", "franken-remediator", "franken-conductor", "wa-bridge", "operator", "kiro-guard", "kernel":
		return strings.TrimSpace(raw)
	case "architect":
		return "franken-architect"
	case "remediator":
		return "franken-remediator"
	default:
		// sentinel, policy-engine, approval-engine, mcp-client, dan aktor lain dicatat oleh Sentinel
		return "franken-sentinel"
	}
}

func severityLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "P1", "POST_OOM":
		return LevelError
	case "P2":
		return LevelWarn
	default:
		return LevelInfo
	}
}

func isAlertableSeverity(sev string) bool {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "P1", "P2", "POST_OOM", "CRITICAL", "EMERGENCY":
		return true
	default:
		return false
	}
}

func triggerLabel(trigger string) string {
	switch trigger {
	case "psi":
		return "PSI"
	case "memory_events":
		return "memory.events"
	case "sample":
		return "sample"
	default:
		return firstNonEmpty(trigger, "unknown")
	}
}

func isReplayError(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "replay") || strings.Contains(l, "already consumed")
}

// splitReasons memecah alasan gagal verifikasi yang digabung "; " oleh worker verifikasi.
func splitReasons(joined string) []string {
	var out []string
	for _, part := range strings.Split(joined, "; ") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// truncateReasonList meniru truncateReasons milik worker verifikasi untuk data SSE failure_reasons.
func truncateReasonList(reasons []string, maxItems, maxLen int) string {
	if len(reasons) > maxItems {
		reasons = reasons[:maxItems]
	}
	joined := strings.Join(reasons, "; ")
	if len(joined) > maxLen {
		joined = joined[:maxLen-3] + "..."
	}
	return joined
}

// relativePostmortemPath memotong path absolut menjadi "<dir>/<incident>/postmortem.md".
func relativePostmortemPath(abs string) string {
	clean := strings.TrimSpace(strings.ReplaceAll(abs, "\\", "/"))
	if clean == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	if len(parts) > 3 {
		parts = parts[len(parts)-3:]
	}
	return strings.Join(parts, "/")
}

func unitOf(cg string) string {
	base := path.Base(strings.TrimSuffix(strings.TrimSpace(cg), "/"))
	if strings.HasSuffix(base, ".service") {
		return base
	}
	return ""
}

func shortTarget(target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "/") {
		return path.Base(strings.TrimSuffix(t, "/"))
	}
	return t
}

func mib(bytes float64) string {
	return fmt.Sprintf("%.1f MiB", bytes/(1024*1024))
}

func msRound(seconds float64) float64 {
	return math.Round(seconds*1000) / 1000
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n-3])) + "..."
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parsePayload(raw string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		return map[string]any{}
	}
	return m
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func num(m map[string]any, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func strSlice(m map[string]any, key string) []string {
	raw, _ := m[key].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func slicesInsert(evs []ReplayEvent, at int, add ...ReplayEvent) []ReplayEvent {
	if at < 0 {
		at = 0
	}
	if at > len(evs) {
		at = len(evs)
	}
	out := make([]ReplayEvent, 0, len(evs)+len(add))
	out = append(out, evs[:at]...)
	out = append(out, add...)
	return append(out, evs[at:]...)
}
