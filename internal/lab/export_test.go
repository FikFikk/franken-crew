package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
)

// allAuditEventTypes adalah setiap tipe audit yang direkam kode Sentinel, wa-bridge (via MCP), dan franken guard.
var allAuditEventTypes = []string{
	"INCIDENT_CREATED", "INCIDENT_CLAIMED", "STATE_TRANSITION", "REFLEX_APPLIED", "REFLEX_LATENCY",
	"REFLEX_ROLLED_BACK", "REFLEX_ROLLBACK_RETRY", "REFLEX_ROLLBACK_ESCALATED", "REFLEX_SWEEP_ERROR",
	"PLAN_REJECTED", "PLAN_ACCEPTED", "ACTION_REJECTED_UNKNOWN", "ACTION_BLOCKED_L3", "ACTION_BLOCKED_PROTECTED",
	"ACTION_BLOCKED_SCOPE", "ACTION_PLAN_MISMATCH", "ACTION_REJECTED_NO_TOKEN", "ACTION_TOKEN_REJECTED",
	"ACTION_TOKEN_VERIFIED", "APPROVAL_REPLAY_REJECTED", "NONCE_CONSUMED", "ACTION_EXECUTED", "ACTION_TIMEOUT",
	"ACTION_FAILED", "PROCESS_SIGKILL_ESCALATION", "HEALTH_VERIFIED", "POSTMORTEM_FAILED", "POSTMORTEM_WRITTEN",
	"POSTMORTEM_GENERATED", "DAEMON_STARTED", "HOST_PSI_WATCH_WARN", "JOURNAL_STREAM_WARN", "TARGET_ADDED",
	"TARGET_REMOVED", "PSI_WATCH_WARN", "EVENTS_WATCH_WARN", "SAMPLE_ERROR", "PRE_TOOL_GUARD_ALLOW", "PRE_TOOL_GUARD_BLOCK",
}

var replayVocabulary = map[string]string{
	"psi.rising": LaneKernel, "oom.kill": LaneKernel,
	"incident.opened": LaneSentinel, "reflex.applied": LaneSentinel, "reflex.rolled_back": LaneSentinel, "plan.rejected": LaneSentinel,
	"action.blocked": LaneSentinel, "token.rejected": LaneSentinel, "token.replay_rejected": LaneSentinel, "state": LaneSentinel,
	"phase": LaneCrew, "spawn": LaneCrew, "incident.claimed": LaneCrew, "evidence.recorded": LaneCrew, "plan.accepted": LaneCrew,
	"approval.requested": LaneCrew, "token.verified": LaneCrew, "action.executed": LaneCrew, "action.failed": LaneCrew,
	"verify.requested": LaneCrew, "guard.allow": LaneCrew, "guard.block": LaneCrew,
	"poll.sent": LaneHuman, "vote.granted": LaneHuman, "vote.dismissed": LaneHuman, "poll.expired": LaneHuman,
	"verify.started": LaneVerify, "verify.passed": LaneVerify, "verify.failed": LaneVerify, "postmortem.written": LaneVerify,
	"incident.resolved": LaneVerify, "incident.escalated": LaneVerify,
}

type exportFixture struct {
	store *incident.Store
	clock *simClock
}

func newExportFixture(t *testing.T) *exportFixture {
	t.Helper()
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "export.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	clock := &simClock{now: time.Date(2026, 11, 13, 5, 0, 0, 0, time.UTC)}
	store.SetClock(clock.Now)
	return &exportFixture{store: store, clock: clock}
}

func (f *exportFixture) audit(t *testing.T, incID, actor, event string, payload any) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	f.clock.Advance(time.Second)
	if err := f.store.RecordAudit(context.Background(), incID, actor, event, string(raw)); err != nil {
		t.Fatalf("RecordAudit %s: %v", event, err)
	}
}

func (f *exportFixture) incident(t *testing.T, id string, plan *policy.Plan) {
	t.Helper()
	ctx := context.Background()
	if err := f.store.CreateIncident(ctx, &incident.Incident{ID: id, Node: "pi02", Cgroup: "/franken.slice/api.service", Severity: "P1", State: incident.StateDetected, OpenedAt: f.clock.Now()}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	if plan != nil {
		canon, _ := policy.CanonicalJSON(plan)
		if err := f.store.SavePlan(ctx, id, string(canon)); err != nil {
			t.Fatalf("SavePlan: %v", err)
		}
	}
}

func TestBuildReplay_MapsEveryAuditEventTypeToTheVocabulary(t *testing.T) {
	f := newExportFixture(t)
	f.incident(t, "INC-EXPORT-ALL", nil)
	for _, ev := range allAuditEventTypes {
		payload := map[string]any{"step_id": "s1", "action": "unit_restart", "error": "boom", "tool": "@franken-sentinel/action_execute", "reason": "r"}
		if ev == "STATE_TRANSITION" {
			payload = map[string]any{"from": "TRIAGING", "to": "PLANNED", "reason": "plan validated"}
		}
		f.audit(t, "INC-EXPORT-ALL", "sentinel", ev, payload)
	}
	f.audit(t, "INC-EXPORT-ALL", "sentinel", "SOMETHING_NEW", map[string]any{"x": 1})

	rep, err := BuildReplay(context.Background(), f.store, []string{"INC-EXPORT-ALL"}, ReplaySource{}, "")
	if err != nil {
		t.Fatalf("BuildReplay: %v", err)
	}
	inc := rep.Incidents[0]
	for _, ev := range inc.Events {
		if lane, ok := replayVocabulary[ev.Kind]; !ok || lane != ev.Lane {
			t.Errorf("event %q on lane %q is outside the vocabulary: %+v", ev.Kind, ev.Lane, ev)
		}
		if ev.Title == "" {
			t.Errorf("event without title: %+v", ev)
		}
	}
	kinds := kindsOf(inc)
	for kind, min := range map[string]int{"guard.allow": 1, "guard.block": 1, "action.failed": 2, "action.blocked": 5, "token.rejected": 2, "state": 5} {
		if kinds[kind] < min {
			t.Errorf("expected at least %d %q events, got %v", min, kind, kinds)
		}
	}
	if rep.Source.Kind != SourceKindRecording || !strings.Contains(rep.Source.Detail, "rebuilt") || rep.Node != "pi02" {
		t.Errorf("default source/node not applied: %+v node=%q", rep.Source, rep.Node)
	}
}

func TestBuildReplay_CountsEachReflexOnceAndMapsHumanOutcomes(t *testing.T) {
	f := newExportFixture(t)
	ctx := context.Background()
	plan := &policy.Plan{IncidentID: "INC-EXPORT-DISMISS", SuspectedRootCause: "leak in api", Options: []policy.PlanOption{
		{ID: "A", Steps: []policy.PlanStep{{ID: "A1", Action: "unit_restart", Params: map[string]any{"unit": "api.service"}, EvidenceIDs: []string{"ev-1"}, ExpectedEffect: "x"}}},
	}, HumanFollowUp: []string{"fix it"}}
	f.incident(t, "INC-EXPORT-DISMISS", plan)
	planHash, _ := policy.ComputePlanHash(plan)

	for i := 0; i < 2; i++ {
		f.clock.Advance(time.Second)
		if err := f.store.SaveReflexAction(ctx, &incident.ReflexAction{
			ID: "RFX-00000000000" + string(rune('1'+i)), IncidentID: "INC-EXPORT-DISMISS", Action: "cgroup_reclaim",
			Target: "/sys/fs/cgroup/franken.slice/api.service", ParamsJSON: `{"reclaim_bytes":1048576,"memory_current":10485760}`,
			AppliedAt: f.clock.Now(), TTLSeconds: 120,
		}); err != nil {
			t.Fatalf("SaveReflexAction: %v", err)
		}
	}
	f.audit(t, "INC-EXPORT-DISMISS", "sentinel", "REFLEX_LATENCY", map[string]any{"reflex_id": "RFX-000000000001", "action": "cgroup_reclaim", "latency_ms": 1.25, "trigger": "psi"})
	f.clock.Advance(time.Second)
	if err := f.store.TransitionState(ctx, "INC-EXPORT-DISMISS", incident.StateWaitingApproval, "wa-bridge", "WhatsApp approval poll APR-BEEF sent for plan "+planHash[:8]); err != nil {
		t.Fatalf("TransitionState WAITING_APPROVAL: %v", err)
	}
	f.clock.Advance(20 * time.Second)
	if err := f.store.TransitionState(ctx, "INC-EXPORT-DISMISS", incident.StateDismissed, "wa-bridge", "dismissed via WhatsApp by [REDACTED_PHONE]"); err != nil {
		t.Fatalf("TransitionState DISMISSED: %v", err)
	}

	rep, err := BuildReplay(ctx, f.store, []string{"INC-EXPORT-DISMISS"}, ReplaySource{Kind: "recording", Label: "Pi 02", Detail: "Exported from a test store."}, "pi02")
	if err != nil {
		t.Fatalf("BuildReplay: %v", err)
	}
	inc := rep.Incidents[0]
	kinds := kindsOf(inc)
	if kinds["reflex.applied"] != 2 || inc.Stats.Reflexes != 2 {
		t.Fatalf("each reflex must be counted once (rows + REFLEX_APPLIED audit), got %v stats=%+v", kinds, inc.Stats)
	}
	if inc.ReflexLatencyMS == nil || *inc.ReflexLatencyMS != 1.25 || inc.ReflexTrigger != "psi" {
		t.Fatalf("reflex latency must come from REFLEX_LATENCY, got %v %q", inc.ReflexLatencyMS, inc.ReflexTrigger)
	}
	if kinds["poll.sent"] != 1 || kinds["vote.dismissed"] != 1 {
		t.Fatalf("expected poll.sent and vote.dismissed, got %v", kinds)
	}
	if inc.Poll == nil || inc.Poll.Chosen != len(inc.Poll.Options)-1 || inc.Poll.Options[inc.Poll.Chosen] != policy.PollOptionDismiss || inc.Poll.Approver != "allowlisted admin" {
		t.Fatalf("dismissed poll must point at Dismiss without an approver hash, got %+v", inc.Poll)
	}
	if !strings.HasPrefix(inc.Poll.Title, "[BEEF] INC-EXPORT-DISMISS (plan "+planHash[:8]+")") {
		t.Fatalf("poll title must reuse the approval short code, got %q", inc.Poll.Title)
	}
	last := inc.Messages[len(inc.Messages)-1]
	if last.Text != "Incident INC-EXPORT-DISMISS dismissed by operator." {
		t.Fatalf("dismissal message must use the wa-bridge text, got %+v", inc.Messages)
	}
	if inc.State != "DISMISSED" || inc.ClosedAt == nil {
		t.Fatalf("unexpected state %s closed=%v", inc.State, inc.ClosedAt)
	}
}

func TestBuildReplay_ValidatesInputs(t *testing.T) {
	f := newExportFixture(t)
	f.incident(t, "INC-EXPORT-SRC", nil)
	ctx := context.Background()
	if _, err := BuildReplay(ctx, f.store, []string{"INC-EXPORT-SRC"}, ReplaySource{Kind: "screenshot"}, ""); err == nil {
		t.Fatal("invalid source kind must be rejected")
	}
	if _, err := BuildReplay(ctx, f.store, nil, ReplaySource{}, ""); err == nil {
		t.Fatal("empty incident list must be rejected")
	}
	if _, err := BuildReplay(ctx, f.store, []string{"INC-MISSING"}, ReplaySource{}, ""); err == nil {
		t.Fatal("unknown incident must be rejected")
	}
	if _, err := BuildReplay(ctx, nil, []string{"INC-EXPORT-SRC"}, ReplaySource{}, ""); err == nil {
		t.Fatal("nil store must be rejected")
	}
}

func TestRecentTerminalIncidentIDs_PicksTerminalIncidentsChronologically(t *testing.T) {
	f := newExportFixture(t)
	ctx := context.Background()
	states := []incident.State{incident.StateResolved, incident.StateVerifying, incident.StateEscalated, incident.StateDismissed, incident.StateExpired}
	for i, st := range states {
		f.clock.Advance(time.Minute)
		if err := f.store.CreateIncident(ctx, &incident.Incident{ID: "INC-R-" + string(rune('a'+i)), Node: "n", Cgroup: "/x.service", Severity: "P2", State: st, OpenedAt: f.clock.Now()}); err != nil {
			t.Fatalf("CreateIncident: %v", err)
		}
	}
	ids, err := RecentTerminalIncidentIDs(ctx, f.store, 3)
	if err != nil {
		t.Fatalf("RecentTerminalIncidentIDs: %v", err)
	}
	if strings.Join(ids, ",") != "INC-R-c,INC-R-d,INC-R-e" {
		t.Fatalf("expected the three newest terminal incidents oldest first, got %v", ids)
	}
	if all, _ := RecentTerminalIncidentIDs(ctx, f.store, 0); len(all) != 4 {
		t.Fatalf("default limit must include all four terminal incidents, got %v", all)
	}
}

func TestMarshalReplay_CompactsNumericArraysOnly(t *testing.T) {
	rep := &Replay{Schema: ReplaySchema, Incidents: []ReplayIncident{{
		ID:       "INC-1",
		Series:   &ReplaySeries{LimitBytes: 1, Points: [][4]float64{{-1.5, 1024, 0.5, 0}, {2, 2048, 1.25, 0.1}}},
		Events:   []ReplayEvent{{Title: "ids: [ 0, 1, 2 ]", Detail: "line one\nline two"}},
		Messages: []ReplayMessage{},
	}}}
	raw, err := MarshalReplay(rep)
	if err != nil {
		t.Fatalf("MarshalReplay: %v", err)
	}
	if !bytes.Contains(raw, []byte("[-1.5,1024,0.5,0]")) || !bytes.Contains(raw, []byte("[2,2048,1.25,0.1]")) {
		t.Fatalf("series points must be compacted to one line:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte(`"ids: [ 0, 1, 2 ]"`)) || !bytes.Contains(raw, []byte(`line one\nline two`)) {
		t.Fatalf("string content must be preserved exactly:\n%s", raw)
	}
	var back Replay
	if err := json.Unmarshal(raw, &back); err != nil || back.Incidents[0].Series.Points[1][2] != 1.25 {
		t.Fatalf("compacted JSON must round-trip: %v", err)
	}
	if !bytes.HasSuffix(raw, []byte("}\n")) {
		t.Fatalf("output must end with a newline")
	}
}
