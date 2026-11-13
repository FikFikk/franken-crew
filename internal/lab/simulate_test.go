package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/FikFikk/franken-crew/internal/policy"
)

var (
	simOnce   sync.Once
	simReplay *Replay
	simJSON   []byte
	simErr    error
)

// steppingMonotonic adalah jam monotonik injeksi yang maju 250 µs per bacaan, untuk uji byte-identik.
func steppingMonotonic() func() time.Time {
	var mu sync.Mutex
	t := time.Unix(0, 0)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(250 * time.Microsecond)
		return t
	}
}

func testSimulateOptions() SimulateOptions {
	return SimulateOptions{PolicyPath: filepath.Join("..", "..", "policy", "actions.yaml"), Monotonic: steppingMonotonic()}
}

// sharedSimulation menjalankan simulasi sekali per paket test dan berbagi hasilnya antar test.
func sharedSimulation(t *testing.T) (*Replay, []byte) {
	t.Helper()
	simOnce.Do(func() {
		simReplay, simErr = Simulate(context.Background(), testSimulateOptions())
		if simErr == nil {
			simJSON, simErr = MarshalReplay(simReplay)
		}
	})
	if simErr != nil {
		t.Fatalf("Simulate: %v", simErr)
	}
	return simReplay, simJSON
}

func kindsOf(inc ReplayIncident) map[string]int {
	out := make(map[string]int)
	for _, ev := range inc.Events {
		out[ev.Kind]++
	}
	return out
}

func TestSimulate_ProducesThreeScenariosWithExpectedOutcomes(t *testing.T) {
	rep, _ := sharedSimulation(t)
	if rep.Schema != ReplaySchema || rep.Node != SimulationNode {
		t.Fatalf("unexpected header: schema=%q node=%q", rep.Schema, rep.Node)
	}
	if rep.Source.Kind != SourceKindSimulation || rep.Source.Label != "Chaos simulation" {
		t.Fatalf("unexpected source: %+v", rep.Source)
	}
	for _, phrase := range []string{"detector", "reflex engine", "policy", "scope", "Ed25519", "verification", "postmortem", "in-memory", "fake", "scripted MCP tool calls", "in-process", "rebuilt"} {
		if !strings.Contains(rep.Source.Detail, phrase) {
			t.Errorf("source.detail must state %q honestly, got %q", phrase, rep.Source.Detail)
		}
	}
	if len(rep.Incidents) != 3 {
		t.Fatalf("expected 3 incidents, got %d", len(rep.Incidents))
	}
	want := []struct{ scenario, state string }{
		{"heap_leak", "RESOLVED"},
		{"prompt_injection", "RESOLVED"},
		{"zombie_storm", "ESCALATED"},
	}
	for i, w := range want {
		inc := rep.Incidents[i]
		if inc.Scenario != w.scenario || inc.State != w.state {
			t.Errorf("incident %d = %s/%s, want %s/%s", i, inc.Scenario, inc.State, w.scenario, w.state)
		}
		if inc.ClosedAt == nil || inc.DurationS <= 0 || !strings.HasPrefix(inc.ID, "INC-20261113-") || !strings.HasSuffix(inc.ID, SimulationNode) && !strings.Contains(inc.ID, SimulationNode+"-") {
			t.Errorf("incident %d must be closed with a detector ID, got id=%s closed=%v duration=%v", i, inc.ID, inc.ClosedAt, inc.DurationS)
		}
		if inc.Series == nil || len(inc.Series.Points) < 60 {
			t.Errorf("incident %s must carry >= 60 series points", inc.ID)
		} else {
			pts := inc.Series.Points
			for j := 1; j < len(pts); j++ {
				if pts[j][0] < pts[j-1][0] {
					t.Fatalf("incident %s series is not ascending at %d", inc.ID, j)
				}
			}
			if pts[0][0] >= 0 || pts[len(pts)-1][0] <= 0 {
				t.Errorf("incident %s series must start before opening and end after it: %v .. %v", inc.ID, pts[0][0], pts[len(pts)-1][0])
			}
		}
		if inc.ReflexLatencyMS == nil || *inc.ReflexLatencyMS < 0 || inc.ReflexTrigger != "sample" {
			t.Errorf("incident %s must report the real reflex latency from REFLEX_LATENCY, got %v %q", inc.ID, inc.ReflexLatencyMS, inc.ReflexTrigger)
		}
		if inc.PlanHash == "" || inc.RootCause == "" || len(inc.FollowUps) == 0 || inc.Postmortem == "" {
			t.Errorf("incident %s is missing plan hash, root cause, follow-ups, or postmortem", inc.ID)
		}
		if inc.Stats.Reflexes < 1 || inc.Stats.L2Steps < 1 || inc.Stats.VerifyWindowS != 120 {
			t.Errorf("incident %s stats = %+v", inc.ID, inc.Stats)
		}
	}

	heap := rep.Incidents[0]
	if heap.Class != "heap_leak" || heap.Confidence == nil || *heap.Confidence != 0.86 || heap.TriageSummary == "" {
		t.Errorf("heap_leak triage must come from triage_json, got class=%q confidence=%v", heap.Class, heap.Confidence)
	}
	if heap.Unit != "haunted-api.service" || heap.Cgroup != "/franken.slice/haunted-api.service" {
		t.Errorf("heap_leak unit/cgroup = %q/%q", heap.Unit, heap.Cgroup)
	}
	if heap.Series.LimitBytes != 512<<20 {
		t.Errorf("heap_leak limit = %d, want memory.max 512 MiB", heap.Series.LimitBytes)
	}
	if zombie := rep.Incidents[2]; zombie.Class != "zombie_accumulation" || zombie.Unit != "worker.service" {
		t.Errorf("zombie_storm triage/unit = %q/%q", zombie.Class, zombie.Unit)
	}
}

func TestSimulate_EventsCoverTheIncidentStory(t *testing.T) {
	rep, _ := sharedSimulation(t)
	required := []string{"incident.opened", "reflex.applied", "plan.accepted", "poll.sent", "vote.granted", "token.verified", "action.executed", "verify.started", "postmortem.written"}
	for _, inc := range rep.Incidents {
		kinds := kindsOf(inc)
		for _, k := range required {
			if kinds[k] == 0 {
				t.Errorf("%s (%s) is missing event %q (have %v)", inc.Scenario, inc.ID, k, kinds)
			}
		}
		if kinds["verify.passed"]+kinds["verify.failed"] != 1 {
			t.Errorf("%s must have exactly one verification verdict, got %v", inc.Scenario, kinds)
		}
		for i := 1; i < len(inc.Events); i++ {
			if inc.Events[i].T < inc.Events[i-1].T {
				t.Fatalf("%s events are not sorted by t at %d (%v < %v)", inc.Scenario, i, inc.Events[i].T, inc.Events[i-1].T)
			}
		}
		var opened *ReplayEvent
		for i := range inc.Events {
			ev := &inc.Events[i]
			if ev.Kind == "incident.opened" {
				opened = ev
			}
			if ev.Kind == "reflex.applied" && strings.Contains(ev.Detail, "sample trigger") && !strings.Contains(ev.Detail, " ms") {
				t.Errorf("%s reflex.applied detail must include the latency: %q", inc.Scenario, ev.Detail)
			}
			if (ev.Kind == "phase" || ev.Kind == "spawn") && (!ev.Inferred || ev.Actor != "franken-conductor" || ev.Lane != LaneCrew) {
				t.Errorf("%s conductor event must be inferred crew/franken-conductor: %+v", inc.Scenario, ev)
			}
		}
		if opened == nil || opened.T != 0 || opened.Lane != LaneSentinel {
			t.Errorf("%s incident.opened must be the sentinel event at t=0, got %+v", inc.Scenario, opened)
		}
		if kinds["phase"] < 2 || kinds["spawn"] < 3 {
			t.Errorf("%s must reconstruct TRIAGE/EXECUTE phases and agent spawns, got %v", inc.Scenario, kinds)
		}
	}

	if kinds := kindsOf(rep.Incidents[0]); kinds["verify.passed"] != 1 || kinds["psi.rising"] != 1 || kinds["reflex.rolled_back"] == 0 {
		t.Errorf("heap_leak must pass verification, show psi.rising, and roll back its reflex: %v", kinds)
	}
	inj := kindsOf(rep.Incidents[1])
	for _, k := range []string{"plan.rejected", "action.blocked", "token.replay_rejected", "verify.passed"} {
		if inj[k] == 0 {
			t.Errorf("prompt_injection is missing %q (have %v)", k, inj)
		}
	}
	if inj["token.rejected"] != 0 {
		t.Errorf("the replayed token must be counted once as token.replay_rejected, not also as token.rejected: %v", inj)
	}
	if rep.Incidents[1].Stats.Blocked != inj["plan.rejected"]+inj["action.blocked"]+inj["token.replay_rejected"] {
		t.Errorf("prompt_injection blocked stat = %d, events %v", rep.Incidents[1].Stats.Blocked, inj)
	}
	zombie := kindsOf(rep.Incidents[2])
	if zombie["verify.failed"] != 1 || zombie["incident.escalated"] != 1 || zombie["reflex.rolled_back"] < 2 {
		t.Errorf("zombie_storm must fail verification, escalate, and roll back reflexes: %v", zombie)
	}
}

func TestSimulate_EventVocabularyAndTextLimits(t *testing.T) {
	rep, _ := sharedSimulation(t)
	vocab := map[string]string{
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
	actors := []string{"kernel", "franken-sentinel", "franken-conductor", "franken-sentry", "franken-architect", "franken-remediator", "wa-bridge", "operator", "kiro-guard"}
	levels := []string{LevelInfo, LevelOK, LevelWarn, LevelError}
	for _, inc := range rep.Incidents {
		for _, ev := range inc.Events {
			if lane, ok := vocab[ev.Kind]; !ok || lane != ev.Lane {
				t.Errorf("%s: event kind %q on lane %q is outside the fixed vocabulary", inc.Scenario, ev.Kind, ev.Lane)
			}
			if !slices.Contains(actors, ev.Actor) || !slices.Contains(levels, ev.Level) {
				t.Errorf("%s: invalid actor/level in %+v", inc.Scenario, ev)
			}
			if ev.Title == "" || utf8.RuneCountInString(ev.Title) > 60 || utf8.RuneCountInString(ev.Detail) > 280 {
				t.Errorf("%s: title/detail limits violated in %+v", inc.Scenario, ev)
			}
			if math.Abs(ev.T*1000-math.Round(ev.T*1000)) > 1e-6 {
				t.Errorf("%s: t must have ms precision, got %v", inc.Scenario, ev.T)
			}
			if d := ev.At.Sub(inc.OpenedAt.Add(time.Duration(math.Round(ev.T*1000)) * time.Millisecond)); d.Abs() > time.Millisecond {
				t.Errorf("%s: event at/t mismatch (%v) in %+v", inc.Scenario, d, ev)
			}
		}
		for _, m := range inc.Messages {
			if (m.From != "bot" && m.From != "operator") || !slices.Contains([]string{"alert", "poll", "vote", "text", "report"}, m.Kind) || m.Text == "" {
				t.Errorf("%s: invalid message %+v", inc.Scenario, m)
			}
		}
	}
}

func TestSimulate_PollLabelsAndChosenOptionMatchPolicy(t *testing.T) {
	rep, _ := sharedSimulation(t)
	for _, inc := range rep.Incidents {
		if inc.Poll == nil {
			t.Fatalf("%s has no poll", inc.Scenario)
		}
		// Label poll hanya bergantung pada ID opsi, aksi, target, dan plan_hash, bukan pada evidence_id
		plan := &policy.Plan{Options: acceptedPlanOptions(inc.Scenario, nil)}
		if len(plan.Options) == 0 {
			t.Fatalf("no accepted plan options known for scenario %q", inc.Scenario)
		}
		want := policy.PollOptionLabels(plan, inc.PlanHash)
		if !slices.Equal(inc.Poll.Options, want) {
			t.Fatalf("%s poll options = %q, want policy labels %q", inc.Scenario, inc.Poll.Options, want)
		}
		for i, opt := range plan.Options {
			if inc.Poll.Options[i] != policy.FormatOptionLabel(opt, inc.PlanHash) {
				t.Errorf("%s option %d label differs from policy.FormatOptionLabel", inc.Scenario, i)
			}
		}
		if inc.Poll.Chosen != 0 || !strings.HasPrefix(inc.Poll.Options[inc.Poll.Chosen], "A: ") {
			t.Errorf("%s chosen = %d, want the executed option A", inc.Scenario, inc.Poll.Chosen)
		}
		if inc.Poll.VotedT == nil || *inc.Poll.VotedT <= inc.Poll.T {
			t.Errorf("%s vote must come after the poll: poll t=%v voted=%v", inc.Scenario, inc.Poll.T, inc.Poll.VotedT)
		}
		if !strings.HasPrefix(inc.Poll.Approver, "allowlisted admin ") || len(inc.Poll.Approver) != len("allowlisted admin ")+8 {
			t.Errorf("%s approver must be 'allowlisted admin' plus the short hash, got %q", inc.Scenario, inc.Poll.Approver)
		}
		if !strings.Contains(inc.Poll.Title, inc.ID) || !strings.Contains(inc.Poll.Title, "(plan "+policy.ShortPlanHash(inc.PlanHash)+")") || !strings.Contains(inc.Poll.Title, "Choose action or reply APPROVE <OPT>") {
			t.Errorf("%s poll title must use the wa-bridge format, got %q", inc.Scenario, inc.Poll.Title)
		}

		var kinds []string
		for _, m := range inc.Messages {
			kinds = append(kinds, m.From+":"+m.Kind)
		}
		if !slices.Equal(kinds, []string{"bot:alert", "bot:poll", "operator:vote", "bot:text", "bot:report"}) {
			t.Errorf("%s messages = %v", inc.Scenario, kinds)
		}
		summary := inc.Messages[3].Text
		if !strings.HasPrefix(summary, "Approved option A (") || !strings.Contains(summary, "for "+inc.ID+" [plan "+policy.ShortPlanHash(inc.PlanHash)+"]") || !strings.HasSuffix(summary, "single-use Ed25519 step token(s) issued to Franken-Remediator.") {
			t.Errorf("%s approval summary must use the wa-bridge format, got %q", inc.Scenario, summary)
		}
		if report := inc.Messages[4].Text; !strings.HasPrefix(report, "[REPORT] *"+inc.ID+"* "+inc.State+" (verification ") || !strings.Contains(report, "Postmortem: incidents/"+inc.ID+"/postmortem.md") {
			t.Errorf("%s final report must use the wa-bridge format with a relative postmortem path, got %q", inc.Scenario, report)
		}
		if alert := inc.Messages[0].Text; !strings.HasPrefix(alert, "["+inc.Severity+"] *"+inc.ID+"* | DETECTED\nNode: `"+SimulationNode+"`") {
			t.Errorf("%s first alert must use the wa-bridge format, got %q", inc.Scenario, alert)
		}
	}
	if !strings.Contains(rep.Incidents[2].Messages[3].Text, "2 single-use Ed25519 step token(s)") {
		t.Errorf("zombie_storm option A has two steps and must mint two tokens: %q", rep.Incidents[2].Messages[3].Text)
	}
}

func TestSimulate_JSONHasNoSecretsOrHostPaths(t *testing.T) {
	_, raw := sharedSimulation(t)
	for _, needle := range []string{"Bearer ", "sk-", "+62", "PRIVATE KEY", "hunter2", "10.0.4.12", "/tmp/", "franken-lab-sim-", "lab-admin@"} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("replay JSON must not contain %q", needle)
		}
	}
	for _, needle := range []string{"[REDACTED_IP]", "[REDACTED_PASSWORD]", "IGNORE ALL PREVIOUS INSTRUCTIONS"} {
		if !bytes.Contains(raw, []byte(needle)) {
			t.Errorf("replay JSON should show redaction and the injected text as evidence, missing %q", needle)
		}
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("replay JSON is invalid: %v", err)
	}
}

func TestSimulate_TwoRunsAreByteIdentical(t *testing.T) {
	_, first := sharedSimulation(t)
	rep, err := Simulate(context.Background(), testSimulateOptions())
	if err != nil {
		t.Fatalf("second Simulate: %v", err)
	}
	second, err := MarshalReplay(rep)
	if err != nil {
		t.Fatalf("MarshalReplay: %v", err)
	}
	if !bytes.Equal(first, second) {
		a, b := string(first), string(second)
		i := 0
		for i < len(a) && i < len(b) && a[i] == b[i] {
			i++
		}
		lo := max(0, i-200)
		t.Fatalf("two simulation runs differ at byte %d:\n first: %q\nsecond: %q", i, a[lo:min(len(a), i+200)], b[lo:min(len(b), i+200)])
	}
	if !rep.GeneratedAt.Equal(simReplay.GeneratedAt) || rep.GeneratedAt.Year() != 2026 {
		t.Fatalf("generated_at must come from the simulated clock, got %s", rep.GeneratedAt)
	}
}
