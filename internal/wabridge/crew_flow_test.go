package wabridge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"go.mau.fi/whatsmeow/types"
)

// recordingCrew mencatat setiap permintaan fase Crew yang dipicu bridge.
type recordingCrew struct {
	mu   sync.Mutex
	reqs []CrewPhaseRequest
	ch   chan CrewPhaseRequest
}

func newRecordingCrew() *recordingCrew {
	return &recordingCrew{ch: make(chan CrewPhaseRequest, 16)}
}

func (r *recordingCrew) Trigger(_ context.Context, req CrewPhaseRequest) error {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	r.ch <- req
	return nil
}

func (r *recordingCrew) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

func waitCrewRequest(t *testing.T, r *recordingCrew) CrewPhaseRequest {
	t.Helper()
	select {
	case req := <-r.ch:
		return req
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Crew phase trigger")
		return CrewPhaseRequest{}
	}
}

func newCrewTestBridge(t *testing.T, crew CrewNotifier) (*Bridge, *mockMessenger, *incident.Store, *SentinelClient, *spyCommandRunner) {
	t.Helper()
	store, _, _, minter, runner, ts := setupSentinelHarness(t)
	sentinelClient, err := NewSentinelClient(ts.URL, "bridge-test-token")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	t.Cleanup(func() { _ = sentinelClient.Close() })
	messenger := newMockMessenger()
	bridge, err := New(Config{
		NodeName:       "pi-crew",
		AdminAllowlist: []string{"+6281234567890"},
		Minter:         minter,
		Sentinel:       sentinelClient,
		Messenger:      messenger,
		Crew:           crew,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return bridge, messenger, store, sentinelClient, runner
}

func TestCrewWebhook_PostsBearerJSONAndRetriesServerErrors(t *testing.T) {
	var attempts atomic.Int32
	var gotAuth, gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			http.Error(w, "gateway warming up", http.StatusServiceUnavailable)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		gotAuth, gotBody = r.Header.Get("Authorization"), string(raw)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer ts.Close()

	wh, err := NewCrewWebhook(CrewWebhookConfig{URL: ts.URL + "/api/hooks/agent", Token: "crew-tok", MaxAttempts: 3, Backoff: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewCrewWebhook: %v", err)
	}
	err = wh.Trigger(context.Background(), CrewPhaseRequest{
		Phase: CrewPhaseTriage, IncidentID: "INC-20261113-1200-pi01", Severity: "P1", Node: "pi01",
		Cgroup: "/franken.slice/haunted-api.service",
	})
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("expected 2 retries after 503, got %d attempts", attempts.Load())
	}
	if gotAuth != "Bearer crew-tok" {
		t.Fatalf("expected bearer auth header, got %q", gotAuth)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("webhook body is not JSON: %v (%s)", err, gotBody)
	}
	msg, _ := body["message"].(string)
	for _, want := range []string{"FRANKENCREW phase=TRIAGE", "incident=INC-20261113-1200-pi01", "franken-conductor"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q missing %q", msg, want)
		}
	}
	if _, hasAgent := body["agent"]; hasAgent {
		t.Fatalf("agent field must only be sent when configured, got body %s", gotBody)
	}
}

func TestCrewWebhook_DoesNotRetryClientErrorsOrLeakToken(t *testing.T) {
	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "bad token "+r.Header.Get("Authorization"), http.StatusUnauthorized)
	}))
	defer ts.Close()

	wh, err := NewCrewWebhook(CrewWebhookConfig{URL: ts.URL + "/api/hooks/agent", Token: "crew-secret-tok", MaxAttempts: 3, Backoff: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewCrewWebhook: %v", err)
	}
	err = wh.Trigger(context.Background(), CrewPhaseRequest{Phase: CrewPhaseTriage, IncidentID: "INC-1"})
	if err == nil {
		t.Fatal("expected an error for HTTP 401")
	}
	if attempts.Load() != 1 {
		t.Fatalf("client errors must not be retried, got %d attempts", attempts.Load())
	}
	if strings.Contains(err.Error(), "crew-secret-tok") {
		t.Fatalf("webhook error leaked the bearer token: %v", err)
	}
}

func TestNewCrewWebhook_RejectsPlainHTTPToPublicHosts(t *testing.T) {
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"http://127.0.0.1:5476/api/hooks/agent", true},
		{"http://localhost:5476/api/hooks/agent", true},
		{"http://100.101.102.103:5476/api/hooks/agent", true},
		{"https://crew.example.com/api/hooks/agent", true},
		{"http://8.8.8.8/api/hooks/agent", false},
		{"http://crew.example.com/api/hooks/agent", false},
		{"ftp://127.0.0.1/api/hooks/agent", false},
	} {
		_, err := NewCrewWebhook(CrewWebhookConfig{URL: tc.url, Token: "tok"})
		if (err == nil) != tc.ok {
			t.Errorf("NewCrewWebhook(%q) err=%v, want ok=%v", tc.url, err, tc.ok)
		}
	}
	if _, err := NewCrewWebhook(CrewWebhookConfig{URL: "http://127.0.0.1:5476/api/hooks/agent"}); err == nil {
		t.Error("expected an error when the Crew token is empty")
	}
}

func TestBridge_IncidentOpenedTriggersCrewTriageOnce(t *testing.T) {
	crew := newRecordingCrew()
	bridge, messenger, _, _, _ := newCrewTestBridge(t, crew)
	ctx := context.Background()

	opened := mcpserver.StreamEvent{
		Type: "incident.opened", IncidentID: "INC-CREW-1", Severity: "P1", State: string(incident.StateDetected),
		Node: "pi-crew", Summary: "TTO 40s", Data: map[string]any{"cgroup": "/franken.slice/haunted-api.service"},
	}
	bridge.HandleSSEEvent(ctx, opened)
	bridge.HandleSSEEvent(ctx, opened)
	bridge.HandleSSEEvent(ctx, mcpserver.StreamEvent{Type: "incident.escalated_severity", IncidentID: "INC-CREW-1", Severity: "POST_OOM"})
	bridge.HandleSSEEvent(ctx, mcpserver.StreamEvent{Type: "incident.opened", IncidentID: "INC-CREW-P3", Severity: "P3"})

	req := waitCrewRequest(t, crew)
	if req.Phase != CrewPhaseTriage || req.IncidentID != "INC-CREW-1" || req.Severity != "P1" || req.Cgroup != "/franken.slice/haunted-api.service" {
		t.Fatalf("unexpected triage request: %+v", req)
	}
	time.Sleep(150 * time.Millisecond)
	if crew.count() != 1 {
		t.Fatalf("expected exactly one TRIAGE trigger, got %d", crew.count())
	}
	if len(messenger.Texts()) != 1 {
		t.Fatalf("expected the first alert text to still be sent once, got %d", len(messenger.Texts()))
	}
}

func TestBridge_GrantedVoteTriggersCrewExecutePhase(t *testing.T) {
	crew := newRecordingCrew()
	bridge, messenger, store, sentinelClient, _ := newCrewTestBridge(t, crew)
	ctx := context.Background()

	incID := "INC-CREW-EXEC"
	if err := store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi-crew", Cgroup: "/franken.slice/haunted-api.service", Severity: "P1", State: incident.StateDetected}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	planHash := submitTwoOptionTestPlan(t, ctx, store, sentinelClient, incID)
	poll, err := bridge.SendApprovalPoll(ctx, PollRequest{IncidentID: incID, PlanHash: planHash})
	if err != nil {
		t.Fatalf("SendApprovalPoll: %v", err)
	}

	admin := types.NewJID("6281234567890", types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-CREW-B", poll.Options[1].Label)
	bridge.HandleWhatsAppEvent(ctx, makePollVoteEvent("VOTE-CREW-B", poll.PollMessageID, admin, types.EmptyJID))

	req := waitCrewRequest(t, crew)
	if req.Phase != CrewPhaseExecute || req.IncidentID != incID || req.ApprovalID != poll.ApprovalID || req.OptionID != "B" || !slices.Equal(req.StepIDs, []string{"step-b1"}) {
		t.Fatalf("unexpected execute request: %+v", req)
	}
}

func TestBridge_DismissVoteDoesNotTriggerCrew(t *testing.T) {
	crew := newRecordingCrew()
	bridge, messenger, store, sentinelClient, _ := newCrewTestBridge(t, crew)
	ctx := context.Background()

	incID := "INC-CREW-DISMISS"
	_ = store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi-crew", Cgroup: "/franken.slice/haunted-api.service", Severity: "P1", State: incident.StateDetected})
	planHash := submitTwoOptionTestPlan(t, ctx, store, sentinelClient, incID)
	poll, err := bridge.SendApprovalPoll(ctx, PollRequest{IncidentID: incID, PlanHash: planHash})
	if err != nil {
		t.Fatalf("SendApprovalPoll: %v", err)
	}
	admin := types.NewJID("6281234567890", types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-CREW-DISMISS", OptionDismiss)
	bridge.HandleWhatsAppEvent(ctx, makePollVoteEvent("VOTE-CREW-DISMISS", poll.PollMessageID, admin, types.EmptyJID))
	if _, err := bridge.AwaitDecision(ctx, poll.ApprovalID, 2*time.Second); err != nil {
		t.Fatalf("AwaitDecision: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if crew.count() != 0 {
		t.Fatalf("a dismissed poll must not start an EXECUTE phase, got %d triggers", crew.count())
	}
}

func TestBridge_TwoStepOptionMintsOneTokenPerStep(t *testing.T) {
	bridge, messenger, store, sentinelClient, runner := newCrewTestBridge(t, nil)
	ctx := context.Background()

	incID := "INC-TWO-STEP"
	if err := store.CreateIncident(ctx, &incident.Incident{ID: incID, Node: "pi-crew", Cgroup: "/franken.slice/haunted-api.service", Severity: "P1", State: incident.StateDetected}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	if err := store.SaveEvidence(ctx, &incident.EvidenceSnapshot{ID: "EVD-TWO-STEP", IncidentID: incID, Kind: "telemetry_sample", RawData: `{"memory_current":1}`}); err != nil {
		t.Fatalf("SaveEvidence: %v", err)
	}
	plan := policy.Plan{
		IncidentID:         incID,
		SuspectedRootCause: "One leaking worker inside haunted-api",
		HumanFollowUp:      []string{"profile worker heap"},
		Options: []policy.PlanOption{
			{ID: "A", Label: "Restart worker, then unit", Steps: []policy.PlanStep{
				{ID: "a1", Action: "pm2_restart_instance", Params: map[string]any{"app": "haunted-api", "pm_id": 0}, EvidenceIDs: []string{"EVD-TWO-STEP"}, ExpectedEffect: "restart leaking worker"},
				{ID: "a2", Action: "unit_restart", Params: map[string]any{"unit": "haunted-api.service"}, EvidenceIDs: []string{"EVD-TWO-STEP"}, ExpectedEffect: "restart unit if needed"},
			}},
			{ID: "B", Label: "Reload all", Steps: []policy.PlanStep{
				{ID: "b1", Action: "pm2_reload", Params: map[string]any{"app": "haunted-api"}, EvidenceIDs: []string{"EVD-TWO-STEP"}, ExpectedEffect: "reload workers"},
			}},
		},
	}
	sub, err := sentinelClient.PlanSubmit(ctx, incID, plan)
	if err != nil || !sub.Valid {
		t.Fatalf("PlanSubmit: err=%v out=%+v", err, sub)
	}
	poll, err := bridge.SendApprovalPoll(ctx, PollRequest{IncidentID: incID, PlanHash: sub.PlanHash})
	if err != nil {
		t.Fatalf("SendApprovalPoll: %v", err)
	}
	if !strings.Contains(poll.Options[0].Label, "pm2_restart_instance haunted-api pm_id=0") {
		t.Fatalf("poll label must show which PM2 worker is restarted, got %q", poll.Options[0].Label)
	}

	admin := types.NewJID("6281234567890", types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-TWO-A", poll.Options[0].Label)
	bridge.HandleWhatsAppEvent(ctx, makePollVoteEvent("VOTE-TWO-A", poll.PollMessageID, admin, types.EmptyJID))
	dec, err := bridge.AwaitDecision(ctx, poll.ApprovalID, 2*time.Second)
	if err != nil {
		t.Fatalf("AwaitDecision: %v", err)
	}
	if dec.Status != "GRANTED" || len(dec.StepTokens) != 2 ||
		dec.StepTokens[0].StepID != "a1" || dec.StepTokens[0].Action != "pm2_restart_instance" ||
		dec.StepTokens[1].StepID != "a2" || dec.StepTokens[1].Action != "unit_restart" {
		t.Fatalf("expected one token per step bound to its own action, got %+v", dec)
	}

	for i, st := range plan.Options[0].Steps {
		if _, err := sentinelClient.ActionExecute(ctx, mcpserver.ActionExecuteInput{
			IncidentID: incID, StepID: st.ID, Action: st.Action, Params: st.Params, ApprovalToken: dec.StepTokens[i].Token,
		}); err != nil {
			t.Fatalf("step %s must execute with its own token: %v", st.ID, err)
		}
	}
	if _, err := sentinelClient.ActionExecute(ctx, mcpserver.ActionExecuteInput{
		IncidentID: incID, StepID: "a2", Action: "unit_restart", Params: map[string]any{"unit": "haunted-api.service"}, ApprovalToken: dec.StepTokens[1].Token,
	}); err == nil {
		t.Fatal("replaying a step token must be rejected")
	}
	calls := strings.Join(runner.Calls(), " | ")
	if !strings.Contains(calls, "pm2 restart haunted-api 0") || !strings.Contains(calls, "systemctl restart haunted-api.service") {
		t.Fatalf("expected both steps to run exactly as approved, got %s", calls)
	}
}

func TestBridge_VerificationCompletedSendsFinalReportOnce(t *testing.T) {
	bridge, messenger, _, _, _ := newCrewTestBridge(t, nil)
	ctx := context.Background()

	done := mcpserver.StreamEvent{
		Type: "verification.completed", IncidentID: "INC-REPORT-1", Severity: "P1", State: string(incident.StateResolved),
		Summary: "forward health verification stabilized over 120s window",
		Data:    map[string]any{"status": "RESOLVED", "healthy": true, "rolled_back": 1, "postmortem_path": "/var/lib/franken/incidents/INC-REPORT-1/postmortem.md"},
	}
	bridge.HandleSSEEvent(ctx, done)
	bridge.HandleSSEEvent(ctx, done)

	texts := messenger.Texts()
	if len(texts) != 1 {
		t.Fatalf("expected exactly one final report, got %d", len(texts))
	}
	for _, want := range []string{"INC-REPORT-1", "RESOLVED", "postmortem.md", "1"} {
		if !strings.Contains(texts[0].Text, want) {
			t.Fatalf("final report %q missing %q", texts[0].Text, want)
		}
	}

	bridge.HandleSSEEvent(ctx, mcpserver.StreamEvent{
		Type: "verification.completed", IncidentID: "INC-REPORT-2", Severity: "P1", State: string(incident.StateEscalated),
		Data: map[string]any{"status": "FAILED", "healthy": false, "rolled_back": 1, "failure_reasons": "memory trend unstable"},
	})
	texts = messenger.Texts()
	if len(texts) != 2 || !strings.Contains(texts[1].Text, "ESCALATED") || !strings.Contains(texts[1].Text, "memory trend unstable") {
		t.Fatalf("expected an escalation report with the failure reason, got %+v", texts)
	}
}
