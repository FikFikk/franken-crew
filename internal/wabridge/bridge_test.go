package wabridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
	"pgregory.net/rapid"
)

type sentTextRecord struct {
	ID   types.MessageID
	To   types.JID
	Text string
	At   time.Time
}

type sentPollRecord struct {
	ID      types.MessageID
	To      types.JID
	Title   string
	Options []string
	At      time.Time
}

type mockMessenger struct {
	mu           sync.Mutex
	seq          int
	texts        []sentTextRecord
	polls        []sentPollRecord
	lidToPN      map[string]types.JID
	voteToHashes map[types.MessageID][][]byte
	notifyCh     chan string
}

func newMockMessenger() *mockMessenger {
	return &mockMessenger{
		lidToPN:      make(map[string]types.JID),
		voteToHashes: make(map[types.MessageID][][]byte),
		notifyCh:     make(chan string, 32),
	}
}

func (m *mockMessenger) SendText(_ context.Context, to types.JID, text string) (types.MessageID, error) {
	m.mu.Lock()
	m.seq++
	id := types.MessageID(fmt.Sprintf("WA-TXT-%d", m.seq))
	m.texts = append(m.texts, sentTextRecord{ID: id, To: to, Text: text, At: time.Now().UTC()})
	m.mu.Unlock()
	select {
	case m.notifyCh <- "text:" + string(id):
	default:
	}
	return id, nil
}

func (m *mockMessenger) SendPoll(_ context.Context, to types.JID, title string, options []string, _ int) (types.MessageID, error) {
	m.mu.Lock()
	m.seq++
	id := types.MessageID(fmt.Sprintf("WA-POLL-%d", m.seq))
	m.polls = append(m.polls, sentPollRecord{
		ID:      id,
		To:      to,
		Title:   title,
		Options: append([]string(nil), options...),
		At:      time.Now().UTC(),
	})
	m.mu.Unlock()
	select {
	case m.notifyCh <- "poll:" + string(id):
	default:
	}
	return id, nil
}

func (m *mockMessenger) DecryptVote(_ context.Context, vote *events.Message) (*waE2E.PollVoteMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if vote == nil {
		return nil, fmt.Errorf("nil message")
	}
	hashes, ok := m.voteToHashes[vote.Info.ID]
	if !ok {
		return nil, fmt.Errorf("missing simulated poll vote hashes for msg %s", vote.Info.ID)
	}
	return &waE2E.PollVoteMessage{SelectedOptions: hashes}, nil
}

func (m *mockMessenger) ResolveLID(_ context.Context, lid types.JID) types.JID {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lidToPN[lid.ToNonAD().String()]
}

func (m *mockMessenger) setVoteSelection(voteMsgID types.MessageID, optionText string) {
	m.setMultiVoteSelection(voteMsgID, optionText)
}

func (m *mockMessenger) setMultiVoteSelection(voteMsgID types.MessageID, optionTexts ...string) {
	hashes := make([][]byte, 0, len(optionTexts))
	for _, txt := range optionTexts {
		sum := sha256.Sum256([]byte(txt))
		hashes = append(hashes, sum[:])
	}
	m.mu.Lock()
	m.voteToHashes[voteMsgID] = hashes
	m.mu.Unlock()
}

func (m *mockMessenger) Texts() []sentTextRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentTextRecord(nil), m.texts...)
}

func (m *mockMessenger) Polls() []sentPollRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentPollRecord(nil), m.polls...)
}

type spyCommandRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *spyCommandRunner) Execute(_ context.Context, binary string, args []string, _ time.Duration) (*executor.Result, error) {
	r.mu.Lock()
	r.calls = append(r.calls, binary+" "+strings.Join(args, " "))
	r.mu.Unlock()
	return &executor.Result{
		Binary:   binary,
		Args:     args,
		ExitCode: 0,
		Stdout:   "restarted cleanly",
		Duration: 25 * time.Millisecond,
	}, nil
}

func (r *spyCommandRunner) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func setupSentinelHarness(t *testing.T) (*incident.Store, *mcpserver.Server, *reflex.Engine, *approval.Minter, *spyCommandRunner, *httptest.Server) {
	t.Helper()
	tmp := t.TempDir()

	_, privPath, pubPath := func() (string, string, string) {
		p, u, _, err := approval.InitKeys(filepath.Join(tmp, "keys"), false)
		if err != nil {
			t.Fatalf("InitKeys: %v", err)
		}
		return filepath.Join(tmp, "keys"), p, u
	}()

	privKey, err := approval.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	pubKey, err := approval.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	minter, err := approval.NewMinter(privKey, nil)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	store, err := incident.NewStore(filepath.Join(tmp, "sentinel.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	verifier, err := approval.NewVerifier(pubKey, store, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "memory cpu io pids\n")
	mfs.SetFile("/proc/meminfo", "MemTotal: 4194304 kB\nMemAvailable: 2097152 kB\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=1.00 avg60=0.50 avg300=0.10 total=100\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	cg := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	mfs.SetFile(cg+"/memory.current", "262144000\n")
	mfs.SetFile(cg+"/memory.max", "524288000\n")
	mfs.SetFile(cg+"/memory.reclaim", "0\n")

	eng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:           store,
		FS:              mfs,
		Catalog:         cat,
		AdmissionDriver: reflex.NewFSAdmissionDriver(tmp),
	})
	if err != nil {
		t.Fatalf("reflex.NewEngine: %v", err)
	}

	runner := &spyCommandRunner{}
	srv, err := mcpserver.New(mcpserver.Config{
		NodeName:          "pi-wa-test",
		Store:             store,
		Catalog:           cat,
		Reflex:            eng,
		Verifier:          verifier,
		Runner:            runner,
		FS:                mfs,
		BearerToken:       "bridge-test-token",
		HeartbeatInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	handler, err := srv.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	return store, srv, eng, minter, runner, ts
}

func makePollVoteEvent(msgID types.MessageID, pollMsgID types.MessageID, sender, senderAlt types.JID) *events.Message {
	return &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{
				Chat:      sender,
				Sender:    sender,
				SenderAlt: senderAlt,
			},
			ID: msgID,
		},
		Message: &waE2E.Message{
			PollUpdateMessage: &waE2E.PollUpdateMessage{
				PollCreationMessageKey: &waCommon.MessageKey{
					ID: proto.String(string(pollMsgID)),
				},
			},
		},
	}
}

func TestOpenWhatsAppClient_ModerncSQLiteSchemaInit(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "whatsmeow.db")
	client, container, err := OpenWhatsAppClient(context.Background(), dbPath, "ERROR")
	if err != nil {
		t.Fatalf("OpenWhatsAppClient with modernc sqlite failed: %v", err)
	}
	defer func() {
		client.Disconnect()
		_ = container.Close()
	}()

	if client.Store == nil {
		t.Fatalf("expected non-nil whatsmeow device store")
	}
}

func TestAllowlist_PhoneJIDAndLIDResolution(t *testing.T) {
	al := NewAllowlist([]string{"+6281234567890", "1122334455@lid"})
	if al.IsEmpty() {
		t.Fatalf("expected non-empty allowlist")
	}

	// Cocok dengan nomor PN dan device suffix AD (:12)
	pnWithDevice := types.JID{User: "6281234567890", Device: 12, Server: types.DefaultUserServer}
	if ok, _ := al.IsAllowed(pnWithDevice); !ok {
		t.Errorf("expected PN with device suffix to match allowlist")
	}

	// Cocok via SenderAlt saat Sender memakai @lid acak
	unknownLID := types.NewJID("99887766", types.HiddenUserServer)
	if ok, _ := al.IsAllowed(unknownLID); ok {
		t.Errorf("expected unknown LID without SenderAlt to be rejected")
	}
	if ok, _ := al.IsAllowed(unknownLID, pnWithDevice); !ok {
		t.Errorf("expected SenderAlt PN to pass allowlist check")
	}

	// Tolak pengirim liar
	stranger := types.NewJID("6289999999999", types.DefaultUserServer)
	if ok, _ := al.IsAllowed(stranger); ok {
		t.Errorf("expected unauthorized sender to be rejected")
	}
}

func TestOpenWhatsAppClient_LoggerNeverWritesToStdout(t *testing.T) {
	// Tangkap os.Stdout untuk membuktikan logger whatsmeow sama sekali tidak menulis ke stdout (Temuan C6)
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = origStdout
	})

	var logBuf bytes.Buffer
	l := NewWriterLogger("WA-Client", "DEBUG", &logBuf)
	l.Debugf("debug line")
	l.Warnf("warn line")
	l.Sub("Socket").Errorf("sub error line")

	dbPath := filepath.Join(t.TempDir(), "whatsmeow-stderr.db")
	client, container, err := OpenWhatsAppClientWithWriter(context.Background(), dbPath, "WARN", &logBuf)
	if err != nil {
		t.Fatalf("OpenWhatsAppClientWithWriter: %v", err)
	}
	client.Disconnect()
	_ = container.Close()

	_ = w.Close()
	var capturedStdout bytes.Buffer
	_, _ = capturedStdout.ReadFrom(r)
	_ = r.Close()

	if capturedStdout.Len() != 0 {
		t.Fatalf("expected 0 bytes written to os.Stdout, got %q", capturedStdout.String())
	}
	if !strings.Contains(logBuf.String(), "[WA-Client] warn line") || !strings.Contains(logBuf.String(), "[WA-Client/Socket] sub error line") {
		t.Fatalf("expected formatted logs written to designated writer, got %q", logBuf.String())
	}
}

// submitTwoOptionTestPlan mendaftarkan plan 2-opsi yang seluruh targetnya berada di dalam cgroup insiden
// (/franken.slice/haunted-api.service) dan mengutip evidence yang benar-benar tercatat untuk insiden tersebut.
func submitTwoOptionTestPlan(t *testing.T, ctx context.Context, store *incident.Store, sentinelClient *SentinelClient, incID string) string {
	t.Helper()
	evID := "EVD-PLAN-" + incID
	if err := store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
		ID: evID, IncidentID: incID, Kind: "telemetry_sample", RawData: `{"memory_current":490000000}`,
	}); err != nil {
		t.Fatalf("SaveEvidence(%s): %v", evID, err)
	}
	plan := policy.Plan{
		IncidentID:         incID,
		SuspectedRootCause: "Heap growth detected inside haunted-api.service",
		Options: []policy.PlanOption{
			{
				ID:    "A",
				Label: "Graceful PM2 reload",
				Steps: []policy.PlanStep{
					{
						ID:             "step-a1",
						Action:         "pm2_reload",
						Params:         map[string]any{"app": "haunted-api"},
						EvidenceIDs:    []string{evID},
						ExpectedEffect: "Reload haunted-api workers one at a time",
					},
				},
			},
			{
				ID:    "B",
				Label: "Restart the unit",
				Steps: []policy.PlanStep{
					{
						ID:             "step-b1",
						Action:         "unit_restart",
						Params:         map[string]any{"unit": "haunted-api.service"},
						EvidenceIDs:    []string{evID},
						ExpectedEffect: "Restart haunted-api.service",
					},
				},
			},
		},
		HumanFollowUp: []string{"Inspect heap allocation profile"},
	}
	subOut, err := sentinelClient.PlanSubmit(ctx, incID, plan)
	if err != nil {
		t.Fatalf("PlanSubmit(%s): %v", incID, err)
	}
	if !subOut.Valid || subOut.PlanHash == "" {
		t.Fatalf("expected valid plan_submit output for %s, got %+v", incID, subOut)
	}
	return subOut.PlanHash
}

func TestBridge_SSECriticalAlertAndPollFlow_EndToEnd(t *testing.T) {
	store, srv, _, minter, runner, ts := setupSentinelHarness(t)
	messenger := newMockMessenger()

	sentinelClient, err := NewSentinelClient(ts.URL, "bridge-test-token")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = sentinelClient.Close() }()

	adminPhone := "6281234567890"
	bridge, err := New(Config{
		NodeName:       "pi-wa-test",
		AdminAllowlist: []string{"+" + adminPhone},
		Minter:         minter,
		Sentinel:       sentinelClient,
		Messenger:      messenger,
	})
	if err != nil {
		t.Fatalf("wabridge.New: %v", err)
	}

	// Buat insiden kritis P1 dan bukti awal di Sentinel sebelum mempublikasikan SSE
	incID := "INC-WA-E2E-pi-wa-test"
	if err := store.CreateIncident(context.Background(), &incident.Incident{
		ID:       incID,
		Node:     "pi-wa-test",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P1",
		State:    incident.StateDetected,
	}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	_ = store.SaveEvidence(context.Background(), &incident.EvidenceSnapshot{
		ID:         "EVD-01",
		IncidentID: incID,
		Kind:       "telemetry_sample",
		RawData:    `{"memory_current":490000000}`,
	})

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = bridge.Run(runCtx)
	}()

	// 1. Publikasikan event SSE critical P1: Bridge hanya boleh mengirim alert teks pertama (< 2s),
	//    TIDAK BOLEH membuat poll otonom maupun mengeksekusi rencana sendiri (Temuan C1).
	start := time.Now()
	srv.Broker().Publish(mcpserver.StreamEvent{
		Type:       "incident.opened",
		IncidentID: incID,
		Severity:   "P1",
		State:      string(incident.StateDetected),
		Summary:    "TTO < 25s dengan Authorization: Bearer sk-secret999 pada haunted-api.service",
		Data:       map[string]any{"cgroup": "/franken.slice/haunted-api.service"},
	})

	deadline := time.After(2 * time.Second)
	for len(messenger.Texts()) < 1 {
		select {
		case <-messenger.notifyCh:
		case <-deadline:
			t.Fatalf("timed out waiting for <2s alert text (texts=%d)", len(messenger.Texts()))
		}
	}
	if time.Since(start) >= 2*time.Second {
		t.Errorf("first WhatsApp alert exceeded 2s budget: %v", time.Since(start))
	}

	firstTxt := messenger.Texts()[0].Text
	if strings.Contains(firstTxt, "sk-secret999") {
		t.Errorf("WhatsApp alert leaked unredacted secret: %s", firstTxt)
	}
	// Pastikan SSE tidak menciptakan poll otonom maupun memanggil executor
	time.Sleep(100 * time.Millisecond)
	if len(messenger.Polls()) != 0 {
		t.Fatalf("expected 0 autonomous polls on SSE (C1), got %d", len(messenger.Polls()))
	}
	if len(runner.Calls()) != 0 {
		t.Fatalf("expected 0 autonomous runner calls on SSE (C1), got %v", runner.Calls())
	}

	// 2. Kiro Architect mendaftarkan plan 2-opsi di Sentinel (`plan_submit`), lalu Remediator memanggil `SendApprovalPoll`
	planHash := submitTwoOptionTestPlan(t, context.Background(), store, sentinelClient, incID)

	// Pastikan plan_hash yang salah selalu ditolak (Temuan C2)
	if _, badErr := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID: incID,
		PlanHash:   strings.Repeat("0", 64),
	}); !errors.Is(badErr, ErrPlanHashMismatch) {
		t.Fatalf("expected ErrPlanHashMismatch for wrong plan_hash, got %v", badErr)
	}
	// Pastikan ExecuteOnVote=true selalu ditolak (Temuan C1)
	if _, execErr := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID:    incID,
		PlanHash:      planHash,
		ExecuteOnVote: true,
	}); execErr == nil {
		t.Fatalf("expected error when ExecuteOnVote=true")
	}

	pendingPoll, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID: incID,
		PlanHash:   planHash,
		// Meski agent mengirim label palsu, bridge wajib mengabaikannya dan membangun label dari plan Sentinel
		Options: []string{"Fake harmless diagnostics"},
	})
	if err != nil {
		t.Fatalf("SendApprovalPoll: %v", err)
	}

	polls := messenger.Polls()
	if len(polls) != 1 {
		t.Fatalf("expected 1 poll sent, got %d", len(polls))
	}
	poll := polls[0]
	expectedHash8 := planHash[:8]
	if len(poll.Options) != 4 ||
		!strings.Contains(poll.Options[0], "A: pm2_reload haunted-api ["+expectedHash8+"]") ||
		!strings.Contains(poll.Options[1], "B: unit_restart haunted-api.service ["+expectedHash8+"]") ||
		poll.Options[2] != OptionRollbackReflex ||
		poll.Options[3] != OptionDismiss {
		t.Fatalf("unexpected deterministic poll options: %+v", poll.Options)
	}

	// 3. Tolak suara dari pengirim tidak dikenal
	rogueJID := types.NewJID("6280000000001", types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-ROGUE", poll.Options[1])
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-ROGUE", poll.ID, rogueJID, types.EmptyJID))
	if pendingPoll.Resolved {
		t.Fatalf("unauthorized voter must not resolve pending poll")
	}

	// 4. Tolak suara ganda/ambigu (memilih opsi A dan B sekaligus dalam satu PollUpdateMessage)
	adminJID := types.NewJID(adminPhone, types.DefaultUserServer)
	messenger.setMultiVoteSelection("VOTE-MULTI", poll.Options[0], poll.Options[1])
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-MULTI", poll.ID, adminJID, types.EmptyJID))
	if pendingPoll.Resolved {
		t.Fatalf("ambiguous multi-option vote must not resolve poll")
	}

	// 5. Admin memilih OPSI B -> bridge mencetak token KHUSUS untuk opsi B & TIDAK mengeksekusi sendiri
	messenger.setVoteSelection("VOTE-ADMIN-B", poll.Options[1])
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-ADMIN-B", poll.ID, adminJID, types.EmptyJID))

	decision, err := bridge.AwaitDecision(context.Background(), pendingPoll.ApprovalID, 2*time.Second)
	if err != nil {
		t.Fatalf("AwaitDecision: %v", err)
	}
	if decision.Status != "GRANTED" || decision.OptionID != "B" || decision.PlanHash != planHash || !slices.Equal(decision.StepIDs, []string{"step-b1"}) {
		t.Fatalf("expected GRANTED bound strictly to Option B (step-b1), got %+v", decision)
	}
	if len(runner.Calls()) != 0 {
		t.Fatalf("wa-bridge must NOT execute L2 command itself after C1 fix; got calls=%v", runner.Calls())
	}

	// 6. Token opsi B HARUS GAGAL dipakai untuk menjalankan opsi A (`step-a1` / `pm2_reload haunted-api`)!
	_, wrongStepErr := sentinelClient.ActionExecute(context.Background(), mcpserver.ActionExecuteInput{
		IncidentID:    incID,
		StepID:        "step-a1",
		Action:        "pm2_reload",
		Params:        map[string]any{"app": "haunted-api"},
		ApprovalToken: decision.Token,
	})
	if wrongStepErr == nil {
		t.Fatalf("expected Option B token to be rejected when used for Option A (step-a1)")
	}

	// 7. Remediator memanggil `action_execute` dengan step-b1 + token Opsi B -> BERHASIL
	execOut, execErr := sentinelClient.ActionExecute(context.Background(), mcpserver.ActionExecuteInput{
		IncidentID:    incID,
		StepID:        "step-b1",
		Action:        "unit_restart",
		Params:        map[string]any{"unit": "haunted-api.service"},
		ApprovalToken: decision.Token,
	})
	if execErr != nil {
		t.Fatalf("expected ActionExecute for step-b1 to succeed, got %v", execErr)
	}
	if execOut.ExitCode != 0 {
		t.Fatalf("expected exit_code=0, got %+v", execOut)
	}

	calls := runner.Calls()
	if len(calls) != 1 || !strings.Contains(calls[0], "systemctl restart haunted-api.service") {
		t.Fatalf("expected 1 L2 systemctl restart call for haunted-api.service, got %v", calls)
	}

	updatedInc, err := store.GetIncident(context.Background(), incID)
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if updatedInc.State != incident.StateRemediating {
		t.Errorf("expected Sentinel incident state REMEDIATING, got %s", updatedInc.State)
	}
	verifiedCount, err := store.CountAuditByEvent(context.Background(), incID, "ACTION_TOKEN_VERIFIED")
	if err != nil || verifiedCount != 1 {
		t.Errorf("expected ACTION_TOKEN_VERIFIED audit entry=1, got %d (err=%v)", verifiedCount, err)
	}

	// 8. Suara ulang (replay) pada poll yang sama diabaikan
	messenger.setVoteSelection("VOTE-ADMIN-REPLAY", poll.Options[0])
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-ADMIN-REPLAY", poll.ID, adminJID, types.EmptyJID))
	if len(runner.Calls()) != 1 {
		t.Errorf("expected poll replay to be ignored, got %d calls", len(runner.Calls()))
	}
}

func TestBridge_RollbackReflexAndDismissAndTextFallback(t *testing.T) {
	store, _, eng, minter, _, ts := setupSentinelHarness(t)
	messenger := newMockMessenger()

	sentinelClient, err := NewSentinelClient(ts.URL, "bridge-test-token")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = sentinelClient.Close() }()

	adminPhone := "628111222333"
	bridge, err := New(Config{
		NodeName:       "pi-rb",
		AdminAllowlist: []string{adminPhone},
		Minter:         minter,
		Sentinel:       sentinelClient,
		Messenger:      messenger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Kasus A: "Rollback Reflex" melalui Poll Vote memulihkan aksi refleks L1 di Sentinel
	incA := "INC-RB-01"
	_ = store.CreateIncident(context.Background(), &incident.Incident{
		ID: incA, Node: "pi-rb", Cgroup: "/franken.slice/haunted-api.service", Severity: "P2", State: incident.StateDetected,
	})
	act, err := eng.ApplyAdmissionClose(context.Background(), reflex.AdmissionRequest{
		IncidentID: incA, App: "haunted-api", TTLSeconds: 120,
	})
	if err != nil {
		t.Fatalf("ApplyAdmissionClose: %v", err)
	}
	planHashA := submitTwoOptionTestPlan(t, context.Background(), store, sentinelClient, incA)

	pollA, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID: incA,
		PlanHash:   planHashA,
		Cgroup:     "/franken.slice/haunted-api.service",
	})
	if err != nil {
		t.Fatalf("SendApprovalPoll A: %v", err)
	}

	adminJID := types.NewJID(adminPhone, types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-RB", OptionRollbackReflex)
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-RB", pollA.PollMessageID, adminJID, types.EmptyJID))

	updatedAct, err := store.GetReflexAction(context.Background(), act.ID)
	if err != nil {
		t.Fatalf("GetReflexAction: %v", err)
	}
	if updatedAct.Status != "ROLLED_BACK" {
		t.Errorf("expected reflex status ROLLED_BACK, got %s", updatedAct.Status)
	}

	// Kasus B: Fallback teks ambigu `APPROVE <CODE>` pada poll multi-opsi ditolak; `APPROVE B <CODE>` mengikat ke Opsi B
	incMulti := "INC-MULTI-02"
	_ = store.CreateIncident(context.Background(), &incident.Incident{
		ID: incMulti, Node: "pi-rb", Cgroup: "/franken.slice/haunted-api.service", Severity: "P2", State: incident.StateDetected,
	})
	planHashMulti := submitTwoOptionTestPlan(t, context.Background(), store, sentinelClient, incMulti)
	pollMulti, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID: incMulti,
		PlanHash:   planHashMulti,
	})
	if err != nil {
		t.Fatalf("SendApprovalPoll multi: %v", err)
	}

	// `APPROVE <shortCode>` tanpa huruf opsi wajib ditolak saat > 1 opsi tersedia
	bridge.HandleWhatsAppEvent(context.Background(), &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: adminJID, Sender: adminJID},
			ID:            "TXT-AMBIG",
		},
		Message: &waE2E.Message{Conversation: proto.String("APPROVE " + pollMulti.ShortCode)},
	})
	if pollMulti.Resolved {
		t.Fatalf("ambiguous `APPROVE <shortCode>` must NOT resolve multi-option poll")
	}

	// `APPROVE B <shortCode>` mengikat persis ke Opsi B (`step-b1`)
	bridge.HandleWhatsAppEvent(context.Background(), &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: adminJID, Sender: adminJID},
			ID:            "TXT-EXPLICIT-B",
		},
		Message: &waE2E.Message{Conversation: proto.String("APPROVE B " + pollMulti.ShortCode)},
	})
	decMulti, err := bridge.AwaitDecision(context.Background(), pollMulti.ApprovalID, 2*time.Second)
	if err != nil || decMulti.Status != "GRANTED" || decMulti.OptionID != "B" || !slices.Equal(decMulti.StepIDs, []string{"step-b1"}) {
		t.Fatalf("expected explicit APPROVE B decision bound to step-b1, got %+v (err=%v)", decMulti, err)
	}

	// Kasus C: Fallback perintah teks "DISMISS <shortCode>" memindahkan insiden menjadi DISMISSED
	incB := "INC-DISMISS-02"
	_ = store.CreateIncident(context.Background(), &incident.Incident{
		ID: incB, Node: "pi-rb", Cgroup: "/franken.slice/haunted-api.service", Severity: "P2", State: incident.StateDetected,
	})
	planHashB := submitTwoOptionTestPlan(t, context.Background(), store, sentinelClient, incB)
	pollB, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID: incB,
		PlanHash:   planHashB,
		Cgroup:     "/franken.slice/haunted-api.service",
	})
	if err != nil {
		t.Fatalf("SendApprovalPoll B: %v", err)
	}

	bridge.HandleWhatsAppEvent(context.Background(), &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: adminJID, Sender: adminJID},
			ID:            "TXT-DISMISS",
		},
		Message: &waE2E.Message{
			Conversation: proto.String("DISMISS " + pollB.ShortCode),
		},
	})

	dismissedInc, err := store.GetIncident(context.Background(), incB)
	if err != nil {
		t.Fatalf("GetIncident incB: %v", err)
	}
	if dismissedInc.State != incident.StateDismissed {
		t.Errorf("expected DISMISSED state via text fallback, got %s", dismissedInc.State)
	}
}

func TestBridge_PollPlanChangedBeforeVote_Rejected(t *testing.T) {
	store, _, _, minter, _, ts := setupSentinelHarness(t)
	messenger := newMockMessenger()
	sentinelClient, err := NewSentinelClient(ts.URL, "bridge-test-token")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = sentinelClient.Close() }()

	adminPhone := "6281234567890"
	bridge, err := New(Config{
		NodeName:       "pi-stale",
		AdminAllowlist: []string{adminPhone},
		Minter:         minter,
		Sentinel:       sentinelClient,
		Messenger:      messenger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	incID := "INC-STALE-PLAN"
	_ = store.CreateIncident(context.Background(), &incident.Incident{
		ID: incID, Node: "pi-stale", Cgroup: "/franken.slice/haunted-api.service", Severity: "P1", State: incident.StateDetected,
	})
	planHashV1 := submitTwoOptionTestPlan(t, context.Background(), store, sentinelClient, incID)

	poll, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID: incID,
		PlanHash:   planHashV1,
	})
	if err != nil {
		t.Fatalf("SendApprovalPoll: %v", err)
	}

	// Simulasikan plan di Sentinel ditimpa dengan target lain setelah poll terkirim ke WhatsApp
	changedPlan := policy.Plan{
		IncidentID:         incID,
		SuspectedRootCause: "Replaced plan after poll creation",
		Options: []policy.PlanOption{
			{
				ID:    "A",
				Label: "Replaced target",
				Steps: []policy.PlanStep{
					{
						ID:             "step-a1",
						Action:         "unit_restart",
						Params:         map[string]any{"unit": "evil-other.service"},
						EvidenceIDs:    []string{"EVD-01"},
						ExpectedEffect: "Restart evil-other.service",
					},
				},
			},
		},
		HumanFollowUp: []string{"Inspect"},
	}
	canon, _ := policy.CanonicalJSON(changedPlan)
	if err := store.SavePlan(context.Background(), incID, string(canon)); err != nil {
		t.Fatalf("SavePlan overwrite: %v", err)
	}

	adminJID := types.NewJID(adminPhone, types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-STALE", poll.Options[0].Label)
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-STALE", poll.PollMessageID, adminJID, types.EmptyJID))

	dec, err := bridge.AwaitDecision(context.Background(), poll.ApprovalID, 2*time.Second)
	if err != nil {
		t.Fatalf("AwaitDecision: %v", err)
	}
	if dec.Status != "DENIED" || dec.Token != "" {
		t.Fatalf("expected stale plan vote to be DENIED with empty token, got %+v", dec)
	}
}

func TestBridge_HeartbeatMonitor_ThreeMissedSendsNodeSilentAlert(t *testing.T) {
	_, _, _, minter, _, ts := setupSentinelHarness(t)
	messenger := newMockMessenger()

	// Simulasikan Sentinel mati dengan menutup HTTP server uji
	deadURL := ts.URL
	ts.Close()

	sentinelClient, err := NewSentinelClient(deadURL, "bridge-test-token")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = sentinelClient.Close() }()

	var mu sync.Mutex
	baseNow := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	curNow := baseNow

	bridge, err := New(Config{
		NodeName:            "pi-dead",
		AdminAllowlist:      []string{"6281234567890"},
		Minter:              minter,
		Sentinel:            sentinelClient,
		Messenger:           messenger,
		HeartbeatInterval:   15 * time.Second,
		MaxMissedHeartbeats: 3,
		Clock: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return curNow
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Lewatkan 3 jendela 15 detik: alert harus muncul TEPAT pada missed ke-3 (45 detik)
	for i := 1; i <= 4; i++ {
		mu.Lock()
		curNow = baseNow.Add(time.Duration(i*15) * time.Second)
		mu.Unlock()
		bridge.CheckHeartbeatOnce(context.Background())

		texts := messenger.Texts()
		if i < 3 && len(texts) != 0 {
			t.Fatalf("expected 0 Node Silent Alert before 3 missed heartbeats (step=%d), got %d", i, len(texts))
		}
		if i >= 3 && len(texts) != 1 {
			t.Fatalf("expected exactly 1 deduplicated Node Silent Alert at step=%d, got %d", i, len(texts))
		}
	}

	if !strings.Contains(messenger.Texts()[0].Text, "Node Silent Alert") {
		t.Errorf("expected 'Node Silent Alert' prefix, got: %s", messenger.Texts()[0].Text)
	}
}

func TestBridge_RateLimitAndMCPStdioTools(t *testing.T) {
	store, _, _, minter, _, ts := setupSentinelHarness(t)
	messenger := newMockMessenger()
	sentinelClient, err := NewSentinelClient(ts.URL, "bridge-test-token")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = sentinelClient.Close() }()

	adminPhone := "628555666777"
	bridge, err := New(Config{
		NodeName:       "pi-mcp",
		AdminAllowlist: []string{adminPhone},
		Minter:         minter,
		Sentinel:       sentinelClient,
		Messenger:      messenger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv := bridge.NewMCPServer()
	tClient, tServer := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var serverDone atomic.Bool
	go func() {
		_ = srv.Run(ctx, tServer)
		serverDone.Store(true)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-crew", Version: "1.0"}, nil)
	sess, err := client.Connect(ctx, tClient, nil)
	if err != nil {
		t.Fatalf("connect in-memory wa-bridge MCP: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// 1. Uji wa_notify hingga melebihi batas 6 pesan per insiden
	for i := 1; i <= MaxMessagesPerIncident; i++ {
		res, callErr := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "wa_notify",
			Arguments: map[string]any{"incident_id": "INC-RATE-1", "severity": "P2", "text": fmt.Sprintf("msg %d", i)},
		})
		if callErr != nil || res.IsError {
			t.Fatalf("wa_notify #%d failed unexpectedly: %v", i, callErr)
		}
	}
	resOver, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "wa_notify",
		Arguments: map[string]any{"incident_id": "INC-RATE-1", "severity": "P2", "text": "msg 7 over cap"},
	})
	if err == nil && !resOver.IsError {
		t.Errorf("expected 7th message on same incident to hit 6/incident rate limit")
	}

	// 2. Uji wa_request_approval wajib menolak plan_hash tidak valid & menerima plan_hash kanonik Sentinel
	_ = store.CreateIncident(ctx, &incident.Incident{
		ID:       "INC-MCP-WAIT",
		Node:     "pi-mcp",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P1",
		State:    incident.StateDetected,
	})
	validPlanHash := submitTwoOptionTestPlan(t, ctx, store, sentinelClient, "INC-MCP-WAIT")

	badRes, badErr := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "wa_request_approval",
		Arguments: map[string]any{
			"incident_id": "INC-MCP-WAIT",
			"plan_hash":   "abc123",
			"options":     []string{"Spoofed label"},
		},
	})
	if badErr == nil && !badRes.IsError {
		t.Fatalf("expected wa_request_approval with mismatched plan_hash to fail")
	}

	reqRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "wa_request_approval",
		Arguments: map[string]any{
			"incident_id": "INC-MCP-WAIT",
			"plan_hash":   validPlanHash,
			"options":     []string{"Spoofed harmless text"},
		},
	})
	if err != nil || reqRes.IsError {
		t.Fatalf("wa_request_approval failed: %v", err)
	}

	raw, _ := json.Marshal(reqRes.StructuredContent)
	var reqOut WARequestApprovalOutput
	if err := json.Unmarshal(raw, &reqOut); err != nil {
		t.Fatalf("decode wa_request_approval output: %v", err)
	}
	if reqOut.ApprovalID == "" || reqOut.ShortCode == "" {
		t.Fatalf("missing approval metadata: %+v", reqOut)
	}

	// Pastikan label poll disusun dari plan tersimpan, bukan teks spoof agent
	sentPolls := messenger.Polls()
	lastPoll := sentPolls[len(sentPolls)-1]
	if strings.Contains(strings.Join(lastPoll.Options, ","), "Spoofed harmless text") {
		t.Fatalf("poll leaked untrusted agent option label: %+v", lastPoll.Options)
	}
	if !strings.Contains(lastPoll.Options[0], "A: pm2_reload haunted-api ["+validPlanHash[:8]+"]") {
		t.Fatalf("expected option A from stored plan, got %+v", lastPoll.Options)
	}

	// Timeout singkat -> EXPIRED
	waitRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "wa_await_decision",
		Arguments: map[string]any{"approval_id": reqOut.ApprovalID, "timeout_seconds": 1},
	})
	if err != nil || waitRes.IsError {
		t.Fatalf("wa_await_decision failed: %v", err)
	}
}

func TestProperty_VoteToTokenExactBinding(t *testing.T) {
	store, _, _, _, _, ts := setupSentinelHarness(t)
	defer ts.Close()
	sentinelClient, err := NewSentinelClient(ts.URL, "bridge-test-token")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = sentinelClient.Close() }()

	// Bangkitkan pasangan kunci Ed25519 terhubung untuk Minter & Verifier PBT
	privPath, pubPath, _, err := approval.InitKeys(filepath.Join(t.TempDir(), "pbt-keys"), false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	privKey, err := approval.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	pubKey, err := approval.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	minter, err := approval.NewMinter(privKey, nil)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	verifier, err := approval.NewVerifier(pubKey, store, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	var incSeq atomic.Int64
	rapid.Check(t, func(rt *rapid.T) {
		messenger := newMockMessenger()
		adminPhone := fmt.Sprintf("628%09d", rapid.IntRange(100000000, 999999999).Draw(rt, "adminPhone"))
		bridge, err := New(Config{
			NodeName:       "pi-pbt",
			AdminAllowlist: []string{adminPhone},
			Minter:         minter,
			Sentinel:       sentinelClient,
			Messenger:      messenger,
		})
		if err != nil {
			rt.Fatalf("wabridge.New: %v", err)
		}

		numOpts := rapid.IntRange(2, 4).Draw(rt, "numOpts")
		chosenIdx := rapid.IntRange(0, numOpts-1).Draw(rt, "chosenIdx")
		incID := fmt.Sprintf("INC-PBT-%d-%d", incSeq.Add(1), rapid.IntRange(10, 99).Draw(rt, "incSalt"))
		// Insiden berada di unit daemon PM2 sehingga setiap aplikasi PM2 acak tetap di dalam cgroup insiden
		if err := store.CreateIncident(context.Background(), &incident.Incident{
			ID:       incID,
			Node:     "pi-pbt",
			Cgroup:   "/system.slice/pm2-pi.service",
			Severity: "P1",
			State:    incident.StateDetected,
		}); err != nil {
			rt.Fatalf("CreateIncident: %v", err)
		}
		if err := store.SaveEvidence(context.Background(), &incident.EvidenceSnapshot{
			ID: "EVD-PBT-" + incID, IncidentID: incID, Kind: "telemetry_sample", RawData: `{"memory_current":1}`,
		}); err != nil {
			rt.Fatalf("SaveEvidence: %v", err)
		}

		optLetters := []string{"A", "B", "C", "D"}
		planOpts := make([]policy.PlanOption, 0, numOpts)
		for i := 0; i < numOpts; i++ {
			id := optLetters[i]
			usePM2 := rapid.Bool().Draw(rt, fmt.Sprintf("pm2_%d", i))
			stepID := fmt.Sprintf("step-%s-%d", strings.ToLower(id), rapid.IntRange(10, 999).Draw(rt, fmt.Sprintf("step_%d", i)))
			var st policy.PlanStep
			if usePM2 {
				appName := fmt.Sprintf("api-%s-%d", strings.ToLower(id), i)
				st = policy.PlanStep{
					ID:             stepID,
					Action:         "pm2_reload",
					Params:         map[string]any{"app": appName},
					EvidenceIDs:    []string{"EVD-PBT-" + incID},
					ExpectedEffect: "Reload " + appName,
				}
			} else {
				appName := fmt.Sprintf("api-%s-%d", strings.ToLower(id), i)
				st = policy.PlanStep{
					ID:             stepID,
					Action:         "pm2_restart_instance",
					Params:         map[string]any{"app": appName, "pm_id": i},
					EvidenceIDs:    []string{"EVD-PBT-" + incID},
					ExpectedEffect: "Restart one worker of " + appName,
				}
			}
			planOpts = append(planOpts, policy.PlanOption{
				ID:    id,
				Label: "Candidate " + id,
				Steps: []policy.PlanStep{st},
			})
		}

		plan := policy.Plan{
			IncidentID:         incID,
			SuspectedRootCause: "Property test multi-option binding verification",
			Options:            planOpts,
			HumanFollowUp:      []string{"Inspect"},
		}
		subOut, err := sentinelClient.PlanSubmit(context.Background(), incID, plan)
		if err != nil || !subOut.Valid {
			rt.Fatalf("PlanSubmit failed: %v %+v", err, subOut)
		}

		pendingPoll, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
			IncidentID: incID,
			PlanHash:   subOut.PlanHash,
		})
		if err != nil {
			rt.Fatalf("SendApprovalPoll: %v", err)
		}

		// Vote pada opsi indeks ke-`chosenIdx`
		adminJID := types.NewJID(adminPhone, types.DefaultUserServer)
		voteID := types.MessageID("VOTE-PBT-" + optLetters[chosenIdx])
		chosenLabel := pendingPoll.Options[chosenIdx].Label
		if !strings.Contains(chosenLabel, optLetters[chosenIdx]+": ") || !strings.Contains(chosenLabel, subOut.PlanHash[:8]) {
			rt.Fatalf("option label missing ID or hash tag: %q", chosenLabel)
		}

		messenger.setVoteSelection(voteID, chosenLabel)
		bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent(voteID, pendingPoll.PollMessageID, adminJID, types.EmptyJID))

		dec, err := bridge.AwaitDecision(context.Background(), pendingPoll.ApprovalID, 2*time.Second)
		if err != nil {
			rt.Fatalf("AwaitDecision: %v", err)
		}
		expectedOpt := planOpts[chosenIdx]
		expectedStep := expectedOpt.Steps[0]

		if dec.Status != "GRANTED" || dec.OptionID != expectedOpt.ID || dec.PlanHash != subOut.PlanHash || !slices.Equal(dec.StepIDs, []string{expectedStep.ID}) {
			rt.Fatalf("vote-to-decision binding mismatch: want opt=%s step=%s, got %+v", expectedOpt.ID, expectedStep.ID, dec)
		}

		// Pastikan verifier menolak SEMUA opsi j != chosenIdx (tanpa mengonsumsi nonce) dan menerima persis opsi chosenIdx
		for j, otherOpt := range planOpts {
			if j == chosenIdx {
				continue
			}
			_, rejErr := verifier.VerifyAndConsume(context.Background(), dec.Token, approval.VerifyContext{
				IncidentID: incID,
				PlanHash:   subOut.PlanHash,
				ActionName: otherOpt.Steps[0].Action,
				OptionID:   otherOpt.ID,
				StepID:     otherOpt.Steps[0].ID,
			})
			if rejErr == nil {
				rt.Fatalf("token for option %s unexpectedly accepted for option %s", expectedOpt.ID, otherOpt.ID)
			}
		}

		claims, okErr := verifier.VerifyAndConsume(context.Background(), dec.Token, approval.VerifyContext{
			IncidentID: incID,
			PlanHash:   subOut.PlanHash,
			ActionName: expectedStep.Action,
			OptionID:   expectedOpt.ID,
			StepID:     expectedStep.ID,
		})
		if okErr != nil {
			rt.Fatalf("expected token to verify strictly for option %s (%s): %v", expectedOpt.ID, expectedStep.ID, okErr)
		}
		if claims.OptionID != expectedOpt.ID || !slices.Contains(claims.StepIDs, expectedStep.ID) {
			rt.Fatalf("token claims mismatch: %+v", claims)
		}
	})
}
