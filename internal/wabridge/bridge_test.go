package wabridge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
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
	sum := sha256.Sum256([]byte(optionText))
	m.mu.Lock()
	m.voteToHashes[voteMsgID] = [][]byte{sum[:]}
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
	incID := "INC-20261113-1000-pi-wa-test"
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

	// Publikasikan event SSE critical P1 dan ukur latensi alert pertama (< 2 detik)
	start := time.Now()
	srv.Broker().Publish(mcpserver.StreamEvent{
		Type:       "incident.opened",
		IncidentID: incID,
		Severity:   "P1",
		State:      string(incident.StateDetected),
		Summary:    "TTO < 25s dengan Authorization: Bearer sk-secret999 pada haunted-api.service",
		Data:       map[string]any{"cgroup": "/franken.slice/haunted-api.service"},
	})

	// Tunggu text alert pertama dan poll persetujuan dikirim via WhatsApp messenger
	deadline := time.After(2 * time.Second)
	for len(messenger.Texts()) < 1 || len(messenger.Polls()) < 1 {
		select {
		case <-messenger.notifyCh:
		case <-deadline:
			t.Fatalf("timed out waiting for <2s alert + poll (texts=%d, polls=%d)", len(messenger.Texts()), len(messenger.Polls()))
		}
	}
	if time.Since(start) >= 2*time.Second {
		t.Errorf("first WhatsApp alert exceeded 2s budget: %v", time.Since(start))
	}

	firstTxt := messenger.Texts()[0].Text
	if strings.Contains(firstTxt, "sk-secret999") {
		t.Errorf("WhatsApp alert leaked unredacted secret: %s", firstTxt)
	}

	poll := messenger.Polls()[0]
	if len(poll.Options) != 3 ||
		poll.Options[0] != OptionApproveL2Restart ||
		poll.Options[1] != OptionRollbackReflex ||
		poll.Options[2] != OptionDismiss {
		t.Fatalf("unexpected native poll options: %+v", poll.Options)
	}

	// 1. Uji penolakan suara dari pengirim tidak dikenal (bukan allowlist admin)
	rogueJID := types.NewJID("6280000000001", types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-ROGUE", OptionApproveL2Restart)
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-ROGUE", poll.ID, rogueJID, types.EmptyJID))
	if len(runner.Calls()) != 0 {
		t.Fatalf("unauthorized voter triggered L2 execution: %v", runner.Calls())
	}

	// 2. Uji persetujuan dari admin allowlisted -> mint Ed25519 token -> MCP `action_execute`
	adminJID := types.NewJID(adminPhone, types.DefaultUserServer)
	messenger.setVoteSelection("VOTE-ADMIN-1", OptionApproveL2Restart)
	bridge.HandleWhatsAppEvent(context.Background(), makePollVoteEvent("VOTE-ADMIN-1", poll.ID, adminJID, types.EmptyJID))

	calls := runner.Calls()
	if len(calls) != 1 || !strings.Contains(calls[0], "systemctl restart haunted-api.service") {
		t.Fatalf("expected 1 L2 systemctl restart call on Sentinel, got %v", calls)
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

	// 3. Pastikan suara ulang (replay) pada poll yang sama diabaikan
	messenger.setVoteSelection("VOTE-ADMIN-REPLAY", OptionApproveL2Restart)
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

	pollA, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID:    incA,
		Cgroup:        "/franken.slice/haunted-api.service",
		ExecuteOnVote: true,
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

	// Kasus B: Fallback perintah teks "DISMISS <shortCode>" memindahkan insiden menjadi DISMISSED
	incB := "INC-DISMISS-02"
	_ = store.CreateIncident(context.Background(), &incident.Incident{
		ID: incB, Node: "pi-rb", Cgroup: "/franken.slice/haunted-api.service", Severity: "P2", State: incident.StateDetected,
	})
	pollB, err := bridge.SendApprovalPoll(context.Background(), PollRequest{
		IncidentID:    incB,
		Cgroup:        "/franken.slice/haunted-api.service",
		ExecuteOnVote: true,
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
	_, _, _, minter, _, ts := setupSentinelHarness(t)
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

	// 2. Uji wa_request_approval & wa_await_decision -> mint token
	reqRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "wa_request_approval",
		Arguments: map[string]any{
			"incident_id": "INC-MCP-WAIT",
			"plan_hash":   "abc123",
			"options":     []string{"Approve L2 Restart", "Dismiss"},
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

	// Timeout singkat -> EXPIRED
	waitRes, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "wa_await_decision",
		Arguments: map[string]any{"approval_id": reqOut.ApprovalID, "timeout_seconds": 1},
	})
	if err != nil || waitRes.IsError {
		t.Fatalf("wa_await_decision failed: %v", err)
	}
}

