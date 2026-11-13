package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/wabridge"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

func TestWABridgeCLI_ValidationAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// 1. Uji `--help`
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "wa-bridge") {
		t.Fatalf("expected help exit 0, got %d (out=%q err=%q)", code, stdout.String(), stderr.String())
	}

	// 2. Tanpa bearer token wajib ditolak
	stdout.Reset()
	stderr.Reset()
	t.Setenv("WA_BRIDGE_EMPTY_TOK", "")
	code = run([]string{"serve", "--token-env", "WA_BRIDGE_EMPTY_TOK", "--admins", "6281234567890"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "bearer token") {
		t.Fatalf("expected error on missing bearer token, got %d (stderr=%s)", code, stderr.String())
	}

	// 3. Tanpa admin allowlist wajib ditolak (fail-closed)
	stdout.Reset()
	stderr.Reset()
	t.Setenv("WA_BRIDGE_TEST_TOK", "secret-tok")
	t.Setenv("FRANKEN_WA_ADMINS", "")
	code = run([]string{"serve", "--token-env", "WA_BRIDGE_TEST_TOK"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "allowlist") {
		t.Fatalf("expected error when admin allowlist missing, got %d (stderr=%s)", code, stderr.String())
	}

	// 4. Sesi WhatsApp belum pairing QR wajib meminta pengguna menjalankan `franken wa-login`
	tmp := t.TempDir()
	privPath, _, _, err := approval.InitKeys(filepath.Join(tmp, "keys"), false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	waDB := filepath.Join(tmp, "unpaired.db")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"serve",
		"--token-env", "WA_BRIDGE_TEST_TOK",
		"--admins", "+6281234567890",
		"--priv-key", privPath,
		"--wa-db", waDB,
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "franken wa-login") {
		t.Fatalf("expected unpaired session guidance mentioning franken wa-login, got %d (stderr=%s)", code, stderr.String())
	}

	// 5. Alamat bind tidak aman wajib ditolak pada mode serve maupun proxy
	if _, err := validateBridgeBaseURL("http://8.8.8.8:8091"); err == nil {
		t.Errorf("expected plain HTTP public host bridge-url to be rejected")
	}
	if _, err := validateBridgeBaseURL("http://127.0.0.1:8091"); err != nil {
		t.Errorf("expected loopback bridge-url to be accepted, got %v", err)
	}
}

func TestWABridge_HandleLifecycleEvents_StreamReplacedAndLoggedOutFatal(t *testing.T) {
	// Uji kedua event putus permanen WhatsApp (StreamReplaced & LoggedOut) wajib memicu fatal callback + stderr
	cases := []struct {
		name      string
		evt       any
		wantInErr string
	}{
		{
			name:      "StreamReplaced",
			evt:       &events.StreamReplaced{},
			wantInErr: "replaced",
		},
		{
			name:      "LoggedOut",
			evt:       &events.LoggedOut{OnConnect: true},
			wantInErr: "logged out",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			var gotErr error
			handleWhatsAppLifecycleEvent(context.Background(), tc.evt, nil, &stderr, func(err error) {
				gotErr = err
			})
			if gotErr == nil || !strings.Contains(strings.ToLower(gotErr.Error()), tc.wantInErr) {
				t.Fatalf("expected fatal error mentioning %q, got %v", tc.wantInErr, gotErr)
			}
			if !strings.Contains(stderr.String(), "[wa-bridge] FATAL:") {
				t.Fatalf("expected FATAL log in stderr, got %q", stderr.String())
			}
		})
	}
}

type fakeMessenger struct {
	sentTexts []string
}

func (f *fakeMessenger) SendText(_ context.Context, _ types.JID, text string) (types.MessageID, error) {
	f.sentTexts = append(f.sentTexts, text)
	return "MSG-PROXY-1", nil
}

func (f *fakeMessenger) SendPoll(_ context.Context, _ types.JID, _ string, _ []string, _ int) (types.MessageID, error) {
	return "POLL-PROXY-1", nil
}

func (f *fakeMessenger) DecryptVote(_ context.Context, _ *events.Message) (*waE2E.PollVoteMessage, error) {
	return nil, nil
}

func (f *fakeMessenger) ResolveLID(_ context.Context, _ types.JID) types.JID {
	return types.EmptyJID
}

func TestWABridge_MCPStdioProxy_SingleOwnerHTTP(t *testing.T) {
	// Uji `wa-bridge mcp` berjalan tanpa membuka SQLite WA maupun koneksi WhatsApp kedua (Temuan C6)
	tmp := t.TempDir()
	privPath, _, _, err := approval.InitKeys(filepath.Join(tmp, "keys"), false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	privKey, err := approval.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	minter, err := approval.NewMinter(privKey, nil)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	sentinelClient, err := wabridge.NewSentinelClient("http://127.0.0.1:8090", "tok-test")
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = sentinelClient.Close() }()

	messenger := &fakeMessenger{}
	bridge, err := wabridge.New(wabridge.Config{
		NodeName:       "pi-single",
		AdminAllowlist: []string{"6281234567890"},
		Minter:         minter,
		Sentinel:       sentinelClient,
		Messenger:      messenger,
	})
	if err != nil {
		t.Fatalf("wabridge.New: %v", err)
	}

	httpSrv := httptest.NewServer(buildServeHTTPHandler(bridge, "pi-single", "proxy-secret-tok"))
	defer httpSrv.Close()

	// Pastikan `/mcp` menolak akses tanpa Bearer token
	unauthResp, err := http.Post(httpSrv.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("unauthenticated POST /mcp: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without bearer token, got %d", unauthResp.StatusCode)
	}

	t.Setenv("WA_BRIDGE_PROXY_TOK", "proxy-secret-tok")
	tClient, tServer := mcp.NewInMemoryTransports()
	var stderr bytes.Buffer
	doneCh := make(chan int, 1)
	go func() {
		doneCh <- runMCPStdioWithTransport([]string{
			"--bridge-url", httpSrv.URL,
			"--token-env", "WA_BRIDGE_PROXY_TOK",
		}, tServer, &stderr)
	}()

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-kiro", Version: "1.0"}, nil)
	sess, err := client.Connect(ctx, tClient, nil)
	if err != nil {
		t.Fatalf("connect stdio proxy transport: %v", err)
	}

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "wa_notify",
		Arguments: map[string]any{
			"incident_id": "INC-PROXY-01",
			"severity":    "P1",
			"text":        "single-owner delivery verified",
		},
	})
	if err != nil || res.IsError {
		t.Fatalf("proxy call wa_notify failed: err=%v res=%+v stderr=%s", err, res, stderr.String())
	}
	_ = sess.Close()

	code := <-doneCh
	if code != 0 {
		t.Fatalf("expected runMCPStdioWithTransport exit 0, got %d (stderr=%s)", code, stderr.String())
	}
	if len(messenger.sentTexts) != 1 || !strings.Contains(messenger.sentTexts[0], "single-owner delivery verified") {
		t.Fatalf("expected single-owner serve messenger to receive proxied notification, got %+v", messenger.sentTexts)
	}
}

