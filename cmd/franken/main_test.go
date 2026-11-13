package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

func TestCLI_KeysInitCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "franken-keys")
	var stdout, stderr bytes.Buffer

	// 1. Uji perintah `franken keys init --dir <dir>`
	code := run([]string{"keys", "init", "--dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%s)", code, stderr.String())
	}

	out := stdout.String()
	privPath := filepath.Join(dir, approval.DefaultPrivateKeyName)
	pubPath := filepath.Join(dir, approval.DefaultPublicKeyName)
	if !strings.Contains(out, privPath) || !strings.Contains(out, pubPath) {
		t.Errorf("expected key paths in stdout, got: %s", out)
	}

	// Pastikan kunci yang dihasilkan valid dan dapat dimuat kembali
	if _, err := approval.LoadPrivateKey(privPath); err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	if _, err := approval.LoadPublicKey(pubPath); err != nil {
		t.Fatalf("LoadPublicKey failed: %v", err)
	}

	// 2. Jalankan ulang tanpa --force wajib gagal (exit code 1)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"keys", "init", "--dir", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 when overwriting without --force, got %d", code)
	}

	// 3. Jalankan ulang dengan --force wajib sukses
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"keys", "init", "--dir", dir, "--force"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 with --force, got %d (stderr=%s)", code, stderr.String())
	}

	// 4. Argumen tidak dikenal wajib mengembalikan exit code 2
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown command, got %d", code)
	}
}

func TestCLI_MCPServeSecurityChecks(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Tanpa bearer token pada env var wajib menolak startup (exit code 1)
	t.Setenv("FRANKEN_TEST_EMPTY_TOKEN", "")
	code := run([]string{"mcp", "serve", "--token-env", "FRANKEN_TEST_EMPTY_TOKEN"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 when bearer token is empty, got %d (stderr=%s)", code, stderr.String())
	}

	// Alamat bind wildcard 0.0.0.0 wajib ditolak sebelum membuka socket
	stdout.Reset()
	stderr.Reset()
	t.Setenv("FRANKEN_TEST_TOKEN", "valid-test-bearer")
	code = run([]string{"mcp", "serve", "--token-env", "FRANKEN_TEST_TOKEN", "--listen", "0.0.0.0:8090"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "unsafe bind address") {
		t.Fatalf("expected exit code 1 with unsafe bind address error, got %d (stderr=%s)", code, stderr.String())
	}
}

func TestCLI_GuardPreToolUseAndAuditRedaction(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	policyPath := filepath.Join("..", "..", "policy", "actions.yaml")

	cases := []struct {
		name     string
		payload  string
		wantCode int
	}{
		{
			name:     "Allow L0 read tool",
			payload:  `{"tool_name":"@franken-sentinel/node_snapshot","tool_input":{"incident_id":"INC-GUARD-1"}}`,
			wantCode: 0,
		},
		{
			name:     "Block execute_bash raw shell",
			payload:  `{"tool_name":"execute_bash","tool_input":{"command":"bash -c 'rm -rf /'"}}`,
			wantCode: 2,
		},
		{
			name:     "Block L3 action_execute",
			payload:  `{"tool_name":"@franken-sentinel/action_execute","tool_input":{"action":"global_drop_caches"}}`,
			wantCode: 2,
		},
		{
			name:     "Block protected unit sshd.service",
			payload:  `{"tool_name":"@franken-sentinel/action_execute","tool_input":{"action":"unit_restart","unit":"sshd.service","approval_token":"tok"}}`,
			wantCode: 2,
		},
		{
			name:     "Block protected PID 1 inside plan_submit",
			payload:  `{"tool_name":"@franken-sentinel/plan_submit","tool_input":{"incident_id":"INC-GUARD-1","steps":[{"action":"process_terminate","params":{"pid":1}}]}}`,
			wantCode: 2,
		},
		{
			name:     "Block L2 action_execute missing approval_token",
			payload:  `{"tool_name":"@franken-sentinel/action_execute","tool_input":{"action":"unit_restart","unit":"haunted-api.service"}}`,
			wantCode: 2,
		},
		{
			name:     "Allow L2 action_execute with approval_token and redact secret",
			payload:  `{"tool_name":"@franken-sentinel/action_execute","tool_input":{"incident_id":"INC-GUARD-1","action":"unit_restart","unit":"haunted-api.service","approval_token":"ed25519.sig","note":"Authorization: Bearer sk-secretToken998877"}}`,
			wantCode: 0,
		},
		{
			name:     "Block Kiro V3 mcp_franken-sentinel_action_execute missing approval_token",
			payload:  `{"tool_name":"mcp_franken-sentinel_action_execute","tool_input":{"action":"unit_restart","unit":"haunted-api.service"}}`,
			wantCode: 2,
		},
		{
			name:     "Block Kiro V3 mcp_franken_sentinel_plan_submit with protected PID 1",
			payload:  `{"tool_name":"mcp_franken_sentinel_plan_submit","tool_input":{"incident_id":"INC-GUARD-1","steps":[{"action":"process_terminate","params":{"pid":1}}]}}`,
			wantCode: 2,
		},
		{
			name:     "Allow Kiro V3 mcp_franken-sentinel_action_execute with approval_token",
			payload:  `{"tool_name":"mcp_franken-sentinel_action_execute","tool_input":{"incident_id":"INC-GUARD-1","action":"unit_restart","unit":"haunted-api.service","approval_token":"ed25519.sig"}}`,
			wantCode: 0,
		},
		{
			name:     "Allow Kiro V3 mcp_franken_wa_wa_notify",
			payload:  `{"tool_name":"mcp_franken_wa_wa_notify","tool_input":{"incident_id":"INC-GUARD-1","severity":"P3","text":"Healthy summary"}}`,
			wantCode: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runWithInput(
				[]string{"guard", "--audit", "--db", dbPath, "--policy", policyPath},
				strings.NewReader(tc.payload),
				&stdout,
				&stderr,
			)
			if code != tc.wantCode {
				t.Fatalf("expected exit code %d, got %d (stdout=%s, stderr=%s)", tc.wantCode, code, stdout.String(), stderr.String())
			}
		})
	}

	store, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	entries, err := store.GetAuditTrail(context.Background(), "INC-GUARD-1")
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected audited guard records for INC-GUARD-1, got %d", len(entries))
	}
	for _, entry := range entries {
		if strings.Contains(entry.PayloadJSON, "sk-secretToken998877") {
			t.Errorf("unredacted secret persisted in guard audit_trail: %s", entry.PayloadJSON)
		}
	}
}

func TestCLI_MCPConnectProxyAndEndpointValidation(t *testing.T) {
	// 1. Validasi resolusi alias dan blokir HTTP publik tanpa TLS
	if got, err := resolveSentinelMCPEndpoint("sentinel@localhost", false); err != nil || got != "http://localhost:8090/mcp" {
		t.Fatalf("unexpected sentinel@localhost endpoint: %q (err=%v)", got, err)
	}
	if got, err := resolveSentinelMCPEndpoint("sentinel@100.64.10.5", false); err != nil || got != "http://100.64.10.5:8090/mcp" {
		t.Fatalf("unexpected sentinel@tailscale endpoint: %q (err=%v)", got, err)
	}
	if _, err := resolveSentinelMCPEndpoint("http://8.8.8.8:8090/mcp", false); err == nil {
		t.Fatalf("expected plain HTTP to public IP to be rejected")
	}

	// 2. Uji round-trip stdio JSON-RPC <-> Streamable HTTP MCP Server
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/proc/meminfo", "MemTotal: 1048576 kB\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=1.00 avg60=0.50 avg300=0.10 total=10\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	eng, err := reflex.NewEngine(reflex.EngineConfig{Store: store, FS: mfs, Catalog: cat})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	srv, err := mcpserver.New(mcpserver.Config{
		NodeName:    "node-connect",
		Store:       store,
		Catalog:     cat,
		Reflex:      eng,
		FS:          mfs,
		BearerToken: "connect-secret-token",
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}

	handler, err := srv.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	stdinStream := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test-cli","version":"1.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}, "\n") + "\n"

	var stdout, stderr bytes.Buffer
	t.Setenv("FRANKEN_CONNECT_TOKEN", "connect-secret-token")

	code := runWithInput(
		[]string{"mcp", "connect", "--token-env", "FRANKEN_CONNECT_TOKEN", ts.URL + "/mcp"},
		strings.NewReader(stdinStream),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("mcp connect returned %d (stderr=%s)", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, `"protocolVersion"`) || !strings.Contains(out, `"node_snapshot"`) || !strings.Contains(out, `"action_execute"`) {
		t.Errorf("expected initialize & tools/list response on stdout, got:\n%s", out)
	}

	// Pastikan setiap baris output berupa JSON valid satu baris
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected >= 2 JSON-RPC response lines, got %d (%q)", len(lines), out)
	}
	for _, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("non-JSON response line emitted by mcp connect: %q (%v)", line, err)
		}
	}

	// Pastikan Bearer auth ditegakkan jika proxy menggunakan token salah
	badProxy := newStdioHTTPMCPProxy(ts.URL+"/mcp", "wrong-token", &http.Client{Timeout: 5 * time.Second})
	var badOut, badErr bytes.Buffer
	_ = badProxy.Relay(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n"), &badOut, &badErr)
	if !strings.Contains(badErr.String(), "401") {
		t.Errorf("expected HTTP 401 warning on wrong bearer token, got %q", badErr.String())
	}
}

func TestCLI_SentinelServeSecurityChecks(t *testing.T) {
	var stdout, stderr bytes.Buffer

	t.Setenv("FRANKEN_SENTINEL_EMPTY", "")
	code := run([]string{"sentinel", "serve", "--token-env", "FRANKEN_SENTINEL_EMPTY"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "bearer token") {
		t.Fatalf("expected exit code 1 when bearer token is empty, got %d (stderr=%s)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	t.Setenv("FRANKEN_SENTINEL_TOK", "valid-sentinel-token")
	code = run([]string{"sentinel", "serve", "--token-env", "FRANKEN_SENTINEL_TOK", "--listen", "0.0.0.0:8090"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "unsafe bind address") {
		t.Fatalf("expected exit code 1 for 0.0.0.0 bind, got %d (stderr=%s)", code, stderr.String())
	}
}

func TestCLI_WALoginValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Argumen posisional liar pada wa-login wajib ditolak dengan exit code 2
	code := run([]string{"wa-login", "unexpected-arg"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for extra positional arg on wa-login, got %d (stderr=%s)", code, stderr.String())
	}

	// Uji bantuan --help (Flag.Parse memanggil exit code 2 untuk flag --help di FlagSet default ContinueOnError, cukup pastikan usage tercetak)
	stdout.Reset()
	stderr.Reset()
	_ = run([]string{"wa-login", "--help"}, &stdout, &stderr)
	if !strings.Contains(stderr.String(), "wa-login") {
		t.Errorf("expected wa-login usage help, got %s", stderr.String())
	}
}

func TestCLI_PostmortemAndChaosCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// 1. Uji postmortem tanpa --incident -> exit code 2
	code := run([]string{"postmortem"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing --incident, got %d", code)
	}

	// 2. Uji chaos run 5 skenario lengkap lewat CLI franken chaos run
	stdout.Reset()
	stderr.Reset()
	outDir := filepath.Join(t.TempDir(), "chaos-out")
	code = run([]string{"chaos", "run", "--runs", "5", "--policy", filepath.Join("..", "..", "policy", "actions.yaml"), "--out", outDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected franken chaos run exit 0, got %d (stdout=%s stderr=%s)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Summary: passed=5/5 failed=0") {
		t.Errorf("unexpected chaos CLI output: %s", stdout.String())
	}
}

func TestCLI_PublicKeyFailFast(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "sentinel.db")
	policyPath := filepath.Join("..", "..", "policy", "actions.yaml")
	missingPub := filepath.Join(tmpDir, "missing-sentinel-ed25519.pub")

	t.Setenv("FRANKEN_FAILFAST_TOK", "valid-sentinel-token")

	// 1. Subcommand serve dan stdio wajib gagal fatal jika --pub-key tidak ditemukan atau kosong (dilarang fallback nil verifier)
	cases := [][]string{
		{"mcp", "serve", "--db", dbPath, "--policy", policyPath, "--pub-key", missingPub, "--token-env", "FRANKEN_FAILFAST_TOK"},
		{"sentinel", "serve", "--db", dbPath, "--policy", policyPath, "--pub-key", missingPub, "--token-env", "FRANKEN_FAILFAST_TOK"},
		{"mcp", "stdio", "--db", dbPath, "--policy", policyPath, "--pub-key", missingPub},
		{"mcp", "serve", "--db", dbPath, "--policy", policyPath, "--pub-key", "", "--token-env", "FRANKEN_FAILFAST_TOK"},
	}

	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 1 {
			t.Errorf("args %v: expected exit code 1 on missing/empty pub-key, got %d (stderr=%s)", args, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "public key") {
			t.Errorf("args %v: expected explicit public key error in stderr, got %s", args, stderr.String())
		}
	}

	// 2. Pastikan file sentinel-ed25519.pub hasil `keys init` dapat dimuat sukses oleh buildMCPServerWithDeps
	keyDir := filepath.Join(tmpDir, "keys")
	_, pubPath, _, err := approval.InitKeys(keyDir, false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	if filepath.Base(pubPath) != "sentinel-ed25519.pub" {
		t.Fatalf("expected sentinel-ed25519.pub, got %s", pubPath)
	}

	store, err := incident.NewStore(filepath.Join(tmpDir, "ok.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	cat, err := policy.LoadCatalog(policyPath)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	eng, err := reflex.NewEngine(reflex.EngineConfig{Store: store, FS: kernelfs.NewMemFS(), Catalog: cat})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	srv, cleanup, err := buildMCPServerWithDeps(mcpFlagsConfig{
		nodeName:   "pi01",
		pubKeyPath: pubPath,
	}, "valid-sentinel-token", store, cat, nil, eng, kernelfs.NewMemFS())
	if err != nil || srv == nil {
		t.Fatalf("expected valid sentinel-ed25519.pub to initialize MCP server, got err=%v", err)
	}
	if cleanup != nil {
		cleanup()
	}
}

