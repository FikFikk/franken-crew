package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/wabridge"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.mau.fi/whatsmeow/types/events"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run mengeksekusi CLI standalone `wa-bridge` (`serve`, `login`, `mcp`).
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return runServe(nil, stdout, stderr)
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:], stdout, stderr)
	case "login":
		return runLogin(args[1:], stdout, stderr)
	case "mcp":
		return runMCPStdio(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		// Dukung pemanggilan langsung `wa-bridge --sentinel ...` tanpa subcommand `serve`
		if strings.HasPrefix(args[0], "-") {
			return runServe(args, stdout, stderr)
		}
		fmt.Fprintf(stderr, "unknown wa-bridge subcommand: %s\n", args[0])
		printUsage(stderr)
		return 2
	}
}

const defaultWAMCPListenFallback = "127.0.0.1:8091"

type bridgeFlags struct {
	waDBPath       string
	sentinelURL    string
	tokenEnv       string
	privKeyPath    string
	adminsCSV      string
	targetJID      string
	nodeName       string
	mcpListen      string
	heartbeatEvery time.Duration
	missedMax      int
	pollTTL        time.Duration
	crewWebhookURL string
	crewTokenEnv   string
	crewAgent      string
}

func defaultWAMCPListenAddr() string {
	if v := strings.TrimSpace(os.Getenv("FRANKEN_WA_MCP_ADDR")); v != "" {
		return v
	}
	return defaultWAMCPListenFallback
}

func defaultWABridgeURL() string {
	if v := strings.TrimSpace(os.Getenv("FRANKEN_WA_BRIDGE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://" + defaultWAMCPListenAddr()
}

func registerBridgeFlags(fs *flag.FlagSet, f *bridgeFlags) {
	fs.StringVar(&f.waDBPath, "wa-db", "wa-bridge-session.db", "path to pure-Go modernc SQLite whatsmeow store")
	fs.StringVar(&f.sentinelURL, "sentinel", "http://127.0.0.1:8090", "Sentinel base URL (Tailscale IP or localhost)")
	fs.StringVar(&f.tokenEnv, "token-env", "FRANKEN_BEARER_TOKEN", "environment variable holding Sentinel HTTP bearer auth token")
	fs.StringVar(&f.privKeyPath, "priv-key", "keys/bridge-ed25519.key", "path to Ed25519 0600 private key PEM")
	fs.StringVar(&f.adminsCSV, "admins", "", "comma-separated admin WhatsApp phone numbers or JIDs (required)")
	fs.StringVar(&f.targetJID, "target", "", "override destination JID/group for alerts (defaults to first admin)")
	fs.StringVar(&f.nodeName, "node", "node01", "monitored Sentinel node name")
	fs.StringVar(&f.mcpListen, "mcp-listen", defaultWAMCPListenAddr(), "listen address for single-owner MCP HTTP endpoint (empty disables HTTP MCP server)")
	fs.DurationVar(&f.heartbeatEvery, "heartbeat-interval", wabridge.DefaultHeartbeatInterval, "Sentinel heartbeat watch interval")
	fs.IntVar(&f.missedMax, "missed-heartbeats", wabridge.DefaultMaxMissedHeartbeats, "consecutive missed heartbeats before Node Silent Alert")
	fs.DurationVar(&f.pollTTL, "poll-ttl", wabridge.DefaultPollTTL, "expiration duration for WhatsApp approval polls")
	fs.StringVar(&f.crewWebhookURL, "crew-webhook-url", strings.TrimSpace(os.Getenv("FRANKEN_CREW_WEBHOOK_URL")), "Kiro Crew webhook (POST /api/hooks/agent) used to start TRIAGE and EXECUTE phases; empty disables event-driven triggers")
	fs.StringVar(&f.crewTokenEnv, "crew-token-env", "KIROCREW_TOKEN", "environment variable holding the Kiro Crew webhook bearer token (mint with `kirocrew token`)")
	fs.StringVar(&f.crewAgent, "crew-agent", strings.TrimSpace(os.Getenv("FRANKEN_CREW_AGENT")), "optional agent field sent with the webhook (only if your Crew gateway accepts it)")
}

// buildCrewNotifier membangun klien webhook Kiro Crew bila URL dikonfigurasi; nil berarti pemicu event-driven nonaktif.
func buildCrewNotifier(cfg bridgeFlags, getenv func(string) string) (wabridge.CrewNotifier, error) {
	webhookURL := strings.TrimSpace(cfg.crewWebhookURL)
	if webhookURL == "" {
		return nil, nil
	}
	tokenEnv := strings.TrimSpace(cfg.crewTokenEnv)
	if tokenEnv == "" {
		tokenEnv = "KIROCREW_TOKEN"
	}
	token := strings.TrimSpace(getenv(tokenEnv))
	if token == "" {
		return nil, fmt.Errorf("kiro crew webhook token env var %s is empty", tokenEnv)
	}
	wh, err := wabridge.NewCrewWebhook(wabridge.CrewWebhookConfig{URL: webhookURL, Token: token, Agent: cfg.crewAgent})
	if err != nil {
		return nil, err
	}
	return wh, nil
}

func runLogin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wa-bridge login", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbPath := fs.String("db", "wa-bridge-session.db", "path to pure-Go modernc SQLite whatsmeow session DB")
	relogin := fs.Bool("relogin", false, "wipe any existing device session and pair a new QR code")
	timeout := fs.Duration("timeout", wabridge.DefaultLoginTimeout, "QR pairing and post-pair handshake timeout")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loginCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	jid, err := wabridge.LoginWithQR(loginCtx, *dbPath, stdout, *relogin)
	if err != nil {
		fmt.Fprintf(stderr, "wa-bridge login error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "WhatsApp session paired successfully as %s (store=%s)\n", jid.String(), *dbPath)
	return 0
}

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wa-bridge serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg bridgeFlags
	registerBridgeFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runCtx, cancelRun := context.WithCancelCause(sigCtx)
	defer cancelRun(nil)

	bridge, bearerToken, cleanup, err := buildBridgeRuntime(cfg, stderr, func(fatalErr error) {
		cancelRun(fatalErr)
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer cleanup()

	var httpErrCh chan error
	if listenAddr := strings.TrimSpace(cfg.mcpListen); listenAddr != "" {
		validatedAddr, valErr := mcpserver.ValidateBindAddr(listenAddr, false)
		if valErr != nil {
			fmt.Fprintf(stderr, "error: unsafe --mcp-listen address %q: %v\n", listenAddr, valErr)
			return 1
		}
		ln, listenErr := net.Listen("tcp", validatedAddr)
		if listenErr != nil {
			fmt.Fprintf(stderr, "error: listen MCP HTTP %s: %v\n", validatedAddr, listenErr)
			return 1
		}
		httpSrv := &http.Server{
			Handler:           buildServeHTTPHandler(bridge, cfg.nodeName, bearerToken),
			ReadHeaderTimeout: 10 * time.Second,
		}
		httpErrCh = make(chan error, 1)
		go func() {
			if serveErr := httpSrv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				httpErrCh <- serveErr
				cancelRun(serveErr)
				return
			}
			httpErrCh <- nil
		}()
		defer func() {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer shutCancel()
			_ = httpSrv.Shutdown(shutCtx)
		}()
		fmt.Fprintf(stdout, "wa-bridge MCP HTTP listening on http://%s/mcp\n", ln.Addr().String())
	}

	fmt.Fprintf(stdout, "wa-bridge running (sentinel=%s, node=%s, heartbeat=%s x %d)\n",
		cfg.sentinelURL, cfg.nodeName, cfg.heartbeatEvery, cfg.missedMax)

	if err := bridge.Run(runCtx); err != nil {
		fmt.Fprintf(stderr, "wa-bridge runtime error: %v\n", err)
		return 1
	}
	// Keluar dengan kode non-zero jika berhenti akibat StreamReplaced, LoggedOut, atau kegagalan HTTP server (Temuan C6)
	if cause := context.Cause(runCtx); cause != nil && !errors.Is(cause, context.Canceled) {
		fmt.Fprintf(stderr, "wa-bridge terminated fatally: %v\n", cause)
		return 1
	}
	if httpErrCh != nil {
		select {
		case hErr := <-httpErrCh:
			if hErr != nil {
				fmt.Fprintf(stderr, "wa-bridge MCP HTTP error: %v\n", hErr)
				return 1
			}
		default:
		}
	}
	return 0
}

// runMCPStdio bertindak murni sebagai proxy MCP stdio ke endpoint HTTP milik `wa-bridge serve` (Temuan C6).
// Proses ini tidak pernah membuka database SQLite whatsmeow maupun memanggil waClient.Connect().
func runMCPStdio(args []string, _ io.Writer, stderr io.Writer) int {
	return runMCPStdioWithTransport(args, &mcp.StdioTransport{}, stderr)
}

func runMCPStdioWithTransport(args []string, transport mcp.Transport, stderr io.Writer) int {
	fs := flag.NewFlagSet("wa-bridge mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)

	bridgeURL := fs.String("bridge-url", defaultWABridgeURL(), "base URL of the single running `wa-bridge serve` process")
	tokenEnv := fs.String("token-env", "FRANKEN_BEARER_TOKEN", "environment variable holding HTTP bearer auth token")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	bearerToken := strings.TrimSpace(os.Getenv(*tokenEnv))
	if bearerToken == "" {
		fmt.Fprintf(stderr, "error: bearer token env var %s is empty\n", *tokenEnv)
		return 1
	}

	cleanURL, err := validateBridgeBaseURL(*bridgeURL)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	proxy := newRemoteBridgeProxy(cleanURL, bearerToken)
	defer func() { _ = proxy.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := proxy.newMCPServer()
	if err := srv.Run(ctx, transport); err != nil {
		fmt.Fprintf(stderr, "wa-bridge mcp stdio error: %v\n", err)
		return 1
	}
	return 0
}

func buildServeHTTPHandler(bridge *wabridge.Bridge, nodeName, bearerToken string) http.Handler {
	mcpSrv := bridge.NewMCPServer()
	streamable := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpSrv
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    false,
		DisableLocalhostProtection:   false,
		PropagateRequestCancellation: false,
		SessionTimeout:               15 * time.Minute,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"node":   nodeName,
		})
	})
	mux.Handle("/mcp", mcpserver.BearerAuthMiddleware(bearerToken, streamable))
	return mux
}

func buildBridgeRuntime(cfg bridgeFlags, stderr io.Writer, onFatal func(error)) (*wabridge.Bridge, string, func(), error) {
	bearerToken := strings.TrimSpace(os.Getenv(cfg.tokenEnv))
	if bearerToken == "" {
		return nil, "", nil, fmt.Errorf("bearer token env var %s is empty", cfg.tokenEnv)
	}

	admins := splitCSV(cfg.adminsCSV)
	if len(admins) == 0 {
		admins = splitCSV(os.Getenv("FRANKEN_WA_ADMINS"))
	}
	if len(admins) == 0 {
		return nil, "", nil, fmt.Errorf("admin allowlist is required via --admins or FRANKEN_WA_ADMINS")
	}

	privKey, err := approval.LoadPrivateKey(cfg.privKeyPath)
	if err != nil {
		return nil, "", nil, fmt.Errorf("load Ed25519 private key %q: %w", cfg.privKeyPath, err)
	}
	minter, err := approval.NewMinter(privKey, nil)
	if err != nil {
		return nil, "", nil, err
	}

	sentinelClient, err := wabridge.NewSentinelClient(cfg.sentinelURL, bearerToken)
	if err != nil {
		return nil, "", nil, err
	}

	// Wajib arahkan seluruh log whatsmeow ke stderr agar tidak merusak stdout (Temuan C6)
	ctx := context.Background()
	waClient, container, err := wabridge.OpenWhatsAppClientWithWriter(ctx, cfg.waDBPath, "WARN", stderr)
	if err != nil {
		_ = sentinelClient.Close()
		return nil, "", nil, err
	}
	if waClient.Store.ID == nil {
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, "", nil, fmt.Errorf("WhatsApp session in %q is not paired yet; run `franken wa-login --db %s` first", cfg.waDBPath, cfg.waDBPath)
	}

	messenger, err := wabridge.NewWhatsmeowMessenger(waClient)
	if err != nil {
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, "", nil, err
	}

	crewNotifier, err := buildCrewNotifier(cfg, os.Getenv)
	if err != nil {
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, "", nil, err
	}

	bridge, err := wabridge.New(wabridge.Config{
		NodeName:            cfg.nodeName,
		AdminAllowlist:      admins,
		TargetJID:           cfg.targetJID,
		Minter:              minter,
		Sentinel:            sentinelClient,
		Messenger:           messenger,
		HeartbeatInterval:   cfg.heartbeatEvery,
		MaxMissedHeartbeats: cfg.missedMax,
		PollTTL:             cfg.pollTTL,
		Crew:                crewNotifier,
		OnAudit: func(evType, detail string) {
			fmt.Fprintf(stderr, "[wa-bridge] %s: %s\n", evType, detail)
		},
	})
	if err != nil {
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, "", nil, err
	}

	// Pasang event handler sebelum Connect agar PollUpdateMessage, StreamReplaced, dan LoggedOut tertangani penuh
	handlerCtx, cancelHandler := context.WithCancel(context.Background())
	waClient.AddEventHandler(func(evt any) {
		handleWhatsAppLifecycleEvent(handlerCtx, evt, bridge, stderr, onFatal)
	})

	if err := waClient.Connect(); err != nil {
		cancelHandler()
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, "", nil, fmt.Errorf("connect whatsmeow client: %w", err)
	}

	cleanup := func() {
		cancelHandler()
		waClient.Disconnect()
		_ = container.Close()
		_ = sentinelClient.Close()
	}
	return bridge, bearerToken, cleanup, nil
}

// handleWhatsAppLifecycleEvent meneruskan pesan masuk ke bridge serta memicu exit non-zero jika sesi WA digantikan atau terputus permanen.
func handleWhatsAppLifecycleEvent(ctx context.Context, evt any, bridge *wabridge.Bridge, stderr io.Writer, onFatal func(error)) {
	switch v := evt.(type) {
	case *events.Message:
		if bridge != nil {
			bridge.HandleWhatsAppEvent(ctx, v)
		}
	case *events.StreamReplaced:
		err := fmt.Errorf("WhatsApp session replaced by another connection (%s)", v.PermanentDisconnectDescription())
		fmt.Fprintf(stderr, "[wa-bridge] FATAL: %v\n", err)
		if onFatal != nil {
			onFatal(err)
		}
	case *events.LoggedOut:
		err := fmt.Errorf("WhatsApp logged out from phone (%s); re-run franken wa-login", v.PermanentDisconnectDescription())
		fmt.Fprintf(stderr, "[wa-bridge] FATAL: %v\n", err)
		if onFatal != nil {
			onFatal(err)
		}
	}
}

func validateBridgeBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(strings.TrimRight(raw, "/"))
	if trimmed == "" {
		return "", errors.New("bridge-url is required")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid bridge-url %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported bridge-url scheme %q", u.Scheme)
	}
	if _, err := mcpserver.ValidateBindAddr(u.Host, false); err != nil {
		if u.Scheme != "https" {
			return "", fmt.Errorf("unsafe HTTP bridge-url host %q: %w", u.Host, err)
		}
	}
	return trimmed, nil
}

type bearerHeaderRT struct {
	token string
	base  http.RoundTripper
}

func (rt *bearerHeaderRT) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+rt.token)
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

type remoteBridgeProxy struct {
	mcpEndpoint string
	httpClient  *http.Client

	mu      sync.Mutex
	session *mcp.ClientSession
}

func newRemoteBridgeProxy(baseURL, bearerToken string) *remoteBridgeProxy {
	return &remoteBridgeProxy{
		mcpEndpoint: strings.TrimRight(baseURL, "/") + "/mcp",
		httpClient: &http.Client{
			Transport: &bearerHeaderRT{token: bearerToken},
		},
	}
}

func (p *remoteBridgeProxy) Close() error {
	p.mu.Lock()
	sess := p.session
	p.session = nil
	p.mu.Unlock()
	if sess != nil {
		return sess.Close()
	}
	return nil
}

func (p *remoteBridgeProxy) ensureSession(ctx context.Context) (*mcp.ClientSession, error) {
	p.mu.Lock()
	existing := p.session
	p.mu.Unlock()
	if existing != nil {
		return existing, nil
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "franken-wa-bridge-stdio-proxy",
		Version: "0.1.0",
	}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             p.mcpEndpoint,
		HTTPClient:           p.httpClient,
		DisableStandaloneSSE: true,
	}
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect wa-bridge serve at %s (is `wa-bridge serve` running?): %w", p.mcpEndpoint, err)
	}

	p.mu.Lock()
	if p.session != nil {
		p.mu.Unlock()
		_ = sess.Close()
		return p.session, nil
	}
	p.session = sess
	p.mu.Unlock()
	return sess, nil
}

func (p *remoteBridgeProxy) callTool(ctx context.Context, name string, args any, out any) error {
	sess, err := p.ensureSession(ctx)
	if err != nil {
		return err
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		// Pulihkan sesi hanya jika session HTTP kedaluwarsa (404 / Session not found) agar tool non-idempoten aman
		if strings.Contains(strings.ToLower(err.Error()), "session") || strings.Contains(err.Error(), "404") {
			_ = p.Close()
			if newSess, recErr := p.ensureSession(ctx); recErr == nil {
				res, err = newSess.CallTool(ctx, &mcp.CallToolParams{
					Name:      name,
					Arguments: args,
				})
			}
		}
		if err != nil {
			return fmt.Errorf("forward %s to wa-bridge serve: %w", name, err)
		}
	}
	if res.IsError {
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok && tc.Text != "" {
				return errors.New(tc.Text)
			}
		}
		return fmt.Errorf("remote tool %s returned error", name)
	}
	if out == nil || res.StructuredContent == nil {
		return nil
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return fmt.Errorf("marshal proxy response %s: %w", name, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode proxy response %s: %w", name, err)
	}
	return nil
}

func (p *remoteBridgeProxy) newMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "franken-wa-bridge",
		Version: "0.1.0",
	}, &mcp.ServerOptions{
		Instructions: "Stdio MCP proxy to the single `wa-bridge serve` WhatsApp owner process.",
		SchemaCache:  mcp.NewSchemaCache(),
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_notify",
		Description: "Send rate-limited, redacted incident alert to WhatsApp admin.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in wabridge.WANotifyInput) (*mcp.CallToolResult, wabridge.WANotifyOutput, error) {
		var out wabridge.WANotifyOutput
		err := p.callTool(ctx, "wa_notify", in, &out)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_request_approval",
		Description: "Send Native WhatsApp Poll for human approval of a validated L2 remediation plan.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in wabridge.WARequestApprovalInput) (*mcp.CallToolResult, wabridge.WARequestApprovalOutput, error) {
		var out wabridge.WARequestApprovalOutput
		err := p.callTool(ctx, "wa_request_approval", in, &out)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_await_decision",
		Description: "Wait for allowlisted admin vote/reply and return GRANTED (with single-use Ed25519 token), ROLLED_BACK, DENIED, or EXPIRED.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in wabridge.WAAwaitDecisionInput) (*mcp.CallToolResult, wabridge.ApprovalDecision, error) {
		var out wabridge.ApprovalDecision
		err := p.callTool(ctx, "wa_await_decision", in, &out)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_send_report",
		Description: "Send terminal incident resolution or escalation report to WhatsApp admin.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in wabridge.WASendReportInput) (*mcp.CallToolResult, wabridge.WANotifyOutput, error) {
		var out wabridge.WANotifyOutput
		err := p.callTool(ctx, "wa_send_report", in, &out)
		return nil, out, err
	})

	return srv
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: wa-bridge <command> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  serve    Start single-owner WhatsApp daemon (SSE listener, Poll signer, Heartbeat, and MCP HTTP)")
	fmt.Fprintln(w, "  login    Pair WhatsApp session via terminal QR code using modernc SQLite store")
	fmt.Fprintln(w, "  mcp      Forward MCP stdio JSON-RPC to the running `wa-bridge serve` process")
}
