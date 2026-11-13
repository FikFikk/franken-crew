package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
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

type bridgeFlags struct {
	waDBPath       string
	sentinelURL    string
	tokenEnv       string
	privKeyPath    string
	adminsCSV      string
	targetJID      string
	nodeName       string
	heartbeatEvery time.Duration
	missedMax      int
	pollTTL        time.Duration
}

func registerBridgeFlags(fs *flag.FlagSet, f *bridgeFlags) {
	fs.StringVar(&f.waDBPath, "wa-db", "wa-bridge-session.db", "path to pure-Go modernc SQLite whatsmeow store")
	fs.StringVar(&f.sentinelURL, "sentinel", "http://127.0.0.1:8090", "Sentinel base URL (Tailscale IP or localhost)")
	fs.StringVar(&f.tokenEnv, "token-env", "FRANKEN_BEARER_TOKEN", "environment variable holding Sentinel HTTP bearer auth token")
	fs.StringVar(&f.privKeyPath, "priv-key", "keys/bridge-ed25519.key", "path to Ed25519 0600 private key PEM")
	fs.StringVar(&f.adminsCSV, "admins", "", "comma-separated admin WhatsApp phone numbers or JIDs (required)")
	fs.StringVar(&f.targetJID, "target", "", "override destination JID/group for alerts (defaults to first admin)")
	fs.StringVar(&f.nodeName, "node", "node01", "monitored Sentinel node name")
	fs.DurationVar(&f.heartbeatEvery, "heartbeat-interval", wabridge.DefaultHeartbeatInterval, "Sentinel heartbeat watch interval")
	fs.IntVar(&f.missedMax, "missed-heartbeats", wabridge.DefaultMaxMissedHeartbeats, "consecutive missed heartbeats before Node Silent Alert")
	fs.DurationVar(&f.pollTTL, "poll-ttl", wabridge.DefaultPollTTL, "expiration duration for WhatsApp approval polls")
}

func runLogin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wa-bridge login", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbPath := fs.String("db", "wa-bridge-session.db", "path to pure-Go modernc SQLite whatsmeow session DB")
	relogin := fs.Bool("relogin", false, "wipe any existing device session and pair a new QR code")
	timeout := fs.Duration("timeout", 2*time.Minute, "QR pairing timeout")

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

	bridge, cleanup, err := buildBridgeRuntime(cfg, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "wa-bridge running (sentinel=%s, node=%s, heartbeat=%s x %d)\n",
		cfg.sentinelURL, cfg.nodeName, cfg.heartbeatEvery, cfg.missedMax)

	if err := bridge.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "wa-bridge runtime error: %v\n", err)
		return 1
	}
	return 0
}

func runMCPStdio(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wa-bridge mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg bridgeFlags
	registerBridgeFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	bridge, cleanup, err := buildBridgeRuntime(cfg, stderr, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Jalankan bridge SSE + heartbeat loop di latar belakang sembari melayani MCP stdio ke Kiro Crew
	go func() {
		_ = bridge.Run(ctx)
	}()

	srv := bridge.NewMCPServer()
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(stderr, "wa-bridge mcp stdio error: %v\n", err)
		return 1
	}
	return 0
}

func buildBridgeRuntime(cfg bridgeFlags, _ io.Writer, stderr io.Writer) (*wabridge.Bridge, func(), error) {
	bearerToken := strings.TrimSpace(os.Getenv(cfg.tokenEnv))
	if bearerToken == "" {
		return nil, nil, fmt.Errorf("bearer token env var %s is empty", cfg.tokenEnv)
	}

	admins := splitCSV(cfg.adminsCSV)
	if len(admins) == 0 {
		admins = splitCSV(os.Getenv("FRANKEN_WA_ADMINS"))
	}
	if len(admins) == 0 {
		return nil, nil, fmt.Errorf("admin allowlist is required via --admins or FRANKEN_WA_ADMINS")
	}

	privKey, err := approval.LoadPrivateKey(cfg.privKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load Ed25519 private key %q: %w", cfg.privKeyPath, err)
	}
	minter, err := approval.NewMinter(privKey, nil)
	if err != nil {
		return nil, nil, err
	}

	sentinelClient, err := wabridge.NewSentinelClient(cfg.sentinelURL, bearerToken)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	waClient, container, err := wabridge.OpenWhatsAppClient(ctx, cfg.waDBPath, "WARN")
	if err != nil {
		_ = sentinelClient.Close()
		return nil, nil, err
	}
	if waClient.Store.ID == nil {
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, nil, fmt.Errorf("WhatsApp session in %q is not paired yet; run `franken wa-login --db %s` first", cfg.waDBPath, cfg.waDBPath)
	}

	messenger, err := wabridge.NewWhatsmeowMessenger(waClient)
	if err != nil {
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, nil, err
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
		OnAudit: func(evType, detail string) {
			fmt.Fprintf(stderr, "[wa-bridge] %s: %s\n", evType, detail)
		},
	})
	if err != nil {
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, nil, err
	}

	// Pasang event handler sebelum Connect agar PollUpdateMessage dan fallback teks tertangani penuh
	handlerCtx, cancelHandler := context.WithCancel(context.Background())
	waClient.AddEventHandler(func(evt any) {
		switch v := evt.(type) {
		case *events.Message:
			bridge.HandleWhatsAppEvent(handlerCtx, v)
		case *events.LoggedOut:
			fmt.Fprintf(stderr, "[wa-bridge] WhatsApp logged out from phone (%s); re-run franken wa-login\n", v.PermanentDisconnectDescription())
		}
	})

	if err := waClient.Connect(); err != nil {
		cancelHandler()
		_ = container.Close()
		_ = sentinelClient.Close()
		return nil, nil, fmt.Errorf("connect whatsmeow client: %w", err)
	}

	cleanup := func() {
		cancelHandler()
		waClient.Disconnect()
		_ = container.Close()
		_ = sentinelClient.Close()
	}
	return bridge, cleanup, nil
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
	fmt.Fprintln(w, "  serve    Start headless WhatsApp SSE listener, Poll handler, and heartbeat monitor")
	fmt.Fprintln(w, "  login    Pair WhatsApp session via terminal QR code using modernc SQLite store")
	fmt.Fprintln(w, "  mcp      Run wa-bridge MCP stdio tools alongside the SSE event loop")
}

