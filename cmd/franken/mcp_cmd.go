package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

type mcpFlagsConfig struct {
	dbPath     string
	policyPath string
	pubKeyPath string
	listenAddr string
	tailscale  bool
	port       int
	tokenEnv   string
	nodeName   string
	// postmortemDir menentukan lokasi postmortem; autoPostmortem menulisnya otomatis saat verifikasi selesai
	postmortemDir  string
	autoPostmortem bool
}

func runMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printMCPUsage(stderr)
		return 2
	}

	switch args[0] {
	case "serve":
		return runMCPServe(args[1:], stdout, stderr)
	case "stdio":
		return runMCPStdio(args[1:], stderr)
	case "connect":
		return runMCPConnect(args[1:], stdin, stdout, stderr)
	case "-h", "--help", "help":
		printMCPUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown mcp subcommand: %s\n", args[0])
		printMCPUsage(stderr)
		return 2
	}
}

func runMCPServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg mcpFlagsConfig
	fs.StringVar(&cfg.dbPath, "db", "franken-sentinel.db", "path to SQLite incident store")
	fs.StringVar(&cfg.policyPath, "policy", "policy/actions.yaml", "path to action policy catalog YAML")
	fs.StringVar(&cfg.pubKeyPath, "pub-key", "keys/sentinel-ed25519.pub", "path to Ed25519 public key PEM")
	fs.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:8090", "HTTP listen host:port (Tailscale IP or localhost)")
	fs.BoolVar(&cfg.tailscale, "tailscale", false, "bind automatically to detected Tailscale interface IP")
	fs.IntVar(&cfg.port, "port", 8090, "TCP port used when --tailscale is enabled")
	fs.StringVar(&cfg.tokenEnv, "token-env", "FRANKEN_BEARER_TOKEN", "environment variable holding HTTP bearer auth token")
	fs.StringVar(&cfg.nodeName, "node", "", "override Sentinel node identifier (defaults to hostname)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	addr, bearerToken, ok := resolveHTTPBind(cfg, stderr)
	if !ok {
		return 1
	}

	srv, cleanup, err := buildMCPServer(cfg, bearerToken)
	if err != nil {
		fmt.Fprintf(stderr, "error initializing Sentinel MCP server: %v\n", err)
		return 1
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "Sentinel MCP HTTP server listening on http://%s (/mcp, /v1/events, /healthz)\n", addr)
	if err := srv.ListenAndServe(ctx, addr); err != nil {
		fmt.Fprintf(stderr, "server error: %v\n", err)
		return 1
	}
	return 0
}

func resolveHTTPBind(cfg mcpFlagsConfig, stderr io.Writer) (string, string, bool) {
	// Baca token bearer dari env var agar kredensial tidak terlihat pada daftar argumen `/proc/PID/cmdline`
	bearerToken := strings.TrimSpace(os.Getenv(cfg.tokenEnv))
	if bearerToken == "" {
		fmt.Fprintf(stderr, "error: %s\n", mcpserver.ErrMissingBearerToken)
		return "", "", false
	}

	addr := cfg.listenAddr
	if cfg.tailscale {
		tsIP, err := mcpserver.FindTailscaleIP()
		if err != nil {
			fmt.Fprintf(stderr, "error detecting tailscale IP: %v\n", err)
			return "", "", false
		}
		addr = net.JoinHostPort(tsIP, fmt.Sprintf("%d", cfg.port))
	}

	if _, err := mcpserver.ValidateBindAddr(addr, false); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return "", "", false
	}
	return addr, bearerToken, true
}

func runMCPStdio(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp stdio", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg mcpFlagsConfig
	fs.StringVar(&cfg.dbPath, "db", "franken-sentinel.db", "path to SQLite incident store")
	fs.StringVar(&cfg.policyPath, "policy", "policy/actions.yaml", "path to action policy catalog YAML")
	fs.StringVar(&cfg.pubKeyPath, "pub-key", "keys/sentinel-ed25519.pub", "path to Ed25519 public key PEM")
	fs.StringVar(&cfg.nodeName, "node", "", "override Sentinel node identifier (defaults to hostname)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	srv, cleanup, err := buildMCPServer(cfg, "")
	if err != nil {
		fmt.Fprintf(stderr, "error initializing Sentinel MCP stdio server: %v\n", err)
		return 1
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.RunStdio(ctx); err != nil {
		fmt.Fprintf(stderr, "mcp stdio error: %v\n", err)
		return 1
	}
	return 0
}

func buildMCPServer(cfg mcpFlagsConfig, bearerToken string) (*mcpserver.Server, func(), error) {
	store, err := incident.NewStore(cfg.dbPath)
	if err != nil {
		return nil, nil, err
	}
	cat, err := policy.LoadCatalog(cfg.policyPath)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}

	fsys := kernelfs.NewOSFS()
	hostTotal, _ := kernelfs.ReadMemTotalBytes(fsys, kernelfs.DefaultProcRoot)
	execRunner := executor.NewExecutor(15 * time.Second)

	reflexEng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                fsys,
		Catalog:           cat,
		PropertyDriver:    reflex.NewExecutorPropertyDriver(execRunner, 5*time.Second),
		AdmissionDriver:   reflex.NewFSAdmissionDriver("/run/franken"),
		HostMemTotalBytes: hostTotal,
	})
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}

	srv, _, err := buildMCPServerWithDeps(cfg, bearerToken, store, cat, execRunner, reflexEng, fsys)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}

	cleanup := func() {
		_ = store.Close()
	}
	return srv, cleanup, nil
}

// loadRequiredPublicKey memastikan berkas kunci publik Ed25519 tersedia dan valid saat startup (fail-fast).
func loadRequiredPublicKey(path string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("public key path (--pub-key) is required")
	}
	pubKey, err := approval.LoadPublicKey(path)
	if err != nil {
		return nil, fmt.Errorf("load Ed25519 public key %q: %w", path, err)
	}
	return pubKey, nil
}

func buildMCPServerWithDeps(
	cfg mcpFlagsConfig,
	bearerToken string,
	store *incident.Store,
	cat *policy.Catalog,
	execRunner *executor.Executor,
	reflexEng *reflex.Engine,
	fsys kernelfs.FS,
) (*mcpserver.Server, func(), error) {
	// Kegagalan memuat kunci publik Ed25519 wajib fail-fast saat startup agar Sentinel tidak berjalan tanpa verifikator token L2/L3.
	pubKey, err := loadRequiredPublicKey(cfg.pubKeyPath)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := approval.NewVerifier(pubKey, store, nil)
	if err != nil {
		return nil, nil, err
	}

	srv, err := mcpserver.New(mcpserver.Config{
		NodeName:       cfg.nodeName,
		Store:          store,
		Catalog:        cat,
		Reflex:         reflexEng,
		Verifier:       verifier,
		Runner:         execRunner,
		FS:             fsys,
		BearerToken:    bearerToken,
		PostmortemDir:  cfg.postmortemDir,
		AutoPostmortem: cfg.autoPostmortem,
	})
	if err != nil {
		return nil, nil, err
	}

	return srv, func() {}, nil
}

func printMCPUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: franken mcp <subcommand> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  serve    Start Sentinel Streamable HTTP/SSE server bound to Tailscale or localhost")
	fmt.Fprintln(w, "  stdio    Start Sentinel JSON-RPC stdio MCP transport")
	fmt.Fprintln(w, "  connect  Relay stdio JSON-RPC to remote Streamable HTTP Sentinel server")
}
