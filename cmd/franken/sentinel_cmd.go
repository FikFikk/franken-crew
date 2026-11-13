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

	"github.com/FikFikk/franken-crew/internal/detector"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
	"github.com/FikFikk/franken-crew/internal/sentinel"
)

func runSentinel(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printSentinelUsage(stderr)
		return 2
	}

	switch args[0] {
	case "serve":
		return runSentinelServe(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printSentinelUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown sentinel subcommand: %s\n", args[0])
		printSentinelUsage(stderr)
		return 2
	}
}

func runSentinelServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sentinel serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var cfg mcpFlagsConfig
	var cgroupsCSV string
	var journalUnitsCSV string
	var sampleInterval time.Duration
	var rollbackInterval time.Duration
	var rediscoverInterval time.Duration

	fs.StringVar(&cfg.dbPath, "db", "franken-sentinel.db", "path to SQLite incident store")
	fs.StringVar(&cfg.policyPath, "policy", "policy/actions.yaml", "path to action policy catalog YAML")
	fs.StringVar(&cfg.pubKeyPath, "pub-key", "keys/sentinel-ed25519.pub", "path to Ed25519 public key PEM")
	fs.StringVar(&cfg.listenAddr, "listen", "127.0.0.1:8090", "HTTP listen host:port (Tailscale IP or localhost)")
	fs.BoolVar(&cfg.tailscale, "tailscale", false, "bind automatically to detected Tailscale interface IP")
	fs.IntVar(&cfg.port, "port", 8090, "TCP port used when --tailscale is enabled")
	fs.StringVar(&cfg.tokenEnv, "token-env", "FRANKEN_BEARER_TOKEN", "environment variable holding HTTP bearer auth token")
	fs.StringVar(&cfg.nodeName, "node", "", "override Sentinel node identifier (defaults to hostname)")
	fs.StringVar(&cfg.postmortemDir, "postmortem-dir", "incidents", "directory for incident postmortems written automatically when verification finishes (use /var/lib/franken/incidents under systemd)")
	// Daemon Sentinel menutup loop insiden secara deterministik tanpa menunggu agen LLM
	cfg.autoPostmortem = true
	fs.StringVar(&cgroupsCSV, "cgroups", "", "comma-separated cgroup v2 paths to monitor (auto-discovered if omitted)")
	fs.StringVar(&journalUnitsCSV, "journal-units", "", "comma-separated systemd units to follow via journalctl")
	fs.DurationVar(&sampleInterval, "sample-interval", 1*time.Second, "1 Hz sampler tick interval")
	fs.DurationVar(&rollbackInterval, "rollback-interval", 1*time.Second, "TTL reflex rollback sweep interval")
	fs.DurationVar(&rediscoverInterval, "rediscover-interval", 10*time.Second, "interval for rescanning cgroup targets so workloads started after Sentinel are monitored")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	addr, bearerToken, ok := resolveHTTPBind(cfg, stderr)
	if !ok {
		return 1
	}
	if _, err := loadRequiredPublicKey(cfg.pubKeyPath); err != nil {
		fmt.Fprintf(stderr, "error initializing Sentinel: %v\n", err)
		return 1
	}

	// Lakukan fail-fast capability probe sebelum mengikat HTTP socket atau membuka worker
	osFS := kernelfs.NewOSFS()
	caps, probeErr := kernelfs.Probe(osFS, kernelfs.DefaultCgroupRoot, kernelfs.DefaultProcRoot)
	if probeErr != nil || !caps.CgroupV2 || !caps.PSI {
		fmt.Fprintf(stderr, "error: Linux cgroup v2 and PSI are required to run sentinel daemon (%v)\n", probeErr)
		return 1
	}

	store, err := incident.NewStore(cfg.dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error opening incident store: %v\n", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	cat, err := policy.LoadCatalog(cfg.policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "error loading policy catalog: %v\n", err)
		return 1
	}

	hostTotal, _ := kernelfs.ReadMemTotalBytes(osFS, kernelfs.DefaultProcRoot)
	execRunner := executor.NewExecutor(15 * time.Second)
	reflexEng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                osFS,
		Catalog:           cat,
		PropertyDriver:    reflex.NewExecutorPropertyDriver(execRunner, 5*time.Second),
		AdmissionDriver:   reflex.NewFSAdmissionDriver("/run/franken"),
		HostMemTotalBytes: hostTotal,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error initializing reflex engine: %v\n", err)
		return 1
	}

	srv, cleanup, err := buildMCPServerWithDeps(cfg, bearerToken, store, cat, execRunner, reflexEng, osFS)
	if err != nil {
		fmt.Fprintf(stderr, "error initializing Sentinel MCP server: %v\n", err)
		return 1
	}
	defer cleanup()

	nodeName := cfg.nodeName
	if nodeName == "" {
		if h, hErr := os.Hostname(); hErr == nil && h != "" {
			nodeName = h
		} else {
			nodeName = "node01"
		}
	}

	daemon, err := sentinel.New(sentinel.Config{
		NodeName:           nodeName,
		FS:                 osFS,
		Store:              store,
		Catalog:            cat,
		Reflex:             reflexEng,
		MCPServer:          srv,
		HTTPAddr:           addr,
		CgroupPaths:        splitCSV(cgroupsCSV),
		JournalUnits:       splitCSV(journalUnitsCSV),
		SampleInterval:     sampleInterval,
		RollbackInterval:   rollbackInterval,
		RediscoverInterval: rediscoverInterval,
		Detector: detector.NewDetector(detector.Config{
			NodeName:          nodeName,
			HostMemTotalBytes: hostTotal,
		}),
	})
	if err != nil {
		fmt.Fprintf(stderr, "error initializing Sentinel daemon: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "Franken-Crew Sentinel daemon running on http://%s (node=%s, psi=%t, memory_reclaim=%t)\n",
		addr, nodeName, caps.PSI, caps.MemoryReclaim)

	if err := daemon.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "sentinel daemon error: %v\n", err)
		return 1
	}
	return 0
}

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func printSentinelUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: franken sentinel <subcommand> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  serve    Start unified Sentinel kernel daemon (telemetry + reflex + HTTP/SSE MCP server)")
}
