package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FikFikk/franken-crew/internal/chaos"
)

func runChaos(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printChaosUsage(stderr)
		return 2
	}

	switch args[0] {
	case "run":
		return runChaosSuiteCmd(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printChaosUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown chaos subcommand: %s\n", args[0])
		printChaosUsage(stderr)
		return 2
	}
}

func runChaosSuiteCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("chaos run", flag.ContinueOnError)
	fs.SetOutput(stderr)

	runs := fs.Int("runs", chaos.DefaultRuns, "number of consecutive chaos test cycles to execute")
	policyPath := fs.String("policy", "policy/actions.yaml", "path to policy/actions.yaml catalog")
	outDir := fs.String("out", "", "optional output directory for generated postmortem files")
	node := fs.String("node", "chaos-pi01", "simulated node name")
	approver := fs.String("approver", "+6281234567890", "approver WhatsApp phone or JID")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	report, err := chaos.RunSuite(runCtx, chaos.Config{
		Runs:       *runs,
		PolicyPath: *policyPath,
		OutputDir:  *outDir,
		NodeName:   *node,
		Approver:   *approver,
	})
	if err != nil {
		fmt.Fprintf(stderr, "chaos suite error: %v\n", err)
		return 1
	}

	for _, r := range report.Results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(stdout, "[%02d/%02d] %-12s status=%s incident=%s class=%s reflex=%d (%.2fms) l2=%s state=%s\n",
			r.RunNumber, report.Runs, r.Scenario, status, r.IncidentID, r.TriageClass, r.ReflexCount, r.ReflexLatencyMs, r.L2Action, r.FinalState)
		if !r.Passed && r.Error != "" {
			fmt.Fprintf(stderr, "  -> error: %s\n", r.Error)
		}
	}

	fmt.Fprintf(stdout, "Summary: passed=%d/%d failed=%d max_reflex_ms=%.2f avg_reflex_ms=%.2f\n",
		report.Passed, report.Runs, report.Failed, report.MaxReflexLatencyMs, report.AvgReflexLatencyMs)
	if report.Failed > 0 {
		return 1
	}
	return 0
}

func printChaosUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: franken chaos <subcommand> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  run     Execute 20 consecutive chaos scenarios (leak, spike, fork_storm, zombie_storm, log_flood)")
}

