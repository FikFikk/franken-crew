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

	"github.com/FikFikk/franken-crew/internal/wabridge"
)

func runWALogin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wa-login", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbPath := fs.String("db", "wa-bridge-session.db", "path to pure-Go modernc SQLite whatsmeow session DB")
	relogin := fs.Bool("relogin", false, "reset existing device pairing and generate a fresh QR code")
	timeout := fs.Duration("timeout", 2*time.Minute, "QR pairing timeout")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pairCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	jid, err := wabridge.LoginWithQR(pairCtx, *dbPath, stdout, *relogin)
	if err != nil {
		fmt.Fprintf(stderr, "wa-login error: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "WhatsApp session paired cleanly as %s (store=%s)\n", jid.String(), *dbPath)
	return 0
}
