package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/FikFikk/franken-crew/internal/approval"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run mengeksekusi router subcommand CLI `franken` dan mengembalikan exit code POSIX.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stderr)
		return 2
	}

	switch args[0] {
	case "keys":
		return runKeys(args[1:], stdout, stderr)
	case "mcp":
		return runMCP(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printRootUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		printRootUsage(stderr)
		return 2
	}
}

func runKeys(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printKeysUsage(stderr)
		return 2
	}

	switch args[0] {
	case "init":
		return runKeysInit(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printKeysUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown keys subcommand: %s\n", args[0])
		printKeysUsage(stderr)
		return 2
	}
}

func runKeysInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keys init", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dir := fs.String("dir", "keys", "target directory for Ed25519 approval keys")
	force := fs.Bool("force", false, "overwrite existing Ed25519 keys if present")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return 2
	}

	privPath, pubPath, kp, err := approval.InitKeys(*dir, *force)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	// Tampilkan lokasi kunci privat (0600 untuk wa-bridge) dan publik (0644 untuk Sentinel) beserta fingerprint
	fmt.Fprintf(stdout, "Ed25519 approval keypair initialized.\n")
	fmt.Fprintf(stdout, "  Private key (wa-bridge, 0600): %s\n", privPath)
	fmt.Fprintf(stdout, "  Public key  (sentinel,  0644): %s\n", pubPath)
	fmt.Fprintf(stdout, "  Fingerprint (SHA-256)        : %s\n", kp.Fingerprint)
	return 0
}

func printRootUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: franken <command> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  keys    Manage Ed25519 approval keys")
	fmt.Fprintln(w, "  mcp     Run Sentinel MCP server (serve HTTP/SSE or stdio JSON-RPC)")
}

func printKeysUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: franken keys <subcommand> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  init    Generate Ed25519 keypair (0600 private key for wa-bridge, 0644 public key for sentinel)")
}

