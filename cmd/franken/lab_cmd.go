package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/lab"
	"github.com/FikFikk/franken-crew/internal/wabridge"
	"github.com/FikFikk/franken-crew/ui"
)

const (
	// labDefaultListen mengikat dashboard ke loopback; publikasi dilakukan reverse proxy/tunnel di depannya.
	labDefaultListen = "127.0.0.1:3008"
	// labShutdownTimeout memberi request yang sedang berjalan waktu untuk selesai setelah SIGINT/SIGTERM.
	labShutdownTimeout = 10 * time.Second
	// labExportLimit adalah jumlah maksimum insiden terminal terbaru yang diekspor tanpa --incident.
	labExportLimit = 10
)

// runLab merutekan subcommand `franken lab` (serve, export, simulate) untuk dashboard Graveyard.
func runLab(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printLabUsage(stderr)
		return 2
	}

	switch args[0] {
	case "serve":
		return runLabServe(args[1:], stdout, stderr)
	case "export":
		return runLabExport(args[1:], stdout, stderr)
	case "simulate":
		return runLabSimulate(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printLabUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown lab subcommand: %s\n", args[0])
		printLabUsage(stderr)
		return 2
	}
}

// runLabServe melayani dashboard statis read-only beserta /api/status tersaring sampai SIGINT/SIGTERM diterima.
func runLabServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lab serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	listen := fs.String("listen", labDefaultListen, "HTTP listen host:port (keep it on loopback and publish through a reverse proxy or tunnel)")
	dataDir := fs.String("data-dir", "", "optional directory whose files override the embedded /data/* replays")
	sentinelURL := fs.String("sentinel", "", "optional Sentinel base URL for the filtered /api/status summary (empty = replay-only mode)")
	tokenEnv := fs.String("token-env", "FRANKEN_BEARER_TOKEN", "environment variable holding the Sentinel bearer token (read only when --sentinel is set)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return 2
	}

	dir, err := resolveLabDataDir(*dataDir, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	cfg := lab.HandlerConfig{Files: ui.Files, DataDir: dir}
	statusLabel := "replay"
	if raw := strings.TrimSpace(*sentinelURL); raw != "" {
		client, err := newLabSentinelClient(raw, *tokenEnv)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		defer func() { _ = client.Close() }()
		// Status hanya diisi bila client benar-benar ada agar interface tidak pernah berisi typed-nil
		cfg.Status = lab.NewSentinelStatusSource(client)
		statusLabel = "live"
	}

	handler, err := lab.NewHandler(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", strings.TrimSpace(*listen))
	if err != nil {
		fmt.Fprintf(stderr, "error: listen on %s: %v\n", *listen, err)
		return 1
	}

	srv := newLabHTTPServer(handler, stderr)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	dirLabel := "embedded"
	if dir != "" {
		dirLabel = dir
	}
	fmt.Fprintf(stdout, "FrankenCrew lab dashboard listening on http://%s (data-dir=%s, status=%s)\n", ln.Addr(), dirLabel, statusLabel)

	select {
	case err := <-serveErr:
		// Serve hanya kembali sebelum sinyal bila listener gagal
		fmt.Fprintf(stderr, "lab server error: %v\n", err)
		return 1
	case <-ctx.Done():
	}

	// Kembalikan perilaku sinyal default sehingga sinyal kedua langsung menghentikan proses
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), labShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		fmt.Fprintf(stderr, "error: graceful shutdown: %v\n", err)
		return 1
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "lab server error: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "FrankenCrew lab dashboard stopped")
	return 0
}

// newLabHTTPServer memasang batas waktu dan ukuran header yang ketat untuk dashboard publik.
func newLabHTTPServer(h http.Handler, errLog io.Writer) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(errLog, "lab: ", log.LstdFlags),
	}
}

// resolveLabDataDir memvalidasi --data-dir. Direktori yang belum ada hanya diperingatkan: handler membacanya per
// request, jadi data bawaan dilayani sampai direktori itu muncul (cocok dengan BindReadOnlyPaths=- di systemd).
func resolveLabDataDir(raw string, stderr io.Writer) (string, error) {
	dir := strings.TrimSpace(raw)
	if dir == "" {
		return "", nil
	}
	st, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(stderr, "warning: data dir %s does not exist; serving embedded replay data until it appears\n", dir)
		return dir, nil
	case err != nil:
		return "", fmt.Errorf("data dir: %w", err)
	case !st.IsDir():
		return "", fmt.Errorf("data dir %s is not a directory", dir)
	}
	return dir, nil
}

// newLabSentinelClient memvalidasi URL Sentinel dan membaca bearer token dari env var. HTTP polos hanya diizinkan
// ke host privat/Tailscale/loopback agar token tidak melintasi internet tanpa TLS; pesan galat tidak pernah memuat
// kredensial.
func newLabSentinelClient(rawURL, tokenEnv string) (*wabridge.SentinelClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("invalid --sentinel URL")
	}
	if u.User != nil {
		return nil, errors.New("--sentinel URL must not embed credentials; pass the bearer token through --token-env")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported --sentinel URL scheme %q (must be http or https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("--sentinel URL %q is missing a host", rawURL)
	}
	if u.Scheme == "http" {
		if validatePrivateHTTPTarget(u.Hostname()) != nil {
			return nil, fmt.Errorf("refusing plain HTTP to %s for --sentinel: the bearer token would travel unencrypted (use https:// or a loopback, private, or Tailscale address)", u.Hostname())
		}
	}

	envName := strings.TrimSpace(tokenEnv)
	if envName == "" {
		return nil, errors.New("--token-env must name the environment variable holding the Sentinel bearer token")
	}
	token := strings.TrimSpace(os.Getenv(envName))
	if token == "" {
		return nil, fmt.Errorf("--sentinel requires a non-empty bearer token in environment variable %s", envName)
	}
	return wabridge.NewSentinelClient(u.String(), token)
}

// runLabExport menyusun replay dari DB SQLite Sentinel yang sudah ada lalu menulisnya secara atomik.
func runLabExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lab export", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dbPath := fs.String("db", "", "path to an existing Sentinel SQLite incident DB (required; never created)")
	out := fs.String("out", "", "output replay JSON file, replaced atomically (required)")
	var ids labIncidentList
	fs.Var(&ids, "incident", "incident ID to export; repeat for several (default: up to 10 most recent terminal incidents)")
	sourceKind := fs.String("source-kind", lab.SourceKindRecording, "replay source kind: recording or simulation")
	sourceLabel := fs.String("source-label", "", "source label shown on the dashboard (default depends on --source-kind)")
	node := fs.String("node", "", "node name shown on the dashboard (default: node recorded on the incidents)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return 2
	}
	if strings.TrimSpace(*dbPath) == "" {
		fmt.Fprintln(stderr, "error: --db is required")
		return 2
	}
	if strings.TrimSpace(*out) == "" {
		fmt.Fprintln(stderr, "error: --out is required")
		return 2
	}
	kind := strings.TrimSpace(*sourceKind)
	if kind != lab.SourceKindRecording && kind != lab.SourceKindSimulation {
		fmt.Fprintf(stderr, "error: --source-kind must be %q or %q, got %q\n", lab.SourceKindRecording, lab.SourceKindSimulation, kind)
		return 2
	}

	// incident.NewStore membuat DB baru bila berkas belum ada; periksa dulu agar ekspor tidak pernah membuat DB kosong
	st, err := os.Stat(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: incident DB: %v\n", err)
		return 1
	}
	if st.IsDir() {
		fmt.Fprintf(stderr, "error: incident DB %s is a directory\n", *dbPath)
		return 1
	}

	store, err := incident.NewStore(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "error opening incident store: %v\n", err)
		return 1
	}
	defer func() { _ = store.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	selected := ids.values
	if len(selected) == 0 {
		selected, err = lab.RecentTerminalIncidentIDs(ctx, store, labExportLimit)
		if err != nil {
			fmt.Fprintf(stderr, "error listing incidents: %v\n", err)
			return 1
		}
		if len(selected) == 0 {
			fmt.Fprintf(stderr, "error: no terminal incidents in %s; pass --incident ID to export a specific incident\n", *dbPath)
			return 1
		}
	}

	rep, err := lab.BuildReplay(ctx, store, selected, lab.ReplaySource{Kind: kind, Label: *sourceLabel}, *node)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	size, err := writeReplayFile(*out, rep)
	if err != nil {
		fmt.Fprintf(stderr, "error writing replay: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Exported %s replay with %s to %s (%d bytes)\n", rep.Source.Kind, incidentCount(len(rep.Incidents)), *out, size)
	for _, inc := range rep.Incidents {
		fmt.Fprintf(stdout, "  %-30s %-10s %.0fs\n", inc.ID, inc.State, inc.DurationS)
	}
	return 0
}

// runLabSimulate menjalankan simulasi chaos in-process dengan komponen Sentinel asli lalu menulis replay-nya.
func runLabSimulate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lab simulate", flag.ContinueOnError)
	fs.SetOutput(stderr)

	out := fs.String("out", "", "output replay JSON file, replaced atomically (required)")
	policyPath := fs.String("policy", "policy/actions.yaml", "path to action policy catalog YAML")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected positional arguments: %v\n", fs.Args())
		return 2
	}
	if strings.TrimSpace(*out) == "" {
		fmt.Fprintln(stderr, "error: --out is required")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep, err := lab.Simulate(ctx, lab.SimulateOptions{PolicyPath: *policyPath})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	size, err := writeReplayFile(*out, rep)
	if err != nil {
		fmt.Fprintf(stderr, "error writing replay: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Simulated %s into %s (%d bytes)\n", incidentCount(len(rep.Incidents)), *out, size)
	for _, inc := range rep.Incidents {
		fmt.Fprintf(stdout, "  %-16s %-30s %-10s %.0fs\n", inc.Scenario, inc.ID, inc.State, inc.DurationS)
	}
	return 0
}

// labIncidentList mengumpulkan flag --incident berulang dengan urutan terjaga dan tanpa duplikat.
type labIncidentList struct {
	values []string
	seen   map[string]bool
}

func (l *labIncidentList) String() string {
	return strings.Join(l.values, ",")
}

func (l *labIncidentList) Set(v string) error {
	id := strings.TrimSpace(v)
	if id == "" {
		return errors.New("--incident needs a non-empty incident ID")
	}
	if l.seen == nil {
		l.seen = make(map[string]bool)
	}
	if !l.seen[id] {
		l.seen[id] = true
		l.values = append(l.values, id)
	}
	return nil
}

// writeReplayFile menulis replay ter-indentasi (lab.MarshalReplay) secara atomik dan mengembalikan ukurannya.
func writeReplayFile(path string, rep *lab.Replay) (int, error) {
	data, err := lab.MarshalReplay(rep)
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return 0, err
	}
	return len(data), nil
}

// writeFileAtomic menulis ke berkas sementara tersembunyi di direktori tujuan, fsync, lalu rename, sehingga pembaca
// (dashboard, rsync, go:embed) tidak pernah melihat JSON setengah jadi. Berkas sementara dihapus bila gagal.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	// fsync direktori agar rename bertahan saat listrik padam; galat diabaikan (tidak didukung di semua OS)
	if d, dirErr := os.Open(dir); dirErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func incidentCount(n int) string {
	if n == 1 {
		return "1 incident"
	}
	return fmt.Sprintf("%d incidents", n)
}

func printLabUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: franken lab <subcommand> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  serve       Serve the read-only Graveyard dashboard [--listen 127.0.0.1:3008] [--data-dir DIR] [--sentinel URL] [--token-env FRANKEN_BEARER_TOKEN]")
	fmt.Fprintln(w, "  export      Build replay JSON from a Sentinel SQLite DB --db PATH --out FILE [--incident ID ...] [--source-kind recording|simulation] [--source-label TEXT] [--node NAME]")
	fmt.Fprintln(w, "  simulate    Run the in-process chaos simulation and write replay JSON --out FILE [--policy policy/actions.yaml]")
}
