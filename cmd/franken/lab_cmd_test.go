package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/lab"
)

// labPolicyPath menunjuk katalog policy repo relatif terhadap direktori paket cmd/franken.
var labPolicyPath = filepath.Join("..", "..", "policy", "actions.yaml")

func TestCLI_LabUsageAndUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Tanpa subcommand: usage ke stderr dengan exit code 2
	if code := run([]string{"lab"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "Usage: franken lab") {
		t.Fatalf("expected exit 2 with lab usage, got %d (stderr=%s)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"lab", "bogus"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "unknown lab subcommand: bogus") {
		t.Fatalf("expected exit 2 for unknown lab subcommand, got %d (stderr=%s)", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"lab", "help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected exit 0 for lab help, got %d", code)
	}
	for _, sub := range []string{"serve", "export", "simulate"} {
		if !strings.Contains(stdout.String(), sub) {
			t.Errorf("lab usage must list %q, got %s", sub, stdout.String())
		}
	}

	// Usage root wajib mendaftarkan perintah lab
	stdout.Reset()
	stderr.Reset()
	_ = run([]string{"help"}, &stdout, &stderr)
	if !regexp.MustCompile(`(?m)^\s+lab\s+\S`).MatchString(stdout.String()) {
		t.Errorf("root usage must list the lab command, got %s", stdout.String())
	}
}

func TestCLI_LabHTTPServerTimeouts(t *testing.T) {
	h := http.NewServeMux()
	srv := newLabHTTPServer(h, io.Discard)

	if srv.Handler != h {
		t.Fatalf("server must use the lab handler")
	}
	checks := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout, 5 * time.Second},
		{"ReadTimeout", srv.ReadTimeout, 10 * time.Second},
		{"WriteTimeout", srv.WriteTimeout, 30 * time.Second},
		{"IdleTimeout", srv.IdleTimeout, 60 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
	if srv.MaxHeaderBytes != 16<<10 {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 16<<10)
	}
	if srv.ErrorLog == nil {
		t.Errorf("server errors must go to the command stderr, not the global logger")
	}
}

func TestCLI_LabSimulateWritesIndentedReplayAtomically(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "data")
	out := filepath.Join(outDir, "replay.json")
	var stdout, stderr bytes.Buffer

	// Direktori induk dibuat otomatis; hasil adalah JSON ter-indentasi persis keluaran lab.MarshalReplay
	code := run([]string{"lab", "simulate", "--out", out, "--policy", labPolicyPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected lab simulate exit 0, got %d (stdout=%s stderr=%s)", code, stdout.String(), stderr.String())
	}
	raw, rep := readReplayFile(t, out)
	if rep.Schema != lab.ReplaySchema || rep.Source.Kind != lab.SourceKindSimulation || rep.Node != lab.SimulationNode {
		t.Fatalf("unexpected replay header: schema=%q kind=%q node=%q", rep.Schema, rep.Source.Kind, rep.Node)
	}
	var scenarios []string
	for _, inc := range rep.Incidents {
		scenarios = append(scenarios, inc.Scenario)
	}
	if got := strings.Join(scenarios, ","); got != "heap_leak,prompt_injection,zombie_storm" {
		t.Fatalf("expected the three chaos scenarios in order, got %q", got)
	}
	canonical, err := lab.MarshalReplay(&rep)
	if err != nil {
		t.Fatalf("MarshalReplay: %v", err)
	}
	if !bytes.Equal(raw, canonical) {
		t.Fatalf("simulate output must be exactly lab.MarshalReplay output (indented JSON, trailing newline)")
	}
	assertOnlyFiles(t, outDir, "replay.json")
	assertMode0644(t, out)
	if !strings.Contains(stdout.String(), out) || !strings.Contains(stdout.String(), "3 incidents") {
		t.Errorf("simulate summary must name the output file and incident count, got %s", stdout.String())
	}
	for _, sc := range scenarios {
		if !strings.Contains(stdout.String(), sc) {
			t.Errorf("simulate summary must list scenario %s, got %s", sc, stdout.String())
		}
	}

	// Kegagalan simulasi tidak boleh menyentuh berkas keluaran yang sudah ada
	if err := os.WriteFile(out, []byte("previous\n"), 0o644); err != nil {
		t.Fatalf("seed previous output: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"lab", "simulate", "--out", out, "--policy", filepath.Join(t.TempDir(), "missing.yaml")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 for a missing policy catalog, got %d (stderr=%s)", code, stderr.String())
	}
	if got, _ := os.ReadFile(out); string(got) != "previous\n" {
		t.Fatalf("failed simulate must leave the existing output untouched, got %q", got)
	}
	assertOnlyFiles(t, outDir, "replay.json")

	for _, args := range [][]string{
		{"lab", "simulate"},
		{"lab", "simulate", "--out", out, "extra"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("expected exit 2 for %v, got %d (stderr=%s)", args, code, stderr.String())
		}
	}
}

func TestCLI_LabExportDefaultsToTenMostRecentTerminalIncidents(t *testing.T) {
	dbPath, terminalIDs, openID := newLabExportDB(t)
	outDir := filepath.Join(t.TempDir(), "replays")
	out := filepath.Join(outDir, "replay.json")
	var stdout, stderr bytes.Buffer

	code := run([]string{"lab", "export", "--db", dbPath, "--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected lab export exit 0, got %d (stdout=%s stderr=%s)", code, stdout.String(), stderr.String())
	}
	raw, rep := readReplayFile(t, out)
	want := terminalIDs[len(terminalIDs)-10:]
	if got := replayIDs(rep); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("default export must hold the 10 most recent terminal incidents oldest first\n got: %v\nwant: %v", got, want)
	}
	for _, id := range replayIDs(rep) {
		if id == openID {
			t.Fatalf("default export must skip non-terminal incident %s", openID)
		}
	}
	if rep.Schema != lab.ReplaySchema || rep.Source.Kind != lab.SourceKindRecording || rep.Node != "pi01" {
		t.Fatalf("unexpected replay header: schema=%q kind=%q node=%q", rep.Schema, rep.Source.Kind, rep.Node)
	}
	if !bytes.HasPrefix(raw, []byte("{\n  \"schema\": ")) || !bytes.HasSuffix(raw, []byte("}\n")) {
		t.Fatalf("export must write indented JSON with a trailing newline, got prefix %q", raw[:min(len(raw), 40)])
	}
	assertOnlyFiles(t, outDir, "replay.json")
	assertMode0644(t, out)
	if !strings.Contains(stdout.String(), "10 incidents") || !strings.Contains(stdout.String(), out) {
		t.Errorf("export summary must name the output file and incident count, got %s", stdout.String())
	}
}

func TestCLI_LabExportSelectedIncidentsAndSourceFlags(t *testing.T) {
	dbPath, terminalIDs, openID := newLabExportDB(t)
	out := filepath.Join(t.TempDir(), "replay.json")
	var stdout, stderr bytes.Buffer

	// --incident berulang menjaga urutan, membuang duplikat, dan boleh menunjuk insiden non-terminal
	code := run([]string{
		"lab", "export", "--db", dbPath, "--out", out,
		"--incident", openID, "--incident", terminalIDs[0], "--incident", openID,
		"--source-kind", "simulation", "--source-label", "Pi bench rehearsal", "--node", "bench-01",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected lab export exit 0, got %d (stderr=%s)", code, stderr.String())
	}
	_, rep := readReplayFile(t, out)
	if got := strings.Join(replayIDs(rep), ","); got != openID+","+terminalIDs[0] {
		t.Fatalf("explicit --incident list must be exported in order without duplicates, got %s", got)
	}
	if rep.Source.Kind != lab.SourceKindSimulation || rep.Source.Label != "Pi bench rehearsal" || rep.Node != "bench-01" {
		t.Fatalf("source flags not applied: %+v node=%q", rep.Source, rep.Node)
	}
}

func TestCLI_LabExportRejectsBadInputWithoutWritingFiles(t *testing.T) {
	dbPath, _, _ := newLabExportDB(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "replay.json")
	absentDB := filepath.Join(dir, "absent.db")

	emptyDB := filepath.Join(t.TempDir(), "open-only.db")
	store, err := incident.NewStore(emptyDB)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.CreateIncident(context.Background(), &incident.Incident{ID: "INC-20261113-0500-pi01", Node: "pi01", Cgroup: "/franken.slice/api.service", Severity: "P3", State: incident.StateDetected}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	_ = store.Close()

	cases := []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"missing db flag", []string{"lab", "export", "--out", out}, 2, "--db is required"},
		{"missing out flag", []string{"lab", "export", "--db", dbPath}, 2, "--out is required"},
		{"unknown source kind", []string{"lab", "export", "--db", dbPath, "--out", out, "--source-kind", "live"}, 2, "--source-kind"},
		{"blank incident id", []string{"lab", "export", "--db", dbPath, "--out", out, "--incident", " "}, 2, "--incident"},
		{"positional argument", []string{"lab", "export", "--db", dbPath, "--out", out, "extra"}, 2, "unexpected positional"},
		{"missing db file", []string{"lab", "export", "--db", absentDB, "--out", out}, 1, "absent.db"},
		{"unknown incident", []string{"lab", "export", "--db", dbPath, "--out", out, "--incident", "INC-NOPE"}, 1, "INC-NOPE"},
		{"no terminal incidents", []string{"lab", "export", "--db", emptyDB, "--out", out}, 1, "no terminal incidents"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(c.args, &stdout, &stderr)
			if code != c.code || !strings.Contains(stderr.String(), c.stderr) {
				t.Fatalf("expected exit %d with %q, got %d (stderr=%s)", c.code, c.stderr, code, stderr.String())
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("failed export must not create %s (stat err=%v)", out, err)
			}
			if _, err := os.Stat(absentDB); !os.IsNotExist(err) {
				t.Fatalf("export must never create a missing incident DB (stat err=%v)", err)
			}
			assertOnlyFiles(t, dir)
		})
	}
}

func TestCLI_LabExportReplacesOutputAtomically(t *testing.T) {
	dbPath, _, _ := newLabExportDB(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "replay.json")
	if err := os.WriteFile(out, []byte("stale\n"), 0o600); err != nil {
		t.Fatalf("seed stale output: %v", err)
	}

	// Ekspor gagal: berkas lama utuh dan tidak ada berkas sementara yang tertinggal
	var stdout, stderr bytes.Buffer
	if code := run([]string{"lab", "export", "--db", dbPath, "--out", out, "--incident", "INC-NOPE"}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d (stderr=%s)", code, stderr.String())
	}
	if got, _ := os.ReadFile(out); string(got) != "stale\n" {
		t.Fatalf("failed export must not touch the existing output, got %q", got)
	}

	// Ekspor sukses mengganti berkas lama lewat rename dengan mode 0644
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"lab", "export", "--db", dbPath, "--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%s)", code, stderr.String())
	}
	if _, rep := readReplayFile(t, out); len(rep.Incidents) != 10 {
		t.Fatalf("expected the stale file to be replaced by a 10-incident replay, got %d incidents", len(rep.Incidents))
	}
	assertMode0644(t, out)
	assertOnlyFiles(t, dir, "replay.json")

	// Rename ke direktori yang ada gagal; berkas sementara wajib dibersihkan
	target := filepath.Join(dir, "occupied")
	if err := os.MkdirAll(filepath.Join(target, "keep"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"lab", "export", "--db", dbPath, "--out", target}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1 when --out is a directory, got %d (stderr=%s)", code, stderr.String())
	}
	assertOnlyFiles(t, dir, "occupied", "replay.json")
}

func TestCLI_LabServeRejectsUnsafeConfiguration(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "replay.json")
	if err := os.WriteFile(notDir, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	const token = "lab-test-token-value"
	t.Setenv("LAB_TEST_TOKEN", token)
	t.Setenv("LAB_EMPTY_TOKEN", "")

	cases := []struct {
		name   string
		args   []string
		code   int
		stderr string
	}{
		{"positional argument", []string{"lab", "serve", "extra"}, 2, "unexpected positional"},
		{"sentinel without token", []string{"lab", "serve", "--sentinel", "http://127.0.0.1:8090", "--token-env", "LAB_EMPTY_TOKEN"}, 1, "bearer token"},
		{"sentinel unsupported scheme", []string{"lab", "serve", "--sentinel", "ftp://127.0.0.1:8090", "--token-env", "LAB_TEST_TOKEN"}, 1, "scheme"},
		{"sentinel plain HTTP to public IP", []string{"lab", "serve", "--sentinel", "http://8.8.8.8:8090", "--token-env", "LAB_TEST_TOKEN"}, 1, "refusing plain HTTP"},
		{"sentinel URL with credentials", []string{"lab", "serve", "--sentinel", "http://admin:s3cr3t-pass@127.0.0.1:8090", "--token-env", "LAB_TEST_TOKEN"}, 1, "credentials"},
		{"data dir is a file", []string{"lab", "serve", "--data-dir", notDir}, 1, "not a directory"},
		{"bad listen address", []string{"lab", "serve", "--listen", "127.0.0.1:notaport"}, 1, "listen"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(c.args, &stdout, &stderr)
			if code != c.code || !strings.Contains(stderr.String(), c.stderr) {
				t.Fatalf("expected exit %d with %q, got %d (stderr=%s)", c.code, c.stderr, code, stderr.String())
			}
			if strings.Contains(stdout.String(), "listening") {
				t.Fatalf("invalid configuration must fail before serving, got stdout=%s", stdout.String())
			}
			if all := stdout.String() + stderr.String(); strings.Contains(all, token) || strings.Contains(all, "s3cr3t-pass") {
				t.Fatalf("lab serve must never print credentials, got %s", all)
			}
		})
	}
}

func TestCLI_LabServeGracefulShutdownOnSignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("delivering SIGINT/SIGTERM to the current process is not supported on Windows")
	}
	const token = "lab-e2e-token-value"
	t.Setenv("LAB_E2E_TOKEN", token)
	overrideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(overrideDir, "replay.json"), []byte(`{"schema":"override"}`), 0o644); err != nil {
		t.Fatalf("write override: %v", err)
	}

	cases := []struct {
		name       string
		sig        os.Signal
		args       []string
		wantSchema string
		wantMode   string
	}{
		{
			name:       "SIGTERM with embedded data in replay mode",
			sig:        syscall.SIGTERM,
			args:       []string{"lab", "serve", "--listen", "127.0.0.1:0"},
			wantSchema: lab.ReplaySchema,
			wantMode:   lab.StatusModeReplay,
		},
		{
			name: "SIGINT with data dir and unreachable Sentinel",
			sig:  os.Interrupt,
			args: []string{"lab", "serve", "--listen", "127.0.0.1:0", "--data-dir", overrideDir,
				"--sentinel", "http://127.0.0.1:1", "--token-env", "LAB_E2E_TOKEN"},
			wantSchema: "override",
			wantMode:   lab.StatusModeOffline,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := startLabServe(t, c.args)
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}

			if res, body := labGet(t, client, srv.baseURL+"/healthz"); res.StatusCode != http.StatusOK || body != "ok" {
				t.Fatalf("/healthz = %d %q", res.StatusCode, body)
			}

			res, body := labGet(t, client, srv.baseURL+"/")
			if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/html; charset=utf-8" {
				t.Fatalf("/ = %d %s", res.StatusCode, res.Header.Get("Content-Type"))
			}
			for _, want := range []string{"<!doctype html>", "<title>FrankenCrew", `<div id="graveyard-app"`, `<script type="module" src="./assets/site.js"></script>`} {
				if !strings.Contains(strings.ToLower(body), strings.ToLower(want)) {
					t.Errorf("index.html must contain %q, got %s", want, body)
				}
			}
			// CSP lab hanya mengizinkan script-src 'self', jadi setiap tag script wajib memuat berkas lewat src.
			for _, tag := range regexp.MustCompile(`(?i)<script\b[^>]*>`).FindAllString(body, -1) {
				if !strings.Contains(strings.ToLower(tag), "src=") {
					t.Errorf("index.html must not use inline scripts under the lab CSP, found %s", tag)
				}
			}
			if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
				t.Errorf("dashboard responses must carry the lab CSP, got %q", csp)
			}

			if res, body := labGet(t, client, srv.baseURL+"/dist/index.mjs"); res.StatusCode != http.StatusOK ||
				res.Header.Get("Content-Type") != "text/javascript; charset=utf-8" || !strings.Contains(body, "export { mount") ||
				!strings.Contains(body, "export default function") {
				t.Errorf("/dist/index.mjs = %d %s %q", res.StatusCode, res.Header.Get("Content-Type"), body)
			}
			if res, body := labGet(t, client, srv.baseURL+"/assets/favicon.svg"); res.StatusCode != http.StatusOK ||
				res.Header.Get("Content-Type") != "image/svg+xml" || !strings.Contains(body, "<svg") {
				t.Errorf("/assets/favicon.svg = %d %s", res.StatusCode, res.Header.Get("Content-Type"))
			}

			res, body = labGet(t, client, srv.baseURL+"/data/replay.json")
			var doc struct {
				Schema string `json:"schema"`
			}
			if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &doc) != nil || doc.Schema != c.wantSchema {
				t.Fatalf("/data/replay.json = %d schema %q, want %q", res.StatusCode, doc.Schema, c.wantSchema)
			}

			res, body = labGet(t, client, srv.baseURL+"/api/status")
			var st map[string]any
			if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &st) != nil || st["mode"] != c.wantMode {
				t.Fatalf("/api/status = %d %s, want mode %q", res.StatusCode, body, c.wantMode)
			}
			if strings.Contains(body, "127.0.0.1:1") || strings.Contains(body, token) {
				t.Fatalf("/api/status must not leak Sentinel address or token, got %s", body)
			}

			code, stdout := srv.signalAndWait(t, c.sig)
			if code != 0 {
				t.Fatalf("expected graceful exit 0 after %v, got %d (stdout=%s stderr=%s)", c.sig, code, stdout, srv.stderr.String())
			}
			if !strings.Contains(stdout, "stopped") {
				t.Errorf("expected a shutdown message, got %s", stdout)
			}
			if _, err := client.Get(srv.baseURL + "/healthz"); err == nil {
				t.Errorf("server must stop accepting connections after shutdown")
			}
			if all := stdout + srv.stderr.String(); strings.Contains(all, token) {
				t.Errorf("lab serve must never print the bearer token, got %s", all)
			}
		})
	}
}

// labServeProcess adalah satu eksekusi `franken lab serve` di goroutine terpisah.
type labServeProcess struct {
	baseURL string
	stdout  *labLineWriter
	stderr  *labLineWriter
	done    chan int
}

var labListenPattern = regexp.MustCompile(`listening on (http://\S+)`)

// startLabServe menjalankan lab serve dan menunggu baris "listening" untuk mengetahui port acak yang dipakai.
func startLabServe(t *testing.T, args []string) *labServeProcess {
	t.Helper()
	p := &labServeProcess{stdout: newLabLineWriter(), stderr: newLabLineWriter(), done: make(chan int, 1)}
	go func() { p.done <- run(args, p.stdout, p.stderr) }()

	deadline := time.After(10 * time.Second)
	for p.baseURL == "" {
		select {
		case line := <-p.stdout.lines:
			if m := labListenPattern.FindStringSubmatch(line); m != nil {
				p.baseURL = m[1]
			}
		case code := <-p.done:
			t.Fatalf("lab serve exited early with %d (stdout=%s stderr=%s)", code, p.stdout.String(), p.stderr.String())
		case <-deadline:
			t.Fatalf("lab serve did not report its listen address (stdout=%s stderr=%s)", p.stdout.String(), p.stderr.String())
		}
	}
	// Pastikan server berhenti meski subtest gagal di tengah jalan
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			p.sendSignal(syscall.SIGTERM)
			select {
			case <-p.done:
			case <-time.After(15 * time.Second):
			}
		}
	})
	return p
}

func (p *labServeProcess) sendSignal(sig os.Signal) {
	if proc, err := os.FindProcess(os.Getpid()); err == nil {
		_ = proc.Signal(sig)
	}
}

// signalAndWait mengirim sinyal ke proses test sendiri (ditangkap signal.NotifyContext lab serve) lalu menunggu exit code.
func (p *labServeProcess) signalAndWait(t *testing.T, sig os.Signal) (int, string) {
	t.Helper()
	p.sendSignal(sig)
	select {
	case code := <-p.done:
		p.done <- code
		return code, p.stdout.String()
	case <-time.After(15 * time.Second):
		t.Fatalf("lab serve did not shut down within 15s after %v (stdout=%s)", sig, p.stdout.String())
		return -1, ""
	}
}

// labLineWriter adalah writer aman-konkurensi yang menyimpan seluruh keluaran dan meneruskan tiap baris lengkap.
type labLineWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	pending []byte
	lines   chan string
}

func newLabLineWriter() *labLineWriter {
	return &labLineWriter{lines: make(chan string, 64)}
}

func (w *labLineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	w.pending = append(w.pending, p...)
	for {
		i := bytes.IndexByte(w.pending, '\n')
		if i < 0 {
			break
		}
		line := string(w.pending[:i])
		w.pending = w.pending[i+1:]
		select {
		case w.lines <- line:
		default:
		}
	}
	return len(p), nil
}

func (w *labLineWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func labGet(t *testing.T, client *http.Client, url string) (*http.Response, string) {
	t.Helper()
	res, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return res, string(body)
}

// newLabExportDB membuat DB Sentinel sementara berisi 12 insiden terminal dan 1 insiden terbuka (paling baru).
func newLabExportDB(t *testing.T) (string, []string, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "franken-sentinel.db")
	store, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 11, 13, 1, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return now })
	ctx := context.Background()
	terminal := []incident.State{incident.StateResolved, incident.StateEscalated, incident.StateDismissed, incident.StateExpired}

	var ids []string
	for i := 0; i < 12; i++ {
		now = now.Add(10 * time.Minute)
		id := fmt.Sprintf("INC-20261113-%04d-pi01", i+1)
		if err := store.CreateIncident(ctx, &incident.Incident{
			ID: id, Node: "pi01", Cgroup: "/franken.slice/api.service", Severity: "P2",
			State: terminal[i%len(terminal)], OpenedAt: now,
		}); err != nil {
			t.Fatalf("CreateIncident %s: %v", id, err)
		}
		ids = append(ids, id)
	}
	now = now.Add(10 * time.Minute)
	openID := "INC-20261113-0099-pi01"
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID: openID, Node: "pi01", Cgroup: "/franken.slice/api.service", Severity: "P2",
		State: incident.StateDetected, OpenedAt: now,
	}); err != nil {
		t.Fatalf("CreateIncident %s: %v", openID, err)
	}
	return dbPath, ids, openID
}

func readReplayFile(t *testing.T, path string) ([]byte, lab.Replay) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replay %s: %v", path, err)
	}
	var rep lab.Replay
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("decode replay %s: %v", path, err)
	}
	return raw, rep
}

func replayIDs(rep lab.Replay) []string {
	ids := make([]string, 0, len(rep.Incidents))
	for _, inc := range rep.Incidents {
		ids = append(ids, inc.ID)
	}
	return ids
}

// assertOnlyFiles memastikan direktori hanya berisi nama yang diharapkan (tanpa sisa berkas sementara).
func assertOnlyFiles(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("directory %s must contain exactly %v, got %v", dir, want, got)
	}
}

func assertMode0644(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("%s mode = %v, want 0644", path, st.Mode().Perm())
	}
}
