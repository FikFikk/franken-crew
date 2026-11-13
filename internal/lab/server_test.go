package lab

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const wantCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func testFiles() fstest.MapFS {
	return fstest.MapFS{
		"index.html":         {Data: []byte("<!doctype html><title>FrankenCrew</title>")},
		"dist/index.mjs":     {Data: []byte("export default 1;")},
		"dist/legacy.js":     {Data: []byte("console.log(1)")},
		"dist/app.css":       {Data: []byte("body{}")},
		"assets/favicon.svg": {Data: []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"/>")},
		"data/replay.json":   {Data: []byte(`{"source":"embedded"}`)},
		"data/other.json":    {Data: []byte(`{"source":"embedded-other"}`)},
		"data/notes.txt":     {Data: []byte("plain")},
	}
}

type fakeStatus struct{ st LiveStatus }

func (f fakeStatus) Status(context.Context) LiveStatus { return f.st }

func newTestHandler(t *testing.T, cfg HandlerConfig) http.Handler {
	t.Helper()
	if cfg.Files == nil {
		cfg.Files = testFiles()
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func do(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func assertSecurityHeaders(t *testing.T, target string, rec *httptest.ResponseRecorder) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":    wantCSP,
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"Permissions-Policy":         "camera=(), microphone=(), geolocation=()",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s: header %s = %q, want %q", target, k, got, v)
		}
	}
}

func TestHandler_SecurityHeadersOnEveryResponse(t *testing.T) {
	h := newTestHandler(t, HandlerConfig{})
	for _, tc := range []struct {
		method, target string
		status         int
	}{
		{http.MethodGet, "/", 200},
		{http.MethodGet, "/dist/index.mjs", 200},
		{http.MethodGet, "/assets/favicon.svg", 200},
		{http.MethodGet, "/data/replay.json", 200},
		{http.MethodGet, "/api/status", 200},
		{http.MethodGet, "/healthz", 200},
		{http.MethodGet, "/nope", 404},
		{http.MethodGet, "/dist/missing.mjs", 404},
		{http.MethodPost, "/", 405},
		{http.MethodHead, "/", 200},
	} {
		rec := do(t, h, tc.method, tc.target)
		if rec.Code != tc.status {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.target, rec.Code, tc.status)
		}
		assertSecurityHeaders(t, tc.method+" "+tc.target, rec)
	}
}

func TestHandler_RejectsNonReadMethods(t *testing.T) {
	h := newTestHandler(t, HandlerConfig{})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		for _, target := range []string{"/", "/api/status", "/data/replay.json", "/healthz"} {
			rec := do(t, h, m, target)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405", m, target, rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
				t.Errorf("%s %s Allow = %q", m, target, allow)
			}
		}
	}
}

func TestHandler_UnknownPathsAndTraversalReturn404(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(filepath.Dir(dataDir), "secret.json"), []byte(`{"secret":true}`), 0o644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	h := newTestHandler(t, HandlerConfig{DataDir: dataDir})
	for _, target := range []string{
		"/index.html",
		"/favicon.ico",
		"/dist",
		"/dist/",
		"/assets/",
		"/data/",
		"/data",
		"/api",
		"/api/status/extra",
		"/dist/../index.html",
		"/dist/%2e%2e/index.html",
		"/data/..%2fsecret.json",
		"/data/%2e%2e/secret.json",
		"/data/sub%2fx.json",
		"/data/sub%5Cx.json",
		"/dist//index.mjs",
		"/dist/./index.mjs",
		"/data/../secret.json",
		"/.git/config",
	} {
		rec := do(t, h, http.MethodGet, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (body %q)", target, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("GET %s leaked a file outside the served trees", target)
		}
	}
}

func TestHandler_DataDirOverridesEmbeddedData(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "replay.json"), []byte(`{"source":"datadir"}`), 0o644); err != nil {
		t.Fatalf("write replay: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dataDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	h := newTestHandler(t, HandlerConfig{DataDir: dataDir})

	rec := do(t, h, http.MethodGet, "/data/replay.json")
	if rec.Code != 200 || rec.Body.String() != `{"source":"datadir"}` {
		t.Fatalf("DataDir file must win, got %d %q", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/data/other.json")
	if rec.Code != 200 || rec.Body.String() != `{"source":"embedded-other"}` {
		t.Fatalf("missing DataDir file must fall back to the embedded copy, got %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, http.MethodGet, "/data/nested"); rec.Code != 404 {
		t.Fatalf("directories in DataDir must not be served, got %d", rec.Code)
	}

	// DataDir yang belum ada tidak menggagalkan server
	missing := newTestHandler(t, HandlerConfig{DataDir: filepath.Join(dataDir, "does-not-exist")})
	if rec := do(t, missing, http.MethodGet, "/data/replay.json"); rec.Code != 200 || rec.Body.String() != `{"source":"embedded"}` {
		t.Fatalf("missing DataDir must fall back to embedded data, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandler_ContentTypesCacheAndCORS(t *testing.T) {
	h := newTestHandler(t, HandlerConfig{})
	for _, tc := range []struct {
		target, ctype, cache, acao string
	}{
		{"/", "text/html; charset=utf-8", "no-cache", ""},
		{"/dist/index.mjs", "text/javascript; charset=utf-8", "public, max-age=300", ""},
		{"/dist/legacy.js", "text/javascript; charset=utf-8", "public, max-age=300", ""},
		{"/dist/app.css", "text/css; charset=utf-8", "public, max-age=300", ""},
		{"/assets/favicon.svg", "image/svg+xml", "public, max-age=300", ""},
		{"/data/replay.json", "application/json", "no-cache", "*"},
		{"/data/notes.txt", "text/plain; charset=utf-8", "no-cache", ""},
		{"/api/status", "application/json", "no-cache", "*"},
		{"/healthz", "text/plain; charset=utf-8", "no-cache", ""},
	} {
		rec := do(t, h, http.MethodGet, tc.target)
		if rec.Code != 200 {
			t.Fatalf("GET %s = %d", tc.target, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != tc.ctype {
			t.Errorf("GET %s Content-Type = %q, want %q", tc.target, got, tc.ctype)
		}
		if got := rec.Header().Get("Cache-Control"); got != tc.cache {
			t.Errorf("GET %s Cache-Control = %q, want %q", tc.target, got, tc.cache)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.acao {
			t.Errorf("GET %s Access-Control-Allow-Origin = %q, want %q", tc.target, got, tc.acao)
		}
	}
	if body := do(t, h, http.MethodGet, "/healthz").Body.String(); body != "ok" {
		t.Errorf("/healthz body = %q, want ok", body)
	}
	head := do(t, h, http.MethodHead, "/data/replay.json")
	if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Type") != "application/json" {
		t.Errorf("HEAD must return headers without a body, got %d len=%d", head.Code, head.Body.Len())
	}
}

func TestHandler_StatusModes(t *testing.T) {
	// Tanpa sumber: mode replay persis {"mode":"replay"}
	replay := do(t, newTestHandler(t, HandlerConfig{}), http.MethodGet, "/api/status")
	if strings.TrimSpace(replay.Body.String()) != `{"mode":"replay"}` {
		t.Fatalf("status without a source = %q, want {\"mode\":\"replay\"}", replay.Body.String())
	}

	updated := time.Date(2026, 11, 13, 3, 20, 0, 0, time.UTC)
	uptime := int64(3600)
	pct := 61.5
	open := 1
	live := LiveStatus{
		Mode: "live", Node: "pi01", UptimeS: &uptime, PSI: &LivePSI{SomeAvg10: 1.25, FullAvg10: 0.1},
		MemoryUsedPct: &pct, OpenIncidents: &open,
		Latest:    &LiveIncident{ID: "INC-1", Severity: "P2", State: "VERIFYING", OpenedAt: updated.Add(-time.Minute)},
		UpdatedAt: &updated,
	}
	rec := do(t, newTestHandler(t, HandlerConfig{Status: fakeStatus{st: live}}), http.MethodGet, "/api/status")
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("status JSON: %v (%q)", err, rec.Body.String())
	}
	assertOnlyKeys(t, got, "mode", "node", "uptime_s", "psi", "memory_used_pct", "open_incidents", "latest", "updated_at")
	assertOnlyKeys(t, got["psi"].(map[string]any), "some_avg10", "full_avg10")
	assertOnlyKeys(t, got["latest"].(map[string]any), "id", "severity", "state", "opened_at")

	offline := do(t, newTestHandler(t, HandlerConfig{Status: fakeStatus{st: LiveStatus{Mode: "offline", UpdatedAt: &updated}}}), http.MethodGet, "/api/status")
	if strings.TrimSpace(offline.Body.String()) != `{"mode":"offline","updated_at":"2026-11-13T03:20:00Z"}` {
		t.Fatalf("offline status = %q", offline.Body.String())
	}
}

func assertOnlyKeys(t *testing.T, m map[string]any, allowed ...string) {
	t.Helper()
	ok := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		ok[k] = true
	}
	for k := range m {
		if !ok[k] {
			t.Errorf("unexpected key %q in %v", k, m)
		}
	}
}

func TestNewHandler_RequiresIndex(t *testing.T) {
	if _, err := NewHandler(HandlerConfig{}); err == nil {
		t.Fatal("NewHandler without Files must fail")
	}
	if _, err := NewHandler(HandlerConfig{Files: fstest.MapFS{"dist/a.js": {Data: []byte("x")}}}); err == nil {
		t.Fatal("NewHandler without index.html must fail")
	}
}

func TestHandler_ServesOverRealHTTP(t *testing.T) {
	srv := httptest.NewServer(newTestHandler(t, HandlerConfig{}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/dist/index.mjs")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "export default 1;" {
		t.Fatalf("unexpected response %d %q", resp.StatusCode, body)
	}
}
