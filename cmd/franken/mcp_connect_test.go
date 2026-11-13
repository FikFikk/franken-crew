package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testProxyToken sengaja dibuat pendek (< 16 karakter) agar pola redaksi generik "Bearer <token>" tidak ikut menutupi kebocoran.
const testProxyToken = "s3cr3t-tok-7"

// failingRequestLine adalah request JSON-RPC ber-id 7 yang dipakai skenario kegagalan upstream.
const failingRequestLine = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"psi_history","arguments":{}}}` + "\n"

// jsonRPCResultOfSize membangun respons JSON-RPC satu baris (sudah compact) dengan panjang tepat size byte.
func jsonRPCResultOfSize(t *testing.T, id string, size int) string {
	t.Helper()
	prefix := `{"jsonrpc":"2.0","id":` + id + `,"result":{"blob":"`
	suffix := `"}}`
	fill := size - len(prefix) - len(suffix)
	if fill < 0 {
		t.Fatalf("size %d too small for JSON-RPC envelope", size)
	}
	return prefix + strings.Repeat("x", fill) + suffix
}

// newUpstreamProxy menyalakan upstream httptest dengan handler tertentu dan mengembalikan proxy yang mengarah ke sana.
func newUpstreamProxy(t *testing.T, handler http.HandlerFunc, timeout time.Duration) *stdioHTTPMCPProxy {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return newStdioHTTPMCPProxy(ts.URL+"/mcp", testProxyToken, &http.Client{Timeout: timeout})
}

// relayOutput menjalankan Relay atas input stdin lalu mengembalikan isi stdout dan stderr.
func relayOutput(t *testing.T, proxy *stdioHTTPMCPProxy, stdin string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := proxy.Relay(context.Background(), strings.NewReader(stdin), &stdout, &stderr); err != nil {
		t.Fatalf("Relay returned error: %v", err)
	}
	return stdout.String(), stderr.String()
}

// clip memotong teks panjang agar pesan kegagalan tes tetap terbaca.
func clip(s string) string {
	const limit = 300
	if len(s) <= limit {
		return s
	}
	return fmt.Sprintf("%s...(%d bytes total)", s[:limit], len(s))
}

// assertJSONRPCErrorLine memastikan stdout berisi tepat satu response error JSON-RPC 2.0 (-32603) untuk id yang diharapkan.
func assertJSONRPCErrorLine(t *testing.T, stdout, wantID string) {
	t.Helper()
	if !strings.HasSuffix(stdout, "\n") || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("expected exactly one newline-terminated line on stdout, got %q", clip(stdout))
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("stdout line is not valid JSON: %v (%q)", err, clip(stdout))
	}
	if len(resp) != 3 || string(resp["jsonrpc"]) != `"2.0"` || string(resp["id"]) != wantID || resp["error"] == nil {
		t.Fatalf("expected {jsonrpc:\"2.0\", id:%s, error:{...}} only, got %q", wantID, clip(stdout))
	}
	var errObj map[string]json.RawMessage
	if err := json.Unmarshal(resp["error"], &errObj); err != nil {
		t.Fatalf("error member is not an object: %v (%q)", err, clip(stdout))
	}
	var message string
	if err := json.Unmarshal(errObj["message"], &message); err != nil {
		t.Fatalf("error.message is not a string: %v (%q)", err, clip(stdout))
	}
	if len(errObj) != 2 || string(errObj["code"]) != "-32603" || message == "" {
		t.Fatalf("expected error {code:-32603, message:<non-empty>}, got %q", clip(stdout))
	}
	if len(message) > 512 {
		t.Fatalf("error.message should be a short reason, got %d bytes", len(message))
	}
}

func TestExtractSSEDataMessages_LargeSingleLineYieldsOneMessage(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{name: "600KiB", size: 600 << 10},
		{name: "5MiB", size: 5 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := jsonRPCResultOfSize(t, "1", tc.size)

			msgs, err := extractSSEDataMessages([]byte("event: message\nid: 1\ndata: " + payload + "\n\n"))

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(msgs) != 1 {
				t.Fatalf("expected exactly 1 message, got %d", len(msgs))
			}
			if string(msgs[0]) != payload {
				t.Fatalf("message differs from payload: got %d bytes, want %d", len(msgs[0]), len(payload))
			}
		})
	}
}

func TestExtractSSEDataMessages_EventFraming(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "multi-line data fields are joined with newline",
			raw:  "data: {\"jsonrpc\":\"2.0\",\ndata:  \"id\":2,\"result\":{}}\n\n",
			want: []string{"{\"jsonrpc\":\"2.0\",\n\"id\":2,\"result\":{}}"},
		},
		{
			name: "comment lines are ignored",
			raw:  ": keep-alive\ndata: {\"id\":1}\n: trailing comment\n\n",
			want: []string{`{"id":1}`},
		},
		{
			name: "blank lines separate events",
			raw:  "data: {\"id\":1}\n\ndata: {\"id\":2}\n\n",
			want: []string{`{"id":1}`, `{"id":2}`},
		},
		{
			name: "CRLF line endings",
			raw:  "data: {\"id\":1}\r\n\r\ndata: {\"id\":2}\r\n\r\n",
			want: []string{`{"id":1}`, `{"id":2}`},
		},
		{
			name: "event id and retry fields are ignored and empty priming data is skipped",
			raw:  "event: prime\nid: 0_0\ndata: \n\nevent: message\nid: 0_1\nretry: 100\ndata: {\"id\":3}\n\n",
			want: []string{`{"id":3}`},
		},
		{
			name: "final event without trailing blank line is kept",
			raw:  "data: {\"id\":4}",
			want: []string{`{"id":4}`},
		},
		{
			name: "empty body yields no messages",
			raw:  "",
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := extractSSEDataMessages([]byte(tc.raw))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var got []string
			for _, m := range msgs {
				got = append(got, string(m))
			}
			if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", tc.want) {
				t.Fatalf("messages mismatch:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestExtractSSEDataMessages_RejectsMalformedInput(t *testing.T) {
	const limit = 32 << 20 // 32 MiB = 33554432 byte
	cases := []struct {
		name        string
		raw         string
		errContains string
	}{
		{
			name: "truncated JSON data",
			raw:  "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"points\":[1,2\n\n",
		},
		{
			name: "non-JSON data after a valid event",
			raw:  "data: {\"id\":1}\n\ndata: not json\n\n",
		},
		{
			name:        "line longer than the response cap",
			raw:         "data: " + strings.Repeat("x", limit+1-len("data: ")) + "\n\n",
			errContains: "33554432",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := extractSSEDataMessages([]byte(tc.raw))
			if err == nil {
				t.Fatalf("expected error, got nil and %d message(s)", len(msgs))
			}
			if msgs != nil {
				t.Errorf("expected no partial messages alongside the error, got %d", len(msgs))
			}
			if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
				t.Errorf("error should mention %q, got: %v", tc.errContains, err)
			}
		})
	}
}

func TestMCPConnectRelay_LargeSSEReplyYieldsSingleMessage(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{name: "600KiB", size: 600 << 10},
		{name: "5MiB", size: 5 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := jsonRPCResultOfSize(t, "1", tc.size)
			proxy := newUpstreamProxy(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "event: message\nid: 1\ndata: "+reply+"\n\n")
			}, 30*time.Second)

			stdout, stderr := relayOutput(t, proxy, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"psi_history"}}`+"\n")

			if stderr != "" {
				t.Errorf("unexpected stderr: %q", clip(stderr))
			}
			if got := strings.Count(stdout, "\n"); got != 1 {
				t.Fatalf("expected exactly 1 JSON-RPC line on stdout, got %d lines (%d bytes)", got, len(stdout))
			}
			if line := strings.TrimSuffix(stdout, "\n"); line != reply {
				t.Fatalf("relayed line differs from upstream reply: got %d bytes, want %d", len(line), len(reply))
			}
		})
	}
}

func TestMCPConnectForward_ResponseBodyLimit(t *testing.T) {
	const limit = 32 << 20 // 32 MiB = 33554432 byte
	cases := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "exactly 32MiB is accepted", size: limit},
		{name: "32MiB plus one byte is rejected", size: limit + 1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := jsonRPCResultOfSize(t, "1", tc.size)
			proxy := newUpstreamProxy(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			}, 60*time.Second)

			msgs, err := proxy.forwardMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected explicit oversize error, got nil error and %d message(s)", len(msgs))
				}
				if len(msgs) != 0 {
					t.Errorf("expected no partial messages alongside the error, got %d", len(msgs))
				}
				if !strings.Contains(err.Error(), "exceeds") || !strings.Contains(err.Error(), "33554432") {
					t.Errorf("error should state that the 33554432 byte limit was exceeded, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for body at the limit: %v", err)
			}
			if len(msgs) != 1 || string(msgs[0]) != body {
				got := 0
				if len(msgs) > 0 {
					got = len(msgs[0])
				}
				t.Fatalf("expected the full %d-byte body as 1 message, got %d message(s), first %d bytes", len(body), len(msgs), got)
			}
		})
	}
}

func TestMCPConnectRelay_ForwardFailureWritesJSONRPCError(t *testing.T) {
	oversize := jsonRPCResultOfSize(t, "7", 32<<20+1)
	cases := []struct {
		name    string
		timeout time.Duration
		handler http.HandlerFunc
	}{
		{
			name: "HTTP 500",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "internal failure", http.StatusInternalServerError)
			},
		},
		{
			name: "HTTP 502 with large HTML body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = io.WriteString(w, "<html>"+strings.Repeat("x", 1<<20)+"</html>")
			},
		},
		{
			name: "oversize body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, oversize)
			},
		},
		{
			name: "malformed SSE data",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"points\":[1,2\n\n")
			},
		},
		{
			name: "truncated JSON body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":7,"result":{"points":[1,2`)
			},
		},
		{
			name:    "timeout",
			timeout: 200 * time.Millisecond,
			handler: func(_ http.ResponseWriter, r *http.Request) {
				// Body request dibaca habis agar server mendeteksi klien yang memutus koneksi saat timeout
				_, _ = io.Copy(io.Discard, r.Body)
				select {
				case <-r.Context().Done():
				case <-time.After(10 * time.Second):
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 30 * time.Second
			}
			proxy := newUpstreamProxy(t, tc.handler, timeout)

			stdout, stderr := relayOutput(t, proxy, failingRequestLine)

			if !strings.Contains(stderr, "mcp connect forward warning") {
				t.Errorf("expected forward warning on stderr, got %q", clip(stderr))
			}
			assertJSONRPCErrorLine(t, stdout, "7")
		})
	}
}

func TestMCPConnectRelay_ForwardFailurePreservesRequestIDType(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		wantID string
	}{
		{name: "number id", line: `{"jsonrpc":"2.0","id":7,"method":"tools/call"}`, wantID: `7`},
		{name: "string id", line: `{"jsonrpc":"2.0","id":"7","method":"tools/call"}`, wantID: `"7"`},
		{name: "integer id beyond float64 precision", line: `{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/call"}`, wantID: `9007199254740993`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newUpstreamProxy(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			}, 30*time.Second)

			stdout, _ := relayOutput(t, proxy, tc.line+"\n")

			assertJSONRPCErrorLine(t, stdout, tc.wantID)
		})
	}
}

func TestMCPConnectRelay_ForwardFailureNeverLeaksBearerToken(t *testing.T) {
	// Enam karakter pertama token cukup untuk mendeteksi kebocoran token utuh maupun potongan token
	leakMarker := testProxyToken[:6]
	cases := []struct {
		name string
		path string
		body func(token string) string
	}{
		{
			name: "token echoed in error body",
			path: "/mcp",
			body: func(token string) string { return "rejected credential " + token },
		},
		{
			// Token mulai di byte 250 sehingga terbelah oleh batas 256 byte; spasi panjang akan diringkas menjadi satu
			name: "token straddling the reason length limit",
			path: "/mcp",
			body: func(token string) string { return "x" + strings.Repeat(" ", 249) + token },
		},
		{
			// Endpoint ikut dikutip di pesan error, sehingga token yang tertanam di URL juga wajib disensor
			name: "token embedded in endpoint URL",
			path: "/" + testProxyToken + "/mcp",
			body: func(string) string { return "rejected" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Upstream memantulkan token mentah dari header Authorization ke body error
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				echoed := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				http.Error(w, tc.body(echoed), http.StatusUnauthorized)
			}))
			t.Cleanup(ts.Close)
			proxy := newStdioHTTPMCPProxy(ts.URL+tc.path, testProxyToken, &http.Client{Timeout: 30 * time.Second})

			stdout, stderr := relayOutput(t, proxy, failingRequestLine)

			if strings.Contains(stderr, leakMarker) {
				t.Errorf("bearer token leaked to stderr: %q", clip(stderr))
			}
			if strings.Contains(stdout, leakMarker) {
				t.Errorf("bearer token leaked to stdout: %q", clip(stdout))
			}
			if !strings.Contains(stderr, "401") {
				t.Errorf("expected HTTP status 401 to remain visible on stderr, got %q", clip(stderr))
			}
			assertJSONRPCErrorLine(t, stdout, "7")
		})
	}
}

func TestMCPConnectRelay_ContinuesAfterForwardFailure(t *testing.T) {
	proxy := newUpstreamProxy(t, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || string(req.ID) == "7" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":8,"result":{}}`)
	}, 30*time.Second)

	stdout, _ := relayOutput(t, proxy, failingRequestLine+`{"jsonrpc":"2.0","id":8,"method":"tools/list"}`+"\n")

	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected error line for id 7 then result for id 8, got %d line(s): %q", len(lines), clip(stdout))
	}
	assertJSONRPCErrorLine(t, lines[0]+"\n", "7")
	if lines[1] != `{"jsonrpc":"2.0","id":8,"result":{}}` {
		t.Fatalf("expected result for id 8 after the failure, got %q", clip(lines[1]))
	}
}

func TestMCPConnectRelay_NotificationAndResponseFailuresOnlyLog(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{name: "notification without id", line: `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		{name: "client response to a server request", line: `{"jsonrpc":"2.0","id":5,"result":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newUpstreamProxy(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "internal failure", http.StatusInternalServerError)
			}, 30*time.Second)

			stdout, stderr := relayOutput(t, proxy, tc.line+"\n")

			if stdout != "" {
				t.Errorf("expected nothing on stdout, got %q", clip(stdout))
			}
			if !strings.Contains(stderr, "HTTP 500") {
				t.Errorf("expected HTTP 500 warning on stderr, got %q", clip(stderr))
			}
		})
	}
}

func TestMCPConnectRelay_SmallRepliesUnchanged(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        string
	}{
		{
			name:        "pretty-printed JSON body is compacted to one line",
			contentType: "application/json",
			body:        "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 3,\n  \"result\": {\"ok\": true}\n}\n",
			want:        `{"jsonrpc":"2.0","id":3,"result":{"ok":true}}` + "\n",
		},
		{
			name:        "SSE stream with comment, priming event and message event",
			contentType: "text/event-stream",
			body:        ": keep-alive\n\nevent: prime\nid: 0_0\ndata: \n\nevent: message\nid: 0_1\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}\n\n",
			want:        `{"jsonrpc":"2.0","id":3,"result":{}}` + "\n",
		},
		{
			name:        "SSE notification then response keep their order",
			contentType: "text/event-stream",
			body:        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}\n\n",
			want:        `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}` + "\n" + `{"jsonrpc":"2.0","id":3,"result":{}}` + "\n",
		},
		{
			name:   "202 Accepted writes nothing",
			status: http.StatusAccepted,
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxy := newUpstreamProxy(t, func(w http.ResponseWriter, _ *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = io.WriteString(w, tc.body)
			}, 30*time.Second)

			stdout, stderr := relayOutput(t, proxy, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`+"\n")

			if stdout != tc.want {
				t.Errorf("stdout mismatch:\n got %q\nwant %q", stdout, tc.want)
			}
			if stderr != "" {
				t.Errorf("unexpected stderr: %q", clip(stderr))
			}
		})
	}
}
