package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/redact"
)

const (
	// maxMCPResponseBodyBytes adalah batas atas body respons HTTP dari Sentinel (32 MiB); respons yang lebih besar ditolak dengan error eksplisit, tidak pernah dipotong.
	maxMCPResponseBodyBytes = 32 << 20

	// maxForwardErrorReasonBytes membatasi panjang alasan kegagalan yang ditulis ke stderr dan ke pesan error JSON-RPC.
	maxForwardErrorReasonBytes = 256

	// jsonRPCInternalErrorCode adalah kode "Internal error" JSON-RPC 2.0 untuk request yang gagal diteruskan.
	jsonRPCInternalErrorCode = -32603
)

func runMCPConnect(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp connect", flag.ContinueOnError)
	fs.SetOutput(stderr)

	tokenEnv := fs.String("token-env", "FRANKEN_BEARER_TOKEN", "environment variable containing Sentinel HTTP bearer token")
	allowRemoteHTTP := fs.Bool("allow-insecure-remote", false, "allow plain HTTP to non-private hosts (not recommended)")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")

	// Ekstrak argumen posisional pertama meskipun berada sebelum atau sesudah flag
	endpointArg, flagArgs := extractConnectArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	if endpointArg == "" && fs.NArg() > 0 {
		endpointArg = fs.Arg(0)
	}
	if endpointArg == "" {
		fmt.Fprintln(stderr, "error: target endpoint or alias is required (e.g. sentinel@localhost or http://100.x.y.z:8090/mcp)")
		return 2
	}

	bearerToken := strings.TrimSpace(os.Getenv(*tokenEnv))
	if bearerToken == "" {
		fmt.Fprintf(stderr, "error: bearer token env var %s is empty\n", *tokenEnv)
		return 1
	}

	endpointURL, err := resolveSentinelMCPEndpoint(endpointArg, *allowRemoteHTTP)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxy := newStdioHTTPMCPProxy(endpointURL, bearerToken, &http.Client{Timeout: *timeout})
	if err := proxy.Relay(ctx, stdin, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "mcp connect error: %v\n", err)
		return 1
	}
	return 0
}

func extractConnectArgs(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// resolveSentinelMCPEndpoint mengonversi alias `sentinel@<host>` atau URL lengkap menjadi URL endpoint `/mcp` yang tervalidasi.
func resolveSentinelMCPEndpoint(raw string, allowInsecureRemote bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty MCP endpoint")
	}

	if strings.HasPrefix(trimmed, "sentinel@") {
		hostPart := strings.TrimPrefix(trimmed, "sentinel@")
		if hostPart == "" {
			return "", fmt.Errorf("missing host in alias %q", trimmed)
		}
		if !strings.Contains(hostPart, ":") {
			hostPart = net.JoinHostPort(hostPart, "8090")
		}
		trimmed = "http://" + hostPart + "/mcp"
	} else if !strings.Contains(trimmed, "://") {
		if !strings.Contains(trimmed, ":") {
			trimmed = net.JoinHostPort(trimmed, "8090")
		}
		trimmed = "http://" + trimmed + "/mcp"
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q (must be http or https)", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("endpoint URL %q missing host", raw)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/mcp"
	}

	if u.Scheme == "http" && !allowInsecureRemote {
		if err := validatePrivateHTTPTarget(u.Hostname()); err != nil {
			return "", err
		}
	}

	return u.String(), nil
}

func validatePrivateHTTPTarget(hostname string) error {
	host := strings.TrimSpace(hostname)
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".ts.net") {
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsLoopback() || mcpserver.IsTailscaleAddr(addr) || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			return nil
		}
		return fmt.Errorf("refusing plain HTTP to non-private IP %s (use HTTPS, Tailscale IP, or --allow-insecure-remote)", host)
	}
	// Validasi melalui resolver MCP server agar aturan bind & endpoint konsisten
	_, err := mcpserver.ValidateBindAddr(net.JoinHostPort(host, "8090"), false)
	if err != nil {
		return fmt.Errorf("refusing plain HTTP to untrusted host %q: %w", host, err)
	}
	return nil
}

// stdioHTTPMCPProxy meneruskan pesan JSON-RPC berbasis baris stdin ke server MCP Streamable HTTP.
type stdioHTTPMCPProxy struct {
	endpoint    string
	bearerToken string
	client      *http.Client

	mu        sync.Mutex
	sessionID string
}

func newStdioHTTPMCPProxy(endpoint, bearerToken string, client *http.Client) *stdioHTTPMCPProxy {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &stdioHTTPMCPProxy{
		endpoint:    endpoint,
		bearerToken: bearerToken,
		client:      client,
	}
}

// Relay membaca baris JSON-RPC dari in, mengirimnya via HTTP POST, dan menulis balasan ke out.
func (p *stdioHTTPMCPProxy) Relay(ctx context.Context, in io.Reader, out, errOut io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		responses, err := p.forwardMessage(ctx, line)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Catat kegagalan pada stderr tanpa menghentikan sesi; request ber-id wajib menerima error JSON-RPC agar klien tidak menunggu selamanya
			reason := p.forwardFailureReason(err)
			fmt.Fprintf(errOut, "mcp connect forward warning: %s\n", reason)
			if id, ok := jsonRPCRequestID(line); ok {
				if writeErr := writeJSONRPCError(out, id, reason); writeErr != nil {
					return writeErr
				}
			}
			continue
		}
		for _, msg := range responses {
			if _, writeErr := out.Write(append(msg, '\n')); writeErr != nil {
				return fmt.Errorf("write JSON-RPC response: %w", writeErr)
			}
		}
	}

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("read stdin json-rpc stream: %w", err)
	}
	return nil
}

func (p *stdioHTTPMCPProxy) forwardMessage(ctx context.Context, payload []byte) ([][]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+p.bearerToken)

	p.mu.Lock()
	sid := p.sessionID
	p.mu.Unlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", p.endpoint, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if nextSID := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); nextSID != "" {
		p.mu.Lock()
		p.sessionID = nextSID
		p.mu.Unlock()
	}

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}

	body, readErr := readMCPResponseBody(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Token disensor dari seluruh body sebelum dipotong agar potongan token tidak ikut lolos
		detail := truncateUTF8(strings.TrimSpace(p.scrubBearerToken(string(body))), maxForwardErrorReasonBytes)
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, p.endpoint, detail)
	}
	if readErr != nil {
		return nil, readErr
	}

	var messages [][]byte
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		messages, err = extractSSEDataMessages(body)
		if err != nil {
			return nil, fmt.Errorf("parse SSE response: %w", err)
		}
	} else if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 {
		messages = [][]byte{trimmed}
	}

	// Setiap pesan dipadatkan menjadi satu baris JSON valid; satu pesan rusak menggagalkan seluruh respons agar tidak ada JSON parsial yang diteruskan
	var lines [][]byte
	for _, msg := range messages {
		line, err := compactJSONLine(msg)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// readMCPResponseBody membaca body respons hingga maxMCPResponseBodyBytes; body yang lebih besar menghasilkan error eksplisit, bukan dipotong.
func readMCPResponseBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxMCPResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	if len(body) > maxMCPResponseBodyBytes {
		return nil, fmt.Errorf("HTTP response body exceeds %d byte limit", maxMCPResponseBodyBytes)
	}
	return body, nil
}

// extractSSEDataMessages mengekstrak payload JSON dari blok event SSE `data: ...`.
// Baris dipotong langsung dari body yang ukurannya sudah dibatasi, sehingga satu baris boleh sebesar batas body respons.
// Baris yang melebihi batas atau payload yang bukan JSON valid menghasilkan error, bukan dibuang diam-diam.
func extractSSEDataMessages(raw []byte) ([][]byte, error) {
	var messages [][]byte
	var dataLines [][]byte

	flush := func() error {
		if len(dataLines) == 0 {
			return nil
		}
		joined := bytes.TrimSpace(bytes.Join(dataLines, []byte("\n")))
		dataLines = nil
		// Event dengan data kosong (mis. priming event) bukan pesan JSON-RPC sehingga dilewati
		if len(joined) == 0 {
			return nil
		}
		if !json.Valid(joined) {
			return fmt.Errorf("event %d data is not valid JSON", len(messages)+1)
		}
		messages = append(messages, joined)
		return nil
	}

	for rest := raw; len(rest) > 0; {
		var line []byte
		line, rest, _ = bytes.Cut(rest, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > maxMCPResponseBodyBytes {
			return nil, fmt.Errorf("line exceeds %d byte limit", maxMCPResponseBodyBytes)
		}
		switch {
		case len(line) == 0:
			if err := flush(); err != nil {
				return nil, err
			}
		case line[0] == ':':
			// Baris komentar SSE (mis. keep-alive) diabaikan
		case bytes.HasPrefix(line, []byte("data:")):
			dataLines = append(dataLines, bytes.TrimSpace(line[len("data:"):]))
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return messages, nil
}

// compactJSONLine memadatkan satu pesan JSON menjadi satu baris; JSON tidak valid ditolak agar tidak pernah diteruskan sebagian.
func compactJSONLine(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, fmt.Errorf("response is not valid JSON: %w", err)
	}
	return buf.Bytes(), nil
}

// scrubBearerToken mengganti setiap kemunculan token bearer dengan penanda tersensor.
func (p *stdioHTTPMCPProxy) scrubBearerToken(s string) string {
	if p.bearerToken == "" {
		return s
	}
	return strings.ReplaceAll(s, p.bearerToken, "[REDACTED_TOKEN]")
}

// forwardFailureReason menyusun alasan kegagalan singkat satu baris untuk stderr dan stdout dengan token bearer serta data sensitif lain disensor.
func (p *stdioHTTPMCPProxy) forwardFailureReason(err error) string {
	reason := strings.Join(strings.Fields(p.scrubBearerToken(err.Error())), " ")
	return truncateUTF8(redact.String(reason), maxForwardErrorReasonBytes)
}

// truncateUTF8 memotong s menjadi paling banyak limit byte tanpa memecah rune UTF-8.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// jsonRPCRequestID mengembalikan id mentah (tipe JSON aslinya dipertahankan) bila line adalah request JSON-RPC.
// Notifikasi (tanpa id) dan response dari klien (tanpa method) tidak menghasilkan id.
func jsonRPCRequestID(line []byte) (json.RawMessage, bool) {
	var envelope struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(line, &envelope); err != nil || envelope.Method == "" || len(envelope.ID) == 0 {
		return nil, false
	}
	return envelope.ID, true
}

// jsonRPCErrorResponse adalah response error JSON-RPC 2.0 yang dikirim proxy ketika request gagal diteruskan.
type jsonRPCErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   jsonRPCError    `json:"error"`
}

// jsonRPCError adalah objek error JSON-RPC 2.0.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// writeJSONRPCError menulis tepat satu response error JSON-RPC 2.0 berakhiran newline untuk id request yang gagal.
func writeJSONRPCError(out io.Writer, id json.RawMessage, message string) error {
	line, err := json.Marshal(jsonRPCErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   jsonRPCError{Code: jsonRPCInternalErrorCode, Message: message},
	})
	if err != nil {
		return fmt.Errorf("encode JSON-RPC error response: %w", err)
	}
	if _, err := out.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write JSON-RPC error response: %w", err)
	}
	return nil
}
