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

	"github.com/FikFikk/franken-crew/internal/mcpserver"
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
			// Catat kegagalan transport pada stderr tanpa menghentikan sesi secara mendadak kecuali fatal
			fmt.Fprintf(errOut, "mcp connect forward warning: %v\n", err)
			continue
		}
		for _, msg := range responses {
			compact := compactJSONLine(msg)
			if _, writeErr := fmt.Fprintln(out, string(compact)); writeErr != nil {
				return writeErr
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, p.endpoint, strings.TrimSpace(string(body)))
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		return extractSSEDataMessages(body), nil
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}
	return [][]byte{trimmed}, nil
}

// extractSSEDataMessages mengekstrak payload JSON dari blok event SSE `data: ...`.
func extractSSEDataMessages(raw []byte) [][]byte {
	var messages [][]byte
	var dataLines []string

	flush := func() {
		if len(dataLines) == 0 {
			return
		}
		joined := strings.TrimSpace(strings.Join(dataLines, "\n"))
		if joined != "" {
			messages = append(messages, []byte(joined))
		}
		dataLines = nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	flush()
	return messages
}

func compactJSONLine(raw []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err == nil {
		return buf.Bytes()
	}
	return bytes.ReplaceAll(bytes.TrimSpace(raw), []byte("\n"), []byte(" "))
}
