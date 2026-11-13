package wabridge

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bearerRoundTripper menyisipkan header Bearer auth Sentinel pada seluruh HTTP request MCP dan SSE.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (rt *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	if rt.token != "" {
		cloned.Header.Set("Authorization", "Bearer "+rt.token)
	}
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(cloned)
}

// SentinelClient berkomunikasi dengan Sentinel node via Streamable HTTP MCP, SSE `/v1/events`, dan `/healthz`.
type SentinelClient struct {
	baseURL     string
	bearerToken string
	httpClient  *http.Client
	sseClient   *http.Client

	mu      sync.Mutex
	session *mcp.ClientSession
}

// NewSentinelClient membuat client Sentinel HTTP/MCP terautentikasi Bearer token.
func NewSentinelClient(baseURL, bearerToken string) (*SentinelClient, error) {
	cleanURL := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if cleanURL == "" {
		return nil, errors.New("wabridge: sentinel base URL is required")
	}
	if _, err := url.ParseRequestURI(cleanURL); err != nil {
		return nil, fmt.Errorf("invalid sentinel base URL %q: %w", baseURL, err)
	}
	if strings.TrimSpace(bearerToken) == "" {
		return nil, errors.New("wabridge: sentinel bearer token is required")
	}

	rt := &bearerRoundTripper{token: bearerToken}
	return &SentinelClient{
		baseURL:     cleanURL,
		bearerToken: bearerToken,
		httpClient:  &http.Client{Timeout: 20 * time.Second, Transport: rt},
		sseClient:   &http.Client{Transport: rt},
	}, nil
}

// Close menutup sesi MCP yang terbuka ke Sentinel secara rapi.
func (c *SentinelClient) Close() error {
	c.mu.Lock()
	sess := c.session
	c.session = nil
	c.mu.Unlock()
	if sess != nil {
		return sess.Close()
	}
	return nil
}

// CheckHealthz memeriksa endpoint unauthenticated `/healthz` Sentinel.
func (c *SentinelClient) CheckHealthz(ctx context.Context) (*mcpserver.HealthzResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var health mcpserver.HealthzResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&health); decErr != nil {
		return nil, fmt.Errorf("decode /healthz (status=%d): %w", resp.StatusCode, decErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &health, fmt.Errorf("/healthz returned status %d (%s)", resp.StatusCode, health.Status)
	}
	return &health, nil
}

// StreamEvents berlangganan stream SSE `/v1/events` Sentinel dan memanggil handler untuk setiap event yang masuk.
func (c *SentinelClient) StreamEvents(ctx context.Context, lastEventID string, onEvent func(mcpserver.StreamEvent)) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/events", nil)
	if err != nil {
		return lastEventID, err
	}
	req.Header.Set("Accept", "text/event-stream")
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}

	resp, err := c.sseClient.Do(req)
	if err != nil {
		return lastEventID, fmt.Errorf("connect SSE /v1/events: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return lastEventID, fmt.Errorf("SSE /v1/events returned HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 16*1024), 1024*1024)

	var evID string
	var evName string
	var dataLines []string

	flush := func() {
		if len(dataLines) == 0 && evName == "" {
			return
		}
		rawData := strings.TrimSpace(strings.Join(dataLines, "\n"))
		dataLines = nil
		if evName == "heartbeat" && rawData == "" {
			rawData = fmt.Sprintf(`{"type":"heartbeat","timestamp":%q}`, time.Now().UTC().Format(time.RFC3339))
		}
		if rawData == "" {
			evName = ""
			return
		}
		var ev mcpserver.StreamEvent
		if jsonErr := json.Unmarshal([]byte(rawData), &ev); jsonErr == nil {
			if ev.Type == "" && evName != "" {
				ev.Type = evName
			}
			if evID != "" {
				lastEventID = evID
			}
			if onEvent != nil {
				onEvent(ev)
			}
		}
		evName = ""
	}

	for scanner.Scan() {
		if ctx.Err() != nil {
			return lastEventID, nil
		}
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			// Komentar SSE keep-alive tetap menandakan server aktif
			if onEvent != nil {
				onEvent(mcpserver.StreamEvent{Type: "heartbeat", Timestamp: time.Now().UTC()})
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "id:"):
			evID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(line, "event:"):
			evName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	flush()

	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return lastEventID, fmt.Errorf("read SSE stream: %w", err)
	}
	if ctx.Err() == nil {
		return lastEventID, errors.New("SSE stream closed by Sentinel")
	}
	return lastEventID, nil
}

// CallTool memanggil tool MCP di endpoint `/mcp` Sentinel menggunakan official StreamableClientTransport.
func (c *SentinelClient) CallTool(ctx context.Context, name string, args any, out any) error {
	sess, err := c.ensureSession(ctx)
	if err != nil {
		return err
	}

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		// Reset sesi lalu coba satu kali lagi jika session ID kedaluwarsa di sisi Sentinel
		_ = c.Close()
		sess, reconnectErr := c.ensureSession(ctx)
		if reconnectErr != nil {
			return fmt.Errorf("call mcp tool %s: %w", name, err)
		}
		res, err = sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		})
		if err != nil {
			return fmt.Errorf("call mcp tool %s: %w", name, err)
		}
	}

	if res.IsError {
		return fmt.Errorf("mcp tool %s error: %s", name, extractResultText(res))
	}
	if out == nil {
		return nil
	}

	if res.StructuredContent != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return fmt.Errorf("marshal structured output %s: %w", name, err)
		}
		if err := json.Unmarshal(raw, out); err == nil {
			return nil
		}
	}

	txt := extractResultText(res)
	if txt == "" {
		return fmt.Errorf("empty output from mcp tool %s", name)
	}
	if err := json.Unmarshal([]byte(txt), out); err != nil {
		return fmt.Errorf("decode json output from %s: %w", name, err)
	}
	return nil
}

func (c *SentinelClient) ensureSession(ctx context.Context) (*mcp.ClientSession, error) {
	c.mu.Lock()
	existing := c.session
	c.mu.Unlock()
	if existing != nil {
		return existing, nil
	}

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "franken-wa-bridge",
		Version: "0.1.0",
	}, nil)

	transport := &mcp.StreamableClientTransport{
		Endpoint:             c.baseURL + "/mcp",
		HTTPClient:           c.httpClient,
		DisableStandaloneSSE: true,
	}
	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect MCP HTTP %s/mcp: %w", c.baseURL, err)
	}

	c.mu.Lock()
	if c.session != nil {
		c.mu.Unlock()
		_ = sess.Close()
		return c.session, nil
	}
	c.session = sess
	c.mu.Unlock()
	return sess, nil
}

func extractResultText(res *mcp.CallToolResult) string {
	for _, content := range res.Content {
		if tc, ok := content.(*mcp.TextContent); ok && strings.TrimSpace(tc.Text) != "" {
			return tc.Text
		}
	}
	return ""
}

// IncidentGet mengambil detail insiden beserta daftar refleks L1 dan plan dari Sentinel MCP.
func (c *SentinelClient) IncidentGet(ctx context.Context, incidentID string) (*mcpserver.IncidentGetOutput, error) {
	var out mcpserver.IncidentGetOutput
	err := c.CallTool(ctx, "incident_get", mcpserver.IncidentGetInput{IncidentID: incidentID}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PlanSubmit mengirim remediation plan agar divalidasi dan dihitung plan_hash kanoniknya oleh Sentinel.
func (c *SentinelClient) PlanSubmit(ctx context.Context, incidentID string, plan policy.Plan) (*mcpserver.PlanSubmitOutput, error) {
	var out mcpserver.PlanSubmitOutput
	err := c.CallTool(ctx, "plan_submit", mcpserver.PlanSubmitInput{
		IncidentID: incidentID,
		Plan:       plan,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ActionExecute mengeksekusi satu langkah aksi terotorisasi (membawa Ed25519 approval token untuk L2).
func (c *SentinelClient) ActionExecute(ctx context.Context, in mcpserver.ActionExecuteInput) (*mcpserver.ActionExecuteOutput, error) {
	var out mcpserver.ActionExecuteOutput
	err := c.CallTool(ctx, "action_execute", in, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ActionRollback mengembalikan aksi refleks L1 yang sedang aktif.
func (c *SentinelClient) ActionRollback(ctx context.Context, reflexID string) (*mcpserver.ActionRollbackOutput, error) {
	var out mcpserver.ActionRollbackOutput
	err := c.CallTool(ctx, "action_rollback", mcpserver.ActionRollbackInput{ReflexID: reflexID}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// IncidentTransition memindahkan state insiden pada Sentinel state machine.
func (c *SentinelClient) IncidentTransition(ctx context.Context, in mcpserver.IncidentTransitionInput) (*mcpserver.IncidentTransitionOutput, error) {
	var out mcpserver.IncidentTransitionOutput
	err := c.CallTool(ctx, "incident_transition", in, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
