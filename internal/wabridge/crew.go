package wabridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/redact"
)

// CrewPhase menamai fase alur Kiro Crew yang dipicu oleh wa-bridge.
type CrewPhase string

const (
	// CrewPhaseTriage memulai triage, perencanaan, dan permintaan persetujuan untuk insiden baru.
	CrewPhaseTriage CrewPhase = "TRIAGE"
	// CrewPhaseExecute menjalankan langkah yang sudah disetujui manusia lewat WhatsApp.
	CrewPhaseExecute CrewPhase = "EXECUTE"

	// CrewConductorAgent adalah agen orkestrator FrankenCrew yang menerima seluruh pesan fase.
	CrewConductorAgent = "franken-conductor"

	defaultCrewMaxAttempts = 3
	defaultCrewBackoff     = 1 * time.Second
	defaultCrewTimeout     = 10 * time.Second
	maxCrewFieldLen        = 128
)

// CrewPhaseRequest memuat konteks yang dikirim ke Kiro Crew untuk satu fase.
type CrewPhaseRequest struct {
	Phase      CrewPhase
	IncidentID string
	Severity   string
	Node       string
	Cgroup     string
	ApprovalID string
	OptionID   string
	StepIDs    []string
}

// CrewNotifier memicu sesi agen Kiro Crew untuk sebuah fase insiden.
type CrewNotifier interface {
	Trigger(ctx context.Context, req CrewPhaseRequest) error
}

// CrewWebhookConfig mengatur klien webhook Kiro Crew (`POST /api/hooks/agent`).
type CrewWebhookConfig struct {
	URL   string
	Token string
	// Agent opsional; hanya dikirim bila diisi karena dokumentasi webhook Crew hanya menjamin field `message`
	Agent       string
	HTTPClient  *http.Client
	MaxAttempts int
	Backoff     time.Duration
	Timeout     time.Duration
}

// CrewWebhook memanggil webhook Kiro Crew dengan Bearer token dan retry terbatas untuk galat sementara.
type CrewWebhook struct {
	endpoint    string
	token       string
	agent       string
	client      *http.Client
	maxAttempts int
	backoff     time.Duration
}

// NewCrewWebhook memvalidasi URL (HTTPS, atau HTTP hanya ke loopback/jaringan privat/Tailscale) dan token.
func NewCrewWebhook(cfg CrewWebhookConfig) (*CrewWebhook, error) {
	endpoint, err := validateCrewWebhookURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(cfg.Token)
	if token == "" {
		return nil, errors.New("wabridge: Kiro Crew webhook token is empty (mint one with `kirocrew token`)")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultCrewTimeout
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			// Jangan pernah mengikuti redirect agar Bearer token tidak terkirim ke host lain
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	attempts := cfg.MaxAttempts
	if attempts <= 0 {
		attempts = defaultCrewMaxAttempts
	}
	backoff := cfg.Backoff
	if backoff <= 0 {
		backoff = defaultCrewBackoff
	}
	return &CrewWebhook{
		endpoint:    endpoint,
		token:       token,
		agent:       strings.TrimSpace(cfg.Agent),
		client:      client,
		maxAttempts: attempts,
		backoff:     backoff,
	}, nil
}

func validateCrewWebhookURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("wabridge: invalid Kiro Crew webhook URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return u.String(), nil
	case "http":
		if isPrivateOrLoopbackHost(u.Hostname()) {
			return u.String(), nil
		}
		return "", fmt.Errorf("wabridge: plain HTTP Crew webhook is only allowed to loopback, private, or Tailscale addresses (got %q)", u.Hostname())
	default:
		return "", fmt.Errorf("wabridge: unsupported Crew webhook scheme %q", u.Scheme)
	}
}

// isPrivateOrLoopbackHost mengizinkan localhost, loopback, RFC1918/ULA, dan CGNAT Tailscale (100.64.0.0/10).
func isPrivateOrLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}

// Trigger mengirim satu fase ke Kiro Crew; galat jaringan, 429, dan 5xx dicoba ulang dengan backoff eksponensial.
func (w *CrewWebhook) Trigger(ctx context.Context, req CrewPhaseRequest) error {
	payload := map[string]any{"message": FormatCrewMessage(req)}
	if w.agent != "" {
		payload["agent"] = w.agent
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("wabridge: encode Crew webhook payload: %w", err)
	}

	delay := w.backoff
	var lastErr error
	for attempt := 1; attempt <= w.maxAttempts; attempt++ {
		retry, err := w.post(ctx, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry || attempt == w.maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wabridge: Crew webhook canceled after %d attempt(s): %w", attempt, ctx.Err())
		case <-time.After(delay):
		}
		delay *= 2
	}
	return lastErr
}

// post mengirim satu permintaan dan melaporkan apakah galatnya layak dicoba ulang.
func (w *CrewWebhook) post(ctx context.Context, body []byte) (bool, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("wabridge: build Crew webhook request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+w.token)

	resp, err := w.client.Do(httpReq)
	if err != nil {
		return true, fmt.Errorf("wabridge: Crew webhook request failed: %s", w.scrub(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return retry, fmt.Errorf("wabridge: Crew webhook returned HTTP %d: %s", resp.StatusCode, w.scrub(strings.TrimSpace(string(snippet))))
}

// scrub menghapus token dari teks galat lalu menjalankan redaksi standar.
func (w *CrewWebhook) scrub(text string) string {
	if w.token != "" {
		text = strings.ReplaceAll(text, w.token, "[REDACTED_TOKEN]")
	}
	return redact.String(text)
}

// FormatCrewMessage menyusun pesan fase yang deterministik dan mudah diurai oleh agen franken-conductor.
// Nilai disanitasi agar teks dari SSE tidak bisa menyisipkan instruksi tambahan ke prompt agen.
func FormatCrewMessage(req CrewPhaseRequest) string {
	fields := []string{
		"FRANKENCREW",
		"phase=" + crewField(string(req.Phase)),
		"incident=" + crewField(req.IncidentID),
	}
	add := func(key, val string) {
		if v := crewField(val); v != "" {
			fields = append(fields, key+"="+v)
		}
	}
	add("severity", req.Severity)
	add("node", req.Node)
	add("cgroup", req.Cgroup)
	add("approval", req.ApprovalID)
	add("option", req.OptionID)
	if len(req.StepIDs) > 0 {
		steps := make([]string, 0, len(req.StepIDs))
		for _, s := range req.StepIDs {
			if v := crewField(s); v != "" {
				steps = append(steps, v)
			}
		}
		add("steps", strings.Join(steps, ","))
	}
	header := strings.Join(fields, " ")
	return header + "\n" +
		"Handle this with the " + CrewConductorAgent + " agent and follow its " + crewField(string(req.Phase)) + " procedure. " +
		"If you are not " + CrewConductorAgent + ", spawn " + CrewConductorAgent + " with this message verbatim and do nothing else."
}

// crewField hanya meloloskan karakter aman untuk token ID/path dan memotong panjangnya.
func crewField(v string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(v) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case strings.ContainsRune("-_./:@,", r):
			b.WriteRune(r)
		}
		if b.Len() >= maxCrewFieldLen {
			break
		}
	}
	return b.String()
}
