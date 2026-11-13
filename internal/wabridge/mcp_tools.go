package wabridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/redact"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// WANotifyInput memuat parameter untuk mengirim notifikasi status insiden melalui WhatsApp.
type WANotifyInput struct {
	IncidentID string `json:"incident_id" jsonschema:"ID insiden rujukan"`
	Severity   string `json:"severity" jsonschema:"tingkat keparahan insiden"`
	Text       string `json:"text" jsonschema:"teks notifikasi ringkas (maks 700 karakter)"`
}

// WANotifyOutput melaporkan ID pesan WhatsApp yang berhasil terkirim.
type WANotifyOutput struct {
	MessageID string `json:"message_id"`
	SentAt    string `json:"sent_at"`
}

// WARequestApprovalInput memuat parameter pengiriman Native WhatsApp Poll dari Kiro Crew.
type WARequestApprovalInput struct {
	IncidentID string   `json:"incident_id" jsonschema:"ID insiden target persetujuan"`
	PlanHash   string   `json:"plan_hash" jsonschema:"hash SHA-256 kanonik milik plan"`
	Options    []string `json:"options,omitempty" jsonschema:"maksimal 3 label opsi aksi + Dismiss"`
}

// WARequestApprovalOutput mengembalikan identifier poll dan kode teks fallback.
type WARequestApprovalOutput struct {
	ApprovalID    string `json:"approval_id"`
	ShortCode     string `json:"short_code"`
	PollMessageID string `json:"poll_message_id"`
}

// WAAwaitDecisionInput memuat parameter tunggu jawaban operator untuk sebuah approval_id.
type WAAwaitDecisionInput struct {
	ApprovalID     string `json:"approval_id" jsonschema:"ID approval atau ID insiden"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"batas waktu tunggu dalam detik (default 600, maks 600)"`
}

// WASendReportInput memuat ringkasan akhir pasca-remediasi untuk dikirim ke WhatsApp admin.
type WASendReportInput struct {
	IncidentID string `json:"incident_id" jsonschema:"ID insiden yang telah ditutup"`
	Summary    string `json:"summary" jsonschema:"ringkasan akhir postmortem terredaksi"`
}

// NewMCPServer membangun MCP Server stdio `wa-bridge` (Task 9.5) dengan 4 tool WhatsApp.
func (b *Bridge) NewMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "franken-wa-bridge",
		Version: "0.1.0",
	}, &mcp.ServerOptions{
		Instructions: "FrankenCrew headless WhatsApp bridge MCP tools: redacted notifications, native polls, and Ed25519 token minting.",
		SchemaCache:  mcp.NewSchemaCache(),
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_notify",
		Description: "Send rate-limited, redacted incident alert to WhatsApp admin.",
	}, b.handleWANotify)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_request_approval",
		Description: "Send Native WhatsApp Poll for human approval of a validated L2 remediation plan.",
	}, b.handleWARequestApproval)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_await_decision",
		Description: "Wait for allowlisted admin vote/reply and return GRANTED (with single-use Ed25519 token), ROLLED_BACK, DENIED, or EXPIRED.",
	}, b.handleWAAwaitDecision)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "wa_send_report",
		Description: "Send terminal incident resolution or escalation report to WhatsApp admin.",
	}, b.handleWASendReport)

	return srv
}

func (b *Bridge) handleWANotify(ctx context.Context, _ *mcp.CallToolRequest, in WANotifyInput) (*mcp.CallToolResult, WANotifyOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	text := strings.TrimSpace(in.Text)
	if incID == "" || text == "" {
		return nil, WANotifyOutput{}, errors.New("incident_id and text are required")
	}
	if in.Severity != "" {
		text = fmt.Sprintf("[%s] %s\n%s", strings.ToUpper(in.Severity), incID, text)
	}
	msgID, err := b.sendRateLimitedText(ctx, incID, b.targetJID, text)
	if err != nil {
		return nil, WANotifyOutput{}, err
	}
	return nil, WANotifyOutput{
		MessageID: string(msgID),
		SentAt:    b.cfg.Clock().UTC().Format(time.RFC3339),
	}, nil
}

func (b *Bridge) handleWARequestApproval(ctx context.Context, _ *mcp.CallToolRequest, in WARequestApprovalInput) (*mcp.CallToolResult, WARequestApprovalOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	if incID == "" {
		return nil, WARequestApprovalOutput{}, errors.New("incident_id is required")
	}
	if len(in.Options) > 4 {
		return nil, WARequestApprovalOutput{}, errors.New("maximum 4 poll options allowed")
	}
	poll, err := b.SendApprovalPoll(ctx, PollRequest{
		IncidentID:    incID,
		PlanHash:      strings.TrimSpace(in.PlanHash),
		Options:       in.Options,
		ExecuteOnVote: false,
	})
	if err != nil {
		return nil, WARequestApprovalOutput{}, err
	}
	return nil, WARequestApprovalOutput{
		ApprovalID:    poll.ApprovalID,
		ShortCode:     poll.ShortCode,
		PollMessageID: string(poll.PollMessageID),
	}, nil
}

func (b *Bridge) handleWAAwaitDecision(ctx context.Context, _ *mcp.CallToolRequest, in WAAwaitDecisionInput) (*mcp.CallToolResult, ApprovalDecision, error) {
	id := strings.TrimSpace(in.ApprovalID)
	if id == "" {
		return nil, ApprovalDecision{}, errors.New("approval_id is required")
	}
	sec := in.TimeoutSeconds
	if sec <= 0 || sec > 600 {
		sec = 600
	}
	dec, err := b.AwaitDecision(ctx, id, time.Duration(sec)*time.Second)
	if err != nil {
		return nil, ApprovalDecision{}, err
	}
	return nil, dec, nil
}

func (b *Bridge) handleWASendReport(ctx context.Context, _ *mcp.CallToolRequest, in WASendReportInput) (*mcp.CallToolResult, WANotifyOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	summary := redact.String(strings.TrimSpace(in.Summary))
	if incID == "" || summary == "" {
		return nil, WANotifyOutput{}, errors.New("incident_id and summary are required")
	}
	msgID, err := b.sendRateLimitedText(ctx, incID, b.targetJID, fmt.Sprintf("[REPORT] *%s*\n%s", incID, summary))
	if err != nil {
		return nil, WANotifyOutput{}, err
	}
	return nil, WANotifyOutput{
		MessageID: string(msgID),
		SentAt:    b.cfg.Clock().UTC().Format(time.RFC3339),
	}, nil
}

