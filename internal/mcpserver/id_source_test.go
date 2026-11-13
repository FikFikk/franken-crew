package mcpserver

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestJournalTail_EvidenceIDComesFromIDSource(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	h.srv.cfg.IDSource = bytes.NewReader(bytes.Repeat([]byte{0x11}, 32))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "journal_tail", Arguments: map[string]any{
		"unit": "haunted-api.service", "lines": 5, "incident_id": "INC-20261113-0930-pi01",
	}})
	if err != nil {
		t.Fatalf("journal_tail: %v", err)
	}
	out := decodeStructured[JournalTailOutput](t, res)
	if out.EvidenceID != "ev-111111111111" {
		t.Fatalf("evidence_id must come from IDSource, got %q", out.EvidenceID)
	}
}
