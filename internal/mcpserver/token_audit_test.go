package mcpserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Vote manusia tidak tercatat di Sentinel; iat token Ed25519 adalah satu-satunya stempel waktu vote yang tertanda tangan.
func TestActionExecute_AuditsTokenIssuedAtAsVoteTime(t *testing.T) {
	h := setupTestMCPHarness(t)
	defer h.srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, cleanup := connectPipeMCPClient(t, ctx, h.srv)
	defer cleanup()

	incID := "INC-20261113-1830-pi01"
	ev := newScopedIncident(t, h, incID, scopedCgroup)
	planOut := callPlanSubmit(t, ctx, session, incID, singleStepPlan(incID, "unit_restart", map[string]any{"unit": "haunted-api.service"}, ev))
	if !planOut.Valid {
		t.Fatalf("plan rejected: %v", planOut.Violations)
	}
	voteAt := h.Now()
	tok, claims, err := h.minter.Mint(policyMint(incID, planOut.PlanHash, "unit_restart", "s1"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h.AdvanceClock(7 * time.Second)
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "action_execute", Arguments: map[string]any{
		"incident_id": incID, "step_id": "s1", "action": "unit_restart", "params": map[string]any{"unit": "haunted-api.service"}, "approval_token": tok,
	}})
	if err != nil || res.IsError {
		t.Fatalf("action_execute: err=%v res=%+v", err, res)
	}

	audit, err := h.store.GetAuditTrail(ctx, incID)
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	for _, a := range audit {
		if a.EventType != "ACTION_TOKEN_VERIFIED" {
			continue
		}
		var payload struct {
			StepID       string `json:"step_id"`
			ApproverHash string `json:"approver_hash"`
			IssuedAt     int64  `json:"issued_at"`
		}
		if err := json.Unmarshal([]byte(a.PayloadJSON), &payload); err != nil {
			t.Fatalf("ACTION_TOKEN_VERIFIED payload is not JSON: %q", a.PayloadJSON)
		}
		if payload.IssuedAt != claims.IssuedAt || payload.IssuedAt != voteAt.Unix() || payload.StepID != "s1" || payload.ApproverHash != claims.ApproverHash {
			t.Fatalf("ACTION_TOKEN_VERIFIED must carry the token iat (%d), got %+v", voteAt.Unix(), payload)
		}
		return
	}
	t.Fatalf("no ACTION_TOKEN_VERIFIED audit row recorded")
}
