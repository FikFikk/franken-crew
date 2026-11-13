package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Daftar cadangan guard (dipakai saat policy/actions.yaml tidak terbaca) wajib setara dengan katalog:
// unit SSH versi Debian/Ubuntu, unit bridge yang benar-benar di-deploy, jaringan, dan gateway Kiro Crew.
func TestCLI_GuardFallbackBlocksCoreUnitsWithoutPolicyFile(t *testing.T) {
	missingPolicy := filepath.Join(t.TempDir(), "absent-actions.yaml")
	for _, unit := range []string{
		"ssh.service", "ssh.socket", "franken-bridge.service", "systemd-networkd.service",
		"NetworkManager.service", "systemd-resolved.service", "kirocrew.service",
	} {
		t.Run(unit, func(t *testing.T) {
			payload := fmt.Sprintf(`{"tool_name":"mcp_franken_sentinel_action_execute","tool_input":{"action":"unit_restart","params":{"unit":%q},"unit":%q,"approval_token":"tok"}}`, unit, unit)
			var stdout, stderr bytes.Buffer
			code := runWithInput([]string{"guard", "--policy", missingPolicy, "--payload", payload}, nil, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("expected guard to block %s with exit 2 using built-in rules, got %d (stdout=%q stderr=%q)", unit, code, stdout.String(), stderr.String())
			}
		})
	}
}

// action_execute mengirim target di dalam objek `params`; guard wajib memeriksanya, bukan hanya field tingkat atas.
func TestCLI_GuardInspectsNestedActionExecuteParams(t *testing.T) {
	policyPath := filepath.Join("..", "..", "policy", "actions.yaml")
	cases := []struct {
		name    string
		payload string
	}{
		{"protected unit in params", `{"tool_name":"mcp_franken_sentinel_action_execute","tool_input":{"incident_id":"INC-1","step_id":"s1","action":"unit_restart","params":{"unit":"ssh.service"},"approval_token":"tok"}}`},
		{"protected pid in params", `{"tool_name":"mcp_franken_sentinel_action_execute","tool_input":{"incident_id":"INC-1","step_id":"s1","action":"process_terminate","params":{"pid":1},"approval_token":"tok"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runWithInput([]string{"guard", "--policy", policyPath, "--payload", tc.payload}, nil, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("expected exit 2, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
			}
		})
	}
}

// sentinel serve wajib menerima --postmortem-dir agar postmortem otomatis bisa ditulis ke StateDirectory systemd.
func TestCLI_SentinelServeAcceptsPostmortemDirFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	t.Setenv("FRANKEN_SENTINEL_EMPTY", "")
	code := run([]string{"sentinel", "serve", "--postmortem-dir", t.TempDir(), "--token-env", "FRANKEN_SENTINEL_EMPTY"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "bearer token") {
		t.Fatalf("expected --postmortem-dir to parse and reach the bearer token check (exit 1), got %d (stderr=%s)", code, stderr.String())
	}
}
