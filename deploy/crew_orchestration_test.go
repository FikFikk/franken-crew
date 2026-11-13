package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type orchestrationAgent struct {
	Name        string   `json:"name"`
	Prompt      string   `json:"prompt"`
	Tools       []string `json:"tools"`
	Permissions struct {
		Rules []struct {
			Capability string   `json:"capability"`
			Match      []string `json:"match"`
			Effect     string   `json:"effect"`
		} `json:"rules"`
	} `json:"permissions"`
}

func readAgent(t *testing.T, file string) orchestrationAgent {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", ".kiro", "agents", file))
	if err != nil {
		t.Fatalf("read agent %s: %v", file, err)
	}
	var ag orchestrationAgent
	if err := json.Unmarshal(raw, &ag); err != nil {
		t.Fatalf("decode agent %s: %v", file, err)
	}
	return ag
}

func denies(ag orchestrationAgent, capability string) bool {
	for _, r := range ag.Permissions.Rules {
		if r.Capability == capability && r.Effect == "deny" {
			return true
		}
	}
	return false
}

// Hanya conductor yang boleh memegang @kirocrew-core (spawn/wait/send message): spesialis yang bisa men-spawn
// agen lain dapat memakai agen default ber-shell untuk melewati batas tool mereka sendiri.
func TestCrewAgents_OnlyConductorCanOrchestrate(t *testing.T) {
	conductor := readAgent(t, "franken-conductor.json")
	if conductor.Name != "franken-conductor" || !slices.Contains(conductor.Tools, "@kirocrew-core") {
		t.Fatalf("franken-conductor must exist and include @kirocrew-core, got %+v", conductor.Tools)
	}
	if !denies(conductor, "shell") || !denies(conductor, "fs_write") {
		t.Fatalf("franken-conductor must deny shell and fs_write")
	}
	for _, tool := range conductor.Tools {
		for _, mutating := range []string{"action_execute", "plan_submit", "wa_request_approval", "incident_transition", "action_rollback"} {
			if strings.HasSuffix(tool, "/"+mutating) {
				t.Errorf("franken-conductor must stay read-only on Sentinel/WhatsApp, found %s", tool)
			}
		}
	}
	for _, phase := range []string{"phase=TRIAGE", "phase=EXECUTE", "phase=SWEEP", "franken-sentry", "franken-architect", "franken-remediator"} {
		if !strings.Contains(conductor.Prompt, phase) {
			t.Errorf("franken-conductor prompt must describe %q", phase)
		}
	}

	for _, file := range []string{"franken-sentry.json", "franken-architect.json", "franken-remediator.json"} {
		ag := readAgent(t, file)
		if slices.Contains(ag.Tools, "@kirocrew-core") {
			t.Errorf("%s must not hold @kirocrew-core (spawn escalation path)", file)
		}
	}

	remediator := readAgent(t, "franken-remediator.json")
	if !strings.Contains(remediator.Prompt, "step_tokens") {
		t.Errorf("franken-remediator prompt must execute each step with its own token from step_tokens")
	}
	architect := readAgent(t, "franken-architect.json")
	for _, rule := range []string{"incident unit", "evidence_id"} {
		if !strings.Contains(architect.Prompt, rule) {
			t.Errorf("franken-architect prompt must state the Sentinel scope rule about %q", rule)
		}
	}
}

func TestCrewApp_EventDrivenManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "app.json"))
	if err != nil {
		t.Fatalf("read app.json: %v", err)
	}
	var app struct {
		Description  string   `json:"description"`
		Agents       []string `json:"agents"`
		Dependencies struct {
			Commands []string `json:"commands"`
		} `json:"dependencies"`
		Crons []struct {
			Name    string `json:"name"`
			Every   int    `json:"every"`
			Agent   string `json:"agent"`
			Message string `json:"message"`
		} `json:"crons"`
	}
	if err := json.Unmarshal(raw, &app); err != nil {
		t.Fatalf("decode app.json: %v", err)
	}
	if strings.Contains(strings.ToLower(app.Description), "ebpf") {
		t.Errorf("app.json description must not claim eBPF (the Sentinel uses PSI, cgroup v2, and inotify)")
	}
	if !slices.Contains(app.Agents, ".kiro/agents/franken-conductor.json") {
		t.Errorf("app.json must register the conductor agent, got %v", app.Agents)
	}
	for _, cmd := range []string{"franken", "wa-bridge"} {
		if !slices.Contains(app.Dependencies.Commands, cmd) {
			t.Errorf("app.json dependencies.commands must require %q so installs fail fast without the binaries", cmd)
		}
	}
	found := false
	for _, c := range app.Crons {
		if c.Name != "incident-sweep" {
			continue
		}
		found = true
		if c.Every < 900 {
			t.Errorf("incident-sweep must be a >= 15 minute safety net (webhooks drive the fast path), got every=%d", c.Every)
		}
		if c.Agent != "franken-conductor" || !strings.Contains(c.Message, "phase=SWEEP") {
			t.Errorf("incident-sweep must run the conductor SWEEP phase, got agent=%q message=%q", c.Agent, c.Message)
		}
	}
	if !found {
		t.Fatal("incident-sweep cron missing")
	}
}

func TestDeploy_WiresCrewWebhookAndPostmortemDir(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("systemd", "franken-sentinel.service"))
	if err != nil {
		t.Fatalf("read sentinel unit: %v", err)
	}
	if !strings.Contains(string(unit), "--postmortem-dir /var/lib/franken/incidents") {
		t.Errorf("franken-sentinel.service must write postmortems into its StateDirectory")
	}
	env, err := os.ReadFile(filepath.Join("systemd", "franken.env.example"))
	if err != nil {
		t.Fatalf("read env example: %v", err)
	}
	for _, key := range []string{"FRANKEN_CREW_WEBHOOK_URL=", "KIROCREW_TOKEN="} {
		if !strings.Contains(string(env), key) {
			t.Errorf("franken.env.example must document %s", key)
		}
	}
}
