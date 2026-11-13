package deploy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdUnits_HardeningDirectives(t *testing.T) {
	t.Parallel()

	units := []struct {
		file     string
		required []string
	}{
		{
			file: filepath.Join("systemd", "franken-sentinel.service"),
			required: []string{
				"OOMScoreAdjust=-900",
				"MemoryMax=48M",
				"ProtectSystem=strict",
				"NoNewPrivileges=yes",
				"ProtectHome=yes",
				"PrivateTmp=yes",
				"RuntimeDirectory=franken",
				"StateDirectory=franken",
				"sentinel-ed25519.pub",
				"ReadWritePaths=/sys/fs/cgroup /var/lib/franken /run/franken",
			},
		},
		{
			file: filepath.Join("systemd", "franken-bridge.service"),
			required: []string{
				"OOMScoreAdjust=-900",
				"MemoryMax=48M",
				"ProtectSystem=strict",
				"NoNewPrivileges=yes",
				"ProtectHome=yes",
				"PrivateTmp=yes",
				"ProtectControlGroups=yes",
				"StateDirectory=franken",
				"ReadWritePaths=/var/lib/franken",
			},
		},
	}

	for _, unit := range units {
		raw, err := os.ReadFile(unit.file)
		if err != nil {
			t.Fatalf("read systemd unit %s: %v", unit.file, err)
		}
		text := string(raw)
		for _, directive := range unit.required {
			if !strings.Contains(text, directive) {
				t.Errorf("%s missing required security/resource directive %q", unit.file, directive)
			}
		}
		if strings.HasSuffix(unit.file, "franken-sentinel.service") && strings.Contains(text, "bridge-ed25519.pub") {
			t.Errorf("%s must reference sentinel-ed25519.pub instead of bridge-ed25519.pub", unit.file)
		}
	}
}

func TestKiroConfigurations_ValidJSONAndNoRawShell(t *testing.T) {
	t.Parallel()

	jsonFiles := []string{
		filepath.Join("..", ".kiro", "agents", "franken-sentry.json"),
		filepath.Join("..", ".kiro", "agents", "franken-architect.json"),
		filepath.Join("..", ".kiro", "agents", "franken-remediator.json"),
		filepath.Join("..", ".kiro", "hooks", "preToolUse.json"),
		filepath.Join("..", ".kiro", "crons", "incident-sweep.json"),
		filepath.Join("..", ".kiro", "crons", "morning-digest.json"),
		filepath.Join("..", ".kiro", "settings", "mcp.json"),
	}

	for _, path := range jsonFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read Kiro config %s: %v", path, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("invalid JSON in %s: %v", path, err)
		}
	}

	// Pastikan ketiga agen Kiro melarang tool execute_bash
	for _, agent := range []string{"franken-sentry.json", "franken-architect.json", "franken-remediator.json"} {
		raw, err := os.ReadFile(filepath.Join("..", ".kiro", "agents", agent))
		if err != nil {
			t.Fatalf("read agent %s: %v", agent, err)
		}
		if !strings.Contains(string(raw), `"action": "deny"`) || !strings.Contains(string(raw), `"execute_bash"`) {
			t.Errorf("agent %s must explicitly deny execute_bash", agent)
		}
	}
}

