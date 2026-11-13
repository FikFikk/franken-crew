package deploy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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

	// Direktori legacy .kiro/crons harus dihapus karena cron Crew dideklarasikan resmi pada app.json.
	if _, err := os.Stat(filepath.Join("..", ".kiro", "crons")); !os.IsNotExist(err) {
		t.Fatalf("direktori non-standar .kiro/crons seharusnya sudah dihapus")
	}

	jsonFiles := []string{
		filepath.Join("..", "app.json"),
		filepath.Join("..", ".kiro", "agents", "franken-conductor.json"),
		filepath.Join("..", ".kiro", "agents", "franken-sentry.json"),
		filepath.Join("..", ".kiro", "agents", "franken-architect.json"),
		filepath.Join("..", ".kiro", "agents", "franken-remediator.json"),
		filepath.Join("..", ".kiro", "hooks", "preToolUse.json"),
		filepath.Join("..", ".kiro", "hooks", "executor-guard.json"),
		filepath.Join("..", ".kiro", "hooks", "policy-sync.json"),
		filepath.Join("..", ".kiro", "hooks", "redaction-test.json"),
		filepath.Join("..", ".kiro", "hooks", "spec-verify-on-stop.json"),
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

	type kiroRule struct {
		Capability string   `json:"capability"`
		Match      []string `json:"match"`
		Effect     string   `json:"effect"`
	}
	type kiroAgent struct {
		Name        string   `json:"name"`
		Model       string   `json:"model"`
		Tools       []string `json:"tools"`
		Resources   []string `json:"resources"`
		Hooks       any      `json:"hooks"`
		Permissions struct {
			Rules []kiroRule `json:"rules"`
		} `json:"permissions"`
	}

	// Validasi schema Kiro V3 pada ketiga agen dan larangan shell/fs_write.
	for _, agentFile := range []string{"franken-conductor.json", "franken-sentry.json", "franken-architect.json", "franken-remediator.json"} {
		agentPath := filepath.Join("..", ".kiro", "agents", agentFile)
		raw, err := os.ReadFile(agentPath)
		if err != nil {
			t.Fatalf("read agent %s: %v", agentFile, err)
		}
		if strings.Contains(string(raw), `"action":`) || strings.Contains(string(raw), `"tool":`) {
			t.Errorf("agent %s masih memakai field permissions legacy action/tool", agentFile)
		}
		var ag kiroAgent
		if err := json.Unmarshal(raw, &ag); err != nil {
			t.Fatalf("decode agent %s: %v", agentFile, err)
		}
		if ag.Model == "claude-sonnet-4" || ag.Model == "" {
			t.Errorf("agent %s memakai model EOL atau kosong: %q", agentFile, ag.Model)
		}
		if ag.Hooks != nil {
			t.Errorf("agent %s tidak boleh memiliki inline hooks agar tidak diabaikan Kiro IDE", agentFile)
		}

		hasShellDeny := false
		for _, r := range ag.Permissions.Rules {
			if r.Capability == "" || len(r.Match) == 0 || r.Effect == "" {
				t.Errorf("agent %s memiliki rule Kiro V3 tidak lengkap: %+v", agentFile, r)
			}
			if r.Capability == "shell" && r.Effect == "deny" {
				hasShellDeny = true
			}
		}
		if !hasShellDeny {
			t.Errorf("agent %s wajib mendefinisikan capability shell effect deny pada permissions.rules", agentFile)
		}

		for _, res := range ag.Resources {
			if strings.HasPrefix(res, "file://") {
				rel := strings.TrimPrefix(res, "file://")
				if _, statErr := os.Stat(filepath.Join("..", filepath.FromSlash(rel))); statErr != nil {
					t.Errorf("agent %s merujuk resource yang tidak ada (%s): %v", agentFile, rel, statErr)
				}
			}
		}
	}

	// Pastikan agen Architect merujuk schema/plan.schema.json dan tidak menyebut policy/plan.schema.json.
	archRaw, err := os.ReadFile(filepath.Join("..", ".kiro", "agents", "franken-architect.json"))
	if err != nil {
		t.Fatalf("read architect agent: %v", err)
	}
	if !strings.Contains(string(archRaw), "file://schema/plan.schema.json") || strings.Contains(string(archRaw), "policy/plan.schema.json") {
		t.Errorf("franken-architect.json wajib mengarah ke file://schema/plan.schema.json")
	}

	// Validasi schema hooks v1 dan pastikan seluruh matcher adalah regex valid.
	type kiroHookEntry struct {
		Name    string `json:"name"`
		Trigger string `json:"trigger"`
		Matcher string `json:"matcher"`
	}
	type kiroHookFile struct {
		Version string          `json:"version"`
		Hooks   []kiroHookEntry `json:"hooks"`
	}
	hookFiles, err := filepath.Glob(filepath.Join("..", ".kiro", "hooks", "*.json"))
	if err != nil || len(hookFiles) == 0 {
		t.Fatalf("glob hook files: %v (count=%d)", err, len(hookFiles))
	}
	for _, hf := range hookFiles {
		raw, err := os.ReadFile(hf)
		if err != nil {
			t.Fatalf("read hook %s: %v", hf, err)
		}
		var doc kiroHookFile
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("decode hook %s: %v", hf, err)
		}
		if doc.Version != "v1" || len(doc.Hooks) == 0 {
			t.Errorf("hook %s wajib berformat version v1 dengan daftar hooks", hf)
		}
		for _, hk := range doc.Hooks {
			if hk.Matcher == "" {
				continue
			}
			if strings.Contains(hk.Matcher, "**") || strings.Contains(hk.Matcher, "{") {
				t.Errorf("hook %s (%s) masih memakai pola glob non-regex: %q", hf, hk.Name, hk.Matcher)
			}
			re, compErr := regexp.Compile(hk.Matcher)
			if compErr != nil {
				t.Errorf("hook %s (%s) matcher bukan regex valid %q: %v", hf, hk.Name, hk.Matcher, compErr)
			}
			if filepath.Base(hf) == "preToolUse.json" && re != nil {
				for _, matchTool := range []string{
					"mcp_franken-sentinel_action_execute",
					"mcp_franken_sentinel_action_execute",
					"@franken-sentinel/action_execute",
					"mcp_franken-wa_wa_request_approval",
					"@franken-wa/wa_notify",
				} {
					if !re.MatchString(matchTool) {
						t.Errorf("preToolUse matcher %q harus cocok dengan %q", hk.Matcher, matchTool)
					}
				}
				if re.MatchString("execute_bash") {
					t.Errorf("preToolUse matcher %q tidak boleh memblokir execute_bash secara global", hk.Matcher)
				}
			}
		}
	}

	// Validasi manifest resmi Kiro Crew app.json.
	type crewCron struct {
		Name     string `json:"name"`
		Every    *int   `json:"every"`
		CronExpr string `json:"cron_expr"`
		Agent    string `json:"agent"`
		Message  string `json:"message"`
		Enabled  *bool  `json:"enabled"`
	}
	type crewApp struct {
		Name        string         `json:"name"`
		Version     string         `json:"version"`
		DisplayName string         `json:"displayName"`
		Agents      []string       `json:"agents"`
		Skills      []string       `json:"skills"`
		MCPServers  map[string]any `json:"mcpServers"`
		Crons       []crewCron     `json:"crons"`
	}
	appRaw, err := os.ReadFile(filepath.Join("..", "app.json"))
	if err != nil {
		t.Fatalf("read app.json: %v", err)
	}
	var app crewApp
	if err := json.Unmarshal(appRaw, &app); err != nil {
		t.Fatalf("decode app.json: %v", err)
	}
	if app.Name != "franken-crew" || app.Version == "" || app.DisplayName == "" {
		t.Errorf("metadata inti app.json tidak lengkap: %+v", app)
	}
	if len(app.Agents) != 4 || len(app.Skills) != 3 || len(app.Crons) != 2 || len(app.MCPServers) < 2 {
		t.Errorf("app.json harus mendaftarkan 4 agents (conductor + 3 spesialis), 3 skills, 2 crons, dan mcpServers: %+v", app)
	}
	for _, a := range app.Agents {
		if strings.Contains(a, "..") || filepath.IsAbs(a) {
			t.Errorf("path agent di app.json harus relatif tanpa traversal: %q", a)
		}
		if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(a))); err != nil {
			t.Errorf("path agent di app.json tidak ditemukan (%s): %v", a, err)
		}
	}
	for _, s := range app.Skills {
		if strings.Contains(s, "..") || filepath.IsAbs(s) {
			t.Errorf("path skill di app.json harus relatif tanpa traversal: %q", s)
		}
		if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(s), "SKILL.md")); err != nil {
			t.Errorf("SKILL.md skill di app.json tidak ditemukan (%s): %v", s, err)
		}
	}
	for _, c := range app.Crons {
		hasEvery := c.Every != nil && *c.Every > 0
		hasExpr := strings.TrimSpace(c.CronExpr) != ""
		if hasEvery == hasExpr {
			t.Errorf("cron %q wajib memakai tepat salah satu dari every atau cron_expr", c.Name)
		}
		if c.Agent == "" || c.Message == "" || c.Enabled == nil {
			t.Errorf("cron %q memiliki field wajib kosong: %+v", c.Name, c)
		}
	}
}

