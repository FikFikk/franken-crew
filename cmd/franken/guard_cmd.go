package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/redact"
)

const maxGuardPayloadBytes = 1 << 20

// defaultProtectedUnits adalah daftar cadangan unit terlindungi jika berkas policy YAML tidak tersedia.
var defaultProtectedUnits = map[string]struct{}{
	"init":                     {},
	"systemd":                  {},
	"sshd":                     {},
	"sshd.service":             {},
	"systemd-journald":         {},
	"systemd-journald.service": {},
	"systemd-logind":           {},
	"systemd-logind.service":   {},
	"dbus":                     {},
	"dbus.service":             {},
	"tailscaled":               {},
	"tailscaled.service":       {},
	"franken-sentinel":         {},
	"franken-sentinel.service": {},
	"wa-bridge":                {},
	"wa-bridge.service":        {},
	"kiro-crew":                {},
	"kiro-crew.service":        {},
}

// defaultForbiddenActions berisi nama tool atau aksi Level 3 yang mutlak diblokir oleh PreToolUse guard.
var defaultForbiddenActions = map[string]struct{}{
	"execute_bash":       {},
	"raw_shell":          {},
	"file_delete":        {},
	"power_action":       {},
	"persistent_config":  {},
	"global_drop_caches": {},
	"modify_memory_max":  {},
}

type guardInputEnvelope struct {
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	Action        string         `json:"action"`
	IncidentID    string         `json:"incident_id"`
	ApprovalToken string         `json:"approval_token"`
	Unit          string         `json:"unit"`
	Target        string         `json:"target"`
	Cgroup        string         `json:"cgroup"`
	App           string         `json:"app"`
	Command       string         `json:"command"`
	PID           *int           `json:"pid"`
	ParentPID     *int           `json:"parent_pid"`
	Steps         []guardStep    `json:"steps"`
}

type guardStep struct {
	Action string         `json:"action"`
	Params map[string]any `json:"params"`
}

type guardDecision struct {
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason"`
	ToolName   string `json:"tool_name,omitempty"`
	Action     string `json:"action,omitempty"`
	IncidentID string `json:"incident_id,omitempty"`
}

func runGuard(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(stderr)

	audit := fs.Bool("audit", false, "record redacted tool-use inspection to stderr and SQLite audit_trail when available")
	dbPath := fs.String("db", "", "optional path to SQLite incident store for audit_trail persistence")
	policyPath := fs.String("policy", "policy/actions.yaml", "path to policy/actions.yaml catalog")
	payloadFlag := fs.String("payload", "", "inline JSON tool payload (defaults to KIRO_TOOL_INPUT or stdin)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	rawPayload, err := resolveGuardPayload(*payloadFlag, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "guard error: %v\n", err)
		return 1
	}

	cat, catErr := loadOptionalPolicyCatalog(*policyPath)
	if catErr != nil {
		fmt.Fprintf(stderr, "guard warning: policy load failed (%v), using built-in safety rules\n", catErr)
	}

	decision, incidentID, decErr := evaluateGuardPayload(rawPayload, cat)
	if decErr != nil {
		fmt.Fprintf(stderr, "guard error: %v\n", decErr)
		return 1
	}

	if *audit {
		if auditErr := writeGuardAudit(*dbPath, incidentID, rawPayload, decision, stdout, stderr); auditErr != nil {
			fmt.Fprintf(stderr, "guard audit error: %v\n", auditErr)
			return 1
		}
	}

	if !decision.Allowed {
		// Exit code 2 memberi sinyal blokir resmi ke Kiro PreToolUse hook
		fmt.Fprintf(stderr, "BLOCKED by Franken guard: %s\n", decision.Reason)
		return 2
	}

	if !*audit {
		fmt.Fprintf(stdout, "ALLOWED: %s\n", decision.Reason)
	}
	return 0
}

func resolveGuardPayload(inline string, stdin io.Reader) (string, error) {
	if trimmed := strings.TrimSpace(inline); trimmed != "" {
		return trimmed, nil
	}
	if env := strings.TrimSpace(os.Getenv("KIRO_TOOL_INPUT")); env != "" {
		return env, nil
	}
	if env := strings.TrimSpace(os.Getenv("TOOL_INPUT")); env != "" {
		return env, nil
	}
	if stdin == nil {
		return "{}", nil
	}
	// Hindari membaca stdin interaktif yang dapat membuat CLI menggantung jika dipanggil tanpa pipe
	if f, ok := stdin.(*os.File); ok {
		info, err := f.Stat()
		if err == nil && (info.Mode()&os.ModeCharDevice) != 0 {
			return "{}", nil
		}
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxGuardPayloadBytes))
	if err != nil {
		return "", fmt.Errorf("read stdin payload: %w", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return "{}", nil
	}
	return trimmed, nil
}

func loadOptionalPolicyCatalog(path string) (*policy.Catalog, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return policy.LoadCatalog(path)
}

func evaluateGuardPayload(raw string, cat *policy.Catalog) (guardDecision, string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return guardDecision{}, "", fmt.Errorf("invalid guard JSON payload: %w", err)
	}

	var env guardInputEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return guardDecision{}, "", fmt.Errorf("decode guard envelope: %w", err)
	}

	toolName := normalizeGuardToolName(env.ToolName)
	inputMap := env.ToolInput
	if inputMap == nil {
		inputMap = root
	}

	incidentID := extractStringField(inputMap, "incident_id")
	if incidentID == "" {
		incidentID = env.IncidentID
	}

	actionName := extractStringField(inputMap, "action")
	if actionName == "" {
		actionName = env.Action
	}
	if actionName == "" && toolName != "" {
		actionName = toolName
	}

	dec := guardDecision{
		Allowed:    true,
		Reason:     "policy check passed",
		ToolName:   toolName,
		Action:     actionName,
		IncidentID: incidentID,
	}

	// 1. Blokir tool atau aksi Level 3 yang dilarang mutlak
	if reason := checkForbiddenAction(toolName, cat); reason != "" {
		dec.Allowed = false
		dec.Reason = reason
		return dec, incidentID, nil
	}
	if reason := checkForbiddenAction(actionName, cat); reason != "" {
		dec.Allowed = false
		dec.Reason = reason
		return dec, incidentID, nil
	}

	// 2. Periksa indikasi perintah shell mentah atau pola destruktif pada argumen teks
	if cmdStr := firstNonEmptyString(
		extractStringField(inputMap, "command"),
		extractStringField(inputMap, "cmd"),
		extractStringField(inputMap, "script"),
		env.Command,
	); cmdStr != "" {
		if reason := detectUnsafeShellPattern(cmdStr); reason != "" {
			dec.Allowed = false
			dec.Reason = reason
			return dec, incidentID, nil
		}
	}

	// 3. Blokir penargetan PID atau unit yang dilindungi (PID 1, sshd, sentinel, tailscaled, dll.)
	if reason := checkProtectedTargetsInMap(inputMap, cat); reason != "" {
		dec.Allowed = false
		dec.Reason = reason
		return dec, incidentID, nil
	}

	// 4. Periksa langkah-langkah rencana apabila payload adalah plan_submit atau memuat daftar steps
	if rawSteps, ok := inputMap["steps"].([]any); ok {
		for idx, item := range rawSteps {
			stepMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			stepAction := extractStringField(stepMap, "action")
			if reason := checkForbiddenAction(stepAction, cat); reason != "" {
				dec.Allowed = false
				dec.Reason = fmt.Sprintf("step[%d]: %s", idx, reason)
				return dec, incidentID, nil
			}
			if paramsMap, ok := stepMap["params"].(map[string]any); ok {
				if reason := checkProtectedTargetsInMap(paramsMap, cat); reason != "" {
					dec.Allowed = false
					dec.Reason = fmt.Sprintf("step[%d]: %s", idx, reason)
					return dec, incidentID, nil
				}
			}
		}
	}

	// 5. Wajibkan approval_token saat memanggil action_execute untuk aksi L2
	if toolName == "action_execute" && cat != nil {
		if spec, ok := cat.GetAction(actionName); ok && spec.Tier == policy.TierL2 {
			tok := firstNonEmptyString(extractStringField(inputMap, "approval_token"), env.ApprovalToken)
			if tok == "" {
				dec.Allowed = false
				dec.Reason = fmt.Sprintf("L2 action %q via action_execute requires non-empty approval_token", actionName)
				return dec, incidentID, nil
			}
		}
	}

	return dec, incidentID, nil
}

func normalizeGuardToolName(name string) string {
	trimmed := strings.TrimSpace(name)
	// Format Kiro lama/selector eksplisit: @server/tool atau server/tool
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
		trimmed = trimmed[idx+1:]
	}
	// Format tool MCP Kiro V3: mcp_<server>_<tool> (mempertahankan underscore di nama tool)
	for _, prefix := range []string{
		"mcp_franken-sentinel_",
		"mcp_franken_sentinel_",
		"mcp_franken-wa_",
		"mcp_franken_wa_",
	} {
		if len(trimmed) > len(prefix) && strings.EqualFold(trimmed[:len(prefix)], prefix) {
			return trimmed[len(prefix):]
		}
	}
	if len(trimmed) > 4 && strings.EqualFold(trimmed[:4], "mcp_") {
		rest := trimmed[4:]
		if sep := strings.IndexByte(rest, '_'); sep >= 0 && sep+1 < len(rest) {
			return rest[sep+1:]
		}
	}
	return trimmed
}

func checkForbiddenAction(name string, cat *policy.Catalog) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	if _, forbidden := defaultForbiddenActions[strings.ToLower(trimmed)]; forbidden {
		return fmt.Sprintf("forbidden L3 action or raw shell tool %q", trimmed)
	}
	if cat != nil {
		if spec, ok := cat.GetAction(trimmed); ok && spec.Tier == policy.TierL3 {
			return fmt.Sprintf("L3 forbidden catalog action %q", trimmed)
		}
	}
	return ""
}

func checkProtectedTargetsInMap(m map[string]any, cat *policy.Catalog) string {
	for _, key := range []string{"unit", "target", "cgroup", "app"} {
		val := extractStringField(m, key)
		if val == "" {
			continue
		}
		if isProtectedUnitValue(val, cat) {
			return fmt.Sprintf("protected unit/target %q in field %q", val, key)
		}
	}
	for _, key := range []string{"pid", "parent_pid"} {
		if pidVal, ok := extractIntField(m, key); ok {
			if isProtectedPIDValue(pidVal, cat) {
				return fmt.Sprintf("protected PID %d in field %q", pidVal, key)
			}
		}
	}
	return ""
}

func isProtectedUnitValue(val string, cat *policy.Catalog) bool {
	if cat != nil && cat.IsProtectedUnit(val) {
		return true
	}
	norm := strings.ToLower(strings.TrimSpace(val))
	if _, ok := defaultProtectedUnits[norm]; ok {
		return true
	}
	// Cek apabila path cgroup memuat unit yang dilindungi seperti /system.slice/sshd.service
	for unit := range defaultProtectedUnits {
		if strings.Contains(norm, "/"+unit) {
			return true
		}
	}
	return false
}

func isProtectedPIDValue(pid int, cat *policy.Catalog) bool {
	if cat != nil && cat.IsProtectedPID(pid) {
		return true
	}
	return pid <= 1
}

func detectUnsafeShellPattern(cmd string) string {
	lower := strings.ToLower(cmd)
	for _, pat := range []string{
		"sh -c",
		"bash -c",
		"rm -rf",
		"/proc/sys/vm/drop_caches",
		"sysrq",
		"poweroff",
		"reboot",
		"shutdown ",
		"mkfs.",
	} {
		if strings.Contains(lower, pat) {
			return fmt.Sprintf("dangerous shell or destructive pattern %q detected", pat)
		}
	}
	return ""
}

func writeGuardAudit(dbPath, incidentID, rawPayload string, dec guardDecision, stdout, stderr io.Writer) error {
	redactedPayload := redact.String(rawPayload)
	action := "PRE_TOOL_GUARD_ALLOW"
	if !dec.Allowed {
		action = "PRE_TOOL_GUARD_BLOCK"
	}

	record := map[string]any{
		"event":   action,
		"allowed": dec.Allowed,
		"reason":  dec.Reason,
		"tool":    dec.ToolName,
		"action":  dec.Action,
		"payload": redactedPayload,
	}
	if line, err := json.Marshal(record); err == nil {
		if dec.Allowed {
			fmt.Fprintln(stdout, string(line))
		} else {
			fmt.Fprintln(stderr, string(line))
		}
	}

	targetDB := strings.TrimSpace(dbPath)
	if targetDB == "" {
		// Hanya tulis ke berkas SQLite bawaan jika sudah ada agar hook dev tidak membuat DB liar
		if _, err := os.Stat("franken-sentinel.db"); err == nil {
			targetDB = "franken-sentinel.db"
		} else {
			return nil
		}
	}

	store, err := incident.NewStore(targetDB)
	if err != nil {
		return fmt.Errorf("open audit db %s: %w", targetDB, err)
	}
	defer func() {
		_ = store.Close()
	}()

	return store.RecordAudit(context.Background(), incidentID, "kiro-guard", action, string(mustMarshalAuditDetails(dec, redactedPayload)))
}

func mustMarshalAuditDetails(dec guardDecision, redactedPayload string) []byte {
	b, _ := json.Marshal(map[string]any{
		"allowed": dec.Allowed,
		"reason":  dec.Reason,
		"tool":    dec.ToolName,
		"action":  dec.Action,
		"payload": redactedPayload,
	})
	return b
}

func extractStringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func extractIntField(m map[string]any, key string) (int, bool) {
	if m == nil {
		return 0, false
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	default:
		return 0, false
	}
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
