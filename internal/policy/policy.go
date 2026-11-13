package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	// ErrUnknownAction terjadi jika aksi tidak terdaftar pada katalog kebijakan
	ErrUnknownAction = errors.New("policy: action is not registered in catalog")
	// ErrForbiddenTier terjadi jika ada aksi level L3 yang diusulkan dalam rencana
	ErrForbiddenTier = errors.New("policy: action belongs to forbidden tier L3")
	// ErrProtectedTarget terjadi jika aksi menargetkan unit atau proses yang dilindungi
	ErrProtectedTarget = errors.New("policy: target unit or PID is strictly protected")
	// ErrMissingEvidence terjadi jika langkah rencana tidak menyertakan bukti rujukan
	ErrMissingEvidence = errors.New("policy: plan step must cite at least one evidence_id")
)

// Tier mendefinisikan level hak akses aksi
type Tier string

const (
	TierL0 Tier = "L0" // Read-only / Observasi
	TierL1 Tier = "L1" // Refleks otomatis (reversible, TTL)
	TierL2 Tier = "L2" // Persetujuan manusia via WhatsApp
	TierL3 Tier = "L3" // Dilarang mutlak
)

// ActionDef merepresentasikan definisi aksi pada katalog policy/actions.yaml
type ActionDef struct {
	Name          string               `yaml:"name" json:"name"`
	Tier          Tier                 `yaml:"tier" json:"tier"`
	Description   string               `yaml:"description" json:"description"`
	Params        map[string]ParamDef  `yaml:"params,omitempty" json:"params,omitempty"`
	MaxReclaimPct float64              `yaml:"max_reclaim_pct,omitempty" json:"max_reclaim_pct,omitempty"`
	MaxTTLSeconds int                  `yaml:"max_ttl_seconds,omitempty" json:"max_ttl_seconds,omitempty"`
}

// ParamDef mendefinisikan tipe dan keharusan parameter aksi
type ParamDef struct {
	Type     string `yaml:"type" json:"type"`
	Required bool   `yaml:"required" json:"required"`
}

// Catalog menyimpan seluruh definisi kebijakan keamanan aksi dan unit yang dilindungi
type Catalog struct {
	Version        string               `yaml:"version"`
	ProtectedUnits []string             `yaml:"protected_units"`
	ProtectedPIDs  []int                `yaml:"protected_pids"`
	Actions        []ActionDef          `yaml:"actions"`
	actionMap      map[string]ActionDef
	unitMap        map[string]bool
	pidMap         map[int]bool
}

// PlanStep mendefinisikan satu langkah mitigasi
type PlanStep struct {
	ID             string         `json:"id"`
	Action         string         `json:"action"`
	Params         map[string]any `json:"params"`
	EvidenceIDs    []string       `json:"evidence_ids"`
	ExpectedEffect string         `json:"expected_effect"`
}

// PlanOption mendefinisikan pilihan mitigasi yang diajukan ke developer
type PlanOption struct {
	ID    string     `json:"id"`
	Label string     `json:"label"`
	Steps []PlanStep `json:"steps"`
}

// Plan merepresentasikan struktur spesifikasi rencana mitigasi yang dihasilkan Architect
type Plan struct {
	IncidentID         string       `json:"incident_id"`
	SuspectedRootCause string       `json:"suspected_root_cause"`
	Options            []PlanOption `json:"options"`
	HumanFollowUp      []string     `json:"human_follow_up"`
}

// StepValidation merepresentasikan hasil evaluasi per langkah aksi
type StepValidation struct {
	StepID string `json:"step_id"`
	Action string `json:"action"`
	Tier   Tier   `json:"tier"`
	Valid  bool   `json:"valid"`
	Error  string `json:"error,omitempty"`
}

// ValidationResult merepresentasikan ringkasan hasil validasi rencana mitigasi
type ValidationResult struct {
	PlanHash string           `json:"plan_hash"`
	Valid    bool             `json:"valid"`
	Violations []string       `json:"violations,omitempty"`
	Steps    []StepValidation `json:"steps"`
}

// LoadCatalog membaca berkas konfigurasi YAML katalog kebijakan
func LoadCatalog(filePath string) (*Catalog, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read actions catalog %s: %w", filePath, err)
	}
	return LoadCatalogFromBytes(data)
}

// LoadCatalogFromBytes mem-parsing data byte YAML menjadi instance Catalog
func LoadCatalogFromBytes(data []byte) (*Catalog, error) {
	var cat Catalog
	if err := yaml.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse actions yaml: %w", err)
	}

	cat.actionMap = make(map[string]ActionDef, len(cat.Actions))
	for _, a := range cat.Actions {
		cat.actionMap[a.Name] = a
	}

	cat.unitMap = make(map[string]bool, len(cat.ProtectedUnits))
	for _, u := range cat.ProtectedUnits {
		cat.unitMap[strings.ToLower(u)] = true
	}

	cat.pidMap = make(map[int]bool, len(cat.ProtectedPIDs))
	for _, pid := range cat.ProtectedPIDs {
		cat.pidMap[pid] = true
	}

	return &cat, nil
}

// IsProtectedUnit memeriksa apakah sebuah nama unit systemd termasuk yang dilindungi
func (c *Catalog) IsProtectedUnit(unit string) bool {
	clean := strings.ToLower(strings.TrimSpace(unit))
	if c.unitMap[clean] {
		return true
	}
	base := strings.TrimSuffix(clean, ".service")
	return c.unitMap[base]
}

// Daftar nama proses infrastruktur inti yang wajib dilindungi oleh IsProtectedPID.
// Catatan: kernel Linux memotong nama comm di /proc/<pid>/stat maksimal 15 karakter (TASK_COMM_LEN-1).
var defaultProtectedProcessNames = map[string]bool{
	"init":             true,
	"systemd":          true,
	"kthreadd":         true,
	"sshd":             true,
	"sshd-session":     true,
	"sshd-auth":        true,
	"systemd-journald": true,
	"systemd-journal":  true,
	"systemd-logind":   true,
	"systemd-udevd":    true,
	"systemd-resolved": true,
	"dbus-daemon":      true,
	"dbus-broker":      true,
	"tailscaled":       true,
	"franken":          true,
	"franken-sentinel": true,
	"franken-sentine":  true,
	"wa-bridge":        true,
}

// IsProtectedPID memeriksa apakah sebuah PID termasuk proses kernel, infrastruktur sistem, atau daemon Sentinel yang dilindungi.
func (c *Catalog) IsProtectedPID(pid int) bool {
	return c.IsProtectedPIDWithReader(pid, nil)
}

// IsProtectedPIDWithReader memeriksa proteksi PID secara dinamis dengan membaca `/proc/<pid>/stat` dan `/proc/<pid>/cmdline`.
func (c *Catalog) IsProtectedPIDWithReader(pid int, readFile func(string) ([]byte, error)) bool {
	// PID <= 1 (init/process group) dan PID 2 (kthreadd) wajib dilindungi mutlak.
	if pid <= 1 || pid == 2 {
		return true
	}
	if c != nil && c.pidMap[pid] {
		return true
	}
	if readFile == nil {
		if pid == os.Getpid() {
			return true
		}
		readFile = os.ReadFile
	}

	procBase := fmt.Sprintf("/proc/%d", pid)
	statRaw, statErr := readFile(procBase + "/stat")
	cmdRaw, cmdErr := readFile(procBase + "/cmdline")
	if statErr != nil && cmdErr != nil {
		return false
	}

	return c.isProtectedProcessMetadata(statRaw, cmdRaw)
}

func (c *Catalog) isProtectedProcessMetadata(statRaw, cmdRaw []byte) bool {
	hasCmdline := len(bytes.Trim(cmdRaw, "\x00 \t\r\n")) > 0

	if len(statRaw) > 0 {
		if comm, ppid, ok := parseStatCommAndPPID(string(statRaw)); ok {
			if ppid == 2 && !hasCmdline {
				// Kernel thread anak kthreadd selalu memiliki cmdline kosong dan PPID 2.
				return true
			}
			if c.isProtectedProcessName(comm) {
				return true
			}
		}
	}

	if hasCmdline {
		exe, args := parseCmdlineExecutable(cmdRaw)
		if c.isProtectedProcessName(exe) {
			return true
		}
		// Lindungi proses biner Go / custom launcher jika menjalankan subcommand daemon sentinel.
		if exe == "franken" && len(args) > 1 {
			sub := strings.ToLower(args[1])
			if sub == "sentinel" || sub == "mcp" || sub == "wa-login" {
				return true
			}
		}
	}

	return false
}

func (c *Catalog) isProtectedProcessName(raw string) bool {
	clean := normalizeProcToken(raw)
	if clean == "" {
		return false
	}
	if defaultProtectedProcessNames[clean] {
		return true
	}
	if c == nil {
		return false
	}
	base := strings.TrimSuffix(clean, ".service")
	if c.unitMap[clean] || c.unitMap[base] {
		return true
	}
	// Tangani pemotongan comm 15 karakter milik /proc/<pid>/stat untuk protected_units yang panjang.
	if len(base) == 15 {
		for unit := range c.unitMap {
			u := strings.TrimSuffix(unit, ".service")
			if len(u) > 15 && u[:15] == base {
				return true
			}
		}
	}
	return false
}

func parseStatCommAndPPID(rawStat string) (string, int, bool) {
	trimmed := strings.TrimSpace(rawStat)
	openIdx := strings.IndexByte(trimmed, '(')
	closeIdx := strings.LastIndexByte(trimmed, ')')
	if openIdx == -1 || closeIdx == -1 || closeIdx <= openIdx {
		return "", 0, false
	}
	comm := strings.ToLower(strings.TrimSpace(trimmed[openIdx+1 : closeIdx]))
	after := strings.Fields(trimmed[closeIdx+1:])
	ppid := 0
	if len(after) >= 2 {
		if parsed, err := strconv.Atoi(after[1]); err == nil {
			ppid = parsed
		}
	}
	return comm, ppid, true
}

func parseCmdlineExecutable(cmdRaw []byte) (string, []string) {
	parts := bytes.Split(cmdRaw, []byte{0})
	args := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(string(p))
		if s != "" {
			args = append(args, s)
		}
	}
	if len(args) == 0 {
		return "", nil
	}
	return normalizeProcToken(args[0]), args
}

func normalizeProcToken(raw string) string {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return ""
	}
	// Format seperti "sshd: root@pts/0" dipotong sebelum spasi agar hanya nama proses yang dibandingkan.
	if idx := strings.IndexAny(clean, " \t"); idx != -1 {
		clean = clean[:idx]
	}
	clean = strings.TrimPrefix(clean, "-")
	if idx := strings.LastIndexAny(clean, "/\\"); idx != -1 {
		clean = clean[idx+1:]
	}
	clean = strings.TrimSuffix(clean, ":")
	return strings.ToLower(clean)
}

// GetAction mengembalikan definisi aksi berdasarkan nama
func (c *Catalog) GetAction(name string) (ActionDef, bool) {
	def, ok := c.actionMap[name]
	return def, ok
}

// ValidatePlan memvalidasi rencana mitigasi terhadap aturan keamanan ketat
func (c *Catalog) ValidatePlan(plan *Plan) (*ValidationResult, error) {
	res := &ValidationResult{Valid: true}

	if plan == nil {
		return nil, errors.New("policy: plan is nil")
	}

	if len(plan.Options) == 0 {
		res.Valid = false
		res.Violations = append(res.Violations, "plan must contain at least one option")
	}

	// Validasi setiap pilihan dan setiap langkah aksi di dalamnya
	for _, opt := range plan.Options {
		if len(opt.Steps) > 2 {
			res.Valid = false
			res.Violations = append(res.Violations, fmt.Sprintf("option %s has %d steps (max 2 steps allowed per approval)", opt.ID, len(opt.Steps)))
		}

		for _, step := range opt.Steps {
			sv := StepValidation{
				StepID: step.ID,
				Action: step.Action,
				Valid:  true,
			}

			// 1. Periksa ketersediaan evidence_id rujukan
			if len(step.EvidenceIDs) == 0 {
				sv.Valid = false
				sv.Error = ErrMissingEvidence.Error()
				res.Valid = false
				res.Violations = append(res.Violations, fmt.Sprintf("step %s (%s): missing evidence_id", step.ID, step.Action))
			}

			// 2. Periksa apakah aksi terdaftar di katalog
			def, exists := c.GetAction(step.Action)
			if !exists {
				sv.Valid = false
				sv.Error = ErrUnknownAction.Error()
				res.Valid = false
				res.Violations = append(res.Violations, fmt.Sprintf("step %s: unknown action %q", step.ID, step.Action))
				res.Steps = append(res.Steps, sv)
				continue
			}
			sv.Tier = def.Tier

			// 3. Larangan mutlak: tidak boleh ada aksi level L3
			if def.Tier == TierL3 {
				sv.Valid = false
				sv.Error = ErrForbiddenTier.Error()
				res.Valid = false
				res.Violations = append(res.Violations, fmt.Sprintf("step %s uses forbidden L3 action %q", step.ID, step.Action))
			}

			// 4. Periksa apakah parameter wajib terpenuhi
			for pName, pDef := range def.Params {
				val, hasVal := step.Params[pName]
				if pDef.Required && (!hasVal || val == nil || val == "") {
					sv.Valid = false
					sv.Error = fmt.Sprintf("missing required parameter %q", pName)
					res.Valid = false
					res.Violations = append(res.Violations, fmt.Sprintf("step %s (%s): %s", step.ID, step.Action, sv.Error))
				}
			}

			// 5. Periksa apakah target unit atau PID termasuk yang dilindungi
			if unitVal, ok := step.Params["unit"].(string); ok && c.IsProtectedUnit(unitVal) {
				sv.Valid = false
				sv.Error = fmt.Sprintf("%s: unit %s is protected", ErrProtectedTarget, unitVal)
				res.Valid = false
				res.Violations = append(res.Violations, sv.Error)
			}
			if pidVal, ok := toInt(step.Params["pid"]); ok && c.IsProtectedPID(pidVal) {
				sv.Valid = false
				sv.Error = fmt.Sprintf("%s: PID %d is protected", ErrProtectedTarget, pidVal)
				res.Valid = false
				res.Violations = append(res.Violations, sv.Error)
			}
			if ppidVal, ok := toInt(step.Params["parent_pid"]); ok && c.IsProtectedPID(ppidVal) {
				sv.Valid = false
				sv.Error = fmt.Sprintf("%s: Parent PID %d is protected", ErrProtectedTarget, ppidVal)
				res.Valid = false
				res.Violations = append(res.Violations, sv.Error)
			}

			// 6. Batasan parameter TTL refleks
			if ttlVal, ok := toInt(step.Params["ttl_seconds"]); ok && def.MaxTTLSeconds > 0 && ttlVal > def.MaxTTLSeconds {
				sv.Valid = false
				sv.Error = fmt.Sprintf("ttl_seconds %d exceeds maximum allowed %d", ttlVal, def.MaxTTLSeconds)
				res.Valid = false
				res.Violations = append(res.Violations, sv.Error)
			}

			res.Steps = append(res.Steps, sv)
		}
	}

	// Hitung plan_hash deterministik dari canonical JSON
	hash, err := ComputePlanHash(plan)
	if err != nil {
		return nil, fmt.Errorf("compute plan hash: %w", err)
	}
	res.PlanHash = hash

	return res, nil
}

// toInt mengonversi nilai numerik generic dari JSON unmarshaling menjadi int
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// CanonicalJSON mengubah objek data menjadi JSON kanonik dengan kunci terurut secara alfabetis tanpa spasi ekstra
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}

	normalized := sortKeys(generic)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

// sortKeys menata kunci objek JSON secara rekursif agar deterministik
func sortKeys(v any) any {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]any, len(val))
		for _, k := range keys {
			ordered[k] = sortKeys(val[k])
		}
		return ordered
	case []any:
		for i, elem := range val {
			val[i] = sortKeys(elem)
		}
		return val
	default:
		return val
	}
}

// ComputePlanHash menghitung checksum SHA-256 dari representasi canonical JSON rencana mitigasi
func ComputePlanHash(plan *Plan) (string, error) {
	canonicalBytes, err := CanonicalJSON(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(sum[:]), nil
}

