package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/postmortem"
	"github.com/FikFikk/franken-crew/internal/redact"
	"github.com/FikFikk/franken-crew/internal/reflex"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// MaxPlanRevisions membatasi pengajuan ulang rencana gagal maksimal 2 revisi sebelum eskalasi (Requirement 6.4).
	MaxPlanRevisions = 2
	// HealthPSIHalfSomeMax adalah batas sehat PSI some avg10 (< 5.0) selama verifikasi 120 detik (steering Section 7).
	HealthPSIHalfSomeMax = 5.0
	// HealthPSIHalfFullMax adalah batas sehat PSI full avg10 (< 1.0) selama verifikasi 120 detik (steering Section 7).
	HealthPSIHalfFullMax = 1.0
	// MaxVerifyMemoryGrowthPct adalah batas pertumbuhan RAM wajar (%) sepanjang jendela pemulihan 120 detik.
	MaxVerifyMemoryGrowthPct = 15.0
	// MaxCgroupMemoryUtilizationPct menolak kelulusan verifikasi bila RAM live >= 95% dari memory.max cgroup.
	MaxCgroupMemoryUtilizationPct = 95.0
)

var (
	validAppArgRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
)

// PlanSubmitInput memuat rencana remediasi terstruktur yang diajukan oleh Architect.
type PlanSubmitInput struct {
	IncidentID string      `json:"incident_id" jsonschema:"ID insiden target rencana remediasi"`
	Plan       policy.Plan `json:"plan" jsonschema:"objek plan sesuai schema/plan.schema.json"`
}

// PlanSubmitOutput mengembalikan hasil validasi kebijakan, plan_hash kanonik, dan status eskalasi jika melewati batas revisi.
type PlanSubmitOutput struct {
	IncidentID     string                  `json:"incident_id"`
	PlanHash       string                  `json:"plan_hash"`
	Valid          bool                    `json:"valid"`
	Violations     []string                `json:"violations,omitempty"`
	Steps          []policy.StepValidation `json:"steps"`
	State          string                  `json:"state"`
	Escalated      bool                    `json:"escalated"`
	RejectionCount int                     `json:"rejection_count"`
}

// ActionExecuteInput memuat permintaan eksekusi satu langkah aksi (L1 atau L2 dengan token Ed25519).
type ActionExecuteInput struct {
	IncidentID    string         `json:"incident_id" jsonschema:"ID insiden terkait"`
	StepID        string         `json:"step_id" jsonschema:"ID langkah di dalam plan tervalidasi"`
	Action        string         `json:"action" jsonschema:"nama aksi dari katalog policy/actions.yaml"`
	Params        map[string]any `json:"params" jsonschema:"parameter eksekusi langkah sesuai rencana"`
	ApprovalToken string         `json:"approval_token,omitempty" jsonschema:"token Ed25519 bertanda tangan wa-bridge (wajib untuk seluruh aksi L2)"`
}

// ActionExecuteOutput memuat hasil eksekusi yang aman dan terredaksi.
type ActionExecuteOutput struct {
	IncidentID string `json:"incident_id"`
	StepID     string `json:"step_id"`
	Action     string `json:"action"`
	Tier       string `json:"tier"`
	Success    bool   `json:"success"`
	ReflexID   string `json:"reflex_id,omitempty"`
	Binary     string `json:"binary,omitempty"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
	State      string `json:"state"`
}

// ActionRollbackInput memuat ID aksi refleks L1 yang ingin di-rollback manual.
type ActionRollbackInput struct {
	ReflexID string `json:"reflex_id" jsonschema:"ID aksi refleks L1 (awalan RFX-) untuk dikembalikan"`
}

// ActionRollbackOutput melaporkan status pengembalian aksi refleks.
type ActionRollbackOutput struct {
	ReflexID   string `json:"reflex_id"`
	RolledBack bool   `json:"rolled_back"`
	Status     string `json:"status"`
}

// IncidentTransitionInput memuat permintaan perpindahan state machine insiden secara eksplisit.
type IncidentTransitionInput struct {
	IncidentID string `json:"incident_id" jsonschema:"ID insiden yang akan diubah statusnya"`
	To         string `json:"to" jsonschema:"status tujuan yang legal (TRIAGING, PLANNED, WAITING_APPROVAL, REMEDIATING, VERIFYING, RESOLVED, ESCALATED, DISMISSED, EXPIRED)"`
	Reason     string `json:"reason" jsonschema:"alasan transisi yang tercatat pada log audit"`
	Actor      string `json:"actor,omitempty" jsonschema:"identitas pelaku transisi (default: mcp-client)"`
}

// IncidentTransitionOutput mengembalikan status insiden terbaru setelah transisi berhasil.
type IncidentTransitionOutput struct {
	IncidentID string `json:"incident_id"`
	State      string `json:"state"`
}

// VerifyHealthInput memuat parameter evaluasi kesehatan server pasca-remediasi.
type VerifyHealthInput struct {
	IncidentID            string  `json:"incident_id" jsonschema:"ID insiden yang dievaluasi kesehatannya"`
	Cgroup                string  `json:"cgroup,omitempty" jsonschema:"path cgroup opsional (default mengambil cgroup milik insiden)"`
	Unit                  string  `json:"unit,omitempty" jsonschema:"nama unit systemd opsional untuk verifikasi status aktif"`
	WindowSeconds         int     `json:"window_seconds,omitempty" jsonschema:"jendela evaluasi metrik PSI dan stabilitas RAM dalam detik (default 120)"`
	ProbeURL              string  `json:"probe_url,omitempty" jsonschema:"endpoint HTTP loopback opsional untuk healthcheck aplikasi"`
	BaselineOOMKill       *uint64 `json:"baseline_oom_kill,omitempty" jsonschema:"nilai awal oom_kill cgroup untuk mendeteksi OOM baru"`
	RequireWindowCoverage bool    `json:"require_window_coverage,omitempty" jsonschema:"mewajibkan minimal 80 persen cakupan jendela waktu sampel 120s"`
	AutoTransition        bool    `json:"auto_transition,omitempty" jsonschema:"otomatis transisikan ke RESOLVED saat sehat atau rollback L1 + ESCALATED saat gagal"`
}

// HealthChecksDetail merinci hasil setiap aspek pemeriksaan kesehatan PSI & stabilitas RAM.
type HealthChecksDetail struct {
	PSISomeAvg10       float64 `json:"psi_some_avg10"`
	PSIFullAvg10       float64 `json:"psi_full_avg10"`
	PSIStable          bool    `json:"psi_stable"`
	MemoryCurrent      uint64  `json:"memory_current_bytes"`
	MemoryMinBytes     uint64  `json:"memory_min_bytes,omitempty"`
	MemoryPeakBytes    uint64  `json:"memory_peak_bytes,omitempty"`
	MemoryStartBytes   uint64  `json:"memory_start_bytes,omitempty"`
	MemoryEndBytes     uint64  `json:"memory_end_bytes,omitempty"`
	MemoryGrowthPct    float64 `json:"memory_growth_pct,omitempty"`
	MemoryStable       bool    `json:"memory_stable"`
	OOMKillCount       uint64  `json:"oom_kill_count"`
	WindowSamples      int     `json:"window_samples_checked"`
	WindowSpanSeconds  int64   `json:"window_span_seconds"`
	UnitChecked        string  `json:"unit_checked,omitempty"`
	UnitActive         *bool   `json:"unit_active,omitempty"`
	ProbeURLChecked    string  `json:"probe_url_checked,omitempty"`
	ProbeStatusCode    int     `json:"probe_status_code,omitempty"`
}

// VerifyHealthOutput melaporkan kesimpulan kelulusan evaluasi kesehatan dan jumlah refleks yang di-rollback.
type VerifyHealthOutput struct {
	IncidentID         string             `json:"incident_id"`
	Healthy            bool               `json:"healthy"`
	State              string             `json:"state,omitempty"`
	FailureReasons     []string           `json:"failure_reasons,omitempty"`
	RolledBackReflexes int                `json:"rolled_back_reflexes"`
	Checks             HealthChecksDetail `json:"checks"`
}

// PostmortemGenerateInput memuat permintaan pembuatan dokumen markdown postmortem otomatis pasca insiden.
type PostmortemGenerateInput struct {
	IncidentID string `json:"incident_id" jsonschema:"ID insiden yang telah ditutup/dievaluasi"`
	Author     string `json:"author,omitempty" jsonschema:"nama penulis/agen pembuat postmortem (default franken-remediator)"`
	Notes      string `json:"notes,omitempty" jsonschema:"catatan singkat observasi pemulihan (otomatis disensor)"`
}

// PostmortemGenerateOutput mengembalikan lokasi berkas dan isi markdown postmortem yang telah disensor.
type PostmortemGenerateOutput struct {
	IncidentID   string `json:"incident_id"`
	FilePath     string `json:"file_path"`
	State        string `json:"state"`
	EvidenceUsed int    `json:"evidence_used"`
	AuditEntries int    `json:"audit_entries"`
	Markdown     string `json:"markdown"`
}

func (s *Server) registerWriteTools() {
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "plan_submit",
		Description: "Validate remediation plan against plan.schema.json and action policy, compute canonical plan_hash, and persist valid plan.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false},
	}, s.handlePlanSubmit)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "action_execute",
		Description: "Execute an approved remediation step via static argv templates; requires valid Ed25519 approval token for L2 and rejects all L3 or protected targets.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false},
	}, s.handleActionExecute)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "action_rollback",
		Description: "Roll back a specific applied L1 reflex action to restore prior cgroup/unit/admission settings.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false},
	}, s.handleActionRollback)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "incident_transition",
		Description: "Transition an incident through the validated state machine with an audited reason.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false},
	}, s.handleIncidentTransition)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "verify_health",
		Description: "Evaluate 120s PSI (<5/<1) and RAM stability window, OOM counters, optional unit status, and loopback HTTP health; rolls back L1 reflexes.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false},
	}, s.handleVerifyHealth)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "postmortem_generate",
		Description: "Generate a redacted markdown postmortem under incidents/<id>/postmortem.md from incident evidence, reflexes, and audit trail.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false},
	}, s.handlePostmortemGenerate)
}

func (s *Server) handlePlanSubmit(ctx context.Context, _ *mcp.CallToolRequest, in PlanSubmitInput) (*mcp.CallToolResult, PlanSubmitOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	if incID == "" {
		return nil, PlanSubmitOutput{}, errors.New("incident_id is required")
	}

	inc, err := s.cfg.Store.GetIncident(ctx, incID)
	if err != nil {
		return nil, PlanSubmitOutput{}, err
	}
	if isTerminalState(inc.State) {
		return nil, PlanSubmitOutput{}, fmt.Errorf("cannot submit plan for terminal incident %s (state=%s)", incID, inc.State)
	}

	plan := in.Plan
	if plan.IncidentID == "" {
		plan.IncidentID = incID
	}
	if plan.HumanFollowUp == nil {
		plan.HumanFollowUp = []string{}
	}

	res, err := s.cfg.Catalog.ValidatePlan(&plan)
	if err != nil {
		return nil, PlanSubmitOutput{}, err
	}

	// Terapkan aturan struktur tambahan dari schema/plan.schema.json
	schemaViolations := validatePlanSchemaRules(&plan, incID)
	if len(schemaViolations) > 0 {
		res.Valid = false
		res.Violations = append(res.Violations, schemaViolations...)
	}

	if !res.Valid {
		priorRejects, _ := s.cfg.Store.CountAuditByEvent(ctx, incID, "PLAN_REJECTED")
		rejectCount := priorRejects + 1
		violJSON, _ := json.Marshal(redact.Lines(res.Violations))
		_ = s.cfg.Store.RecordAudit(ctx, incID, "policy-engine", "PLAN_REJECTED",
			fmt.Sprintf(`{"attempt":%d,"plan_hash":%q,"violations":%s}`, rejectCount, res.PlanHash, string(violJSON)))

		escalated := false
		curState := inc.State
		if priorRejects >= MaxPlanRevisions && incident.CanTransition(inc.State, incident.StateEscalated) {
			// Lewat 2 kali revisi gagal (kegagalan ke-3), eskalasikan insiden sesuai Requirement 6.4
			if tErr := s.cfg.Store.TransitionState(ctx, incID, incident.StateEscalated, "policy-engine", "exceeded max plan revisions (2)"); tErr == nil {
				escalated = true
				curState = incident.StateEscalated
				s.broker.Publish(StreamEvent{
					Type:       "incident.updated",
					IncidentID: incID,
					Severity:   inc.Severity,
					State:      string(curState),
					Summary:    "Incident escalated after exceeding plan revision limit",
				})
			}
		}

		return nil, PlanSubmitOutput{
			IncidentID:     incID,
			PlanHash:       res.PlanHash,
			Valid:          false,
			Violations:     res.Violations,
			Steps:          res.Steps,
			State:          string(curState),
			Escalated:      escalated,
			RejectionCount: rejectCount,
		}, nil
	}

	canonicalBytes, err := policy.CanonicalJSON(plan)
	if err != nil {
		return nil, PlanSubmitOutput{}, err
	}
	if err := s.cfg.Store.SavePlan(ctx, incID, string(canonicalBytes)); err != nil {
		return nil, PlanSubmitOutput{}, err
	}
	_ = s.cfg.Store.RecordAudit(ctx, incID, "architect", "PLAN_ACCEPTED", fmt.Sprintf(`{"plan_hash":%q}`, res.PlanHash))

	finalState := inc.State
	if inc.State == incident.StateDetected {
		if err := s.cfg.Store.TransitionState(ctx, incID, incident.StateTriaging, "sentinel", "auto-triage before plan persistence"); err == nil {
			finalState = incident.StateTriaging
		}
	}
	if finalState != incident.StatePlanned && incident.CanTransition(finalState, incident.StatePlanned) {
		if err := s.cfg.Store.TransitionState(ctx, incID, incident.StatePlanned, "architect", "plan validated with hash "+res.PlanHash); err == nil {
			finalState = incident.StatePlanned
		}
	}

	s.broker.Publish(StreamEvent{
		Type:       "incident.updated",
		IncidentID: incID,
		Severity:   inc.Severity,
		State:      string(finalState),
		Summary:    "Remediation plan validated and stored",
		Data:       map[string]any{"plan_hash": res.PlanHash},
	})

	return nil, PlanSubmitOutput{
		IncidentID: incID,
		PlanHash:   res.PlanHash,
		Valid:      true,
		Steps:      res.Steps,
		State:      string(finalState),
	}, nil
}

func validatePlanSchemaRules(plan *policy.Plan, expectedIncidentID string) []string {
	var v []string
	if plan.IncidentID != expectedIncidentID {
		v = append(v, fmt.Sprintf("plan.incident_id %q does not match %q", plan.IncidentID, expectedIncidentID))
	}
	if len(strings.TrimSpace(plan.SuspectedRootCause)) < 5 {
		v = append(v, "suspected_root_cause must be at least 5 characters")
	}
	if len(plan.Options) > 4 {
		v = append(v, fmt.Sprintf("plan contains %d options (max 4)", len(plan.Options)))
	}
	for _, opt := range plan.Options {
		switch opt.ID {
		case "A", "B", "C", "D":
		default:
			v = append(v, fmt.Sprintf("option id %q must be one of A, B, C, D", opt.ID))
		}
		if len(opt.Label) > 60 {
			v = append(v, fmt.Sprintf("option %s label exceeds 60 characters", opt.ID))
		}
		if len(opt.Steps) == 0 {
			v = append(v, fmt.Sprintf("option %s must have at least 1 step", opt.ID))
		}
		for _, step := range opt.Steps {
			if strings.TrimSpace(step.ID) == "" {
				v = append(v, "step id is required")
			}
			if strings.TrimSpace(step.ExpectedEffect) == "" {
				v = append(v, fmt.Sprintf("step %s: expected_effect is required", step.ID))
			}
		}
	}
	return v
}

func (s *Server) handleActionExecute(ctx context.Context, _ *mcp.CallToolRequest, in ActionExecuteInput) (*mcp.CallToolResult, ActionExecuteOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	stepID := strings.TrimSpace(in.StepID)
	actionName := strings.TrimSpace(in.Action)
	if incID == "" || stepID == "" || actionName == "" {
		return nil, ActionExecuteOutput{}, errors.New("incident_id, step_id, and action are required")
	}

	// 1. Evaluasi katalog kebijakan (fail-closed)
	def, known := s.cfg.Catalog.GetAction(actionName)
	if !known {
		_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "ACTION_REJECTED_UNKNOWN", fmt.Sprintf(`{"step_id":%q,"action":%q}`, stepID, actionName))
		return nil, ActionExecuteOutput{}, fmt.Errorf("%w: %s", policy.ErrUnknownAction, actionName)
	}
	if def.Tier == policy.TierL3 {
		// Larangan mutlak L3 meski pemanggil membawa token sekalipun
		_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "ACTION_BLOCKED_L3", fmt.Sprintf(`{"step_id":%q,"action":%q}`, stepID, actionName))
		return nil, ActionExecuteOutput{}, fmt.Errorf("%w: action %q cannot be executed even with an approval token", policy.ErrForbiddenTier, actionName)
	}
	if def.Tier == policy.TierL0 {
		return nil, ActionExecuteOutput{}, fmt.Errorf("action %q is Level 0 read-only; call its dedicated MCP tool instead", actionName)
	}

	// 2. Pastikan target tidak pernah menyentuh unit atau PID terlindungi sebelum menyentuh token/nonce
	if err := s.checkProtectedParams(actionName, in.Params); err != nil {
		_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "ACTION_BLOCKED_PROTECTED", fmt.Sprintf(`{"step_id":%q,"action":%q,"error":%q}`, stepID, actionName, err.Error()))
		return nil, ActionExecuteOutput{}, err
	}

	inc, err := s.cfg.Store.GetIncident(ctx, incID)
	if err != nil {
		return nil, ActionExecuteOutput{}, err
	}
	if isTerminalState(inc.State) {
		return nil, ActionExecuteOutput{}, fmt.Errorf("cannot execute action on terminal incident %s (state=%s)", incID, inc.State)
	}

	// 3. Validasi langkah terhadap plan tervalidasi + konsistensi parameter kanonik
	planHash, err := verifyStepAgainstIncidentPlan(inc, stepID, actionName, in.Params, def.Tier == policy.TierL2)
	if err != nil {
		_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "ACTION_PLAN_MISMATCH", fmt.Sprintf(`{"step_id":%q,"action":%q,"error":%q}`, stepID, actionName, err.Error()))
		return nil, ActionExecuteOutput{}, err
	}

	// 4. Wajib verifikasi signature Ed25519 + single-use nonce untuk aksi Level 2
	if def.Tier == policy.TierL2 {
		if strings.TrimSpace(in.ApprovalToken) == "" {
			_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "ACTION_REJECTED_NO_TOKEN", fmt.Sprintf(`{"step_id":%q,"action":%q}`, stepID, actionName))
			return nil, ActionExecuteOutput{}, errors.New("approval_token is required for Level 2 actions")
		}
		if s.cfg.Verifier == nil {
			return nil, ActionExecuteOutput{}, errors.New("approval token verifier is not configured on Sentinel")
		}
		claims, vErr := s.cfg.Verifier.VerifyAndConsume(ctx, in.ApprovalToken, approval.VerifyContext{
			IncidentID: incID,
			PlanHash:   planHash,
			ActionName: actionName,
			StepID:     stepID,
		})
		if vErr != nil {
			_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "ACTION_TOKEN_REJECTED", fmt.Sprintf(`{"step_id":%q,"action":%q,"error":%q}`, stepID, actionName, vErr.Error()))
			return nil, ActionExecuteOutput{}, fmt.Errorf("approval token rejected: %w", vErr)
		}
		_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "ACTION_TOKEN_VERIFIED",
			fmt.Sprintf(`{"step_id":%q,"action":%q,"nonce":%q,"approver_hash":%q}`, stepID, actionName, claims.Nonce, claims.ApproverHash))
	}

	// Gunakan context.WithoutCancel agar eksekusi tetap selesai & tercatat jika client MCP putus di tengah jalan
	runCtx := context.WithoutCancel(ctx)

	curState := inc.State
	if curState != incident.StateRemediating && incident.CanTransition(curState, incident.StateRemediating) {
		if tErr := s.cfg.Store.TransitionState(runCtx, incID, incident.StateRemediating, "remediator", "executing "+actionName); tErr == nil {
			curState = incident.StateRemediating
			s.broker.Publish(StreamEvent{
				Type:       "incident.updated",
				IncidentID: incID,
				Severity:   inc.Severity,
				State:      string(curState),
				Summary:    "Executing remediation step " + actionName,
			})
		}
	}

	if def.Tier == policy.TierL1 {
		return s.executeL1ReflexStep(runCtx, inc, stepID, actionName, in.Params, curState)
	}
	return s.executeL2CommandStep(runCtx, inc, stepID, actionName, in.Params, curState)
}

func (s *Server) executeL1ReflexStep(ctx context.Context, inc *incident.Incident, stepID, actionName string, params map[string]any, curState incident.State) (*mcp.CallToolResult, ActionExecuteOutput, error) {
	if s.cfg.Reflex == nil {
		return nil, ActionExecuteOutput{}, errors.New("reflex engine is not configured")
	}

	ttl, _ := extractPositiveInt(params, "ttl_seconds")
	start := s.cfg.Clock()
	var act *incident.ReflexAction
	var err error

	switch actionName {
	case "cgroup_reclaim":
		cg := extractString(params, "cgroup")
		if cg == "" {
			cg = inc.Cgroup
		}
		absCg, _, cgErr := resolveSafeCgroupDir(s.cfg.CgroupRoot, cg)
		if cgErr != nil {
			return nil, ActionExecuteOutput{}, cgErr
		}
		reclaimBytes, _ := extractUint64(params, "bytes")
		act, err = s.cfg.Reflex.ApplyReclaim(ctx, reflex.ReclaimRequest{
			IncidentID: inc.ID,
			CgroupPath: absCg,
			Bytes:      reclaimBytes,
			TTLSeconds: ttl,
		})
	case "cgroup_throttle":
		unit := extractString(params, "unit")
		cg := extractString(params, "cgroup")
		if cg == "" {
			cg = inc.Cgroup
		}
		absCg, _, cgErr := resolveSafeCgroupDir(s.cfg.CgroupRoot, cg)
		if cgErr != nil {
			return nil, ActionExecuteOutput{}, cgErr
		}
		memHighBytes, _ := parseMemorySizeParam(params["memory_high"])
		act, err = s.cfg.Reflex.ApplyThrottle(ctx, reflex.ThrottleRequest{
			IncidentID:      inc.ID,
			Unit:            unit,
			CgroupPath:      absCg,
			MemoryHighBytes: memHighBytes,
			CPUQuota:        extractString(params, "cpu_quota"),
			IOWeight:        extractString(params, "io_weight"),
			TTLSeconds:      ttl,
		})
	case "admission_close":
		app := extractString(params, "app")
		act, err = s.cfg.Reflex.ApplyAdmissionClose(ctx, reflex.AdmissionRequest{
			IncidentID: inc.ID,
			App:        app,
			TTLSeconds: ttl,
		})
	default:
		return nil, ActionExecuteOutput{}, fmt.Errorf("unsupported L1 reflex action %q", actionName)
	}

	durMs := s.cfg.Clock().Sub(start).Milliseconds()
	if err != nil {
		return nil, ActionExecuteOutput{}, err
	}

	if curState == incident.StateDetected && incident.CanTransition(curState, incident.StateReflexApplied) {
		if tErr := s.cfg.Store.TransitionState(ctx, inc.ID, incident.StateReflexApplied, "sentinel", "reflex "+act.ID); tErr == nil {
			curState = incident.StateReflexApplied
		}
	}

	s.broker.Publish(StreamEvent{
		Type:       "reflex.applied",
		IncidentID: inc.ID,
		Severity:   inc.Severity,
		State:      string(curState),
		Summary:    fmt.Sprintf("L1 reflex %s applied on %s", act.Action, act.Target),
		Data:       map[string]any{"reflex_id": act.ID, "action": act.Action, "target": act.Target},
	})

	return nil, ActionExecuteOutput{
		IncidentID: inc.ID,
		StepID:     stepID,
		Action:     actionName,
		Tier:       string(policy.TierL1),
		Success:    true,
		ReflexID:   act.ID,
		ExitCode:   0,
		DurationMs: durMs,
		State:      string(curState),
	}, nil
}

func (s *Server) executeL2CommandStep(ctx context.Context, inc *incident.Incident, stepID, actionName string, params map[string]any, curState incident.State) (*mcp.CallToolResult, ActionExecuteOutput, error) {
	if s.cfg.Runner == nil {
		return nil, ActionExecuteOutput{}, errors.New("command runner is not configured")
	}

	binary, args, timeout, err := buildL2Command(actionName, params, s.cfg.Catalog)
	if err != nil {
		return nil, ActionExecuteOutput{}, err
	}

	res, execErr := s.cfg.Runner.Execute(ctx, binary, args, timeout)

	var stdoutRedacted, stderrRedacted string
	exitCode := -1
	var durMs int64
	if res != nil {
		stdoutRedacted = redact.String(res.Stdout)
		stderrRedacted = redact.String(res.Stderr)
		exitCode = res.ExitCode
		durMs = res.Duration.Milliseconds()
	}

	if errors.Is(execErr, executor.ErrCommandTimeout) || (res != nil && res.TimedOut) {
		_ = s.cfg.Store.RecordAudit(ctx, inc.ID, "remediator", "ACTION_TIMEOUT",
			fmt.Sprintf(`{"step_id":%q,"action":%q,"binary":%q,"duration_ms":%d,"stderr":%q}`, stepID, actionName, binary, durMs, stderrRedacted))
		if incident.CanTransition(curState, incident.StateEscalated) {
			_ = s.cfg.Store.TransitionState(ctx, inc.ID, incident.StateEscalated, "sentinel", "command timeout on "+actionName)
			curState = incident.StateEscalated
		}
		s.broker.Publish(StreamEvent{
			Type:       "incident.updated",
			IncidentID: inc.ID,
			Severity:   inc.Severity,
			State:      string(curState),
			Summary:    fmt.Sprintf("Command timeout executing %s; incident escalated", actionName),
		})
		return nil, ActionExecuteOutput{
			IncidentID: inc.ID,
			StepID:     stepID,
			Action:     actionName,
			Tier:       string(policy.TierL2),
			Success:    false,
			Binary:     binary,
			ExitCode:   exitCode,
			DurationMs: durMs,
			Stdout:     stdoutRedacted,
			Stderr:     stderrRedacted,
			State:      string(curState),
		}, execErr
	}

	if execErr != nil || exitCode != 0 {
		errMsg := stderrRedacted
		if execErr != nil && errMsg == "" {
			errMsg = redact.String(execErr.Error())
		}
		_ = s.cfg.Store.RecordAudit(ctx, inc.ID, "remediator", "ACTION_FAILED",
			fmt.Sprintf(`{"step_id":%q,"action":%q,"exit_code":%d,"duration_ms":%d,"stderr":%q}`, stepID, actionName, exitCode, durMs, errMsg))
		if incident.CanTransition(curState, incident.StateEscalated) {
			_ = s.cfg.Store.TransitionState(ctx, inc.ID, incident.StateEscalated, "sentinel", "action failed: "+actionName)
			curState = incident.StateEscalated
		}
		s.broker.Publish(StreamEvent{
			Type:       "incident.updated",
			IncidentID: inc.ID,
			Severity:   inc.Severity,
			State:      string(curState),
			Summary:    fmt.Sprintf("Remediation %s failed with exit code %d", actionName, exitCode),
		})
		return nil, ActionExecuteOutput{
			IncidentID: inc.ID,
			StepID:     stepID,
			Action:     actionName,
			Tier:       string(policy.TierL2),
			Success:    false,
			Binary:     binary,
			ExitCode:   exitCode,
			DurationMs: durMs,
			Stdout:     stdoutRedacted,
			Stderr:     errMsg,
			State:      string(curState),
		}, fmt.Errorf("action %s failed (exit=%d): %s", actionName, exitCode, errMsg)
	}

	_ = s.cfg.Store.RecordAudit(ctx, inc.ID, "remediator", "ACTION_EXECUTED",
		fmt.Sprintf(`{"step_id":%q,"action":%q,"binary":%q,"exit_code":%d,"duration_ms":%d}`, stepID, actionName, binary, exitCode, durMs))

	s.broker.Publish(StreamEvent{
		Type:       "action.executed",
		IncidentID: inc.ID,
		Severity:   inc.Severity,
		State:      string(curState),
		Summary:    fmt.Sprintf("Executed L2 action %s successfully", actionName),
		Data:       map[string]any{"step_id": stepID, "action": actionName, "duration_ms": durMs},
	})

	return nil, ActionExecuteOutput{
		IncidentID: inc.ID,
		StepID:     stepID,
		Action:     actionName,
		Tier:       string(policy.TierL2),
		Success:    true,
		Binary:     binary,
		ExitCode:   0,
		DurationMs: durMs,
		Stdout:     stdoutRedacted,
		Stderr:     stderrRedacted,
		State:      string(curState),
	}, nil
}

func (s *Server) handleActionRollback(ctx context.Context, _ *mcp.CallToolRequest, in ActionRollbackInput) (*mcp.CallToolResult, ActionRollbackOutput, error) {
	reflexID := strings.TrimSpace(in.ReflexID)
	if reflexID == "" {
		return nil, ActionRollbackOutput{}, errors.New("reflex_id is required")
	}
	if s.cfg.Reflex == nil {
		return nil, ActionRollbackOutput{}, errors.New("reflex engine is not configured")
	}

	changed, err := s.cfg.Reflex.Rollback(ctx, reflexID, false)
	if err != nil {
		return nil, ActionRollbackOutput{}, err
	}
	rec, err := s.cfg.Store.GetReflexAction(ctx, reflexID)
	if err != nil {
		return nil, ActionRollbackOutput{}, err
	}

	if changed {
		s.broker.Publish(StreamEvent{
			Type:       "reflex.rolled_back",
			IncidentID: rec.IncidentID,
			Summary:    fmt.Sprintf("Rolled back L1 reflex %s (%s)", rec.ID, rec.Action),
			Data:       map[string]any{"reflex_id": rec.ID, "action": rec.Action, "status": rec.Status},
		})
	}

	return nil, ActionRollbackOutput{
		ReflexID:   reflexID,
		RolledBack: changed,
		Status:     rec.Status,
	}, nil
}

func (s *Server) handleIncidentTransition(ctx context.Context, _ *mcp.CallToolRequest, in IncidentTransitionInput) (*mcp.CallToolResult, IncidentTransitionOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	target := incident.State(strings.TrimSpace(in.To))
	reason := redact.String(strings.TrimSpace(in.Reason))
	actor := strings.TrimSpace(in.Actor)
	if actor == "" {
		actor = "mcp-client"
	}
	if incID == "" || target == "" || reason == "" {
		return nil, IncidentTransitionOutput{}, errors.New("incident_id, to, and reason are required")
	}

	if err := s.cfg.Store.TransitionState(ctx, incID, target, actor, reason); err != nil {
		return nil, IncidentTransitionOutput{}, err
	}
	inc, err := s.cfg.Store.GetIncident(ctx, incID)
	if err == nil {
		s.broker.Publish(StreamEvent{
			Type:       "incident.updated",
			IncidentID: incID,
			Severity:   inc.Severity,
			State:      string(inc.State),
			Summary:    "Transitioned to " + string(inc.State),
		})
	}

	return nil, IncidentTransitionOutput{
		IncidentID: incID,
		State:      string(target),
	}, nil
}

func (s *Server) handleVerifyHealth(ctx context.Context, _ *mcp.CallToolRequest, in VerifyHealthInput) (*mcp.CallToolResult, VerifyHealthOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	if incID == "" {
		return nil, VerifyHealthOutput{}, errors.New("incident_id is required")
	}

	inc, err := s.cfg.Store.GetIncident(ctx, incID)
	if err != nil {
		return nil, VerifyHealthOutput{}, err
	}

	cgTarget := strings.TrimSpace(in.Cgroup)
	if cgTarget == "" {
		cgTarget = inc.Cgroup
	}
	absCgDir, normCg, err := resolveSafeCgroupDir(s.cfg.CgroupRoot, cgTarget)
	if err != nil {
		return nil, VerifyHealthOutput{}, err
	}

	windowSec := in.WindowSeconds
	if windowSec <= 0 {
		windowSec = 120
	}

	sampler := cgroup.NewSampler(s.cfg.FS, 1*time.Second)
	sample, err := sampler.SampleCgroup(absCgDir)
	if err != nil {
		return nil, VerifyHealthOutput{}, fmt.Errorf("sample cgroup health on %s: %w", absCgDir, err)
	}

	var failures []string
	psiStable := true
	memStable := true

	if sample.PSISomeAvg10 >= HealthPSIHalfSomeMax {
		psiStable = false
		failures = append(failures, fmt.Sprintf("live psi_some_avg10=%.2f >= %.1f", sample.PSISomeAvg10, HealthPSIHalfSomeMax))
	}
	if sample.PSIFullAvg10 >= HealthPSIHalfFullMax {
		psiStable = false
		failures = append(failures, fmt.Sprintf("live psi_full_avg10=%.2f >= %.1f", sample.PSIFullAvg10, HealthPSIHalfFullMax))
	}
	if sample.MemoryMax > 0 && sample.MemoryCurrent > 0 {
		utilPct := (float64(sample.MemoryCurrent) / float64(sample.MemoryMax)) * 100.0
		if utilPct >= MaxCgroupMemoryUtilizationPct {
			memStable = false
			failures = append(failures, fmt.Sprintf("live memory utilization=%.1f%% >= %.1f%% of memory.max", utilPct, MaxCgroupMemoryUtilizationPct))
		}
	}
	if in.BaselineOOMKill != nil && sample.Events.OOMKill > *in.BaselineOOMKill {
		memStable = false
		failures = append(failures, fmt.Sprintf("new oom_kill detected (%d > baseline %d)", sample.Events.OOMKill, *in.BaselineOOMKill))
	}

	// Evaluasi seluruh titik histori PSI dan stabilitas RAM dalam jendela evaluasi 120 detik
	now := s.cfg.Clock().UTC()
	minutes := int(math.Ceil(float64(windowSec) / 60.0))
	if minutes < 1 {
		minutes = 1
	}
	if minutes > 10 {
		minutes = 10
	}
	cutoff := now.Add(-time.Duration(windowSec) * time.Second)
	var (
		windowSamples int
		firstAt       time.Time
		lastAt        time.Time
		memStart      uint64
		memEnd        uint64
		memMin        uint64
		memPeak       uint64
		memSamples    int
	)
	for _, pt := range s.psiRing.Query(normCg, minutes, now) {
		if pt.At.Before(cutoff) {
			continue
		}
		windowSamples++
		if firstAt.IsZero() || pt.At.Before(firstAt) {
			firstAt = pt.At
		}
		if lastAt.IsZero() || pt.At.After(lastAt) {
			lastAt = pt.At
		}
		if pt.SomeAvg10 >= HealthPSIHalfSomeMax {
			if psiStable {
				psiStable = false
				failures = append(failures, fmt.Sprintf("window psi_some_avg10=%.2f exceeded %.1f at %s", pt.SomeAvg10, HealthPSIHalfSomeMax, pt.At.Format(time.RFC3339)))
			}
		}
		if pt.FullAvg10 >= HealthPSIHalfFullMax {
			if psiStable {
				psiStable = false
				failures = append(failures, fmt.Sprintf("window psi_full_avg10=%.2f exceeded %.1f at %s", pt.FullAvg10, HealthPSIHalfFullMax, pt.At.Format(time.RFC3339)))
			}
		}
		if pt.MemoryCurrent > 0 {
			if memSamples == 0 {
				memStart = pt.MemoryCurrent
				memMin = pt.MemoryCurrent
				memPeak = pt.MemoryCurrent
			} else {
				if pt.MemoryCurrent < memMin {
					memMin = pt.MemoryCurrent
				}
				if pt.MemoryCurrent > memPeak {
					memPeak = pt.MemoryCurrent
				}
			}
			memEnd = pt.MemoryCurrent
			memSamples++
		}
	}

	var spanSec int64
	if !firstAt.IsZero() && !lastAt.IsZero() && !lastAt.Before(firstAt) {
		spanSec = int64(lastAt.Sub(firstAt).Seconds())
	}

	var memGrowthPct float64
	if memSamples >= 2 && memStart > 0 {
		memGrowthPct = (float64(memEnd) - float64(memStart)) / float64(memStart) * 100.0
		// Tolak kelulusan bila RAM masih terus menanjak > 15% dibanding baseline jendela pemulihan
		if memGrowthPct > MaxVerifyMemoryGrowthPct && memEnd >= (memPeak*90)/100 {
			memStable = false
			failures = append(failures, fmt.Sprintf("memory unstable during %ds window: grew %.1f%% (%d -> %d bytes)", windowSec, memGrowthPct, memStart, memEnd))
		}
	}

	if in.RequireWindowCoverage {
		minRequiredSpan := int64(float64(windowSec) * 0.8)
		if windowSamples < 2 || spanSec < minRequiredSpan {
			failures = append(failures, fmt.Sprintf("insufficient verification window coverage: samples=%d span=%ds (need >= %ds)", windowSamples, spanSec, minRequiredSpan))
		}
	}

	details := HealthChecksDetail{
		PSISomeAvg10:      sample.PSISomeAvg10,
		PSIFullAvg10:      sample.PSIFullAvg10,
		PSIStable:         psiStable,
		MemoryCurrent:     sample.MemoryCurrent,
		MemoryMinBytes:    memMin,
		MemoryPeakBytes:   memPeak,
		MemoryStartBytes:  memStart,
		MemoryEndBytes:    memEnd,
		MemoryGrowthPct:   math.Round(memGrowthPct*100) / 100,
		MemoryStable:      memStable,
		OOMKillCount:      sample.Events.OOMKill,
		WindowSamples:     windowSamples,
		WindowSpanSeconds: spanSec,
	}

	if unit := strings.TrimSpace(in.Unit); unit != "" {
		details.UnitChecked = unit
		if s.cfg.UnitInspector == nil {
			failures = append(failures, "unit inspector unavailable")
		} else {
			active, stateStr, uErr := s.cfg.UnitInspector.IsActive(ctx, unit)
			details.UnitActive = &active
			if uErr != nil || !active {
				failures = append(failures, fmt.Sprintf("unit %s not active (state=%s, err=%v)", unit, stateStr, uErr))
			}
		}
	}

	if probeURL := strings.TrimSpace(in.ProbeURL); probeURL != "" {
		details.ProbeURLChecked = probeURL
		if s.cfg.HTTPProber == nil {
			failures = append(failures, "http prober unavailable")
		} else {
			code, pErr := s.cfg.HTTPProber.Probe(ctx, probeURL)
			details.ProbeStatusCode = code
			if pErr != nil || code < 200 || code >= 400 {
				failures = append(failures, fmt.Sprintf("http probe %s unhealthy (status=%d, err=%v)", probeURL, code, pErr))
			}
		}
	}

	healthy := len(failures) == 0
	rolledBack := 0
	if s.cfg.Reflex != nil && (healthy || in.AutoTransition) {
		// Rollback seluruh refleks L1 saat verifikasi lulus maupun saat auto-transition gagal (Requirement 9.2 & 9.3)
		rbCount, rbErr := s.cfg.Reflex.RollbackIncident(ctx, incID)
		rolledBack = rbCount
		if rbErr != nil {
			failures = append(failures, "reflex rollback warning: "+rbErr.Error())
		}
		if rolledBack > 0 {
			s.broker.Publish(StreamEvent{
				Type:       "reflex.rolled_back",
				IncidentID: incID,
				Severity:   inc.Severity,
				State:      string(inc.State),
				Summary:    fmt.Sprintf("Auto-rolled back %d L1 reflex action(s) during health verification (healthy=%t)", rolledBack, healthy),
			})
		}
	}

	finalState := inc.State
	if in.AutoTransition {
		targetState := incident.StateEscalated
		reason := "verify_health failed: " + strings.Join(failures, "; ")
		if healthy {
			targetState = incident.StateResolved
			reason = fmt.Sprintf("verify_health passed over %ds window (psi_some=%.2f, psi_full=%.2f)", windowSec, sample.PSISomeAvg10, sample.PSIFullAvg10)
		}
		if incident.CanTransition(inc.State, targetState) {
			if trErr := s.cfg.Store.TransitionState(ctx, incID, targetState, "sentinel", reason); trErr == nil {
				finalState = targetState
				s.broker.Publish(StreamEvent{
					Type:       "incident.updated",
					IncidentID: incID,
					Severity:   inc.Severity,
					State:      string(finalState),
					Summary:    reason,
				})
			}
		}
	}

	_ = s.cfg.Store.RecordAudit(ctx, incID, "sentinel", "HEALTH_VERIFIED",
		fmt.Sprintf(`{"healthy":%t,"state":%q,"rolled_back":%d,"psi_some_avg10":%.2f,"psi_full_avg10":%.2f,"mem_growth_pct":%.2f,"oom_kill":%d}`,
			healthy, string(finalState), rolledBack, sample.PSISomeAvg10, sample.PSIFullAvg10, details.MemoryGrowthPct, sample.Events.OOMKill))

	return nil, VerifyHealthOutput{
		IncidentID:         incID,
		Healthy:            healthy,
		State:              string(finalState),
		FailureReasons:     failures,
		RolledBackReflexes: rolledBack,
		Checks:             details,
	}, nil
}

func (s *Server) handlePostmortemGenerate(ctx context.Context, _ *mcp.CallToolRequest, in PostmortemGenerateInput) (*mcp.CallToolResult, PostmortemGenerateOutput, error) {
	incID := strings.TrimSpace(in.IncidentID)
	if incID == "" {
		return nil, PostmortemGenerateOutput{}, errors.New("incident_id is required")
	}

	outDir := strings.TrimSpace(s.cfg.PostmortemDir)
	if outDir == "" {
		outDir = "incidents"
	}

	doc, err := postmortem.GenerateAndWrite(ctx, s.cfg.Store, postmortem.Options{
		IncidentID: incID,
		OutputDir:  outDir,
		Author:     strings.TrimSpace(in.Author),
		Notes:      strings.TrimSpace(in.Notes),
		Clock:      s.cfg.Clock,
	})
	if err != nil {
		return nil, PostmortemGenerateOutput{}, err
	}

	return nil, PostmortemGenerateOutput{
		IncidentID:   doc.IncidentID,
		FilePath:     doc.FilePath,
		State:        doc.State,
		EvidenceUsed: doc.EvidenceUsed,
		AuditEntries: doc.AuditEntries,
		Markdown:     doc.Markdown,
	}, nil
}

func (s *Server) checkProtectedParams(actionName string, params map[string]any) error {
	if s.cfg.Catalog == nil {
		return errors.New("policy catalog is not configured")
	}
	if unit := extractString(params, "unit"); unit != "" && s.cfg.Catalog.IsProtectedUnit(unit) {
		return fmt.Errorf("%w: unit %s", policy.ErrProtectedTarget, unit)
	}
	if app := extractString(params, "app"); app != "" && s.cfg.Catalog.IsProtectedUnit(app) {
		return fmt.Errorf("%w: app/unit %s", policy.ErrProtectedTarget, app)
	}
	if pid, ok := extractPositiveInt(params, "pid"); ok {
		if pid <= 1 || s.cfg.Catalog.IsProtectedPID(pid) {
			return fmt.Errorf("%w: pid %d", policy.ErrProtectedTarget, pid)
		}
	}
	if ppid, ok := extractPositiveInt(params, "parent_pid"); ok {
		if ppid <= 1 || s.cfg.Catalog.IsProtectedPID(ppid) {
			return fmt.Errorf("%w: parent_pid %d", policy.ErrProtectedTarget, ppid)
		}
	}
	if (actionName == "process_terminate" || actionName == "zombie_reap") && params == nil {
		return errors.New("params must be provided for process actions")
	}
	return nil
}

func verifyStepAgainstIncidentPlan(inc *incident.Incident, stepID, actionName string, params map[string]any, requirePlan bool) (string, error) {
	if inc.PlanJSON == "" {
		if requirePlan {
			return "", errors.New("incident has no validated remediation plan")
		}
		return "", nil
	}

	var plan policy.Plan
	if err := json.Unmarshal([]byte(inc.PlanJSON), &plan); err != nil {
		return "", fmt.Errorf("decode stored plan_json: %w", err)
	}
	planHash, err := policy.ComputePlanHash(&plan)
	if err != nil {
		return "", err
	}

	var foundStep *policy.PlanStep
	for _, opt := range plan.Options {
		for i := range opt.Steps {
			if opt.Steps[i].ID == stepID {
				foundStep = &opt.Steps[i]
				break
			}
		}
		if foundStep != nil {
			break
		}
	}
	if foundStep == nil {
		return "", fmt.Errorf("step_id %q not found in incident plan", stepID)
	}
	if foundStep.Action != actionName {
		return "", fmt.Errorf("step %q authorizes action %q, not %q", stepID, foundStep.Action, actionName)
	}

	stepCanon, err := policy.CanonicalJSON(nonNilMap(foundStep.Params))
	if err != nil {
		return "", err
	}
	inCanon, err := policy.CanonicalJSON(nonNilMap(params))
	if err != nil {
		return "", err
	}
	if !bytes.Equal(stepCanon, inCanon) {
		return "", errors.New("action parameters differ from approved plan step")
	}
	return planHash, nil
}

// buildL2Command menerjemahkan aksi L2 menjadi template biner & argumen statis tanpa melibatkan shell interpreter.
func buildL2Command(actionName string, params map[string]any, cat *policy.Catalog) (string, []string, time.Duration, error) {
	switch actionName {
	case "pm2_reload":
		app := extractString(params, "app")
		if !validAppArgRegex.MatchString(app) {
			return "", nil, 0, fmt.Errorf("invalid pm2 app name %q", app)
		}
		return "pm2", []string{"reload", app}, 20 * time.Second, nil

	case "pm2_restart_instance":
		app := extractString(params, "app")
		if !validAppArgRegex.MatchString(app) {
			return "", nil, 0, fmt.Errorf("invalid pm2 app name %q", app)
		}
		pmID, ok := extractNonNegativeInt(params, "pm_id")
		if !ok {
			return "", nil, 0, errors.New("integer pm_id >= 0 is required")
		}
		return "pm2", []string{"restart", app, strconv.Itoa(pmID)}, 20 * time.Second, nil

	case "unit_restart":
		unit := extractString(params, "unit")
		if !validSystemdUnitRegex.MatchString(unit) {
			return "", nil, 0, fmt.Errorf("invalid systemd unit %q", unit)
		}
		if cat != nil && cat.IsProtectedUnit(unit) {
			return "", nil, 0, fmt.Errorf("%w: unit %s", policy.ErrProtectedTarget, unit)
		}
		return "systemctl", []string{"restart", unit}, 25 * time.Second, nil

	case "process_terminate":
		pid, ok := extractPositiveInt(params, "pid")
		if !ok || pid <= 1 {
			return "", nil, 0, errors.New("valid pid > 1 is required")
		}
		if cat != nil && cat.IsProtectedPID(pid) {
			return "", nil, 0, fmt.Errorf("%w: pid %d", policy.ErrProtectedTarget, pid)
		}
		return "kill", []string{"-TERM", strconv.Itoa(pid)}, 10 * time.Second, nil

	case "zombie_reap":
		ppid, ok := extractPositiveInt(params, "parent_pid")
		if !ok || ppid <= 1 {
			return "", nil, 0, errors.New("valid parent_pid > 1 is required")
		}
		if cat != nil && cat.IsProtectedPID(ppid) {
			return "", nil, 0, fmt.Errorf("%w: parent_pid %d", policy.ErrProtectedTarget, ppid)
		}
		return "kill", []string{"-CHLD", strconv.Itoa(ppid)}, 10 * time.Second, nil

	default:
		return "", nil, 0, fmt.Errorf("%w: %s", policy.ErrUnknownAction, actionName)
	}
}

func isTerminalState(st incident.State) bool {
	return st == incident.StateResolved ||
		st == incident.StateEscalated ||
		st == incident.StateDismissed ||
		st == incident.StateExpired
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func extractString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, ok := m[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func extractNonNegativeInt(m map[string]any, key string) (int, bool) {
	if m == nil {
		return 0, false
	}
	raw, exists := m[key]
	if !exists || raw == nil {
		return 0, false
	}
	switch v := raw.(type) {
	case int:
		return v, v >= 0
	case int64:
		return int(v), v >= 0
	case uint64:
		return int(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v != math.Trunc(v) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		return int(n), err == nil && n >= 0
	default:
		return 0, false
	}
}

func extractPositiveInt(m map[string]any, key string) (int, bool) {
	n, ok := extractNonNegativeInt(m, key)
	return n, ok && n > 0
}

func extractUint64(m map[string]any, key string) (uint64, bool) {
	n, ok := extractNonNegativeInt(m, key)
	if !ok {
		return 0, false
	}
	return uint64(n), true
}

func parseMemorySizeParam(raw any) (uint64, bool) {
	switch v := raw.(type) {
	case nil:
		return 0, false
	case int:
		return uint64(max(0, v)), v >= 0
	case int64:
		return uint64(max(0, v)), v >= 0
	case uint64:
		return v, true
	case float64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case string:
		s := strings.TrimSpace(strings.ToUpper(v))
		mult := uint64(1)
		switch {
		case strings.HasSuffix(s, "G") || strings.HasSuffix(s, "GIB"):
			mult = 1024 * 1024 * 1024
			s = strings.TrimRight(s, "GIB")
		case strings.HasSuffix(s, "M") || strings.HasSuffix(s, "MIB"):
			mult = 1024 * 1024
			s = strings.TrimRight(s, "MIB")
		case strings.HasSuffix(s, "K") || strings.HasSuffix(s, "KIB"):
			mult = 1024
			s = strings.TrimRight(s, "KIB")
		}
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return 0, false
		}
		return n * mult, true
	default:
		return 0, false
	}
}

