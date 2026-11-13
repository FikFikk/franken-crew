package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/psi"
	"github.com/FikFikk/franken-crew/internal/redact"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// NodeSnapshotInput memuat parameter opsional untuk tool `node_snapshot`.
type NodeSnapshotInput struct {
	TopLimit int `json:"top_limit,omitempty" jsonschema:"maksimum cgroup teratas pada ringkasan snapshot (default 5, maks 10)"`
}

// NodeSnapshotOutput memuat ringkasan kondisi host dan telemetri kernel node saat ini.
type NodeSnapshotOutput struct {
	Node                 string                `json:"node"`
	CapturedAt           time.Time             `json:"captured_at"`
	Capabilities         kernelfs.Capabilities `json:"capabilities"`
	CapabilityHealthy    bool                  `json:"capability_healthy"`
	MemoryTotalBytes     uint64                `json:"memory_total_bytes"`
	MemoryAvailableBytes uint64                `json:"memory_available_bytes"`
	MemoryUsedBytes      uint64                `json:"memory_used_bytes"`
	MemoryUsedPct        float64               `json:"memory_used_pct"`
	LoadAvg1m            float64               `json:"load_avg_1m,omitempty"`
	PSISomeAvg10         float64               `json:"psi_some_avg10"`
	PSISomeAvg60         float64               `json:"psi_some_avg60"`
	PSIFullAvg10         float64               `json:"psi_full_avg10"`
	TopCgroups           []CgroupMemoryStat    `json:"top_cgroups"`
}

// IncidentListInput memuat filter dan batas daftar untuk tool `incident_list`.
type IncidentListInput struct {
	State string `json:"state,omitempty" jsonschema:"filter status insiden opsional (mis. DETECTED, REFLEX_APPLIED, TRIAGING)"`
	Limit int    `json:"limit,omitempty" jsonschema:"jumlah maksimum insiden yang dikembalikan (default 20, maks 100)"`
}

// IncidentSummary merepresentasikan ringkasan insiden untuk tampilan daftar.
type IncidentSummary struct {
	ID         string     `json:"id"`
	Node       string     `json:"node"`
	Cgroup     string     `json:"cgroup"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	TTOSeconds *float64   `json:"tto_seconds,omitempty"`
	OpenedAt   time.Time  `json:"opened_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
}

// IncidentListOutput memuat daftar ringkasan insiden.
type IncidentListOutput struct {
	Count     int               `json:"count"`
	Incidents []IncidentSummary `json:"incidents"`
}

// IncidentGetInput memuat ID insiden untuk tool `incident_get`.
type IncidentGetInput struct {
	IncidentID string `json:"incident_id" jsonschema:"ID unik insiden (format INC-yyyymmdd-hhmm-node)"`
}

// RedactedEvidenceView memastikan bukti yang keluar dari Sentinel tidak pernah membawa RawData mentah.
type RedactedEvidenceView struct {
	ID           string    `json:"id"`
	IncidentID   string    `json:"incident_id"`
	Kind         string    `json:"kind"`
	RedactedData string    `json:"redacted_data"`
	CapturedAt   time.Time `json:"captured_at"`
}

// IncidentGetOutput memuat detail lengkap insiden beserta evidence terredaksi, reflex, dan audit trail.
type IncidentGetOutput struct {
	Incident incident.Incident `json:"incident"`
	// PlanHash adalah hash SHA-256 kanonik dari plan tersimpan (dihitung sebelum redaksi) untuk wa_request_approval
	PlanHash   string                  `json:"plan_hash,omitempty"`
	Evidence   []RedactedEvidenceView  `json:"evidence"`
	Reflexes   []incident.ReflexAction `json:"reflexes"`
	AuditTrail []incident.AuditEntry   `json:"audit_trail"`
}

// IncidentClaimInput memuat parameter untuk klaim atomik insiden.
type IncidentClaimInput struct {
	Claimer    string `json:"claimer" jsonschema:"nama agen yang mengklaim insiden (mis. franken-sentry)"`
	IncidentID string `json:"incident_id,omitempty" jsonschema:"opsional: target ID insiden spesifik; kosongkan untuk mengambil yang paling lama terbuka"`
}

// IncidentClaimOutput mengembalikan hasil klaim atomik insiden.
type IncidentClaimOutput struct {
	Claimed  bool               `json:"claimed"`
	Incident *incident.Incident `json:"incident,omitempty"`
}

// PSIHistoryInput memuat parameter seri histori PSI.
type PSIHistoryInput struct {
	Cgroup  string `json:"cgroup,omitempty" jsonschema:"path cgroup opsional (kosong berarti PSI memori host /proc/pressure/memory)"`
	Minutes int    `json:"minutes,omitempty" jsonschema:"durasi histori dalam menit (1 sampai 10, default 10)"`
}

// PSIHistoryOutput memuat titik seri waktu PSI untuk analisis tren.
type PSIHistoryOutput struct {
	Target  string     `json:"target"`
	Minutes int        `json:"minutes"`
	Points  []PSIPoint `json:"points"`
}

// CgroupTopInput memuat batas jumlah cgroup untuk tool `cgroup_top`.
type CgroupTopInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"jumlah cgroup teratas berdasarkan memory.current (1 sampai 25, default 10)"`
}

// CgroupTopOutput memuat daftar cgroup dengan konsumsi memori tertinggi.
type CgroupTopOutput struct {
	Cgroups []CgroupMemoryStat `json:"cgroups"`
}

// JournalTailInput memuat parameter pembacaan log journal terredaksi.
type JournalTailInput struct {
	Unit       string `json:"unit" jsonschema:"nama systemd unit (contoh: haunted-api.service)"`
	Lines      int    `json:"lines,omitempty" jsonschema:"jumlah baris log terakhir (1 sampai 200, default 50)"`
	IncidentID string `json:"incident_id,omitempty" jsonschema:"opsional: jika diisi, snapshot bukti tersensor ikut disimpan pada insiden"`
}

// JournalTailOutput memuat baris log yang sudah disensor beserta evidence_id rujukannya.
type JournalTailOutput struct {
	EvidenceID string    `json:"evidence_id,omitempty"`
	Unit       string    `json:"unit"`
	Lines      []string  `json:"lines"`
	CapturedAt time.Time `json:"captured_at"`
}

// ProcessTreeInput memuat parameter inspeksi pohon proses pada suatu cgroup.
type ProcessTreeInput struct {
	Cgroup string `json:"cgroup,omitempty" jsonschema:"path cgroup relatif (contoh: /franken.slice/haunted-api.service)"`
}

// ProcessTreeOutput memuat daftar proses di dalam cgroup beserta penanda proteksi.
type ProcessTreeOutput struct {
	Cgroup    string        `json:"cgroup"`
	Processes []ProcessNode `json:"processes"`
}

// ZombieReportInput merepresentasikan input objek kosong untuk `zombie_report`.
type ZombieReportInput struct{}

func (s *Server) registerReadTools() {
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "node_snapshot",
		Description: "Read host memory, PSI pressure, kernel capabilities, load average, and top cgroups (Level 0 read-only).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleNodeSnapshot)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "incident_list",
		Description: "List open or recent incidents sorted by newest opened_at (Level 0 read-only).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleIncidentList)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "incident_get",
		Description: "Retrieve full incident metadata, redacted evidence snapshots, L1 reflex actions, and audit trail (Level 0 read-only).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleIncidentGet)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "incident_claim",
		Description: "Atomically claim an unclaimed DETECTED or REFLEX_APPLIED incident into TRIAGING state to prevent duplicate triage.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, IdempotentHint: false},
	}, s.handleIncidentClaim)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "psi_history",
		Description: "Fetch PSI memory pressure history (some/full avg10/avg60/avg300) up to 10 minutes for host or target cgroup (Level 0 read-only).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handlePSIHistory)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "cgroup_top",
		Description: "Inspect top cgroups ordered descending by current memory consumption (Level 0 read-only).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleCgroupTop)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "journal_tail",
		Description: "Fetch up to 200 redacted journald log lines for a systemd unit (Level 0 read-only). Pass incident_id to persist the lines as evidence and receive a citable evidence_id; without incident_id no evidence_id is returned.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleJournalTail)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "process_tree",
		Description: "Inspect process tree within a cgroup with redacted command lines and protected PID flags (Level 0 read-only).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleProcessTree)

	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "zombie_report",
		Description: "Detect zombie processes (state Z) grouped by parent PID across /proc (Level 0 read-only).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.handleZombieReport)
}

func (s *Server) handleNodeSnapshot(ctx context.Context, _ *mcp.CallToolRequest, in NodeSnapshotInput) (*mcp.CallToolResult, NodeSnapshotOutput, error) {
	topLimit := in.TopLimit
	if topLimit <= 0 {
		topLimit = 5
	}
	if topLimit > 10 {
		topLimit = 10
	}

	caps, probeErr := kernelfs.Probe(s.cfg.FS, s.cfg.CgroupRoot, s.cfg.ProcRoot)
	capHealthy := probeErr == nil && caps.CgroupV2 && caps.PSI

	total, avail, _, memErr := readHostMemInfo(s.cfg.FS, s.cfg.ProcRoot)
	if memErr != nil {
		return nil, NodeSnapshotOutput{}, fmt.Errorf("read /proc/meminfo: %w", memErr)
	}
	var used uint64
	var usedPct float64
	if total >= avail {
		used = total - avail
	}
	if total > 0 {
		usedPct = (float64(used) / float64(total)) * 100.0
	}

	var load1m float64
	if rawLoad, err := s.cfg.FS.ReadFile(kernelfs.JoinPath(s.cfg.ProcRoot, "loadavg")); err == nil {
		fields := strings.Fields(string(rawLoad))
		if len(fields) > 0 {
			load1m, _ = strconv.ParseFloat(fields[0], 64)
		}
	}

	var psiMetrics psi.Metrics
	if m, err := psi.ReadMetrics(s.cfg.FS, kernelfs.JoinPath(s.cfg.ProcRoot, "pressure/memory")); err == nil {
		psiMetrics = m
	}

	topCgroups, _ := collectTopCgroups(s.cfg.FS, s.cfg.CgroupRoot, topLimit)

	out := NodeSnapshotOutput{
		Node:                 s.cfg.NodeName,
		CapturedAt:           s.cfg.Clock().UTC(),
		Capabilities:         caps,
		CapabilityHealthy:    capHealthy,
		MemoryTotalBytes:     total,
		MemoryAvailableBytes: avail,
		MemoryUsedBytes:      used,
		MemoryUsedPct:        usedPct,
		LoadAvg1m:            load1m,
		PSISomeAvg10:         psiMetrics.Some.Avg10,
		PSISomeAvg60:         psiMetrics.Some.Avg60,
		PSIFullAvg10:         psiMetrics.Full.Avg10,
		TopCgroups:           topCgroups,
	}
	return nil, out, nil
}

func (s *Server) handleIncidentList(ctx context.Context, _ *mcp.CallToolRequest, in IncidentListInput) (*mcp.CallToolResult, IncidentListOutput, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		return nil, IncidentListOutput{}, errors.New("limit must not exceed 100")
	}

	list, err := s.cfg.Store.ListIncidents(ctx, strings.TrimSpace(in.State), limit)
	if err != nil {
		return nil, IncidentListOutput{}, err
	}

	summaries := make([]IncidentSummary, 0, len(list))
	for _, inc := range list {
		summaries = append(summaries, IncidentSummary{
			ID:         inc.ID,
			Node:       inc.Node,
			Cgroup:     inc.Cgroup,
			Severity:   inc.Severity,
			State:      string(inc.State),
			TTOSeconds: inc.TTOSeconds,
			OpenedAt:   inc.OpenedAt,
			UpdatedAt:  inc.UpdatedAt,
			ClosedAt:   inc.ClosedAt,
		})
	}
	return nil, IncidentListOutput{Count: len(summaries), Incidents: summaries}, nil
}

func (s *Server) handleIncidentGet(ctx context.Context, _ *mcp.CallToolRequest, in IncidentGetInput) (*mcp.CallToolResult, IncidentGetOutput, error) {
	if strings.TrimSpace(in.IncidentID) == "" {
		return nil, IncidentGetOutput{}, errors.New("incident_id is required")
	}

	inc, err := s.cfg.Store.GetIncident(ctx, in.IncidentID)
	if err != nil {
		return nil, IncidentGetOutput{}, err
	}
	// Pastikan triage_json dan plan_json ikut tersensor sebelum meninggalkan proses Sentinel
	incView := *inc
	incView.TriageJSON = redact.String(incView.TriageJSON)
	incView.PlanJSON = redact.String(incView.PlanJSON)

	rawEvidence, err := s.cfg.Store.GetEvidenceByIncident(ctx, in.IncidentID)
	if err != nil {
		return nil, IncidentGetOutput{}, err
	}
	evidenceView := make([]RedactedEvidenceView, 0, len(rawEvidence))
	for _, ev := range rawEvidence {
		redacted := ev.RedactedData
		if redacted == "" {
			redacted = redact.String(ev.RawData)
		} else {
			redacted = redact.String(redacted)
		}
		// Jangan pernah menyertakan RawData dalam respons MCP
		evidenceView = append(evidenceView, RedactedEvidenceView{
			ID:           ev.ID,
			IncidentID:   ev.IncidentID,
			Kind:         ev.Kind,
			RedactedData: redacted,
			CapturedAt:   ev.CapturedAt,
		})
	}

	reflexes, err := s.cfg.Store.GetReflexActionsByIncident(ctx, in.IncidentID)
	if err != nil {
		return nil, IncidentGetOutput{}, err
	}
	rawAudit, err := s.cfg.Store.GetAuditTrail(ctx, in.IncidentID)
	if err != nil {
		return nil, IncidentGetOutput{}, err
	}
	auditView := make([]incident.AuditEntry, len(rawAudit))
	for i, entry := range rawAudit {
		entry.PayloadJSON = redact.String(entry.PayloadJSON)
		auditView[i] = entry
	}

	// Hitung plan_hash dari plan tersimpan asli (bukan versi tersensor) agar identik dengan hash yang diikat token
	var planHash string
	if strings.TrimSpace(inc.PlanJSON) != "" {
		var stored policy.Plan
		if err := json.Unmarshal([]byte(inc.PlanJSON), &stored); err != nil {
			return nil, IncidentGetOutput{}, fmt.Errorf("decode stored plan_json for %s: %w", inc.ID, err)
		}
		if planHash, err = policy.ComputePlanHash(&stored); err != nil {
			return nil, IncidentGetOutput{}, fmt.Errorf("compute plan_hash for %s: %w", inc.ID, err)
		}
	}

	return nil, IncidentGetOutput{
		Incident:   incView,
		PlanHash:   planHash,
		Evidence:   evidenceView,
		Reflexes:   reflexes,
		AuditTrail: auditView,
	}, nil
}

func (s *Server) handleIncidentClaim(ctx context.Context, _ *mcp.CallToolRequest, in IncidentClaimInput) (*mcp.CallToolResult, IncidentClaimOutput, error) {
	claimer := strings.TrimSpace(in.Claimer)
	if claimer == "" {
		return nil, IncidentClaimOutput{}, errors.New("claimer is required")
	}

	claimed, err := s.cfg.Store.ClaimIncident(ctx, strings.TrimSpace(in.IncidentID), claimer)
	if err != nil {
		return nil, IncidentClaimOutput{}, err
	}
	if claimed == nil {
		return nil, IncidentClaimOutput{Claimed: false}, nil
	}

	s.broker.Publish(StreamEvent{
		Type:       "incident.updated",
		IncidentID: claimed.ID,
		Severity:   claimed.Severity,
		State:      string(claimed.State),
		Summary:    fmt.Sprintf("Incident claimed by %s", claimer),
	})

	return nil, IncidentClaimOutput{Claimed: true, Incident: claimed}, nil
}

func (s *Server) handlePSIHistory(ctx context.Context, _ *mcp.CallToolRequest, in PSIHistoryInput) (*mcp.CallToolResult, PSIHistoryOutput, error) {
	minutes := in.Minutes
	if minutes == 0 {
		minutes = 10
	}
	if minutes < 1 || minutes > 10 {
		return nil, PSIHistoryOutput{}, errors.New("minutes must be between 1 and 10")
	}

	now := s.cfg.Clock().UTC()
	targetKey := normalizePSIKey(in.Cgroup)
	points := s.psiRing.Query(targetKey, minutes, now)

	// Apabila buffer kosong, baca sampel PSI live dari kernelfs agar tetap informatif
	if len(points) == 0 {
		var pressurePath string
		if targetKey == "host" {
			pressurePath = kernelfs.JoinPath(s.cfg.ProcRoot, "pressure/memory")
		} else {
			absDir, _, err := resolveSafeCgroupDir(s.cfg.CgroupRoot, in.Cgroup)
			if err != nil {
				return nil, PSIHistoryOutput{}, err
			}
			pressurePath = kernelfs.JoinPath(absDir, "memory.pressure")
		}
		m, err := psi.ReadMetrics(s.cfg.FS, pressurePath)
		if err != nil {
			return nil, PSIHistoryOutput{}, fmt.Errorf("read PSI metrics from %s: %w", pressurePath, err)
		}
		points = []PSIPoint{{
			At:         now,
			SomeAvg10:  m.Some.Avg10,
			SomeAvg60:  m.Some.Avg60,
			SomeAvg300: m.Some.Avg300,
			FullAvg10:  m.Full.Avg10,
			FullAvg60:  m.Full.Avg60,
			FullAvg300: m.Full.Avg300,
		}}
	}

	return nil, PSIHistoryOutput{
		Target:  targetKey,
		Minutes: minutes,
		Points:  points,
	}, nil
}

func (s *Server) handleCgroupTop(_ context.Context, _ *mcp.CallToolRequest, in CgroupTopInput) (*mcp.CallToolResult, CgroupTopOutput, error) {
	limit := in.Limit
	if limit == 0 {
		limit = 10
	}
	if limit < 1 || limit > 25 {
		return nil, CgroupTopOutput{}, errors.New("limit must be between 1 and 25")
	}

	stats, err := collectTopCgroups(s.cfg.FS, s.cfg.CgroupRoot, limit)
	if err != nil {
		return nil, CgroupTopOutput{}, err
	}
	return nil, CgroupTopOutput{Cgroups: stats}, nil
}

func (s *Server) handleJournalTail(ctx context.Context, _ *mcp.CallToolRequest, in JournalTailInput) (*mcp.CallToolResult, JournalTailOutput, error) {
	unit := strings.TrimSpace(in.Unit)
	if !validSystemdUnitRegex.MatchString(unit) {
		return nil, JournalTailOutput{}, fmt.Errorf("invalid systemd unit %q", in.Unit)
	}

	linesReq := in.Lines
	if linesReq == 0 {
		linesReq = 50
	}
	if linesReq < 1 || linesReq > 200 {
		return nil, JournalTailOutput{}, errors.New("lines must be between 1 and 200 (Requirement 4.2)")
	}

	rawLines, err := s.cfg.JournalReader.Tail(ctx, unit, linesReq)
	if err != nil {
		return nil, JournalTailOutput{}, err
	}

	// Sensor seluruh baris log sebelum meninggalkan Sentinel (Requirement 4.3)
	redactedLines := redact.Lines(rawLines)
	if redactedLines == nil {
		redactedLines = []string{}
	}

	// evidence_id hanya diterbitkan bila snapshot benar-benar tersimpan, karena plan_submit memverifikasi
	// setiap evidence_id terhadap SQLite; ID tanpa snapshot tidak boleh bisa dikutip
	var evID string
	now := s.cfg.Clock().UTC()

	// Jika terhubung ke insiden aktif, simpan snapshot bukti tersensor ke SQLite
	if incID := strings.TrimSpace(in.IncidentID); incID != "" {
		evID = newEvidenceID()
		if _, gErr := s.cfg.Store.GetIncident(ctx, incID); gErr != nil {
			return nil, JournalTailOutput{}, fmt.Errorf("lookup incident %s for evidence snapshot: %w", incID, gErr)
		}
		if err := s.cfg.Store.SaveEvidence(ctx, &incident.EvidenceSnapshot{
			ID:           evID,
			IncidentID:   incID,
			Kind:         "journal_tail:" + unit,
			RawData:      "",
			RedactedData: strings.Join(redactedLines, "\n"),
			CapturedAt:   now,
		}); err != nil {
			return nil, JournalTailOutput{}, err
		}
	}

	return nil, JournalTailOutput{
		EvidenceID: evID,
		Unit:       unit,
		Lines:      redactedLines,
		CapturedAt: now,
	}, nil
}

func (s *Server) handleProcessTree(_ context.Context, _ *mcp.CallToolRequest, in ProcessTreeInput) (*mcp.CallToolResult, ProcessTreeOutput, error) {
	absDir, normRel, err := resolveSafeCgroupDir(s.cfg.CgroupRoot, in.Cgroup)
	if err != nil {
		return nil, ProcessTreeOutput{}, err
	}

	nodes, err := collectProcessTree(s.cfg.FS, s.cfg.ProcRoot, absDir, s.cfg.Catalog)
	if err != nil {
		return nil, ProcessTreeOutput{}, err
	}
	return nil, ProcessTreeOutput{
		Cgroup:    normRel,
		Processes: nodes,
	}, nil
}

func (s *Server) handleZombieReport(_ context.Context, _ *mcp.CallToolRequest, _ ZombieReportInput) (*mcp.CallToolResult, cgroup.ZombieReport, error) {
	report, err := cgroup.ScanZombies(s.cfg.FS, s.cfg.ProcRoot)
	if err != nil {
		return nil, cgroup.ZombieReport{}, err
	}
	return nil, report, nil
}

func newEvidenceID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "ev-" + hex.EncodeToString(b[:])
}
