package wabridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/redact"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

const (
	// DefaultHeartbeatInterval menentukan selang waktu pengecekan heartbeat Sentinel (15 detik).
	DefaultHeartbeatInterval = 15 * time.Second
	// DefaultMaxMissedHeartbeats memicu Node Silent Alert setelah 3 kali heartbeat beruntun hilang (45 detik).
	DefaultMaxMissedHeartbeats = 3
	// DefaultPollTTL menentukan batas waktu tunggu persetujuan poll WhatsApp (10 menit).
	DefaultPollTTL = 10 * time.Minute
	// MaxMessagesPerIncident membatasi pengiriman pesan WhatsApp maksimal 6 kali per insiden.
	MaxMessagesPerIncident = 6
	// MaxMessagesPerHourPerNode membatasi pengiriman pesan WhatsApp maksimal 20 pesan per jam per node.
	MaxMessagesPerHourPerNode = 20

	// Label pilihan sekunder standar pada Native WhatsApp Poll (opsi L2 dibangun deterministik dari plan Sentinel).
	OptionRollbackReflex = "Rollback Reflex"
	OptionDismiss        = "Dismiss"

	// maxPollOptionLabelLen membatasi panjang label opsi WhatsApp Poll agar tetap terbaca utuh beserta hash plan.
	maxPollOptionLabelLen = 96
)

var (
	// ErrRateLimited dikembalikan jika kuota pesan per insiden atau per jam node sudah penuh.
	ErrRateLimited = errors.New("wabridge: WhatsApp message rate limit reached")
	// ErrUnauthorizedSender dikembalikan apabila pengirim pesan atau suara poll tidak masuk allowlist admin.
	ErrUnauthorizedSender = errors.New("wabridge: sender not in admin allowlist")
	// ErrPlanHashMismatch dikembalikan jika plan_hash tidak cocok dengan plan kanonik yang tersimpan di Sentinel.
	ErrPlanHashMismatch = errors.New("wabridge: plan_hash mismatch against stored Sentinel plan")
)

// Config menyimpan konfigurasi dan dependensi dua arah untuk WhatsApp bridge.
type Config struct {
	NodeName            string
	AdminAllowlist      []string
	TargetJID           string
	Minter              *approval.Minter
	Sentinel            *SentinelClient
	Messenger           Messenger
	HeartbeatInterval   time.Duration
	MaxMissedHeartbeats int
	PollTTL             time.Duration
	Clock               func() time.Time
	OnAudit             func(eventType, detail string)
	// Crew memicu fase Kiro Crew (TRIAGE saat insiden dibuka, EXECUTE saat vote disetujui); nil = nonaktif
	Crew CrewNotifier
}

// StepToken mengikat satu token Ed25519 sekali-pakai ke tepat satu langkah plan beserta aksinya.
type StepToken struct {
	StepID string `json:"step_id"`
	Action string `json:"action"`
	Token  string `json:"token"`
}

// PollOptionBinding memetakan satu opsi poll ke aksi beserta digest SHA-256-nya.
type PollOptionBinding struct {
	Label    string            `json:"label"`
	HashHex  string            `json:"hash_hex"`
	Kind     string            `json:"kind"` // "approve", "rollback", "dismiss"
	OptionID string            `json:"option_id,omitempty"`
	Steps    []policy.PlanStep `json:"steps,omitempty"`
}

// ApprovalDecision menyimpan hasil akhir interaksi operator manusia pada poll atau teks fallback.
type ApprovalDecision struct {
	ApprovalID  string   `json:"approval_id"`
	IncidentID  string   `json:"incident_id"`
	Status      string   `json:"status"` // GRANTED, ROLLED_BACK, DENIED, EXPIRED
	OptionID    string   `json:"option_id,omitempty"`
	ChoiceLabel string   `json:"choice_label,omitempty"`
	Token       string   `json:"token,omitempty"`
	Approver    string   `json:"approver,omitempty"`
	PlanHash    string   `json:"plan_hash,omitempty"`
	Action      string   `json:"action,omitempty"`
	StepIDs     []string `json:"step_ids,omitempty"`
	// StepTokens berisi satu token per langkah sesuai urutan plan; Token di atas sama dengan token langkah pertama
	StepTokens []StepToken `json:"step_tokens,omitempty"`
	ResultMsg  string      `json:"result_msg,omitempty"`
	DecidedAt  time.Time   `json:"decided_at"`
}

// PendingPoll merepresentasikan poll persetujuan yang sedang menunggu jawaban admin.
type PendingPoll struct {
	ApprovalID    string
	PollMessageID types.MessageID
	ShortCode     string
	IncidentID    string
	PlanHash      string
	Cgroup        string
	DefaultUnit   string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Options       []PollOptionBinding
	OptionsByHash map[string]PollOptionBinding
	DecisionCh    chan ApprovalDecision
	Resolved      bool
}

// Bridge menghubungkan stream SSE Sentinel, WhatsApp (via whatsmeow), token Ed25519, dan MCP `action_execute`.
type Bridge struct {
	cfg        Config
	allowlist  *Allowlist
	targetJID  types.JID
	mu         sync.Mutex
	alertedInc map[string]bool
	incMsgCnt  map[string]int
	nodeMsgTs  []time.Time
	sentMsgIDs map[types.MessageID]bool

	pollsByID      map[string]*PendingPoll
	pollsByMsgID   map[types.MessageID]*PendingPoll
	pollsByCode    map[string]*PendingPoll
	pollsByInc     map[string]*PendingPoll
	pollOptionPool map[string]PollOptionBinding

	lastHeartbeatAt  time.Time
	missedHeartbeats int
	silentAlertSent  bool

	// Dedupe pemicu fase Crew dan laporan akhir (dilindungi mu), serta pelacak goroutine pemicu Crew
	crewSent *boundedSet
	reported *boundedSet
	crewWG   sync.WaitGroup
}

const (
	// crewTriggerTimeout membatasi total waktu satu pemicu fase Crew termasuk retry.
	crewTriggerTimeout = 60 * time.Second
	// maxDedupeEntries membatasi jumlah kunci dedupe yang diingat bridge.
	maxDedupeEntries = 512
)

// New membuat instance Bridge baru setelah memvalidasi konfigurasi keamanan inti.
func New(cfg Config) (*Bridge, error) {
	if cfg.Minter == nil {
		return nil, errors.New("wabridge: Ed25519 approval minter is required")
	}
	if cfg.Sentinel == nil {
		return nil, errors.New("wabridge: sentinel client is required")
	}
	if cfg.Messenger == nil {
		return nil, errors.New("wabridge: whatsapp messenger is required")
	}
	al := NewAllowlist(cfg.AdminAllowlist)
	if al.IsEmpty() {
		return nil, errors.New("wabridge: at least one admin number/JID must be configured in AdminAllowlist")
	}

	target := types.EmptyJID
	if strings.TrimSpace(cfg.TargetJID) != "" {
		parsed, _ := NormalizeJIDOrPhone(cfg.TargetJID)
		target = parsed
	}
	if target.IsEmpty() {
		primary, ok := al.PrimaryTarget()
		if !ok {
			return nil, errors.New("wabridge: invalid target/admin JID")
		}
		target = primary
	}

	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if cfg.MaxMissedHeartbeats <= 0 {
		cfg.MaxMissedHeartbeats = DefaultMaxMissedHeartbeats
	}
	if cfg.PollTTL <= 0 {
		cfg.PollTTL = DefaultPollTTL
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	if cfg.NodeName == "" {
		cfg.NodeName = "node01"
	}

	now := cfg.Clock().UTC()
	return &Bridge{
		cfg:             cfg,
		allowlist:       al,
		targetJID:       target,
		alertedInc:      make(map[string]bool),
		incMsgCnt:       make(map[string]int),
		sentMsgIDs:      make(map[types.MessageID]bool),
		pollsByID:       make(map[string]*PendingPoll),
		pollsByMsgID:    make(map[types.MessageID]*PendingPoll),
		pollsByCode:     make(map[string]*PendingPoll),
		pollsByInc:      make(map[string]*PendingPoll),
		pollOptionPool:  make(map[string]PollOptionBinding),
		lastHeartbeatAt: now,
		crewSent:        newBoundedSet(maxDedupeEntries),
		reported:        newBoundedSet(maxDedupeEntries),
	}, nil
}

// Run menjalankan loop SSE Sentinel dan pemantau heartbeat (15s x 3 -> Node Silent Alert) hingga ctx batal.
func (b *Bridge) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Worker 1: konsumen stream SSE `/v1/events` dengan reconnect & Last-Event-ID
	go func() {
		defer wg.Done()
		lastID := ""
		backoff := 500 * time.Millisecond
		for {
			if runCtx.Err() != nil {
				return
			}
			nextID, err := b.cfg.Sentinel.StreamEvents(runCtx, lastID, func(ev mcpserver.StreamEvent) {
				b.HandleSSEEvent(runCtx, ev)
			})
			lastID = nextID
			if runCtx.Err() != nil {
				return
			}
			if err != nil {
				b.audit("SSE_DISCONNECTED", err.Error())
			}
			select {
			case <-runCtx.Done():
				return
			case <-time.After(backoff):
				if backoff < 5*time.Second {
					backoff *= 2
				}
			}
		}
	}()

	// Worker 2: heartbeat monitor (15 detik x 3)
	go func() {
		defer wg.Done()
		b.runHeartbeatLoop(runCtx)
	}()

	<-runCtx.Done()
	wg.Wait()
	// Tunggu pemicu Crew yang sedang berjalan agar tidak ada goroutine yang tertinggal saat shutdown
	b.crewWG.Wait()
	return nil
}

func (b *Bridge) runHeartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(b.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.CheckHeartbeatOnce(ctx)
		}
	}
}

// CheckHeartbeatOnce memeriksa aktivitas heartbeat terbaru atau mem-ping `/healthz`;
// memicu "Node Silent Alert" setelah MaxMissedHeartbeats jendela terlewati.
func (b *Bridge) CheckHeartbeatOnce(ctx context.Context) {
	now := b.cfg.Clock().UTC()

	b.mu.Lock()
	sinceLast := now.Sub(b.lastHeartbeatAt)
	b.mu.Unlock()

	// Jika SSE baru saja mengirim event atau heartbeat dalam jendela terakhir, node sehat
	if sinceLast < b.cfg.HeartbeatInterval {
		return
	}

	// Lakukan verifikasi aktif ke /healthz sebelum menghitungnya sebagai missed heartbeat
	probeCtx, cancel := context.WithTimeout(ctx, b.cfg.HeartbeatInterval/2+500*time.Millisecond)
	_, err := b.cfg.Sentinel.CheckHealthz(probeCtx)
	cancel()

	if err == nil {
		b.markHeartbeat(now)
		return
	}

	b.mu.Lock()
	b.missedHeartbeats++
	missed := b.missedHeartbeats
	alreadyAlerted := b.silentAlertSent
	if missed >= b.cfg.MaxMissedHeartbeats && !alreadyAlerted {
		b.silentAlertSent = true
	}
	b.mu.Unlock()

	if missed >= b.cfg.MaxMissedHeartbeats && !alreadyAlerted {
		alertText := fmt.Sprintf(
			"Node Silent Alert: Sentinel node *%s* tidak merespons %dx interval (%s). Terakhir aktif: %s. Error: %s",
			b.cfg.NodeName,
			missed,
			(time.Duration(missed) * b.cfg.HeartbeatInterval).Round(time.Second),
			now.Add(-sinceLast).Format("15:04:05 UTC"),
			redact.String(err.Error()),
		)
		if msgID, sendErr := b.cfg.Messenger.SendText(ctx, b.targetJID, alertText); sendErr != nil {
			b.audit("NODE_SILENT_ALERT_ERROR", sendErr.Error())
		} else {
			b.trackSentMessage(msgID)
			b.audit("NODE_SILENT_ALERT_SENT", alertText)
		}
	}
}

func (b *Bridge) markHeartbeat(at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastHeartbeatAt = at
	b.missedHeartbeats = 0
	b.silentAlertSent = false
}

// HandleSSEEvent memproses satu event stream Sentinel dan hanya mengirim alert pertama untuk insiden kritis.
// Pembuatan Poll persetujuan sepenuhnya didelegasikan ke Kiro Crew lewat MCP `wa_request_approval` (Temuan C1).
func (b *Bridge) HandleSSEEvent(ctx context.Context, ev mcpserver.StreamEvent) {
	now := b.cfg.Clock().UTC()
	b.markHeartbeat(now)

	if ev.Node != "" {
		b.mu.Lock()
		b.cfg.NodeName = ev.Node
		b.mu.Unlock()
	}

	if ev.Type == "verification.completed" {
		b.sendFinalReport(ctx, ev)
		return
	}
	if ev.Type != "incident.opened" && ev.Type != "incident.escalated_severity" {
		return
	}
	if !isAlertableSeverity(ev.Severity) || strings.TrimSpace(ev.IncidentID) == "" {
		return
	}

	b.mu.Lock()
	alreadyAlerted := b.alertedInc[ev.IncidentID]
	if !alreadyAlerted {
		b.alertedInc[ev.IncidentID] = true
	}
	b.mu.Unlock()

	if alreadyAlerted {
		return
	}

	// Kirim notifikasi insiden kritis pertama secepat mungkin (< 2 detik) tanpa membuat poll otonom
	firstAlert := formatCriticalAlertMessage(b.nodeName(), ev)
	if _, err := b.sendRateLimitedText(ctx, ev.IncidentID, b.targetJID, firstAlert); err != nil {
		b.audit("FIRST_ALERT_ERROR", fmt.Sprintf("incident=%s err=%v", ev.IncidentID, err))
	} else {
		b.audit("FIRST_ALERT_SENT", fmt.Sprintf("incident=%s severity=%s", ev.IncidentID, ev.Severity))
	}

	// Mulai fase TRIAGE di Kiro Crew secara event-driven (cron 15 menit hanya jaring pengaman)
	b.triggerCrew(ctx, CrewPhaseRequest{
		Phase:      CrewPhaseTriage,
		IncidentID: ev.IncidentID,
		Severity:   ev.Severity,
		Node:       b.nodeName(),
		Cgroup:     extractAnyString(ev.Data, "cgroup"),
	})
}

// triggerCrew memicu satu fase Kiro Crew secara asinkron, paling banyak sekali per insiden+fase+approval.
func (b *Bridge) triggerCrew(ctx context.Context, req CrewPhaseRequest) {
	if b.cfg.Crew == nil {
		return
	}
	key := strings.Join([]string{req.IncidentID, string(req.Phase), req.ApprovalID}, "|")
	b.mu.Lock()
	fresh := b.crewSent.add(key)
	b.mu.Unlock()
	if !fresh {
		return
	}

	b.crewWG.Add(1)
	go func() {
		defer b.crewWG.Done()
		// Lepaskan dari pembatalan pemanggil (mis. selesainya handler SSE) namun tetap dibatasi waktu
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), crewTriggerTimeout)
		defer cancel()
		if err := b.cfg.Crew.Trigger(tctx, req); err != nil {
			b.audit("CREW_TRIGGER_FAILED", fmt.Sprintf("incident=%s phase=%s err=%v", req.IncidentID, req.Phase, err))
			return
		}
		b.audit("CREW_TRIGGERED", fmt.Sprintf("incident=%s phase=%s approval=%s", req.IncidentID, req.Phase, req.ApprovalID))
	}()
}

// sendFinalReport mengirim laporan akhir deterministik sekali per insiden saat verifikasi forward selesai.
func (b *Bridge) sendFinalReport(ctx context.Context, ev mcpserver.StreamEvent) {
	incID := strings.TrimSpace(ev.IncidentID)
	if incID == "" {
		return
	}
	b.mu.Lock()
	fresh := b.reported.add(incID)
	b.mu.Unlock()
	if !fresh {
		return
	}

	status := extractAnyString(ev.Data, "status")
	lines := []string{fmt.Sprintf("[REPORT] *%s* %s (verification %s)", incID, ev.State, status)}
	if rolled, ok := ev.Data["rolled_back"]; ok {
		lines = append(lines, fmt.Sprintf("L1 reflexes rolled back: %v", rolled))
	}
	if reasons := extractAnyString(ev.Data, "failure_reasons"); reasons != "" {
		lines = append(lines, "Reasons: "+reasons)
	}
	if pm := extractAnyString(ev.Data, "postmortem_path"); pm != "" {
		lines = append(lines, "Postmortem: "+pm)
	}
	if _, err := b.sendRateLimitedText(ctx, incID, b.targetJID, strings.Join(lines, "\n")); err != nil {
		b.audit("FINAL_REPORT_ERROR", fmt.Sprintf("incident=%s err=%v", incID, err))
		return
	}
	b.audit("FINAL_REPORT_SENT", fmt.Sprintf("incident=%s state=%s", incID, ev.State))
}

func (b *Bridge) nodeName() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.NodeName
}

// boundedSet mengingat kunci terbaru dengan kapasitas tetap agar map dedupe tidak tumbuh tanpa batas.
type boundedSet struct {
	limit int
	order []string
	seen  map[string]struct{}
}

func newBoundedSet(limit int) *boundedSet {
	return &boundedSet{limit: limit, seen: make(map[string]struct{}, limit)}
}

// add mengembalikan true bila kunci baru; kunci tertua dibuang saat kapasitas penuh.
func (s *boundedSet) add(key string) bool {
	if _, ok := s.seen[key]; ok {
		return false
	}
	if len(s.order) >= s.limit {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.seen, oldest)
	}
	s.order = append(s.order, key)
	s.seen[key] = struct{}{}
	return true
}

// PollRequest berisi parameter untuk mengirim Native WhatsApp Poll persetujuan atas plan Kiro Crew yang tersimpan di Sentinel.
type PollRequest struct {
	IncidentID    string
	PlanHash      string
	Cgroup        string
	OptionID      string            // Diabaikan: seluruh opsi aktif disusun deterministik dari plan Sentinel
	ApproveSteps  []policy.PlanStep // Diabaikan: langkah diikat langsung per opsi dari plan Sentinel
	Options       []string          // Diabaikan sebagai sumber label tepercaya (Temuan C2)
	ExecuteOnVote bool              // Dilarang: hanya nilainya `false` yang diizinkan (Temuan C1)
	TTL           time.Duration
}

// SendApprovalPoll mengambil plan kanonik dari Sentinel, memverifikasi plan_hash secara constant-time,
// lalu mengirim Native WhatsApp Poll dengan label opsi deterministik yang mengikat tepat `OptionID -> Steps`.
func (b *Bridge) SendApprovalPoll(ctx context.Context, req PollRequest) (*PendingPoll, error) {
	incID := strings.TrimSpace(req.IncidentID)
	if incID == "" {
		return nil, errors.New("wabridge: incident_id is required for poll")
	}
	if req.ExecuteOnVote {
		return nil, errors.New("wabridge: autonomous ExecuteOnVote is forbidden; Kiro Crew executes approved steps")
	}

	reqHash := strings.TrimSpace(req.PlanHash)
	if reqHash == "" {
		return nil, errors.New("wabridge: plan_hash is required and must match Sentinel stored plan")
	}

	// Ambil insiden dan plan tersimpan secara otoritatif langsung dari Sentinel MCP (Temuan C2)
	incOut, err := b.cfg.Sentinel.IncidentGet(ctx, incID)
	if err != nil {
		return nil, fmt.Errorf("wabridge: fetch incident %s for poll: %w", incID, err)
	}
	if incOut == nil {
		return nil, fmt.Errorf("wabridge: sentinel returned nil incident for %s", incID)
	}
	if isTerminalIncidentState(incOut.Incident.State) {
		return nil, fmt.Errorf("wabridge: cannot request approval for terminal incident %s (state=%s)", incID, incOut.Incident.State)
	}
	if strings.TrimSpace(incOut.Incident.PlanJSON) == "" {
		return nil, fmt.Errorf("wabridge: incident %s has no validated plan in Sentinel", incID)
	}

	var plan policy.Plan
	if err := json.Unmarshal([]byte(incOut.Incident.PlanJSON), &plan); err != nil {
		return nil, fmt.Errorf("wabridge: decode Sentinel stored plan_json: %w", err)
	}
	if plan.IncidentID != "" && plan.IncidentID != incID {
		return nil, fmt.Errorf("wabridge: stored plan incident_id %q does not match %q", plan.IncidentID, incID)
	}

	// Utamakan plan_hash dari Sentinel (dihitung dari plan asli sebelum redaksi); hitung sendiri hanya untuk Sentinel lama
	canonicalHash := strings.TrimSpace(incOut.PlanHash)
	if canonicalHash == "" {
		if canonicalHash, err = policy.ComputePlanHash(&plan); err != nil {
			return nil, fmt.Errorf("wabridge: compute canonical plan_hash: %w", err)
		}
	}
	if len(reqHash) != len(canonicalHash) || subtle.ConstantTimeCompare([]byte(reqHash), []byte(canonicalHash)) != 1 {
		b.audit("POLL_PLAN_HASH_MISMATCH", fmt.Sprintf("incident=%s requested=%s stored=%s", incID, shortHash(reqHash), shortHash(canonicalHash)))
		return nil, fmt.Errorf("%w (incident=%s)", ErrPlanHashMismatch, incID)
	}

	if len(plan.Options) == 0 {
		return nil, fmt.Errorf("wabridge: stored plan for %s contains no executable options", incID)
	}

	// Susun binding dan label deterministik langsung dari `plan.Options`, bukan teks bebas LLM
	bindings := make([]PollOptionBinding, 0, len(plan.Options)+2)
	optionLabels := make([]string, 0, len(plan.Options)+2)
	seenOptIDs := make(map[string]bool, len(plan.Options))
	seenHashes := make(map[string]bool, len(plan.Options)+2)

	for _, opt := range plan.Options {
		optID := strings.TrimSpace(opt.ID)
		if optID == "" {
			return nil, errors.New("wabridge: stored plan contains option with empty ID")
		}
		if seenOptIDs[optID] {
			return nil, fmt.Errorf("wabridge: duplicate option ID %q in stored plan", optID)
		}
		if len(opt.Steps) == 0 {
			return nil, fmt.Errorf("wabridge: plan option %s contains no steps", optID)
		}
		for _, st := range opt.Steps {
			if strings.TrimSpace(st.ID) == "" || strings.TrimSpace(st.Action) == "" {
				return nil, fmt.Errorf("wabridge: plan option %s has step with missing id or action", optID)
			}
		}
		seenOptIDs[optID] = true

		lbl := formatPlanOptionLabel(opt, canonicalHash)
		hashHex := HashPollOption(lbl)
		if seenHashes[hashHex] {
			return nil, fmt.Errorf("wabridge: duplicate option hash generated for option %s", optID)
		}
		seenHashes[hashHex] = true

		clonedSteps := make([]policy.PlanStep, len(opt.Steps))
		copy(clonedSteps, opt.Steps)

		bnd := PollOptionBinding{
			Label:    lbl,
			HashHex:  hashHex,
			Kind:     "approve",
			OptionID: optID,
			Steps:    clonedSteps,
		}
		bindings = append(bindings, bnd)
		optionLabels = append(optionLabels, lbl)
	}

	for _, sec := range []struct {
		label string
		kind  string
	}{
		{label: OptionRollbackReflex, kind: "rollback"},
		{label: OptionDismiss, kind: "dismiss"},
	} {
		h := HashPollOption(sec.label)
		bindings = append(bindings, PollOptionBinding{
			Label:   sec.label,
			HashHex: h,
			Kind:    sec.kind,
		})
		optionLabels = append(optionLabels, sec.label)
	}

	shortCode := randomShortCode()
	title := fmt.Sprintf("[%s] %s (plan %s) — Choose action or reply APPROVE <OPT> %s / ROLLBACK %s / DISMISS %s",
		shortCode, incID, shortHash(canonicalHash), shortCode, shortCode, shortCode)

	if err := b.reserveQuota(incID); err != nil {
		return nil, err
	}

	msgID, err := b.cfg.Messenger.SendPoll(ctx, b.targetJID, title, optionLabels, 1)
	if err != nil {
		return nil, fmt.Errorf("send approval poll: %w", err)
	}
	b.trackSentMessage(msgID)

	cg := strings.TrimSpace(req.Cgroup)
	if cg == "" {
		cg = incOut.Incident.Cgroup
	}

	now := b.cfg.Clock().UTC()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = b.cfg.PollTTL
	}

	poll := &PendingPoll{
		ApprovalID:    "APR-" + shortCode,
		PollMessageID: msgID,
		ShortCode:     shortCode,
		IncidentID:    incID,
		PlanHash:      canonicalHash,
		Cgroup:        cg,
		DefaultUnit:   deriveUnitFromCgroup(cg),
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
		Options:       bindings,
		OptionsByHash: make(map[string]PollOptionBinding, len(bindings)),
		DecisionCh:    make(chan ApprovalDecision, 1),
	}

	for _, bnd := range bindings {
		poll.OptionsByHash[bnd.HashHex] = bnd
	}

	// Sinkronkan state insiden ke WAITING_APPROVAL agar status dashboard sesuai selama menunggu suara manusia
	if incOut.Incident.State != incident.StateWaitingApproval && incident.CanTransition(incOut.Incident.State, incident.StateWaitingApproval) {
		_, _ = b.cfg.Sentinel.IncidentTransition(ctx, mcpserver.IncidentTransitionInput{
			IncidentID: incID,
			To:         string(incident.StateWaitingApproval),
			Reason:     fmt.Sprintf("WhatsApp approval poll %s sent for plan %s", poll.ApprovalID, shortHash(canonicalHash)),
			Actor:      "wa-bridge",
		})
	}

	b.mu.Lock()
	b.pollsByID[poll.ApprovalID] = poll
	b.pollsByMsgID[poll.PollMessageID] = poll
	b.pollsByCode[strings.ToUpper(poll.ShortCode)] = poll
	b.pollsByInc[poll.IncidentID] = poll
	b.mu.Unlock()

	return poll, nil
}

// HandleWhatsAppEvent memproses event pesan masuk whatsmeow: dekripsi PollUpdateMessage dan fallback teks berkode.
func (b *Bridge) HandleWhatsAppEvent(ctx context.Context, evt any) {
	msgEvt, ok := evt.(*events.Message)
	if !ok || msgEvt == nil || msgEvt.Message == nil {
		return
	}

	// Abaikan pesan yang dikirim oleh bridge sendiri agar tidak terjadi echo loop
	if b.isOwnSentMessage(msgEvt.Info.ID) {
		return
	}

	// 1. Jalur Poll Update terenkripsi
	if pollUpdate := msgEvt.Message.GetPollUpdateMessage(); pollUpdate != nil {
		senderMatched, allowed := b.authorizeEventSender(ctx, msgEvt)
		if !allowed {
			b.audit("UNAUTHORIZED_POLL_VOTE", fmt.Sprintf("sender=%s", msgEvt.Info.Sender.String()))
			return
		}

		targetMsgID := types.MessageID(pollUpdate.GetPollCreationMessageKey().GetID())
		b.mu.Lock()
		poll := b.pollsByMsgID[targetMsgID]
		b.mu.Unlock()
		if poll == nil {
			return
		}

		vote, err := b.cfg.Messenger.DecryptVote(ctx, msgEvt)
		if err != nil {
			b.audit("POLL_DECRYPT_FAILED", fmt.Sprintf("incident=%s err=%v", poll.IncidentID, err))
			return
		}

		selectedDigests := vote.GetSelectedOptions()
		if len(selectedDigests) == 0 {
			b.audit("POLL_EMPTY_SELECTION", fmt.Sprintf("incident=%s", poll.IncidentID))
			return
		}
		// Tolak suara ambigu (> 1 opsi dipilih) agar tidak memilih opsi pertama secara diam-diam
		if len(selectedDigests) > 1 {
			b.audit("POLL_AMBIGUOUS_SELECTION", fmt.Sprintf("incident=%s count=%d", poll.IncidentID, len(selectedDigests)))
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
				fmt.Sprintf("Multiple options selected for poll %s (%s); please select only one option.", poll.ShortCode, poll.IncidentID))
			return
		}

		hashHex := hex.EncodeToString(selectedDigests[0])
		bnd, ok := poll.OptionsByHash[hashHex]
		if !ok {
			b.audit("POLL_UNKNOWN_HASH", fmt.Sprintf("incident=%s", poll.IncidentID))
			return
		}

		b.processPollSelection(ctx, poll, bnd, senderMatched)
		return
	}

	// 2. Jalur Fallback Perintah Teks ("APPROVE [OPT] CODE", "ROLLBACK CODE", "DISMISS CODE")
	rawText := extractIncomingText(msgEvt)
	if strings.TrimSpace(rawText) == "" {
		return
	}

	cmdKind, cmdOptionID, refCode, matched := parseTextFallbackCommand(rawText)
	if !matched {
		return
	}

	senderMatched, allowed := b.authorizeEventSender(ctx, msgEvt)
	if !allowed {
		b.audit("UNAUTHORIZED_TEXT_CMD", fmt.Sprintf("sender=%s cmd=%s", msgEvt.Info.Sender.String(), cmdKind))
		return
	}

	poll := b.findPollByCodeOrSoleActive(refCode)
	if poll == nil {
		return
	}

	var binding PollOptionBinding
	found := false
	if cmdKind == "approve" {
		var approveOpts []PollOptionBinding
		for _, opt := range poll.Options {
			if opt.Kind == "approve" {
				approveOpts = append(approveOpts, opt)
			}
		}
		if cmdOptionID != "" {
			for _, opt := range approveOpts {
				if strings.EqualFold(opt.OptionID, cmdOptionID) {
					binding = opt
					found = true
					break
				}
			}
			if !found {
				b.audit("TEXT_CMD_UNKNOWN_OPTION", fmt.Sprintf("incident=%s option=%s", poll.IncidentID, cmdOptionID))
				_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
					fmt.Sprintf("Unknown option %q for poll %s (%s); specify a valid option (e.g. APPROVE %s %s).",
						cmdOptionID, poll.ShortCode, poll.IncidentID, firstApproveOptionID(approveOpts), poll.ShortCode))
				return
			}
		} else {
			if len(approveOpts) == 1 {
				binding = approveOpts[0]
				found = true
			} else if len(approveOpts) > 1 {
				// Wajib menolak perintah APPROVE tanpa ID opsi bila ada > 1 opsi aktif (Temuan C2)
				b.audit("TEXT_CMD_AMBIGUOUS_OPTION", fmt.Sprintf("incident=%s options=%d", poll.IncidentID, len(approveOpts)))
				_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
					fmt.Sprintf("Poll %s (%s) has multiple options; reply APPROVE <OPT> %s (e.g. APPROVE %s %s).",
						poll.ShortCode, poll.IncidentID, poll.ShortCode, firstApproveOptionID(approveOpts), poll.ShortCode))
				return
			}
		}
	} else {
		for _, opt := range poll.Options {
			if opt.Kind == cmdKind {
				binding = opt
				found = true
				break
			}
		}
	}
	if !found {
		return
	}

	b.processPollSelection(ctx, poll, binding, senderMatched)
}

func (b *Bridge) authorizeEventSender(ctx context.Context, msgEvt *events.Message) (string, bool) {
	resolvedPN := b.cfg.Messenger.ResolveLID(ctx, msgEvt.Info.Sender)
	allowed, matched := b.allowlist.IsAllowed(msgEvt.Info.Sender, msgEvt.Info.SenderAlt, resolvedPN)
	return matched, allowed
}

func (b *Bridge) processPollSelection(ctx context.Context, poll *PendingPoll, choice PollOptionBinding, approverSender string) {
	now := b.cfg.Clock().UTC()
	if !poll.ExpiresAt.IsZero() && now.After(poll.ExpiresAt) {
		b.resolvePoll(poll, ApprovalDecision{
			ApprovalID: poll.ApprovalID,
			IncidentID: poll.IncidentID,
			Status:     "EXPIRED",
			ResultMsg:  "Approval window exceeded TTL",
			DecidedAt:  now,
		})
		_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, fmt.Sprintf("Poll %s (%s) expired.", poll.ShortCode, poll.IncidentID))
		return
	}

	b.mu.Lock()
	if poll.Resolved {
		b.mu.Unlock()
		return
	}
	poll.Resolved = true
	b.mu.Unlock()

	var decision ApprovalDecision
	decision.ApprovalID = poll.ApprovalID
	decision.IncidentID = poll.IncidentID
	decision.OptionID = choice.OptionID
	decision.ChoiceLabel = choice.Label
	decision.Approver = approverSender
	decision.DecidedAt = now

	var executeReq *CrewPhaseRequest
	switch choice.Kind {
	case "approve":
		minted, err := b.approveAndMintToken(ctx, poll, choice, approverSender)
		if err != nil {
			decision.Status = "DENIED"
			decision.ResultMsg = redact.String(err.Error())
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
				fmt.Sprintf("Approval rejected for *%s* (%s): %s", choice.Label, poll.IncidentID, decision.ResultMsg))
		} else {
			decision.Status = "GRANTED"
			decision.OptionID = minted.OptionID
			decision.PlanHash = minted.PlanHash
			decision.StepIDs = minted.StepIDs
			decision.StepTokens = minted.StepTokens
			// Field lama tetap diisi dengan langkah pertama agar klien yang belum mengenal step_tokens tetap berfungsi
			decision.Token = minted.StepTokens[0].Token
			decision.Action = minted.StepTokens[0].Action
			decision.ResultMsg = minted.Summary
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, minted.Summary)
			executeReq = &CrewPhaseRequest{
				Phase:      CrewPhaseExecute,
				IncidentID: poll.IncidentID,
				Node:       b.nodeName(),
				Cgroup:     poll.Cgroup,
				ApprovalID: poll.ApprovalID,
				OptionID:   minted.OptionID,
				StepIDs:    minted.StepIDs,
			}
		}

	case "rollback":
		rolled, err := b.rollbackIncidentReflexes(ctx, poll.IncidentID)
		if err != nil {
			decision.Status = "DENIED"
			decision.ResultMsg = redact.String(err.Error())
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
				fmt.Sprintf("Failed to rollback L1 reflexes for %s: %s", poll.IncidentID, decision.ResultMsg))
		} else {
			decision.Status = "ROLLED_BACK"
			decision.ResultMsg = fmt.Sprintf("Rolled back %d L1 reflex action(s) for %s.", rolled, poll.IncidentID)
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, decision.ResultMsg)
		}

	default: // "dismiss"
		if err := b.dismissIncident(ctx, poll.IncidentID, approverSender); err != nil {
			decision.Status = "DENIED"
			decision.ResultMsg = redact.String(err.Error())
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
				fmt.Sprintf("Failed to dismiss %s: %s", poll.IncidentID, decision.ResultMsg))
		} else {
			decision.Status = "DENIED"
			decision.ResultMsg = fmt.Sprintf("Incident %s dismissed by operator.", poll.IncidentID)
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, decision.ResultMsg)
		}
	}

	b.resolvePoll(poll, decision)

	// Picu fase EXECUTE setelah keputusan tersimpan, sehingga wa_await_decision milik Remediator langsung kembali
	if executeReq != nil {
		b.triggerCrew(ctx, *executeReq)
	}
}

// approveAndMintToken memverifikasi plan Sentinel saat vote masuk dan mencetak token Ed25519 tepat untuk opsi terpilih.
// Bridge hanya menandatangani token dan mengembalikannya ke Kiro Crew, tanpa pernah mengeksekusi aksi L2 secara langsung (Temuan C1 & C2).
func (b *Bridge) approveAndMintToken(ctx context.Context, poll *PendingPoll, choice PollOptionBinding, approverSender string) (*mintedApproval, error) {
	if strings.TrimSpace(poll.PlanHash) == "" {
		return nil, errors.New("poll missing canonical plan_hash")
	}
	if strings.TrimSpace(choice.OptionID) == "" || len(choice.Steps) == 0 {
		return nil, errors.New("chosen poll option has no bound option_id or steps")
	}

	incOut, err := b.cfg.Sentinel.IncidentGet(ctx, poll.IncidentID)
	if err != nil {
		return nil, fmt.Errorf("fetch incident %s: %w", poll.IncidentID, err)
	}
	if incOut == nil {
		return nil, fmt.Errorf("sentinel returned nil incident for %s", poll.IncidentID)
	}
	if isTerminalIncidentState(incOut.Incident.State) {
		return nil, fmt.Errorf("incident %s is already terminal (%s)", poll.IncidentID, incOut.Incident.State)
	}
	if strings.TrimSpace(incOut.Incident.PlanJSON) == "" {
		return nil, fmt.Errorf("incident %s has no validated plan stored in Sentinel", poll.IncidentID)
	}

	var storedPlan policy.Plan
	if err := json.Unmarshal([]byte(incOut.Incident.PlanJSON), &storedPlan); err != nil {
		return nil, fmt.Errorf("decode stored plan_json: %w", err)
	}
	// Utamakan plan_hash dari Sentinel (dihitung dari plan asli sebelum redaksi); hitung sendiri hanya untuk Sentinel lama
	currentPlanHash := strings.TrimSpace(incOut.PlanHash)
	if currentPlanHash == "" {
		if currentPlanHash, err = policy.ComputePlanHash(&storedPlan); err != nil {
			return nil, fmt.Errorf("compute canonical plan_hash: %w", err)
		}
	}
	// Tolak suara bila plan pada Sentinel berubah sejak poll dikirimkan ke admin
	if len(currentPlanHash) != len(poll.PlanHash) || subtle.ConstantTimeCompare([]byte(currentPlanHash), []byte(poll.PlanHash)) != 1 {
		b.audit("VOTE_PLAN_HASH_MISMATCH", fmt.Sprintf("incident=%s poll_hash=%s stored_hash=%s", poll.IncidentID, shortHash(poll.PlanHash), shortHash(currentPlanHash)))
		return nil, ErrPlanHashMismatch
	}

	// Wajib mencari opsi persis berdasarkan `opt.ID == choice.OptionID` tanpa fallback ke opsi pertama (Temuan C2)
	var matchedOpt *policy.PlanOption
	for i := range storedPlan.Options {
		if storedPlan.Options[i].ID == choice.OptionID {
			matchedOpt = &storedPlan.Options[i]
			break
		}
	}
	if matchedOpt == nil || len(matchedOpt.Steps) == 0 {
		return nil, fmt.Errorf("selected option %q not found or empty in stored plan", choice.OptionID)
	}

	// Verifikasi langkah pada plan tersimpan identik dengan langkah yang ditampilkan saat poll dibuat
	choiceStepsCanon, err := policy.CanonicalJSON(choice.Steps)
	if err != nil {
		return nil, fmt.Errorf("canonicalize poll choice steps: %w", err)
	}
	storedStepsCanon, err := policy.CanonicalJSON(matchedOpt.Steps)
	if err != nil {
		return nil, fmt.Errorf("canonicalize stored option steps: %w", err)
	}
	if !bytes.Equal(choiceStepsCanon, storedStepsCanon) {
		return nil, fmt.Errorf("option %s steps differ from poll snapshot", matchedOpt.ID)
	}

	// Pastikan insiden berada pada WAITING_APPROVAL sebelum menyerahkan token ke Franken-Remediator
	curState := incOut.Incident.State
	if curState != incident.StateWaitingApproval && curState != incident.StateRemediating && incident.CanTransition(curState, incident.StateWaitingApproval) {
		if _, tErr := b.cfg.Sentinel.IncidentTransition(ctx, mcpserver.IncidentTransitionInput{
			IncidentID: poll.IncidentID,
			To:         string(incident.StateWaitingApproval),
			Reason:     fmt.Sprintf("WhatsApp approval granted for option %s", matchedOpt.ID),
			Actor:      "wa-bridge",
		}); tErr != nil {
			return nil, fmt.Errorf("transition to WAITING_APPROVAL: %w", tErr)
		}
	}

	// Cetak satu token sekali-pakai per langkah: setiap token mengikat tepat satu step_id dan aksinya sendiri,
	// sehingga opsi dua langkah (mis. L1 + L2, atau dua aksi L2 berbeda) bisa dieksekusi berurutan tanpa replay
	stepIDs := make([]string, 0, len(matchedOpt.Steps))
	stepTokens := make([]StepToken, 0, len(matchedOpt.Steps))
	for _, st := range matchedOpt.Steps {
		tok, _, mintErr := b.cfg.Minter.Mint(approval.MintRequest{
			IncidentID:     poll.IncidentID,
			PlanHash:       currentPlanHash,
			OptionID:       matchedOpt.ID,
			ActionName:     st.Action,
			StepIDs:        []string{st.ID},
			ApproverSender: approverSender,
		})
		if mintErr != nil {
			return nil, fmt.Errorf("mint approval token for step %s: %w", st.ID, mintErr)
		}
		stepIDs = append(stepIDs, st.ID)
		stepTokens = append(stepTokens, StepToken{StepID: st.ID, Action: st.Action, Token: tok})
	}

	b.audit("APPROVAL_TOKEN_MINTED", fmt.Sprintf("incident=%s option=%s steps=%v tokens=%d plan=%s",
		poll.IncidentID, matchedOpt.ID, stepIDs, len(stepTokens), shortHash(currentPlanHash)))

	summary := fmt.Sprintf("Approved option %s (%s) for %s [plan %s]; %d single-use Ed25519 step token(s) issued to Franken-Remediator.",
		matchedOpt.ID, formatStepsSummary(matchedOpt.Steps), poll.IncidentID, shortHash(currentPlanHash), len(stepTokens))
	return &mintedApproval{
		PlanHash:   currentPlanHash,
		OptionID:   matchedOpt.ID,
		StepIDs:    stepIDs,
		StepTokens: stepTokens,
		Summary:    summary,
	}, nil
}

// mintedApproval merangkum hasil persetujuan yang sudah ditandatangani untuk satu opsi poll.
type mintedApproval struct {
	PlanHash   string
	OptionID   string
	StepIDs    []string
	StepTokens []StepToken
	Summary    string
}

func (b *Bridge) rollbackIncidentReflexes(ctx context.Context, incidentID string) (int, error) {
	incOut, err := b.cfg.Sentinel.IncidentGet(ctx, incidentID)
	if err != nil {
		return 0, err
	}
	rolled := 0
	for _, rfx := range incOut.Reflexes {
		if rfx.Status != "APPLIED" {
			continue
		}
		res, rbErr := b.cfg.Sentinel.ActionRollback(ctx, rfx.ID)
		if rbErr != nil {
			return rolled, fmt.Errorf("rollback %s: %w", rfx.ID, rbErr)
		}
		if res.RolledBack {
			rolled++
		}
	}
	return rolled, nil
}

func (b *Bridge) dismissIncident(ctx context.Context, incidentID, actor string) error {
	incOut, err := b.cfg.Sentinel.IncidentGet(ctx, incidentID)
	if err != nil {
		return err
	}
	cur := incOut.Incident.State
	if cur != incident.StateWaitingApproval && incident.CanTransition(cur, incident.StateWaitingApproval) {
		if _, tErr := b.cfg.Sentinel.IncidentTransition(ctx, mcpserver.IncidentTransitionInput{
			IncidentID: incidentID,
			To:         string(incident.StateWaitingApproval),
			Reason:     "preparing dismiss by operator",
			Actor:      "wa-bridge",
		}); tErr != nil {
			return tErr
		}
	}
	_, err = b.cfg.Sentinel.IncidentTransition(ctx, mcpserver.IncidentTransitionInput{
		IncidentID: incidentID,
		To:         string(incident.StateDismissed),
		Reason:     "dismissed via WhatsApp by " + redact.String(actor),
		Actor:      "wa-bridge",
	})
	return err
}

func (b *Bridge) resolvePoll(poll *PendingPoll, dec ApprovalDecision) {
	select {
	case poll.DecisionCh <- dec:
	default:
	}
}

// AwaitDecision menunggu keputusan manusia pada Poll hingga selesai atau timeout (`<= 600s`).
func (b *Bridge) AwaitDecision(ctx context.Context, approvalID string, timeout time.Duration) (ApprovalDecision, error) {
	b.mu.Lock()
	poll := b.pollsByID[approvalID]
	if poll == nil {
		poll = b.pollsByInc[approvalID]
	}
	b.mu.Unlock()
	if poll == nil {
		return ApprovalDecision{}, fmt.Errorf("wabridge: approval poll %q not found", approvalID)
	}
	if timeout <= 0 || timeout > 600*time.Second {
		timeout = 600 * time.Second
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ApprovalDecision{}, ctx.Err()
	case dec := <-poll.DecisionCh:
		// Masukkan kembali agar pemanggil ulang tetap dapat membaca status final poll
		select {
		case poll.DecisionCh <- dec:
		default:
		}
		return dec, nil
	case <-timer.C:
		b.mu.Lock()
		poll.Resolved = true
		b.mu.Unlock()
		return ApprovalDecision{
			ApprovalID: poll.ApprovalID,
			IncidentID: poll.IncidentID,
			Status:     "EXPIRED",
			ResultMsg:  "approval wait timed out",
			DecidedAt:  b.cfg.Clock().UTC(),
		}, nil
	}
}

func (b *Bridge) findPollByCodeOrSoleActive(codeOrInc string) *PendingPoll {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := strings.ToUpper(strings.TrimSpace(codeOrInc))
	if key != "" {
		if p, ok := b.pollsByCode[key]; ok {
			return p
		}
		if p, ok := b.pollsByInc[strings.TrimSpace(codeOrInc)]; ok {
			return p
		}
	}

	var sole *PendingPoll
	activeCount := 0
	for _, p := range b.pollsByID {
		if !p.Resolved {
			sole = p
			activeCount++
		}
	}
	if activeCount == 1 && key == "" {
		return sole
	}
	return nil
}

func (b *Bridge) reserveQuota(incidentID string) error {
	now := b.cfg.Clock().UTC()
	cutoff := now.Add(-1 * time.Hour)

	b.mu.Lock()
	defer b.mu.Unlock()

	if incidentID != "" && b.incMsgCnt[incidentID] >= MaxMessagesPerIncident {
		return fmt.Errorf("%w: incident %s reached %d messages", ErrRateLimited, incidentID, MaxMessagesPerIncident)
	}

	pruned := b.nodeMsgTs[:0]
	for _, ts := range b.nodeMsgTs {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	b.nodeMsgTs = pruned

	if len(b.nodeMsgTs) >= MaxMessagesPerHourPerNode {
		return fmt.Errorf("%w: node %s reached %d messages/hour", ErrRateLimited, b.cfg.NodeName, MaxMessagesPerHourPerNode)
	}

	if incidentID != "" {
		b.incMsgCnt[incidentID]++
	}
	b.nodeMsgTs = append(b.nodeMsgTs, now)
	return nil
}

func (b *Bridge) sendRateLimitedText(ctx context.Context, incidentID string, to types.JID, text string) (types.MessageID, error) {
	if err := b.reserveQuota(incidentID); err != nil {
		return "", err
	}
	redacted := redact.String(text)
	if len(redacted) > 700 {
		redacted = redacted[:697] + "..."
	}
	msgID, err := b.cfg.Messenger.SendText(ctx, to, redacted)
	if err != nil {
		return "", err
	}
	b.trackSentMessage(msgID)
	return msgID, nil
}

func (b *Bridge) trackSentMessage(id types.MessageID) {
	if id == "" {
		return
	}
	b.mu.Lock()
	b.sentMsgIDs[id] = true
	b.mu.Unlock()
}

func (b *Bridge) isOwnSentMessage(id types.MessageID) bool {
	if id == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sentMsgIDs[id]
}

func (b *Bridge) audit(evType, detail string) {
	if b.cfg.OnAudit != nil {
		b.cfg.OnAudit(evType, redact.String(detail))
	}
}

func isAlertableSeverity(sev string) bool {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "P1", "P2", "POST_OOM", "CRITICAL", "EMERGENCY":
		return true
	default:
		return false
	}
}

// formatPlanOptionLabel menyusun label opsi poll langsung dari aksi & target plan Sentinel beserta 8 karakter hash plan.
func formatPlanOptionLabel(opt policy.PlanOption, planHash string) string {
	hashTag := shortHash(planHash)
	prefix := fmt.Sprintf("%s: ", strings.TrimSpace(opt.ID))
	suffix := fmt.Sprintf(" [%s]", hashTag)
	body := redact.String(formatStepsSummary(opt.Steps))
	if body == "" {
		body = redact.String(strings.TrimSpace(opt.Label))
	}
	maxBody := maxPollOptionLabelLen - len(prefix) - len(suffix)
	if maxBody > 3 && len(body) > maxBody {
		body = strings.TrimSpace(body[:maxBody-3]) + "..."
	}
	return prefix + body + suffix
}

func formatStepsSummary(steps []policy.PlanStep) string {
	if len(steps) == 0 {
		return ""
	}
	parts := make([]string, 0, len(steps))
	for _, st := range steps {
		parts = append(parts, formatStepTarget(st))
	}
	return strings.Join(parts, " + ")
}

func formatStepTarget(st policy.PlanStep) string {
	action := strings.TrimSpace(st.Action)
	if len(st.Params) == 0 {
		return action
	}

	if unit, ok := st.Params["unit"].(string); ok && strings.TrimSpace(unit) != "" {
		return action + " " + strings.TrimSpace(unit)
	}
	if app, ok := st.Params["app"].(string); ok && strings.TrimSpace(app) != "" {
		// Tampilkan worker PM2 yang akan di-restart agar manusia tahu persis instans mana yang disetujui
		if pmID, ok := st.Params["pm_id"]; ok && pmID != nil {
			return fmt.Sprintf("%s %s pm_id=%v", action, strings.TrimSpace(app), pmID)
		}
		return action + " " + strings.TrimSpace(app)
	}
	if pidVal, ok := st.Params["pid"]; ok && pidVal != nil {
		return fmt.Sprintf("%s pid=%v", action, pidVal)
	}

	keys := make([]string, 0, len(st.Params))
	for k := range st.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		return fmt.Sprintf("%s %s=%v", action, keys[0], st.Params[keys[0]])
	}
	return action
}

func shortHash(h string) string {
	clean := strings.TrimSpace(h)
	if len(clean) > 8 {
		return clean[:8]
	}
	return clean
}

func firstApproveOptionID(opts []PollOptionBinding) string {
	if len(opts) == 0 {
		return "A"
	}
	return opts[0].OptionID
}

func isTerminalIncidentState(st incident.State) bool {
	switch st {
	case incident.StateResolved, incident.StateEscalated, incident.StateDismissed, incident.StateExpired:
		return true
	default:
		return false
	}
}

func deriveUnitFromCgroup(cgroupPath string) string {
	base := path.Base(strings.TrimSuffix(strings.TrimSpace(cgroupPath), "/"))
	if strings.HasSuffix(base, ".service") {
		return base
	}
	return ""
}

func formatCriticalAlertMessage(node string, ev mcpserver.StreamEvent) string {
	cg := extractAnyString(ev.Data, "cgroup")
	summary := redact.String(strings.TrimSpace(ev.Summary))
	if summary == "" {
		summary = "Memory/OOM threshold crossed"
	}
	return fmt.Sprintf(
		"[%s] *%s* | %s\nNode: `%s` | Target: `%s`\n%s",
		strings.ToUpper(ev.Severity),
		ev.IncidentID,
		ev.State,
		node,
		cg,
		summary,
	)
}

func extractAnyString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func extractIncomingText(evt *events.Message) string {
	if evt == nil || evt.Message == nil {
		return ""
	}
	if s := strings.TrimSpace(evt.Message.GetConversation()); s != "" {
		return s
	}
	if ext := evt.Message.GetExtendedTextMessage(); ext != nil {
		return strings.TrimSpace(ext.GetText())
	}
	return ""
}

func parseTextFallbackCommand(text string) (kind string, optionID string, ref string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return "", "", "", false
	}
	verb := strings.ToUpper(fields[0])
	switch verb {
	case "APPROVE", "YES":
		kind = "approve"
		if len(fields) == 2 {
			arg := strings.ToUpper(fields[1])
			// Huruf tunggal A-D dikenali sebagai OptionID, sedangkan kode lebih panjang (mis. 4-hex shortCode / INC-...) sebagai referensi poll
			if len(arg) == 1 && arg[0] >= 'A' && arg[0] <= 'D' {
				optionID = arg
			} else {
				ref = fields[1]
			}
		} else if len(fields) >= 3 {
			optionID = strings.ToUpper(fields[1])
			ref = fields[2]
		}
		return kind, optionID, ref, true
	case "ROLLBACK":
		kind = "rollback"
	case "DISMISS", "NO":
		kind = "dismiss"
	default:
		return "", "", "", false
	}
	if len(fields) >= 2 {
		ref = fields[1]
	}
	return kind, "", ref, true
}

func randomShortCode() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}
