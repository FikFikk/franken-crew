package wabridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
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

	// Label pilihan standar pada Native WhatsApp Poll persetujuan.
	OptionApproveL2Restart = "Approve L2 Restart"
	OptionRollbackReflex   = "Rollback Reflex"
	OptionDismiss          = "Dismiss"
)

var (
	// ErrRateLimited dikembalikan jika kuota pesan per insiden atau per jam node sudah penuh.
	ErrRateLimited = errors.New("wabridge: WhatsApp message rate limit reached")
	// ErrUnauthorizedSender dikembalikan apabila pengirim pesan atau suara poll tidak masuk allowlist admin.
	ErrUnauthorizedSender = errors.New("wabridge: sender not in admin allowlist")
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
	ApprovalID  string    `json:"approval_id"`
	IncidentID  string    `json:"incident_id"`
	Status      string    `json:"status"` // GRANTED, ROLLED_BACK, DENIED, EXPIRED
	ChoiceLabel string    `json:"choice_label,omitempty"`
	Token       string    `json:"token,omitempty"`
	Approver    string    `json:"approver,omitempty"`
	PlanHash    string    `json:"plan_hash,omitempty"`
	Action      string    `json:"action,omitempty"`
	ResultMsg   string    `json:"result_msg,omitempty"`
	DecidedAt   time.Time `json:"decided_at"`
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
	ExecuteOnVote bool
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
}

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

// HandleSSEEvent memproses satu event stream Sentinel dan mengirim alert + Poll WhatsApp untuk insiden kritis.
func (b *Bridge) HandleSSEEvent(ctx context.Context, ev mcpserver.StreamEvent) {
	now := b.cfg.Clock().UTC()
	b.markHeartbeat(now)

	if ev.Node != "" {
		b.mu.Lock()
		b.cfg.NodeName = ev.Node
		b.mu.Unlock()
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

	// 1. Kirim pesan ringkas pertama secepat mungkin (< 2 detik sejak event dibuka)
	firstAlert := formatCriticalAlertMessage(b.cfg.NodeName, ev)
	if _, err := b.sendRateLimitedText(ctx, ev.IncidentID, b.targetJID, firstAlert); err != nil {
		b.audit("FIRST_ALERT_ERROR", fmt.Sprintf("incident=%s err=%v", ev.IncidentID, err))
	}

	// 2. Ambil konteks insiden/plan dari Sentinel MCP untuk membangun Poll persetujuan yang akurat
	var incOut *mcpserver.IncidentGetOutput
	getCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	incOut, _ = b.cfg.Sentinel.IncidentGet(getCtx, ev.IncidentID)
	cancel()

	cg := extractAnyString(ev.Data, "cgroup")
	if cg == "" && incOut != nil {
		cg = incOut.Incident.Cgroup
	}

	var planHash string
	var approveSteps []policy.PlanStep
	optionID := "A"

	if incOut != nil && incOut.Incident.PlanJSON != "" {
		var plan policy.Plan
		if json.Unmarshal([]byte(incOut.Incident.PlanJSON), &plan) == nil {
			if h, err := policy.ComputePlanHash(&plan); err == nil {
				planHash = h
			}
			for _, opt := range plan.Options {
				for _, st := range opt.Steps {
					if st.Action != "" {
						optionID = opt.ID
						approveSteps = opt.Steps
						break
					}
				}
				if len(approveSteps) > 0 {
					break
				}
			}
		}
	}

	_, _ = b.SendApprovalPoll(ctx, PollRequest{
		IncidentID:    ev.IncidentID,
		PlanHash:      planHash,
		Cgroup:        cg,
		OptionID:      optionID,
		ApproveSteps:  approveSteps,
		ExecuteOnVote: true,
	})
}

// PollRequest berisi parameter untuk mengirim Native WhatsApp Poll persetujuan ke admin.
type PollRequest struct {
	IncidentID    string
	PlanHash      string
	Cgroup        string
	OptionID      string
	ApproveSteps  []policy.PlanStep
	Options       []string // Opsional: menimpa 3 opsi standar jika dipanggil lewat MCP tool
	ExecuteOnVote bool
	TTL           time.Duration
}

// SendApprovalPoll mengirim Native WhatsApp Poll serta mendaftarkan pemetaan hash SHA-256 dan kode teks fallback.
func (b *Bridge) SendApprovalPoll(ctx context.Context, req PollRequest) (*PendingPoll, error) {
	if strings.TrimSpace(req.IncidentID) == "" {
		return nil, errors.New("wabridge: incident_id is required for poll")
	}

	optionLabels := req.Options
	if len(optionLabels) == 0 {
		optionLabels = []string{
			OptionApproveL2Restart,
			OptionRollbackReflex,
			OptionDismiss,
		}
	}

	shortCode := randomShortCode()
	title := fmt.Sprintf("[%s] %s — Pilih tindakan L2/Refleks (atau balas APPROVE/ROLLBACK/DISMISS %s)",
		shortCode, req.IncidentID, shortCode)

	if err := b.reserveQuota(req.IncidentID); err != nil {
		return nil, err
	}

	msgID, err := b.cfg.Messenger.SendPoll(ctx, b.targetJID, title, optionLabels, 1)
	if err != nil {
		return nil, fmt.Errorf("send approval poll: %w", err)
	}
	b.trackSentMessage(msgID)

	now := b.cfg.Clock().UTC()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = b.cfg.PollTTL
	}

	poll := &PendingPoll{
		ApprovalID:    "APR-" + shortCode,
		PollMessageID: msgID,
		ShortCode:     shortCode,
		IncidentID:    req.IncidentID,
		PlanHash:      req.PlanHash,
		Cgroup:        req.Cgroup,
		DefaultUnit:   deriveUnitFromCgroup(req.Cgroup),
		ExecuteOnVote: req.ExecuteOnVote,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
		OptionsByHash: make(map[string]PollOptionBinding, len(optionLabels)),
		DecisionCh:    make(chan ApprovalDecision, 1),
	}

	for idx, lbl := range optionLabels {
		kind := classifyOptionKind(lbl, idx)
		optID := req.OptionID
		if optID == "" {
			optID = string(rune('A' + idx))
		}
		var steps []policy.PlanStep
		if kind == "approve" {
			steps = req.ApproveSteps
		}
		binding := PollOptionBinding{
			Label:    lbl,
			HashHex:  HashPollOption(lbl),
			Kind:     kind,
			OptionID: optID,
			Steps:    steps,
		}
		poll.Options = append(poll.Options, binding)
		poll.OptionsByHash[binding.HashHex] = binding
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

		var selected *PollOptionBinding
		for _, digest := range vote.GetSelectedOptions() {
			hashHex := hex.EncodeToString(digest)
			if bnd, ok := poll.OptionsByHash[hashHex]; ok {
				copyBnd := bnd
				selected = &copyBnd
				break
			}
		}
		if selected == nil {
			b.audit("POLL_UNKNOWN_HASH", fmt.Sprintf("incident=%s", poll.IncidentID))
			return
		}

		b.processPollSelection(ctx, poll, *selected, senderMatched)
		return
	}

	// 2. Jalur Fallback Perintah Teks ("APPROVE CODE", "ROLLBACK CODE", "DISMISS CODE")
	rawText := extractIncomingText(msgEvt)
	if strings.TrimSpace(rawText) == "" {
		return
	}

	cmdKind, refCode, matched := parseTextFallbackCommand(rawText)
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
	for _, opt := range poll.Options {
		if opt.Kind == cmdKind {
			binding = opt
			found = true
			break
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
		_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, fmt.Sprintf("Poll %s (%s) sudah kedaluwarsa.", poll.ShortCode, poll.IncidentID))
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
	decision.ChoiceLabel = choice.Label
	decision.Approver = approverSender
	decision.DecidedAt = now

	switch choice.Kind {
	case "approve":
		token, planHash, actName, summary, err := b.approveAndOptionallyExecute(ctx, poll, choice, approverSender)
		if err != nil {
			decision.Status = "DENIED"
			decision.ResultMsg = redact.String(err.Error())
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
				fmt.Sprintf("Gagal memproses approval *%s* untuk %s: %s", choice.Label, poll.IncidentID, decision.ResultMsg))
		} else {
			decision.Status = "GRANTED"
			decision.Token = token
			decision.PlanHash = planHash
			decision.Action = actName
			decision.ResultMsg = summary
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, summary)
		}

	case "rollback":
		rolled, err := b.rollbackIncidentReflexes(ctx, poll.IncidentID)
		if err != nil {
			decision.Status = "DENIED"
			decision.ResultMsg = redact.String(err.Error())
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
				fmt.Sprintf("Gagal rollback refleks %s: %s", poll.IncidentID, decision.ResultMsg))
		} else {
			decision.Status = "ROLLED_BACK"
			decision.ResultMsg = fmt.Sprintf("Rollback %d refleks L1 selesai untuk %s.", rolled, poll.IncidentID)
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, decision.ResultMsg)
		}

	default: // "dismiss"
		if err := b.dismissIncident(ctx, poll.IncidentID, approverSender); err != nil {
			decision.Status = "DENIED"
			decision.ResultMsg = redact.String(err.Error())
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID,
				fmt.Sprintf("Gagal dismiss %s: %s", poll.IncidentID, decision.ResultMsg))
		} else {
			decision.Status = "DENIED"
			decision.ResultMsg = fmt.Sprintf("Insiden %s di-dismiss oleh operator.", poll.IncidentID)
			_, _ = b.sendRateLimitedText(ctx, poll.IncidentID, b.targetJID, decision.ResultMsg)
		}
	}

	b.resolvePoll(poll, decision)
}

func (b *Bridge) approveAndOptionallyExecute(ctx context.Context, poll *PendingPoll, choice PollOptionBinding, approverSender string) (string, string, string, string, error) {
	incOut, err := b.cfg.Sentinel.IncidentGet(ctx, poll.IncidentID)
	if err != nil {
		return "", "", "", "", fmt.Errorf("fetch incident %s: %w", poll.IncidentID, err)
	}

	steps := choice.Steps
	planHash := poll.PlanHash
	optionID := choice.OptionID
	if optionID == "" {
		optionID = "A"
	}

	if incOut.Incident.PlanJSON != "" {
		var existingPlan policy.Plan
		if decErr := json.Unmarshal([]byte(incOut.Incident.PlanJSON), &existingPlan); decErr == nil {
			if h, hErr := policy.ComputePlanHash(&existingPlan); hErr == nil {
				planHash = h
			}
			if len(steps) == 0 && len(existingPlan.Options) > 0 {
				for _, opt := range existingPlan.Options {
					if opt.ID == optionID || len(opt.Steps) > 0 {
						optionID = opt.ID
						steps = opt.Steps
						break
					}
				}
			}
		}
	}

	// Jika insiden dipicu langsung dari SSE sebelum Architect mengirim plan, susun & daftarkan plan L2 aman
	if len(steps) == 0 {
		plan, buildErr := b.buildDefaultL2RestartPlan(poll, incOut)
		if buildErr != nil {
			return "", "", "", "", buildErr
		}
		subOut, subErr := b.cfg.Sentinel.PlanSubmit(ctx, poll.IncidentID, plan)
		if subErr != nil {
			return "", "", "", "", fmt.Errorf("plan_submit failed: %w", subErr)
		}
		if !subOut.Valid {
			return "", "", "", "", fmt.Errorf("plan rejected by policy: %v", subOut.Violations)
		}
		planHash = subOut.PlanHash
		optionID = plan.Options[0].ID
		steps = plan.Options[0].Steps
		incOut.Incident.State = incident.State(subOut.State)
	}

	if len(steps) == 0 || planHash == "" {
		return "", "", "", "", errors.New("no executable L2 step or plan_hash available")
	}

	// Pastikan insiden berada pada WAITING_APPROVAL sebelum eksekusi atau klaim token
	curState := incOut.Incident.State
	if curState != incident.StateWaitingApproval && curState != incident.StateRemediating && incident.CanTransition(curState, incident.StateWaitingApproval) {
		if tOut, tErr := b.cfg.Sentinel.IncidentTransition(ctx, mcpserver.IncidentTransitionInput{
			IncidentID: poll.IncidentID,
			To:         string(incident.StateWaitingApproval),
			Reason:     "WhatsApp approval poll granted",
			Actor:      "wa-bridge",
		}); tErr == nil {
			curState = incident.State(tOut.State)
		}
	}

	primaryStep := steps[0]
	stepIDs := make([]string, 0, len(steps))
	for _, st := range steps {
		stepIDs = append(stepIDs, st.ID)
	}

	// Jika dipanggil dari MCP `wa_request_approval`/`wa_await_decision`, cukup kembalikan token bertanda tangan ke Remediator
	if !poll.ExecuteOnVote {
		tok, _, mintErr := b.cfg.Minter.Mint(approval.MintRequest{
			IncidentID:     poll.IncidentID,
			PlanHash:       planHash,
			OptionID:       optionID,
			ActionName:     primaryStep.Action,
			StepIDs:        stepIDs,
			ApproverSender: approverSender,
		})
		if mintErr != nil {
			return "", "", "", "", fmt.Errorf("mint approval token: %w", mintErr)
		}
		summary := fmt.Sprintf("Approval Ed25519 ditandatangani untuk %s (%s).", poll.IncidentID, primaryStep.Action)
		return tok, planHash, primaryStep.Action, summary, nil
	}

	// Eksekusi setiap langkah (maksimal 2 langkah berantai sesuai batasan kebijakan)
	maxSteps := len(steps)
	if maxSteps > 2 {
		maxSteps = 2
	}
	var lastTok string
	var lastOut *mcpserver.ActionExecuteOutput
	for i := 0; i < maxSteps; i++ {
		st := steps[i]
		tok, _, mintErr := b.cfg.Minter.Mint(approval.MintRequest{
			IncidentID:     poll.IncidentID,
			PlanHash:       planHash,
			OptionID:       optionID,
			ActionName:     st.Action,
			StepIDs:        []string{st.ID},
			ApproverSender: approverSender,
		})
		if mintErr != nil {
			return "", "", "", "", fmt.Errorf("mint approval token step %s: %w", st.ID, mintErr)
		}
		lastTok = tok

		execOut, execErr := b.cfg.Sentinel.ActionExecute(ctx, mcpserver.ActionExecuteInput{
			IncidentID:    poll.IncidentID,
			StepID:        st.ID,
			Action:        st.Action,
			Params:        st.Params,
			ApprovalToken: tok,
		})
		if execErr != nil {
			return "", "", "", "", fmt.Errorf("action_execute step %s (%s): %w", st.ID, st.Action, execErr)
		}
		lastOut = execOut
	}

	summary := fmt.Sprintf("Disetujui & dieksekusi: `%s` untuk *%s* (exit=%d, dur=%dms, state=%s).",
		primaryStep.Action, poll.IncidentID, lastOut.ExitCode, lastOut.DurationMs, lastOut.State)
	return lastTok, planHash, primaryStep.Action, summary, nil
}

func (b *Bridge) buildDefaultL2RestartPlan(poll *PendingPoll, incOut *mcpserver.IncidentGetOutput) (policy.Plan, error) {
	unit := poll.DefaultUnit
	if unit == "" && incOut != nil {
		unit = deriveUnitFromCgroup(incOut.Incident.Cgroup)
	}
	if unit == "" {
		return policy.Plan{}, errors.New("cannot infer target systemd unit for L2 restart from incident cgroup")
	}

	var evidenceIDs []string
	if incOut != nil && len(incOut.Evidence) > 0 {
		evidenceIDs = []string{incOut.Evidence[0].ID}
	} else {
		evidenceIDs = []string{"sse-trigger-" + poll.IncidentID}
	}

	return policy.Plan{
		IncidentID:         poll.IncidentID,
		SuspectedRootCause: fmt.Sprintf("Elevated memory pressure / OOM risk detected in %s", unit),
		Options: []policy.PlanOption{
			{
				ID:    "A",
				Label: OptionApproveL2Restart,
				Steps: []policy.PlanStep{
					{
						ID:             "step-l2-restart-1",
						Action:         "unit_restart",
						Params:         map[string]any{"unit": unit},
						EvidenceIDs:    evidenceIDs,
						ExpectedEffect: fmt.Sprintf("Restart %s to reclaim leaked heap memory cleanly", unit),
					},
				},
			},
		},
		HumanFollowUp: []string{"Inspect memory heap growth after service restart"},
	}, nil
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

func classifyOptionKind(label string, idx int) string {
	lower := strings.ToLower(label)
	switch {
	case strings.Contains(lower, "rollback"):
		return "rollback"
	case strings.Contains(lower, "dismiss") || strings.Contains(lower, "do nothing"):
		return "dismiss"
	case strings.Contains(lower, "approve") || strings.Contains(lower, "restart") || idx == 0:
		return "approve"
	default:
		return "dismiss"
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

func parseTextFallbackCommand(text string) (kind string, ref string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return "", "", false
	}
	verb := strings.ToUpper(fields[0])
	switch verb {
	case "APPROVE", "YES":
		kind = "approve"
	case "ROLLBACK":
		kind = "rollback"
	case "DISMISS", "NO":
		kind = "dismiss"
	default:
		return "", "", false
	}
	if len(fields) >= 2 {
		ref = fields[1]
	}
	return kind, ref, true
}

func randomShortCode() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

