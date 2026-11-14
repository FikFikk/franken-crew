package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/redact"
)

const (
	// DefaultEventHistorySize menentukan jumlah event SSE terbaru yang disimpan di memori untuk resume.
	DefaultEventHistorySize = 256
	// DefaultHeartbeatInterval menentukan interval heartbeat SSE standar sesuai Requirement 11.2.
	DefaultHeartbeatInterval = 15 * time.Second
)

// StreamEvent merepresentasikan satu pesan SSE pada endpoint `/v1/events`.
type StreamEvent struct {
	ID         uint64         `json:"id"`
	Type       string         `json:"type"`
	IncidentID string         `json:"incident_id,omitempty"`
	Node       string         `json:"node,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	State      string         `json:"state,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
}

// EventBroker menyiarkan perubahan status insiden dan refleks secara real-time melalui SSE `/v1/events`.
type EventBroker struct {
	mu                sync.RWMutex
	nextID            uint64
	history           []StreamEvent
	maxHistory        int
	subscribers       map[uint64]chan StreamEvent
	nextSubID         uint64
	heartbeatInterval time.Duration
	nodeName          string
	done              chan struct{}
	closeOnce         sync.Once
}

// NewEventBroker membuat broker SSE baru dengan kapasitas riwayat dan interval heartbeat tertentu.
func NewEventBroker(nodeName string, maxHistory int, heartbeatInterval time.Duration) *EventBroker {
	if maxHistory <= 0 {
		maxHistory = DefaultEventHistorySize
	}
	if heartbeatInterval <= 0 {
		heartbeatInterval = DefaultHeartbeatInterval
	}
	return &EventBroker{
		maxHistory:        maxHistory,
		subscribers:       make(map[uint64]chan StreamEvent),
		heartbeatInterval: heartbeatInterval,
		nodeName:          nodeName,
		done:              make(chan struct{}),
	}
}

// Close memberi sinyal kepada seluruh handler SSE aktif agar segera berhenti saat server dimatikan.
func (b *EventBroker) Close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		if b.done != nil {
			close(b.done)
		}
	})
}

// Publish menyensor metadata event lalu mendistribusikannya ke seluruh subscriber SSE yang aktif.
func (b *EventBroker) Publish(ev StreamEvent) StreamEvent {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Node == "" {
		ev.Node = b.nodeName
	}
	// Sensor seluruh field teks agar data rahasia tidak pernah keluar melalui SSE stream
	ev.Summary = redact.String(ev.Summary)
	if ev.Data != nil {
		ev.Data = redact.Map(ev.Data)
	}

	b.mu.Lock()
	b.nextID++
	ev.ID = b.nextID
	b.history = append(b.history, ev)
	if len(b.history) > b.maxHistory {
		trim := len(b.history) - b.maxHistory
		b.history = append([]StreamEvent(nil), b.history[trim:]...)
	}

	// Kirim tetap di bawah lock: Unsubscribe menutup channel di bawah lock yang sama, sehingga pengiriman
	// tidak pernah mengenai channel tertutup (panic) dan urutan ID antar-publisher tetap terjaga.
	// Pengiriman non-blocking sehingga lock tidak pernah tertahan oleh konsumen SSE yang lambat.
	for _, ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
			// Jangan memblokir jalur utama Sentinel apabila salah satu konsumen lambat membaca SSE
		}
	}
	b.mu.Unlock()
	return ev
}

// Subscribe mendaftarkan konsumen SSE baru dan langsung menyertakan event pasca sinceID dari ring buffer.
func (b *EventBroker) Subscribe(sinceID uint64) (uint64, <-chan StreamEvent, []StreamEvent) {
	subID, ch, backlog, _ := b.subscribeWithCursor(sinceID)
	return subID, ch, backlog
}

func (b *EventBroker) subscribeWithCursor(sinceID uint64) (uint64, <-chan StreamEvent, []StreamEvent, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextSubID++
	subID := b.nextSubID
	ch := make(chan StreamEvent, 64)
	b.subscribers[subID] = ch

	// Bila sinceID melampaui nextID broker saat ini, Sentinel telah restart (epoch baru):
	// reset kursor ke 0 agar event bernomor kecil pada epoch baru tidak terbuang.
	cursor := sinceID
	if cursor > b.nextID {
		cursor = 0
	}

	var backlog []StreamEvent
	if cursor > 0 {
		for _, item := range b.history {
			if item.ID > cursor {
				backlog = append(backlog, item)
			}
		}
	} else if len(b.history) > 0 {
		// Apabila konsumen baru menyambung tanpa `since` atau pasca-restart, kirim riwayat terbaru yang aktif di buffer
		backlog = append(backlog, b.history...)
	}

	return subID, ch, backlog, cursor
}

// Unsubscribe menghapus subscriber dan menutup channel miliknya.
func (b *EventBroker) Unsubscribe(subID uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subscribers[subID]; ok {
		delete(b.subscribers, subID)
		close(ch)
	}
}

// ServeHTTP melayani stream Server-Sent Events pada endpoint `GET /v1/events`.
func (b *EventBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported by response writer", http.StatusInternalServerError)
		return
	}

	sinceID := parseSinceEventID(r)
	subID, ch, backlog, lastDelivered := b.subscribeWithCursor(sinceID)
	defer b.Unsubscribe(subID)

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Kirim ulang event yang terlewat (resume) terlebih dahulu
	for _, ev := range backlog {
		if err := writeSSEFrame(w, ev); err != nil {
			return
		}
		if ev.ID > lastDelivered {
			lastDelivered = ev.ID
		}
	}
	flusher.Flush()

	ticker := time.NewTicker(b.heartbeatInterval)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.done:
			// Hentikan loop SSE segera agar http.Server.Shutdown tidak menunggu timeout
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			if ev.ID <= lastDelivered {
				continue
			}
			if err := writeSSEFrame(w, ev); err != nil {
				return
			}
			lastDelivered = ev.ID
			flusher.Flush()
		case <-ticker.C:
			hb := StreamEvent{
				Type:      "heartbeat",
				Node:      b.nodeName,
				Timestamp: time.Now().UTC(),
			}
			if err := writeSSEFrame(w, hb); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func parseSinceEventID(r *http.Request) uint64 {
	raw := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("since"))
	}
	if raw == "" {
		return 0
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func writeSSEFrame(w http.ResponseWriter, ev StreamEvent) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	eventType := ev.Type
	if eventType == "" {
		eventType = "message"
	}
	if ev.ID > 0 {
		if _, err := fmt.Fprintf(w, "id: %d\n", ev.ID); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, payload); err != nil {
		return err
	}
	return nil
}
