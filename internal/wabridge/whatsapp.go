package wabridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	_ "modernc.org/sqlite"
)

// ErrWAAlreadyPaired dikembalikan saat sesi perangkat sudah tertaut dan `--relogin` tidak diminta.
var ErrWAAlreadyPaired = errors.New("wabridge: WhatsApp device session is already paired")

// Messenger mengabstraksikan pengiriman pesan, pembuatan poll, dan dekripsi suara WhatsApp agar mudah diuji.
type Messenger interface {
	SendText(ctx context.Context, to types.JID, text string) (types.MessageID, error)
	SendPoll(ctx context.Context, to types.JID, title string, options []string, selectableCount int) (types.MessageID, error)
	DecryptVote(ctx context.Context, vote *events.Message) (*waE2E.PollVoteMessage, error)
	ResolveLID(ctx context.Context, lid types.JID) types.JID
}

// HashPollOption menghitung digest SHA-256 heksadesimal dari teks opsi poll sesuai protokol enkripsi WhatsApp.
func HashPollOption(optionText string) string {
	sum := sha256.Sum256([]byte(optionText))
	return hex.EncodeToString(sum[:])
}

// OpenWhatsAppClient menginisialisasi whatsmeow di atas modernc.org/sqlite murni Go (`CGO_ENABLED=0`).
func OpenWhatsAppClient(ctx context.Context, dbPath string, logLevel string) (*whatsmeow.Client, *sqlstore.Container, error) {
	cleanPath := strings.TrimSpace(dbPath)
	if cleanPath == "" {
		cleanPath = "wa-bridge-session.db"
	}
	if dir := filepath.Dir(cleanPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create whatsapp store dir %q: %w", dir, err)
		}
	}

	// Gunakan dialek "sqlite" (modernc.org/sqlite) dengan pragma foreign_keys=1 dan WAL sesuai spesifikasi Task 9.1
	dsn := cleanPath
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + filepath.ToSlash(cleanPath)
	}
	if !strings.Contains(dsn, "?") {
		dsn += "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	}

	if strings.TrimSpace(logLevel) == "" {
		logLevel = "WARN"
	}
	dbLog := waLog.Stdout("WA-Store", logLevel, false)
	clientLog := waLog.Stdout("WA-Client", logLevel, false)

	container, err := sqlstore.New(ctx, "sqlite", dsn, dbLog)
	if err != nil {
		return nil, nil, fmt.Errorf("open whatsmeow sqlite store: %w", err)
	}

	deviceStore, err := container.GetFirstDevice(ctx)
	if err != nil {
		_ = container.Close()
		return nil, nil, fmt.Errorf("get first device store: %w", err)
	}

	client := whatsmeow.NewClient(deviceStore, clientLog)
	return client, container, nil
}

// LoginWithQR menautkan sesi WhatsApp pertama kali dengan merender QR code langsung ke terminal.
func LoginWithQR(ctx context.Context, dbPath string, out io.Writer, forceRelogin bool) (types.JID, error) {
	if out == nil {
		out = os.Stdout
	}
	client, container, err := OpenWhatsAppClient(ctx, dbPath, "WARN")
	if err != nil {
		return types.EmptyJID, err
	}
	defer func() {
		client.Disconnect()
		_ = container.Close()
	}()

	if client.Store.ID != nil {
		if !forceRelogin {
			return client.Store.ID.ToNonAD(), nil
		}
		// Hapus sesi lama jika pengguna secara eksplisit meminta re-pairing
		if err := client.Store.Delete(ctx); err != nil {
			return types.EmptyJID, fmt.Errorf("clear existing whatsapp session: %w", err)
		}
	}

	pairedCh := make(chan types.JID, 1)
	client.AddEventHandler(func(evt any) {
		if ps, ok := evt.(*events.PairSuccess); ok {
			select {
			case pairedCh <- ps.ID.ToNonAD():
			default:
			}
		}
	})

	// GetQRChannel wajib dipanggil sebelum Connect sesuai kontrak resmi whatsmeow
	qrChan, err := client.GetQRChannel(ctx)
	if err != nil {
		return types.EmptyJID, fmt.Errorf("register qr channel: %w", err)
	}
	if err := client.Connect(); err != nil {
		return types.EmptyJID, fmt.Errorf("connect whatsapp client: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return types.EmptyJID, ctx.Err()
		case item, ok := <-qrChan:
			if !ok {
				if client.Store.ID != nil {
					return client.Store.ID.ToNonAD(), nil
				}
				return types.EmptyJID, errors.New("whatsapp QR channel closed before pairing completed")
			}
			switch item.Event {
			case "code":
				fmt.Fprintln(out, "\nScan QR berikut menggunakan WhatsApp > Linked Devices:")
				qrterminal.GenerateHalfBlock(item.Code, qrterminal.L, out)
			case "success":
				select {
				case jid := <-pairedCh:
					return jid, nil
				case <-time.After(2 * time.Second):
					if client.Store.ID != nil {
						return client.Store.ID.ToNonAD(), nil
					}
					return types.EmptyJID, nil
				}
			case "timeout":
				return types.EmptyJID, errors.New("whatsapp QR pairing timed out")
			default:
				if item.Error != nil {
					return types.EmptyJID, fmt.Errorf("whatsapp QR event %s: %w", item.Event, item.Error)
				}
			}
		}
	}
}

// WhatsmeowMessenger adalah implementasi produksi Messenger di atas `*whatsmeow.Client`.
type WhatsmeowMessenger struct {
	client *whatsmeow.Client
}

// NewWhatsmeowMessenger membungkus client whatsmeow ke antarmuka Messenger bridge.
func NewWhatsmeowMessenger(client *whatsmeow.Client) (*WhatsmeowMessenger, error) {
	if client == nil {
		return nil, errors.New("wabridge: whatsmeow client is required")
	}
	return &WhatsmeowMessenger{client: client}, nil
}

// SendText mengirim pesan teks biasa ke JID tujuan WhatsApp.
func (m *WhatsmeowMessenger) SendText(ctx context.Context, to types.JID, text string) (types.MessageID, error) {
	if to.IsEmpty() {
		return "", errors.New("wabridge: target JID is empty")
	}
	resp, err := m.client.SendMessage(ctx, to.ToNonAD(), &waE2E.Message{
		Conversation: proto.String(text),
	})
	if err != nil {
		return "", fmt.Errorf("whatsapp send text to %s: %w", to.String(), err)
	}
	return resp.ID, nil
}

// SendPoll mengirim Native WhatsApp Poll satu pilihan beserta secret enkripsi suara.
func (m *WhatsmeowMessenger) SendPoll(ctx context.Context, to types.JID, title string, options []string, selectableCount int) (types.MessageID, error) {
	if to.IsEmpty() {
		return "", errors.New("wabridge: target JID is empty")
	}
	msg := m.client.BuildPollCreation(title, options, selectableCount)
	resp, err := m.client.SendMessage(ctx, to.ToNonAD(), msg)
	if err != nil {
		return "", fmt.Errorf("whatsapp send poll to %s: %w", to.String(), err)
	}
	return resp.ID, nil
}

// DecryptVote mendekripsi suara poll terenkripsi dari event PollUpdateMessage.
func (m *WhatsmeowMessenger) DecryptVote(ctx context.Context, vote *events.Message) (*waE2E.PollVoteMessage, error) {
	return m.client.DecryptPollVote(ctx, vote)
}

// ResolveLID menerjemahkan alamat @lid menjadi JID nomor telepon apabila tersedia di store perangkat.
func (m *WhatsmeowMessenger) ResolveLID(ctx context.Context, lid types.JID) types.JID {
	if lid.Server != types.HiddenUserServer || m.client.Store == nil || m.client.Store.LIDs == nil {
		return types.EmptyJID
	}
	pn, err := m.client.Store.LIDs.GetPNForLID(ctx, lid.ToNonAD())
	if err != nil {
		return types.EmptyJID
	}
	return pn.ToNonAD()
}

