package wabridge

import (
	"slices"
	"strings"

	"go.mau.fi/whatsmeow/types"
)

// Allowlist menyimpan daftar nomor WhatsApp atau JID admin yang berwenang menyetujui aksi L2.
type Allowlist struct {
	raw        []string
	exactJIDs  []string
	phoneUsers []string
}

// NewAllowlist mem-parsing daftar nomor telepon/JID admin menjadi matcher yang dinormalisasi.
func NewAllowlist(entries []string) *Allowlist {
	al := &Allowlist{}
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		al.raw = append(al.raw, trimmed)

		jid, user := NormalizeJIDOrPhone(trimmed)
		if !jid.IsEmpty() {
			s := jid.ToNonAD().String()
			if !slices.Contains(al.exactJIDs, s) {
				al.exactJIDs = append(al.exactJIDs, s)
			}
		}
		if user != "" && !slices.Contains(al.phoneUsers, user) {
			al.phoneUsers = append(al.phoneUsers, user)
		}
	}
	return al
}

// IsEmpty mengembalikan true jika tidak ada admin pada allowlist (kebijakan fail-closed menolak semua pengirim).
func (a *Allowlist) IsEmpty() bool {
	return a == nil || (len(a.exactJIDs) == 0 && len(a.phoneUsers) == 0)
}

// PrimaryTarget mengembalikan JID tujuan utama untuk mengirim alert dan poll insiden.
func (a *Allowlist) PrimaryTarget() (types.JID, bool) {
	if a == nil || len(a.exactJIDs) == 0 {
		return types.EmptyJID, false
	}
	parsed, err := types.ParseJID(a.exactJIDs[0])
	if err != nil {
		return types.EmptyJID, false
	}
	return parsed.ToNonAD(), true
}

// IsAllowed memeriksa apakah pengirim utama, SenderAlt, atau hasil resolusi LID termasuk dalam allowlist admin.
func (a *Allowlist) IsAllowed(candidates ...types.JID) (bool, string) {
	if a.IsEmpty() {
		return false, ""
	}
	for _, cand := range candidates {
		if cand.IsEmpty() {
			continue
		}
		norm := cand.ToNonAD()
		if slices.Contains(a.exactJIDs, norm.String()) {
			return true, norm.String()
		}
		// Cocokkan user numerik hanya pada server WhatsApp reguler (hindari tabrakan ID LID acak)
		if norm.Server == types.DefaultUserServer || norm.Server == "" {
			digits := normalizeDigits(norm.User)
			if digits != "" && slices.Contains(a.phoneUsers, digits) {
				return true, norm.String()
			}
		}
	}
	return false, ""
}

// NormalizeJIDOrPhone mengubah input nomor E.164 atau JID WhatsApp menjadi `types.JID` non-AD yang bersih.
func NormalizeJIDOrPhone(raw string) (types.JID, string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return types.EmptyJID, ""
	}
	if strings.Contains(trimmed, "@") {
		parsed, err := types.ParseJID(trimmed)
		if err != nil {
			return types.EmptyJID, ""
		}
		nonAD := parsed.ToNonAD()
		if nonAD.Server == types.DefaultUserServer {
			return nonAD, normalizeDigits(nonAD.User)
		}
		return nonAD, ""
	}
	digits := normalizeDigits(trimmed)
	if digits == "" {
		return types.EmptyJID, ""
	}
	return types.NewJID(digits, types.DefaultUserServer), digits
}

func normalizeDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

