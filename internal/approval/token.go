package approval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
)

const (
	// DefaultTokenTTL adalah masa berlaku bawaan token persetujuan Ed25519 (10 menit).
	DefaultTokenTTL = 10 * time.Minute
	// MaxTokenTTL adalah batas maksimal masa berlaku token persetujuan agar jendela replay tetap sempit.
	MaxTokenTTL = 10 * time.Minute
	// MaxClockSkewSeconds memberi toleransi selisih jam maksimal 30 detik pada field iat.
	MaxClockSkewSeconds = int64(30)
	// nonceByteLen menghasilkan nonce CSPRNG 128-bit (32 karakter hex).
	nonceByteLen = 16
)

var (
	// ErrInvalidTokenFormat dikembalikan jika struktur token tidak mengikuti `base64url(payload).base64url(sig)`.
	ErrInvalidTokenFormat = errors.New("approval: invalid token format")
	// ErrInvalidSignature dikembalikan jika verifikasi signature Ed25519 gagal.
	ErrInvalidSignature = errors.New("approval: invalid Ed25519 signature")
	// ErrTokenExpired dikembalikan jika waktu saat ini sudah melewati `exp`.
	ErrTokenExpired = errors.New("approval: approval token has expired")
	// ErrTokenNotYetValid dikembalikan jika `iat` berada di masa depan melebihi toleransi clock skew.
	ErrTokenNotYetValid = errors.New("approval: approval token iat is in the future")
	// ErrTokenBindingMismatch dikembalikan jika token tidak cocok dengan incident_id, plan_hash, action_name, atau step_id.
	ErrTokenBindingMismatch = errors.New("approval: token context binding mismatch")
	// ErrTokenReplayed dikembalikan jika nonce token sudah pernah dikonsumsi sebelumnya di SQLite.
	ErrTokenReplayed = errors.New("approval: token nonce already consumed (replay detected)")
	// ErrInvalidClaims dikembalikan jika klaim token tidak lengkap atau TTL tidak valid.
	ErrInvalidClaims = errors.New("approval: invalid or incomplete token claims")
)

// Claims merepresentasikan payload terstruktur yang ditandatangani secara kanonik dengan Ed25519.
type Claims struct {
	IncidentID   string   `json:"incident_id"`
	PlanHash     string   `json:"plan_hash"`
	OptionID     string   `json:"option_id,omitempty"`
	ActionName   string   `json:"action_name"`
	StepIDs      []string `json:"step_ids,omitempty"`
	ApproverHash string   `json:"approver_hash"`
	Nonce        string   `json:"nonce"`
	IssuedAt     int64    `json:"iat"`
	ExpiresAt    int64    `json:"exp"`
}

// MintRequest memuat parameter yang dibutuhkan wa-bridge untuk mencetak token persetujuan baru.
type MintRequest struct {
	IncidentID     string
	PlanHash       string       // Wajib kecuali Plan diisi untuk dihitung otomatis
	Plan           *policy.Plan // Opsional: dihitung dengan policy.ComputePlanHash jika PlanHash kosong
	OptionID       string
	ActionName     string
	StepIDs        []string
	ApproverSender string // Identitas pengirim (mis. nomor WA); di-hash SHA-256 sebelum masuk ke token
	TTL            time.Duration
}

// VerifyContext mendefinisikan konteks eksekusi yang wajib terikat pada token saat diverifikasi Sentinel.
type VerifyContext struct {
	IncidentID string
	PlanHash   string
	ActionName string
	OptionID   string // Opsional: jika diisi, wajib cocok dengan claims.OptionID
	StepID     string // Opsional: jika diisi, wajib tercakup dalam claims.StepIDs
}

// Minter mencetak token persetujuan Ed25519 pada komponen wa-bridge.
type Minter struct {
	privKey ed25519.PrivateKey
	clock   func() time.Time
}

// NewMinter membuat token minter Ed25519 baru dengan jam bawaan UTC.
func NewMinter(privKey ed25519.PrivateKey, clock func() time.Time) (*Minter, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: unexpected Ed25519 private key size %d", ErrInvalidKeyFormat, len(privKey))
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Minter{
		privKey: slices.Clone(privKey),
		clock:   clock,
	}, nil
}

// Mint membuat dan menandatangani token persetujuan dalam format `base64url(canonicalJSON).base64url(sig)`.
func (m *Minter) Mint(req MintRequest) (string, *Claims, error) {
	if strings.TrimSpace(req.IncidentID) == "" {
		return "", nil, fmt.Errorf("%w: incident_id is required", ErrInvalidClaims)
	}
	if strings.TrimSpace(req.ActionName) == "" {
		return "", nil, fmt.Errorf("%w: action_name is required", ErrInvalidClaims)
	}
	if strings.TrimSpace(req.ApproverSender) == "" {
		return "", nil, fmt.Errorf("%w: approver sender is required", ErrInvalidClaims)
	}

	planHash := strings.TrimSpace(req.PlanHash)
	if req.Plan != nil {
		if req.Plan.IncidentID != "" && req.Plan.IncidentID != req.IncidentID {
			return "", nil, fmt.Errorf("%w: plan incident_id mismatch", ErrTokenBindingMismatch)
		}
		computedHash, err := policy.ComputePlanHash(req.Plan)
		if err != nil {
			return "", nil, fmt.Errorf("compute canonical plan hash: %w", err)
		}
		if planHash != "" && planHash != computedHash {
			return "", nil, fmt.Errorf("%w: provided plan_hash differs from canonical plan hash", ErrInvalidClaims)
		}
		planHash = computedHash
	}
	if planHash == "" {
		return "", nil, fmt.Errorf("%w: plan_hash is required", ErrInvalidClaims)
	}

	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}
	if ttl < time.Second || ttl > MaxTokenTTL {
		return "", nil, fmt.Errorf("%w: ttl must be between 1s and %s", ErrInvalidClaims, MaxTokenTTL)
	}

	nonce, err := generateNonce()
	if err != nil {
		return "", nil, err
	}

	now := m.clock().UTC()
	var stepIDs []string
	if len(req.StepIDs) > 0 {
		stepIDs = slices.Clone(req.StepIDs)
	}

	claims := Claims{
		IncidentID:   req.IncidentID,
		PlanHash:     planHash,
		OptionID:     req.OptionID,
		ActionName:   req.ActionName,
		StepIDs:      stepIDs,
		ApproverHash: HashApprover(req.ApproverSender),
		Nonce:        nonce,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(ttl).Unix(),
	}

	canonicalPayload, err := policy.CanonicalJSON(claims)
	if err != nil {
		return "", nil, fmt.Errorf("canonicalize approval claims: %w", err)
	}

	sig := ed25519.Sign(m.privKey, canonicalPayload)
	token := base64.RawURLEncoding.EncodeToString(canonicalPayload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, &claims, nil
}

// HashApprover melakukan hashing SHA-256 pada identitas penyetuju agar PII tidak tersimpan di token atau log.
func HashApprover(sender string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(sender)))
	return hex.EncodeToString(sum[:])
}

// Verifier memverifikasi token persetujuan Ed25519 serta mengonsumsi nonce single-use di SQLite pada Sentinel.
type Verifier struct {
	pubKey ed25519.PublicKey
	store  *incident.Store
	clock  func() time.Time
}

// NewVerifier membuat instance token verifier untuk Sentinel.
func NewVerifier(pubKey ed25519.PublicKey, store *incident.Store, clock func() time.Time) (*Verifier, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: unexpected Ed25519 public key size %d", ErrInvalidKeyFormat, len(pubKey))
	}
	if store == nil {
		return nil, errors.New("approval: incident store is required")
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Verifier{
		pubKey: slices.Clone(pubKey),
		store:  store,
		clock:  clock,
	}, nil
}

// VerifyAndConsume memeriksa signature Ed25519, masa berlaku, keterikatan konteks, dan mencegah replay via SQLite nonce.
func (v *Verifier) VerifyAndConsume(ctx context.Context, rawToken string, expected VerifyContext) (*Claims, error) {
	payloadBytes, sigBytes, err := splitAndDecodeToken(rawToken)
	if err != nil {
		return nil, err
	}

	// Verifikasi signature Ed25519 harus dilakukan pertama sebelum parsing klaim atau akses database
	if !ed25519.Verify(v.pubKey, payloadBytes, sigBytes) {
		return nil, ErrInvalidSignature
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims: %v", ErrInvalidTokenFormat, err)
	}

	// Tolak payload yang tidak persis sama dengan bentuk JSON kanoniknya untuk mencegah key-smuggling
	reCanonical, err := policy.CanonicalJSON(claims)
	if err != nil || !bytes.Equal(payloadBytes, reCanonical) {
		return nil, fmt.Errorf("%w: payload is not canonical JSON", ErrInvalidTokenFormat)
	}

	if err := validateClaimsAndWindow(&claims, v.clock().UTC()); err != nil {
		return nil, err
	}

	if err := validateContextBindings(&claims, expected); err != nil {
		return nil, err
	}

	// Konsumsi nonce secara atomik di SQLite hanya setelah seluruh validasi kriptografi dan konteks lolos
	if err := v.store.ConsumeNonce(ctx, claims.Nonce, claims.IncidentID, claims.PlanHash); err != nil {
		if errors.Is(err, incident.ErrNonceReplayed) {
			_ = v.store.RecordAudit(ctx, claims.IncidentID, "sentinel", "APPROVAL_REPLAY_REJECTED",
				fmt.Sprintf(`{"nonce":"%s","plan_hash":"%s","action":"%s"}`, claims.Nonce, claims.PlanHash, claims.ActionName))
			return nil, fmt.Errorf("%w: %w", ErrTokenReplayed, err)
		}
		return nil, fmt.Errorf("consume approval nonce: %w", err)
	}

	return &claims, nil
}

func splitAndDecodeToken(rawToken string) ([]byte, []byte, error) {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, nil, ErrInvalidTokenFormat
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payloadBytes) == 0 {
		return nil, nil, fmt.Errorf("%w: invalid payload encoding", ErrInvalidTokenFormat)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("%w: invalid signature encoding", ErrInvalidTokenFormat)
	}
	return payloadBytes, sigBytes, nil
}

func validateClaimsAndWindow(claims *Claims, now time.Time) error {
	if claims.IncidentID == "" || claims.PlanHash == "" || claims.ActionName == "" || claims.ApproverHash == "" || claims.Nonce == "" {
		return fmt.Errorf("%w: missing required fields", ErrInvalidClaims)
	}
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt {
		return fmt.Errorf("%w: invalid iat/exp timestamps", ErrInvalidClaims)
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(MaxTokenTTL.Seconds()) {
		return fmt.Errorf("%w: token ttl exceeds max %s", ErrInvalidClaims, MaxTokenTTL)
	}

	nowUnix := now.Unix()
	if claims.IssuedAt > nowUnix+MaxClockSkewSeconds {
		return fmt.Errorf("%w: iat=%d > now=%d", ErrTokenNotYetValid, claims.IssuedAt, nowUnix)
	}
	if nowUnix >= claims.ExpiresAt {
		return fmt.Errorf("%w: expired at %d (now=%d)", ErrTokenExpired, claims.ExpiresAt, nowUnix)
	}
	return nil
}

func validateContextBindings(claims *Claims, expected VerifyContext) error {
	if expected.IncidentID == "" || claims.IncidentID != expected.IncidentID {
		return fmt.Errorf("%w: incident_id mismatch", ErrTokenBindingMismatch)
	}
	if expected.PlanHash == "" || len(claims.PlanHash) != len(expected.PlanHash) ||
		subtle.ConstantTimeCompare([]byte(claims.PlanHash), []byte(expected.PlanHash)) != 1 {
		return fmt.Errorf("%w: plan_hash mismatch", ErrTokenBindingMismatch)
	}
	if expected.ActionName == "" || claims.ActionName != expected.ActionName {
		return fmt.Errorf("%w: action_name mismatch", ErrTokenBindingMismatch)
	}
	if expected.OptionID != "" && claims.OptionID != expected.OptionID {
		return fmt.Errorf("%w: option_id mismatch", ErrTokenBindingMismatch)
	}
	if expected.StepID != "" && !slices.Contains(claims.StepIDs, expected.StepID) {
		return fmt.Errorf("%w: step_id %q not covered by token", ErrTokenBindingMismatch, expected.StepID)
	}
	return nil
}

func generateNonce() (string, error) {
	var raw [nonceByteLen]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}
