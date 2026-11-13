package approval

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
	"pgregory.net/rapid"
)

func setupApprovalStore(t *testing.T, incidentID string) *incident.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "approval_test.db")
	store, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create incident store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID:       incidentID,
		Node:     "pi01",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P1",
		State:    incident.StateWaitingApproval,
	}); err != nil {
		t.Fatalf("failed to seed incident: %v", err)
	}
	return store
}

func samplePlan(incidentID, unit, action string) *policy.Plan {
	return &policy.Plan{
		IncidentID:         incidentID,
		SuspectedRootCause: "Node heap RSS growth caused by unbounded in-memory cache",
		Options: []policy.PlanOption{
			{
				ID:    "opt-1",
				Label: "Restart " + unit,
				Steps: []policy.PlanStep{
					{
						ID:             "step-1",
						Action:         action,
						Params:         map[string]any{"unit": unit},
						EvidenceIDs:    []string{"ev-01"},
						ExpectedEffect: "RSS returns below baseline",
					},
				},
			},
		},
	}
}

func TestKeys_InitLoadOverwriteAndPermissions(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")

	privPath, pubPath, kp, err := InitKeys(keyDir, false)
	if err != nil {
		t.Fatalf("InitKeys failed: %v", err)
	}

	// Pastikan file ada dan kunci hasil muat ulang identik dengan keypair asal
	loadedPriv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	loadedPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey failed: %v", err)
	}
	if !loadedPriv.Equal(kp.PrivateKey) {
		t.Fatal("loaded private key does not match generated key")
	}
	if !loadedPub.Equal(kp.PublicKey) {
		t.Fatal("loaded public key does not match generated key")
	}

	fp, err := PublicKeyFingerprint(loadedPub)
	if err != nil || fp != kp.Fingerprint {
		t.Fatalf("fingerprint mismatch: got %q (err=%v), want %q", fp, err, kp.Fingerprint)
	}

	// Pada OS POSIX (Linux/macOS), wajib verifikasi permission 0600 untuk private key dan 0644 untuk public key
	if runtime.GOOS != "windows" {
		privInfo, err := os.Stat(privPath)
		if err != nil {
			t.Fatalf("stat priv: %v", err)
		}
		if got := privInfo.Mode().Perm(); got != 0o600 {
			t.Errorf("expected private key mode 0600, got %o", got)
		}
		pubInfo, err := os.Stat(pubPath)
		if err != nil {
			t.Fatalf("stat pub: %v", err)
		}
		if got := pubInfo.Mode().Perm(); got != 0o644 {
			t.Errorf("expected public key mode 0644, got %o", got)
		}
	}

	// Jalankan ulang tanpa --force wajib ditolak agar kunci produksi tidak tertimpa tidak sengaja
	if _, _, _, err := InitKeys(keyDir, false); !errors.Is(err, ErrKeysAlreadyExist) {
		t.Fatalf("expected ErrKeysAlreadyExist without --force, got: %v", err)
	}

	// Dengan --force=true, kunci baru harus dihasilkan dan menggantikan pasangan lama
	_, _, kp2, err := InitKeys(keyDir, true)
	if err != nil {
		t.Fatalf("InitKeys with force=true failed: %v", err)
	}
	if kp2.PublicKey.Equal(kp.PublicKey) {
		t.Fatal("expected forced key rotation to produce a different Ed25519 public key")
	}
}

func TestToken_MintVerifyAndAntiReplay(t *testing.T) {
	incID := "INC-20261113-0701-pi01"
	store := setupApprovalStore(t, incID)
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	curTime := now
	clockFn := func() time.Time { return curTime }

	minter, err := NewMinter(kp.PrivateKey, clockFn)
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	verifier, err := NewVerifier(kp.PublicKey, store, clockFn)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	plan := samplePlan(incID, "haunted-api.service", "restart_service")
	planHash, err := policy.ComputePlanHash(plan)
	if err != nil {
		t.Fatalf("ComputePlanHash: %v", err)
	}

	rawPhone := "+6281234567890"
	token, mintedClaims, err := minter.Mint(MintRequest{
		IncidentID:     incID,
		Plan:           plan,
		OptionID:       "opt-1",
		ActionName:     "restart_service",
		StepIDs:        []string{"step-1"},
		ApproverSender: rawPhone,
		TTL:            10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}

	// Pastikan nomor telepon mentah tidak pernah terbaca di payload token
	parts := strings.Split(token, ".")
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if strings.Contains(string(payloadBytes), rawPhone) {
		t.Fatal("raw approver PII leaked in signed token payload")
	}

	ctx := context.Background()
	verifyCtx := VerifyContext{
		IncidentID: incID,
		PlanHash:   planHash,
		ActionName: "restart_service",
		OptionID:   "opt-1",
		StepID:     "step-1",
	}

	// Verifikasi pertama wajib sukses dan mengonsumsi nonce di SQLite
	verified, err := verifier.VerifyAndConsume(ctx, token, verifyCtx)
	if err != nil {
		t.Fatalf("first VerifyAndConsume failed: %v", err)
	}
	if verified.Nonce != mintedClaims.Nonce || verified.PlanHash != planHash {
		t.Errorf("verified claims mismatch: got %+v, want nonce=%s hash=%s", verified, mintedClaims.Nonce, planHash)
	}

	// Serangan replay dengan token persis sama wajib ditolak
	_, err = verifier.VerifyAndConsume(ctx, token, verifyCtx)
	if !errors.Is(err, ErrTokenReplayed) || !errors.Is(err, incident.ErrNonceReplayed) {
		t.Fatalf("expected ErrTokenReplayed / ErrNonceReplayed on second use, got: %v", err)
	}
}

func TestToken_SecurityFailuresDoNotBurnNonce(t *testing.T) {
	incID := "INC-20261113-0702-pi01"
	store := setupApprovalStore(t, incID)
	kp, _ := GenerateKeyPair()
	otherKP, _ := GenerateKeyPair()

	now := time.Date(2026, 11, 13, 9, 10, 0, 0, time.UTC)
	curTime := now
	clockFn := func() time.Time { return curTime }

	minter, _ := NewMinter(kp.PrivateKey, clockFn)
	verifier, _ := NewVerifier(kp.PublicKey, store, clockFn)

	plan := samplePlan(incID, "haunted-api.service", "restart_service")
	planHash, _ := policy.ComputePlanHash(plan)

	token, claims, err := minter.Mint(MintRequest{
		IncidentID:     incID,
		PlanHash:       planHash,
		OptionID:       "opt-1",
		ActionName:     "restart_service",
		StepIDs:        []string{"step-1"},
		ApproverSender: "ops-lead",
		TTL:            5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	ctx := context.Background()
	validCtx := VerifyContext{
		IncidentID: incID,
		PlanHash:   planHash,
		ActionName: "restart_service",
		OptionID:   "opt-1",
		StepID:     "step-1",
	}

	// 1. Token dengan payload termodifikasi wajib ditolak oleh verifikasi signature Ed25519
	tamperedClaims := *claims
	tamperedClaims.ActionName = "kill_pid"
	tamperedJSON, _ := policy.CanonicalJSON(tamperedClaims)
	parts := strings.Split(token, ".")
	tamperedToken := base64.RawURLEncoding.EncodeToString(tamperedJSON) + "." + parts[1]
	if _, err := verifier.VerifyAndConsume(ctx, tamperedToken, validCtx); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for tampered payload, got: %v", err)
	}

	// 2. Token yang ditandatangani kunci privat asing wajib ditolak
	foreignMinter, _ := NewMinter(otherKP.PrivateKey, clockFn)
	foreignToken, _, _ := foreignMinter.Mint(MintRequest{
		IncidentID:     incID,
		PlanHash:       planHash,
		ActionName:     "restart_service",
		ApproverSender: "attacker",
	})
	if _, err := verifier.VerifyAndConsume(ctx, foreignToken, validCtx); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for foreign signer, got: %v", err)
	}

	// 3. Payload JSON non-kanonik meski bertanda tangan sah wajib ditolak
	nonCanonicalPayload := []byte(fmt.Sprintf(`{ "action_name": "restart_service", "approver_hash": %q, "exp": %d, "iat": %d, "incident_id": %q, "nonce": %q, "option_id": "opt-1", "plan_hash": %q, "step_ids": ["step-1"] }`,
		claims.ApproverHash, claims.ExpiresAt, claims.IssuedAt, claims.IncidentID, claims.Nonce, claims.PlanHash))
	nonCanonicalSig := ed25519.Sign(kp.PrivateKey, nonCanonicalPayload)
	nonCanonicalToken := base64.RawURLEncoding.EncodeToString(nonCanonicalPayload) + "." + base64.RawURLEncoding.EncodeToString(nonCanonicalSig)
	if _, err := verifier.VerifyAndConsume(ctx, nonCanonicalToken, validCtx); !errors.Is(err, ErrInvalidTokenFormat) {
		t.Errorf("expected ErrInvalidTokenFormat for non-canonical JSON payload, got: %v", err)
	}

	// 4. Context binding mismatch (plan / incident / action / step berbeda) tidak boleh membakar nonce asli
	mismatchCases := []struct {
		name string
		ctx  VerifyContext
	}{
		{"wrong_incident", VerifyContext{IncidentID: "INC-OTHER", PlanHash: planHash, ActionName: "restart_service"}},
		{"wrong_plan_hash", VerifyContext{IncidentID: incID, PlanHash: strings.Repeat("a", 64), ActionName: "restart_service"}},
		{"wrong_action", VerifyContext{IncidentID: incID, PlanHash: planHash, ActionName: "kill_pid"}},
		{"wrong_option", VerifyContext{IncidentID: incID, PlanHash: planHash, ActionName: "restart_service", OptionID: "opt-2"}},
		{"wrong_step", VerifyContext{IncidentID: incID, PlanHash: planHash, ActionName: "restart_service", StepID: "step-99"}},
	}
	for _, tc := range mismatchCases {
		if _, err := verifier.VerifyAndConsume(ctx, token, tc.ctx); !errors.Is(err, ErrTokenBindingMismatch) {
			t.Errorf("%s: expected ErrTokenBindingMismatch, got: %v", tc.name, err)
		}
	}

	// 5. Token yang kedaluwarsa wajib ditolak
	curTime = now.Add(6 * time.Minute)
	if _, err := verifier.VerifyAndConsume(ctx, token, validCtx); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired after TTL, got: %v", err)
	}

	// 6. Token dengan iat terlalu jauh di masa depan wajib ditolak
	curTime = now.Add(-2 * time.Minute)
	if _, err := verifier.VerifyAndConsume(ctx, token, validCtx); !errors.Is(err, ErrTokenNotYetValid) {
		t.Errorf("expected ErrTokenNotYetValid before clock skew window, got: %v", err)
	}

	// 7. Kembalikan waktu ke masa berlaku -> token sah tetap harus berhasil karena seluruh kegagalan sebelumnya tidak membakar nonce
	curTime = now.Add(1 * time.Minute)
	if _, err := verifier.VerifyAndConsume(ctx, token, validCtx); err != nil {
		t.Fatalf("legitimate verification after rejected probes failed (nonce burned prematurely?): %v", err)
	}
}

// Property test P2: Token yang diterbitkan untuk Plan X tidak pernah bisa mengotorisasi Plan Y yang berbeda,
// tidak membakar nonce Plan X saat dicoba pada Plan Y, dan hanya berlaku satu kali.
func TestApproval_Property_P2_TokenForPlanXNeverAuthorizesPlanY(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "p2_property.db")
	store, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	clockFn := func() time.Time { return now }
	minter, _ := NewMinter(kp.PrivateKey, clockFn)
	verifier, _ := NewVerifier(kp.PublicKey, store, clockFn)

	actions := []string{"restart_service", "pm2_reload", "kill_pid", "pm2_restart"}
	units := []string{"haunted-api.service", "worker.service", "billing.service"}
	iter := 0

	rapid.Check(t, func(rt *rapid.T) {
		iter++
		incX := fmt.Sprintf("INC-P2-%04d-X", iter)
		ctx := context.Background()
		if err := store.CreateIncident(ctx, &incident.Incident{
			ID: incX, Node: "pi01", Cgroup: "/app.service", Severity: "P1", State: incident.StateWaitingApproval,
		}); err != nil {
			rt.Fatalf("CreateIncident: %v", err)
		}

		actX := rapid.SampledFrom(actions).Draw(rt, "actX")
		unitX := rapid.SampledFrom(units).Draw(rt, "unitX")
		ttlSec := rapid.IntRange(10, 600).Draw(rt, "ttlSec")
		approver := fmt.Sprintf("+628%09d", rapid.IntRange(100000000, 999999999).Draw(rt, "phone"))

		planX := samplePlan(incX, unitX, actX)
		hashX, err := policy.ComputePlanHash(planX)
		if err != nil {
			rt.Fatalf("hashX: %v", err)
		}

		// Bangun Plan Y yang berbeda minimal pada aksi, unit, atau insidennya
		mutateKind := rapid.IntRange(0, 2).Draw(rt, "mutateKind")
		incY := incX
		unitY := unitX
		actY := actX
		switch mutateKind {
		case 0:
			// Ubah parameter unit pada Plan Y -> hash kanonik berubah
			unitY = unitX + "-alt"
		case 1:
			// Ubah action name -> baik action binding maupun plan_hash berubah
			actY = actions[(rapid.IntRange(1, len(actions)-1).Draw(rt, "shift")+len(actions))%len(actions)]
			if actY == actX {
				actY = "drain_worker"
			}
		case 2:
			// Ubah incident_id -> kedua hash dan incident binding berubah
			incY = fmt.Sprintf("INC-P2-%04d-Y", iter)
		}

		planY := samplePlan(incY, unitY, actY)
		hashY, err := policy.ComputePlanHash(planY)
		if err != nil {
			rt.Fatalf("hashY: %v", err)
		}
		if hashX == hashY {
			rt.Fatalf("test construction error: expected distinct plan hashes")
		}

		tokenX, _, err := minter.Mint(MintRequest{
			IncidentID:     incX,
			Plan:           planX,
			OptionID:       "opt-1",
			ActionName:     actX,
			StepIDs:        []string{"step-1"},
			ApproverSender: approver,
			TTL:            time.Duration(ttlSec) * time.Second,
		})
		if err != nil {
			rt.Fatalf("Mint failed: %v", err)
		}

		// Pastikan token untuk Plan X selalu gagal mengotorisasi Plan Y
		if _, err := verifier.VerifyAndConsume(ctx, tokenX, VerifyContext{
			IncidentID: incY,
			PlanHash:   hashY,
			ActionName: actY,
			OptionID:   "opt-1",
			StepID:     "step-1",
		}); !errors.Is(err, ErrTokenBindingMismatch) {
			rt.Fatalf("invariant P2 violated: token for Plan X authorized Plan Y! err=%v", err)
		}

		// Pastikan identitas pengirim mentah tidak terbocor pada klaim token hasil JSON
		parts := strings.Split(tokenX, ".")
		rawPayload, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var decoded Claims
		_ = json.Unmarshal(rawPayload, &decoded)
		if strings.Contains(string(rawPayload), approver) || decoded.ApproverHash == approver {
			rt.Fatalf("approver PII was not hashed")
		}

		// Token X yang gagal pada Plan Y masih harus sah digunakan 1x untuk Plan X sendiri
		if _, err := verifier.VerifyAndConsume(ctx, tokenX, VerifyContext{
			IncidentID: incX,
			PlanHash:   hashX,
			ActionName: actX,
			OptionID:   "opt-1",
			StepID:     "step-1",
		}); err != nil {
			rt.Fatalf("legitimate use of Plan X token failed after Plan Y rejection: %v", err)
		}

		// Penggunaan ulang token X pada Plan X wajib diblokir (single-use nonce)
		if _, err := verifier.VerifyAndConsume(ctx, tokenX, VerifyContext{
			IncidentID: incX,
			PlanHash:   hashX,
			ActionName: actX,
			OptionID:   "opt-1",
			StepID:     "step-1",
		}); !errors.Is(err, ErrTokenReplayed) {
			rt.Fatalf("expected ErrTokenReplayed on reuse, got: %v", err)
		}
	})
}

