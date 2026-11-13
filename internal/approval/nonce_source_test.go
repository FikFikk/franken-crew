package approval

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestMinter_SetNonceSourceMakesTokensReproducible(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	clock := func() time.Time { return time.Date(2026, 11, 13, 3, 20, 10, 0, time.UTC) }
	req := MintRequest{IncidentID: "INC-1", PlanHash: "abc", OptionID: "A", ActionName: "pm2_reload", StepIDs: []string{"s1"}, ApproverSender: "lab-admin"}

	mint := func() (string, *Claims) {
		m, err := NewMinter(priv, clock)
		if err != nil {
			t.Fatalf("NewMinter: %v", err)
		}
		m.SetNonceSource(bytes.NewReader(bytes.Repeat([]byte{0xAB, 0xCD}, 64)))
		tok, claims, err := m.Mint(req)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		return tok, claims
	}
	tokA, claimsA := mint()
	tokB, _ := mint()
	if tokA != tokB {
		t.Fatalf("same key, clock, and nonce source must mint identical tokens")
	}
	if claimsA.Nonce != "abcdabcdabcdabcdabcdabcdabcdabcd" {
		t.Fatalf("nonce must come from the injected source, got %q", claimsA.Nonce)
	}

	// Sumber yang habis kembali ke crypto/rand agar nonce tetap terisi
	m, _ := NewMinter(priv, clock)
	m.SetNonceSource(bytes.NewReader(nil))
	_, claims, err := m.Mint(req)
	if err != nil || len(claims.Nonce) != 2*nonceByteLen {
		t.Fatalf("exhausted nonce source must fall back to crypto/rand, got %v %+v", err, claims)
	}
}
