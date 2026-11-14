package wabridge

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWaitForPostPairSession_WaitsForConnectedAndOfflineSync(t *testing.T) {
	connected := make(chan struct{}, 1)
	offlineSynced := make(chan struct{}, 1)
	var out bytes.Buffer

	// Simulasikan reconnect 515 + upload prekeys lalu OfflineSyncCompleted segera setelah terhubung.
	go func() {
		time.Sleep(20 * time.Millisecond)
		connected <- struct{}{}
		time.Sleep(20 * time.Millisecond)
		offlineSynced <- struct{}{}
	}()

	start := time.Now()
	err := waitForPostPairSession(context.Background(), &out, time.Second, 50*time.Millisecond, postPairSignals{
		connected:     connected,
		offlineSynced: offlineSynced,
	})
	if err != nil {
		t.Fatalf("waitForPostPairSession unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 35*time.Millisecond {
		t.Fatalf("expected waitForPostPairSession to block until Connected+sync, returned in %v", elapsed)
	}
	if !strings.Contains(out.String(), "prekey") {
		t.Errorf("expected status message mentioning prekey sync, got %q", out.String())
	}
}

func TestWaitForPostPairSession_FailsOnPostPairDisconnectOrRejection(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
	}{
		{name: "pair error", wantErr: "post-pair handshake failed"},
		{name: "logged out", wantErr: "logged out during pairing"},
		{name: "connect failure", wantErr: "reconnect rejected"},
		{name: "client outdated", wantErr: "outdated (405)"},
		{name: "timeout before Connected", wantErr: "515 reconnect and prekey upload completion"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sigs := postPairSignals{
				connected:     make(chan struct{}, 1),
				offlineSynced: make(chan struct{}, 1),
			}
			// Inject langsung ke kanal event sesuai skenario penolakan pasca-PairSuccess.
			switch tc.name {
			case "pair error":
				sigs.pairErr = func() <-chan error { ch := make(chan error, 1); ch <- errors.New("hmac-mismatch"); return ch }()
			case "logged out":
				sigs.loggedOut = func() <-chan string { ch := make(chan string, 1); ch <- "device_removed"; return ch }()
			case "connect failure":
				sigs.connectFailure = func() <-chan string { ch := make(chan string, 1); ch <- "401 (unauthorized)"; return ch }()
			case "client outdated":
				sigs.clientOutdated = func() <-chan struct{} { ch := make(chan struct{}, 1); ch <- struct{}{}; return ch }()
			}

			err := waitForPostPairSession(context.Background(), nil, 30*time.Millisecond, 10*time.Millisecond, sigs)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestWaitForPostPairSession_LoggedOutDuringSyncSettleFails(t *testing.T) {
	connected := make(chan struct{}, 1)
	loggedOut := make(chan string, 1)
	connected <- struct{}{}

	go func() {
		time.Sleep(15 * time.Millisecond)
		loggedOut <- "401"
	}()

	err := waitForPostPairSession(context.Background(), nil, 500*time.Millisecond, 200*time.Millisecond, postPairSignals{
		connected: connected,
		loggedOut: loggedOut,
	})
	if err == nil || !strings.Contains(err.Error(), "logged out after connect") {
		t.Fatalf("expected post-connect logout error, got %v", err)
	}
}

func TestDefaultLoginTimeoutExceedsWhatsmeowQRWindow(t *testing.T) {
	// whatsmeow memancarkan 1 QR (60s) + 5 QR (20s) = 160s; default timeout harus lebih panjang.
	if DefaultLoginTimeout <= 160*time.Second {
		t.Fatalf("DefaultLoginTimeout=%v must exceed 160s QR window", DefaultLoginTimeout)
	}
}
