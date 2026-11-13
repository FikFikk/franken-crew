package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FikFikk/franken-crew/internal/approval"
)

func TestWABridgeCLI_ValidationAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// 1. Uji `--help`
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "wa-bridge") {
		t.Fatalf("expected help exit 0, got %d (out=%q err=%q)", code, stdout.String(), stderr.String())
	}

	// 2. Tanpa bearer token wajib ditolak
	stdout.Reset()
	stderr.Reset()
	t.Setenv("WA_BRIDGE_EMPTY_TOK", "")
	code = run([]string{"serve", "--token-env", "WA_BRIDGE_EMPTY_TOK", "--admins", "6281234567890"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "bearer token") {
		t.Fatalf("expected error on missing bearer token, got %d (stderr=%s)", code, stderr.String())
	}

	// 3. Tanpa admin allowlist wajib ditolak (fail-closed)
	stdout.Reset()
	stderr.Reset()
	t.Setenv("WA_BRIDGE_TEST_TOK", "secret-tok")
	t.Setenv("FRANKEN_WA_ADMINS", "")
	code = run([]string{"serve", "--token-env", "WA_BRIDGE_TEST_TOK"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "allowlist") {
		t.Fatalf("expected error when admin allowlist missing, got %d (stderr=%s)", code, stderr.String())
	}

	// 4. Sesi WhatsApp belum pairing QR wajib meminta pengguna menjalankan `franken wa-login`
	tmp := t.TempDir()
	privPath, _, _, err := approval.InitKeys(filepath.Join(tmp, "keys"), false)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	waDB := filepath.Join(tmp, "unpaired.db")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"serve",
		"--token-env", "WA_BRIDGE_TEST_TOK",
		"--admins", "+6281234567890",
		"--priv-key", privPath,
		"--wa-db", waDB,
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "franken wa-login") {
		t.Fatalf("expected unpaired session guidance mentioning franken wa-login, got %d (stderr=%s)", code, stderr.String())
	}
}

