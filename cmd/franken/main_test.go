package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FikFikk/franken-crew/internal/approval"
)

func TestCLI_KeysInitCommand(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "franken-keys")
	var stdout, stderr bytes.Buffer

	// 1. Uji perintah `franken keys init --dir <dir>`
	code := run([]string{"keys", "init", "--dir", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr=%s)", code, stderr.String())
	}

	out := stdout.String()
	privPath := filepath.Join(dir, approval.DefaultPrivateKeyName)
	pubPath := filepath.Join(dir, approval.DefaultPublicKeyName)
	if !strings.Contains(out, privPath) || !strings.Contains(out, pubPath) {
		t.Errorf("expected key paths in stdout, got: %s", out)
	}

	// Pastikan kunci yang dihasilkan valid dan dapat dimuat kembali
	if _, err := approval.LoadPrivateKey(privPath); err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}
	if _, err := approval.LoadPublicKey(pubPath); err != nil {
		t.Fatalf("LoadPublicKey failed: %v", err)
	}

	// 2. Jalankan ulang tanpa --force wajib gagal (exit code 1)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"keys", "init", "--dir", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 when overwriting without --force, got %d", code)
	}

	// 3. Jalankan ulang dengan --force wajib sukses
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"keys", "init", "--dir", dir, "--force"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 with --force, got %d (stderr=%s)", code, stderr.String())
	}

	// 4. Argumen tidak dikenal wajib mengembalikan exit code 2
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for unknown command, got %d", code)
	}
}

func TestCLI_MCPServeSecurityChecks(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Tanpa bearer token pada env var wajib menolak startup (exit code 1)
	t.Setenv("FRANKEN_TEST_EMPTY_TOKEN", "")
	code := run([]string{"mcp", "serve", "--token-env", "FRANKEN_TEST_EMPTY_TOKEN"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 when bearer token is empty, got %d (stderr=%s)", code, stderr.String())
	}

	// Alamat bind wildcard 0.0.0.0 wajib ditolak sebelum membuka socket
	stdout.Reset()
	stderr.Reset()
	t.Setenv("FRANKEN_TEST_TOKEN", "valid-test-bearer")
	code = run([]string{"mcp", "serve", "--token-env", "FRANKEN_TEST_TOKEN", "--listen", "0.0.0.0:8090"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "unsafe bind address") {
		t.Fatalf("expected exit code 1 with unsafe bind address error, got %d (stderr=%s)", code, stderr.String())
	}
}

