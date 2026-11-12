package executor

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExecutor_RejectsShellAndDangerousArgs(t *testing.T) {
	execSafe := NewExecutor(5 * time.Second)
	ctx := context.Background()

	// 1. Tolak biner shell langsung
	shells := []string{"sh", "bash", "/bin/sh", "/bin/bash", "zsh", "cmd.exe", "powershell"}
	for _, sh := range shells {
		_, err := execSafe.Execute(ctx, sh, []string{"-c", "ls"}, 2*time.Second)
		if !errors.Is(err, ErrProhibitedShellCommand) {
			t.Errorf("expected ErrProhibitedShellCommand for shell %q, got: %v", sh, err)
		}
	}

	// 2. Tolak biner tidak terdaftar dalam allowlist
	_, err := execSafe.Execute(ctx, "curl", []string{"https://example.com"}, 2*time.Second)
	if !errors.Is(err, ErrUnapprovedBinary) {
		t.Errorf("expected ErrUnapprovedBinary for curl, got: %v", err)
	}

	// 3. Tolak argumen berbahaya seperti '-c', 'eval', atau pipa '|'
	_, err = execSafe.Execute(ctx, "echo", []string{"-c", "hello"}, 2*time.Second)
	if !errors.Is(err, ErrProhibitedShellCommand) {
		t.Errorf("expected ErrProhibitedShellCommand for dangerous arg '-c', got: %v", err)
	}

	_, err = execSafe.Execute(ctx, "echo", []string{"foo | bar"}, 2*time.Second)
	if !errors.Is(err, ErrProhibitedShellCommand) {
		t.Errorf("expected ErrProhibitedShellCommand for pipe character '|', got: %v", err)
	}
}

func TestExecutor_ExecuteAllowlistedCommand(t *testing.T) {
	execSafe := NewExecutor(5 * time.Second)
	ctx := context.Background()

	// Cek apakah perintah 'echo' tersedia pada host
	if _, err := exec.LookPath("echo"); err != nil {
		t.Skip("binary 'echo' not found in PATH, skipping live command test")
	}

	res, err := execSafe.Execute(ctx, "echo", []string{"franken-sentinel-alive"}, 3*time.Second)
	if err != nil {
		t.Fatalf("unexpected error executing allowlisted echo: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Stdout, "franken-sentinel-alive") {
		t.Errorf("expected output to contain token, got: %q", res.Stdout)
	}
}

func TestExecutor_TimeoutEnforcement(t *testing.T) {
	// Temukan biner sleep untuk menguji timeout
	sleepBin := "sleep"
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("binary 'sleep' not found in PATH, skipping timeout test")
	}

	execSafe := NewExecutor(1 * time.Second)
	ctx := context.Background()

	// Eksekusi sleep 5 detik dengan timeout ketat 100 milidetik
	res, err := execSafe.Execute(ctx, sleepBin, []string{"5"}, 100*time.Millisecond)
	if !errors.Is(err, ErrCommandTimeout) {
		t.Fatalf("expected ErrCommandTimeout, got: %v", err)
	}
	if res == nil || !res.TimedOut {
		t.Errorf("expected result to reflect TimedOut=true")
	}
}
