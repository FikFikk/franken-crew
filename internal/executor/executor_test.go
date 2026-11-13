package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func TestExecutor_AllowlistIncludesSystemdRun(t *testing.T) {
	if !AllowlistedBinaries["systemd-run"] {
		t.Fatalf("expected systemd-run to be included in AllowlistedBinaries")
	}
}

func TestExecutorHelperProcess(t *testing.T) {
	mode := ""
	for _, arg := range os.Args {
		switch arg {
		case "franken-helper-orphan-exit", "franken-helper-timeout-pipe", "franken-helper-sleep":
			mode = arg
		}
	}
	if mode == "" {
		return
	}

	switch mode {
	case "franken-helper-sleep":
		time.Sleep(2500 * time.Millisecond)
	case "franken-helper-orphan-exit":
		// Cucu proses menahan pipe stdout/stderr tetap terbuka meski proses induk segera selesai
		child := exec.Command(os.Args[0], "-test.run=^TestExecutorHelperProcess$", "franken-helper-sleep")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "start child: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("parent-exiting-pipe-still-open")
		os.Exit(0)
	case "franken-helper-timeout-pipe":
		child := exec.Command(os.Args[0], "-test.run=^TestExecutorHelperProcess$", "franken-helper-sleep")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "start child: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("parent-blocking-until-cancel")
		time.Sleep(2500 * time.Millisecond)
		os.Exit(0)
	}
}

func TestExecutor_WaitDelayAndCancelPreventsPipeHang(t *testing.T) {
	selfBase := strings.ToLower(filepath.Base(os.Args[0]))
	execSafe := NewExecutor(2 * time.Second).WithWaitDelay(120 * time.Millisecond)
	execSafe.allowed = map[string]bool{selfBase: true}

	t.Run("orphan_holds_pipes_after_parent_exit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		start := time.Now()
		res, err := execSafe.Execute(ctx, os.Args[0], []string{"-test.run=^TestExecutorHelperProcess$", "franken-helper-orphan-exit"}, 2*time.Second)
		elapsed := time.Since(start)

		if !errors.Is(err, ErrCommandTimeout) {
			t.Fatalf("expected ErrCommandTimeout via WaitDelay when grandchild holds stdio pipes, got err=%v", err)
		}
		if res == nil || !res.TimedOut {
			t.Fatalf("expected TimedOut=true, got %+v", res)
		}
		if elapsed >= 1500*time.Millisecond {
			t.Fatalf("WaitDelay did not break pipe hang promptly: took %v (wanted < 1.5s)", elapsed)
		}
		if !strings.Contains(res.Stdout, "parent-exiting-pipe-still-open") {
			t.Errorf("expected captured parent stdout before WaitDelay, got %q", res.Stdout)
		}
	})

	t.Run("cancel_and_waitdelay_on_timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		start := time.Now()
		res, err := execSafe.Execute(ctx, os.Args[0], []string{"-test.run=^TestExecutorHelperProcess$", "franken-helper-timeout-pipe"}, 100*time.Millisecond)
		elapsed := time.Since(start)

		if !errors.Is(err, ErrCommandTimeout) {
			t.Fatalf("expected ErrCommandTimeout on blocked parent + pipe child, got err=%v", err)
		}
		if res == nil || !res.TimedOut {
			t.Fatalf("expected TimedOut=true, got %+v", res)
		}
		if elapsed >= 1500*time.Millisecond {
			t.Fatalf("Cancel + WaitDelay took too long: %v (wanted < 1.5s)", elapsed)
		}
	})

	t.Run("context_cancellation_aborts_immediately", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(80*time.Millisecond, cancel)

		start := time.Now()
		_, err := execSafe.Execute(ctx, os.Args[0], []string{"-test.run=^TestExecutorHelperProcess$", "franken-helper-sleep"}, 3*time.Second)
		elapsed := time.Since(start)

		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled error, got: %v", err)
		}
		if elapsed >= 1500*time.Millisecond {
			t.Fatalf("context cancel did not abort process promptly: %v", elapsed)
		}
	})
}
