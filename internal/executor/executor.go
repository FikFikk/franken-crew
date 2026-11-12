package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/redact"
)

var (
	// ErrProhibitedShellCommand terjadi jika argumen mencoba mengeksekusi shell interpreter
	ErrProhibitedShellCommand = errors.New("executor: raw shell execution (sh, bash, etc.) is strictly forbidden")
	// ErrUnapprovedBinary terjadi jika binary tidak terdaftar dalam allowlist template
	ErrUnapprovedBinary = errors.New("executor: executable binary is not in safe allowlist")
	// ErrCommandTimeout terjadi ketika eksekusi melewati batas waktu yang ditentukan
	ErrCommandTimeout = errors.New("executor: command execution timed out and process group was killed")
)

// AllowlistedBinaries mendefinisikan daftar path biner yang aman dan diperbolehkan dieksekusi
var AllowlistedBinaries = map[string]bool{
	"systemctl": true,
	"pm2":       true,
	"kill":      true,
	"pkill":     true,
	"runuser":   true,
	// Perintah utilitas pengujian lokal
	"echo":      true,
	"sleep":     true,
	"true":      true,
	"false":     true,
}

// ProhibitedShells mendefinisikan interpreter shell yang dilarang keras untuk mencegah shell-injection
var ProhibitedShells = map[string]bool{
	"sh":         true,
	"bash":       true,
	"zsh":        true,
	"dash":       true,
	"ksh":        true,
	"cmd":        true,
	"cmd.exe":    true,
	"powershell": true,
	"pwsh":       true,
}

// Result merepresentasikan hasil eksekusi perintah sistem
type Result struct {
	Binary   string        `json:"binary"`
	Args     []string      `json:"args"`
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	TimedOut bool          `json:"timed_out"`
}

// Executor menjalankan perintah sistem menggunakan template argv tetap tanpa melibatkan shell
type Executor struct {
	defaultTimeout time.Duration
}

// NewExecutor membuat instance safe executor baru
func NewExecutor(defaultTimeout time.Duration) *Executor {
	if defaultTimeout <= 0 {
		defaultTimeout = 15 * time.Second
	}
	return &Executor{defaultTimeout: defaultTimeout}
}

// ExecuteTemplate memverifikasi keamanan biner dan argumen, kemudian mengeksekusinya dengan pembatasan waktu
func (e *Executor) Execute(ctx context.Context, binary string, args []string, timeout time.Duration) (*Result, error) {
	cleanBinary := strings.ToLower(strings.TrimSpace(binary))
	// Bersihkan path agar hanya nama binary dasarnya yang dicek
	baseBinary := cleanBinary
	if idx := strings.LastIndexAny(cleanBinary, "/\\"); idx != -1 {
		baseBinary = cleanBinary[idx+1:]
	}

	// 1. Larangan mutlak: tolak seluruh varian shell interpreter
	if ProhibitedShells[baseBinary] {
		return nil, fmt.Errorf("%w: %q", ErrProhibitedShellCommand, binary)
	}

	// 2. Periksa argumen: cegah penyisipan opsi shell seperti '-c', 'eval', atau pipa
	for _, arg := range args {
		low := strings.ToLower(arg)
		if low == "-c" || low == "/c" || strings.Contains(low, "eval") || strings.Contains(low, "|") || strings.Contains(low, ";") {
			return nil, fmt.Errorf("%w: dangerous argument %q", ErrProhibitedShellCommand, arg)
		}
	}

	// 3. Pastikan biner ada dalam allowlist
	if !AllowlistedBinaries[baseBinary] {
		return nil, fmt.Errorf("%w: %q", ErrUnapprovedBinary, binary)
	}

	if timeout <= 0 {
		timeout = e.defaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, binary, args...)
	// Konfigurasikan process-group agar seluruh anak proses terbunuh jika timeout
	setupProcessGroup(cmd)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	res := &Result{
		Binary:   binary,
		Args:     args,
		Stdout:   stdoutBuf.String(),
		Stderr:   redact.String(stderrBuf.String()),
		Duration: duration,
	}

	if execCtx.Err() == context.DeadlineExceeded {
		// Bunuh process-group secara paksa jika terjadi timeout
		killProcessGroup(cmd)
		res.TimedOut = true
		res.ExitCode = -1
		return res, fmt.Errorf("%w (command %s exceeded %v)", ErrCommandTimeout, binary, timeout)
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, fmt.Errorf("execute %s: %w", binary, err)
	}

	res.ExitCode = 0
	return res, nil
}
