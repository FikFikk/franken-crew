//go:build linux

package executor

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

// setupProcessGroup mengatur PGID proses anak terpisah agar dapat di-kill bersama anak-anaknya di Linux
func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup membunuh seluruh grup proses menggunakan sinyal SIGKILL ke -PGID
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	// Mengirimkan sinyal negatif ke PID untuk mematikan satu grup proses penuh
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	// Fallback matikan PID utama jika kill process-group gagal
	if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
		return fmt.Errorf("kill pgid -%d: %v; fallback kill pid %d: %w", cmd.Process.Pid, err, cmd.Process.Pid, killErr)
	}
	return nil
}

