//go:build !linux

package executor

import (
	"errors"
	"os"
	"os/exec"
)

// setupProcessGroup adalah implementasi no-op untuk sistem operasi non-Linux
func setupProcessGroup(cmd *exec.Cmd) {
	// Pada Windows, pembatalan proses dikelola oleh cmd.Cancel dan cmd.WaitDelay
}

// killProcessGroup membunuh proses utama secara langsung pada sistem operasi non-Linux
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	err := cmd.Process.Kill()
	if err == nil || errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}
