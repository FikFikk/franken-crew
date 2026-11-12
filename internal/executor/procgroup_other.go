//go:build !linux

package executor

import (
	"os/exec"
)

// setupProcessGroup adalah implementasi no-op untuk sistem operasi non-Linux
func setupProcessGroup(cmd *exec.Cmd) {
	// Pada Windows, pembatalan proses dikelola oleh context cancellation CommandContext
}

// killProcessGroup membunuh proses utama secara langsung pada sistem operasi non-Linux
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
