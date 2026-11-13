//go:build linux

package executor

import (
	"os/exec"
	"syscall"
)

// setupProcessGroup mengatur PGID proses anak terpisah agar dapat di-kill bersama anak-anaknya di Linux
func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup membunuh seluruh grup proses menggunakan sinyal SIGKILL ke -PGID
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	// Mengirimkan sinyal negatif ke PID untuk mematikan satu grup proses penuh
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

