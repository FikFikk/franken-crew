//go:build !linux

package psi

import "context"

// fallbackOSTriggerPoller digunakan pada sistem operasi non-Linux untuk langsung mengarahkan Watcher ke mode fallback.
type fallbackOSTriggerPoller struct{}

// newOSTriggerPoller mengembalikan poller yang memicu fallback ke pembacaan berkas secara berkala pada OS non-Linux.
func newOSTriggerPoller() TriggerPoller {
	return &fallbackOSTriggerPoller{}
}

// Watch langsung mengembalikan ErrTriggerUnsupported karena syscall poll(POLLPRI) PSI spesifik untuk kernel Linux.
func (p *fallbackOSTriggerPoller) Watch(_ context.Context, _ string, _ TriggerSpec, _ func()) error {
	return ErrTriggerUnsupported
}
