//go:build !linux

package cgroup

import (
	"context"
)

// fallbackInotifyPoller digunakan pada sistem operasi non-Linux.
type fallbackInotifyPoller struct{}

func newOSInotifyPoller() InotifyPoller {
	return &fallbackInotifyPoller{}
}

// Watch menyimulasikan pemantauan dengan sleep pada sistem non-Linux untuk menjaga portabilitas build.
func (p *fallbackInotifyPoller) Watch(ctx context.Context, _ string, _ func()) error {
	<-ctx.Done()
	return nil
}

// Ensure interface compliance
var _ InotifyPoller = (*fallbackInotifyPoller)(nil)
