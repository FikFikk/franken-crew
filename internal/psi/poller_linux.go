//go:build linux

package psi

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// linuxTriggerPoller mengimplementasikan TriggerPoller menggunakan syscall unix.Open, unix.Write, dan unix.Poll(POLLPRI).
type linuxTriggerPoller struct {
	pollTimeoutMs int
}

// newOSTriggerPoller membuat instance poller native Linux dengan timeout poll 250 ms agar responsif terhadap pembatalan context.
func newOSTriggerPoller() TriggerPoller {
	return &linuxTriggerPoller{pollTimeoutMs: 250}
}

// Watch membuka berkas pressure, menulis konfigurasi trigger PSI, dan mem-poll event prioritas tinggi (POLLPRI).
func (p *linuxTriggerPoller) Watch(ctx context.Context, pressurePath string, spec TriggerSpec, onEvent func()) error {
	fd, err := unix.Open(pressurePath, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("%w: open %s: %v", ErrTriggerUnsupported, pressurePath, err)
		}
		if errors.Is(err, unix.ENOENT) {
			return ErrCgroupGone
		}
		return fmt.Errorf("open pressure file %s: %w", pressurePath, err)
	}
	defer unix.Close(fd)

	// Daftarkan trigger PSI; aktif selama file descriptor tetap terbuka
	if _, err := unix.Write(fd, spec.Bytes()); err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return fmt.Errorf("%w: write %q to %s: %v", ErrTriggerUnsupported, spec.String(), pressurePath, err)
		}
		return fmt.Errorf("register psi trigger on %s: %w", pressurePath, err)
	}

	fds := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLPRI,
	}}

	for {
		if ctx.Err() != nil {
			return nil
		}

		n, err := unix.Poll(fds, p.pollTimeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll psi %s: %w", pressurePath, err)
		}
		if n == 0 {
			continue
		}

		revents := fds[0].Revents
		// POLLERR/POLLHUP/POLLNVAL menandakan cgroup telah dihapus oleh systemd/kernel
		if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return ErrCgroupGone
		}
		if revents&unix.POLLPRI != 0 {
			onEvent()
		}
	}
}
