//go:build linux

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxInotifyPoller mengimplementasikan InotifyPoller menggunakan syscall inotify di Linux.
type linuxInotifyPoller struct {
	pollTimeoutMs int
}

// newOSInotifyPoller membuat poller inotify native untuk Linux.
func newOSInotifyPoller() InotifyPoller {
	return &linuxInotifyPoller{pollTimeoutMs: 250}
}

// Watch memantau event modifikasi berkas menggunakan inotify dan poll.
func (p *linuxInotifyPoller) Watch(ctx context.Context, targetPath string, onChange func()) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	defer unix.Close(fd)

	watchDesc, err := unix.InotifyAddWatch(fd, targetPath, unix.IN_MODIFY|unix.IN_ATTRIB)
	if err != nil {
		return fmt.Errorf("inotify_add_watch on %s: %w", targetPath, err)
	}
	defer unix.InotifyRmWatch(fd, uint32(watchDesc))

	fds := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLIN,
	}}

	buf := make([]byte, unix.SizeofInotifyEvent+4096)

	for {
		if ctx.Err() != nil {
			return nil
		}

		n, err := unix.Poll(fds, p.pollTimeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll inotify: %w", err)
		}
		if n == 0 {
			continue
		}

		if fds[0].Revents&unix.POLLIN != 0 {
			nBytes, readErr := unix.Read(fd, buf)
			if readErr != nil {
				if errors.Is(readErr, unix.EAGAIN) || errors.Is(readErr, unix.EINTR) {
					continue
				}
				return fmt.Errorf("read inotify: %w", readErr)
			}
			if nBytes >= unix.SizeofInotifyEvent {
				// Pastikan event memuat flag modifikasi
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[0]))
				if ev.Mask&(unix.IN_MODIFY|unix.IN_ATTRIB) != 0 {
					onChange()
				}
			}
		}

		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("inotify fd closed or in error state")
		}
	}
}

