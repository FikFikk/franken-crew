//go:build linux

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// inotifyWatchMask meminta notifikasi perubahan isi/atribut dan penghapusan inode. IN_IGNORED, IN_UNMOUNT,
	// dan IN_Q_OVERFLOW selalu dikirim kernel tanpa perlu diminta.
	inotifyWatchMask = unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_DELETE_SELF
	// inotifyReadBufSize memuat ratusan event tanpa name dan selalu cukup untuk satu event dengan name terpanjang.
	inotifyReadBufSize = 4096 + unix.SizeofInotifyEvent + unix.NAME_MAX + 1
)

// linuxInotifyPoller mengimplementasikan InotifyPoller menggunakan syscall inotify di Linux.
type linuxInotifyPoller struct {
	// pollTimeoutMs membatasi lama satu poll(2) agar pembatalan ctx cepat teramati.
	pollTimeoutMs int
	// livenessInterval adalah jeda minimum antar-pemeriksaan bahwa targetPath masih menunjuk inode yang dipantau.
	livenessInterval time.Duration
}

// newOSInotifyPoller membuat poller inotify native untuk Linux.
func newOSInotifyPoller() InotifyPoller {
	return &linuxInotifyPoller{pollTimeoutMs: 250, livenessInterval: time.Second}
}

// fileIdentity mengidentifikasi satu inode secara unik melalui pasangan device dan nomor inode.
type fileIdentity struct {
	dev uint64
	ino uint64
}

func statIdentity(path string) (fileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, nil
}

// verifyIdentity mengembalikan ErrWatchGone bila targetPath hilang atau kini menunjuk inode selain armed.
// Error stat lain (mis. EACCES sementara) diabaikan dan diperiksa lagi pada interval berikutnya.
func verifyIdentity(targetPath string, armed fileIdentity) error {
	current, err := statIdentity(targetPath)
	switch {
	case err == nil && current == armed:
		return nil
	case err == nil:
		return fmt.Errorf("%w: %s now refers to a different inode", ErrWatchGone, targetPath)
	case errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%w: %s no longer exists", ErrWatchGone, targetPath)
	default:
		return nil
	}
}

// Watch memasang watch inotify pada targetPath dan memanggil onChange setiap kali berkas perlu dibaca ulang.
//
// Watch mengembalikan ErrWatchGone ketika kernel melepas watch (IN_IGNORED, IN_DELETE_SELF, IN_UNMOUNT) atau
// ketika targetPath tidak lagi menunjuk inode yang dipantau. Pemeriksaan identitas kedua ini diperlukan karena
// cgroupfs (kernfs) pada kernel yang beredar saat ini tidak mengirim IN_DELETE_SELF/IN_IGNORED saat direktori
// cgroup dihapus: tanpa pemeriksaan itu watch pada memory.events cgroup lama diam selamanya setelah unit di-restart.
func (p *linuxInotifyPoller) Watch(ctx context.Context, targetPath string, onChange func()) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return fmt.Errorf("inotify_init1: %w", err)
	}
	// Menutup fd inotify sekaligus melepas watch yang masih terpasang, pada semua jalur keluar.
	defer unix.Close(fd)

	armed, err := statIdentity(targetPath)
	if err != nil {
		return fmt.Errorf("stat %s before inotify_add_watch: %w", targetPath, err)
	}
	wd, err := unix.InotifyAddWatch(fd, targetPath, inotifyWatchMask)
	if err != nil {
		return fmt.Errorf("inotify_add_watch on %s: %w", targetPath, err)
	}
	// Path yang berganti di antara stat dan inotify_add_watch berarti watch mungkin menempel pada inode lain.
	if err := verifyIdentity(targetPath, armed); err != nil {
		return err
	}

	fds := []unix.PollFd{{
		Fd:     int32(fd),
		Events: unix.POLLIN,
	}}
	buf := make([]byte, inotifyReadBufSize)
	lastCheck := time.Now()

	for {
		if ctx.Err() != nil {
			return nil
		}

		n, err := unix.Poll(fds, p.pollTimeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll inotify on %s: %w", targetPath, err)
		}

		if n > 0 {
			revents := fds[0].Revents
			switch {
			case revents&unix.POLLIN != 0:
				batch, readErr := readInotifyBatch(fd, buf, int32(wd))
				if readErr != nil {
					return fmt.Errorf("inotify on %s: %w", targetPath, readErr)
				}
				if batch.modified {
					onChange()
				}
				if batch.gone {
					return fmt.Errorf("%w: kernel removed the inotify watch on %s", ErrWatchGone, targetPath)
				}
			case revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0:
				// Tidak terjadi pada fd inotify yang valid; kembali agar poll tidak berputar tanpa henti.
				return fmt.Errorf("inotify fd for %s in error state (revents %#x)", targetPath, revents)
			}
		}

		if time.Since(lastCheck) >= p.livenessInterval {
			lastCheck = time.Now()
			if err := verifyIdentity(targetPath, armed); err != nil {
				return err
			}
		}
	}
}

// readInotifyBatch membaca event yang tersedia dari fd inotify non-blocking lalu mem-parsing seluruh record-nya.
func readInotifyBatch(fd int, buf []byte, wd int32) (inotifyBatch, error) {
	n, err := unix.Read(fd, buf)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return inotifyBatch{}, nil
		}
		return inotifyBatch{}, fmt.Errorf("read inotify events: %w", err)
	}
	batch, err := parseInotifyEvents(buf[:n], wd)
	if err != nil {
		return inotifyBatch{}, fmt.Errorf("parse inotify events: %w", err)
	}
	return batch, nil
}
