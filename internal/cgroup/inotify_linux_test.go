//go:build linux

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

const (
	linuxTestTimeout = 2 * time.Second
	// Fixture berlebar tetap agar penulisan di tempat (tanpa O_TRUNC) selalu menimpa seluruh isi berkas.
	paddedZeroEvents = "low 000\nhigh 000\nmax 000\noom 000\noom_kill 000\n"
)

func TestInotifyABIConstantsMatchKernelHeaders(t *testing.T) {
	cases := []struct {
		name      string
		got, want uint32
	}{
		{name: "IN_MODIFY", got: inModify, want: unix.IN_MODIFY},
		{name: "IN_ATTRIB", got: inAttrib, want: unix.IN_ATTRIB},
		{name: "IN_DELETE_SELF", got: inDeleteSelf, want: unix.IN_DELETE_SELF},
		{name: "IN_UNMOUNT", got: inUnmount, want: unix.IN_UNMOUNT},
		{name: "IN_Q_OVERFLOW", got: inQOverflow, want: unix.IN_Q_OVERFLOW},
		{name: "IN_IGNORED", got: inIgnored, want: unix.IN_IGNORED},
		{name: "sizeof(struct inotify_event)", got: inotifyEventHeaderSize, want: unix.SizeofInotifyEvent},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, kernel ABI (x/sys/unix) is %#x", tc.name, tc.got, tc.want)
		}
	}
}

// newTestLinuxPoller membuat poller inotify sungguhan dengan timeout poll pendek dan interval cek identitas tertentu.
func newTestLinuxPoller(liveness time.Duration) *linuxInotifyPoller {
	return &linuxInotifyPoller{pollTimeoutMs: 10, livenessInterval: liveness}
}

func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

// overwriteInPlace menulis content di offset 0 tanpa O_TRUNC dalam satu write(2), meniru kernel yang memperbarui
// memory.events tanpa pernah mengosongkannya. Panjang content harus sama dengan isi sebelumnya.
func overwriteInPlace(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s for overwrite: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte(content), 0); err != nil {
		t.Fatalf("overwrite %s: %v", path, err)
	}
}

// linuxWatch menjalankan linuxInotifyPoller.Watch sungguhan di goroutine terpisah.
type linuxWatch struct {
	cancel   context.CancelFunc
	modified chan struct{}
	done     chan struct{}
	err      error // hanya valid setelah done ditutup
}

func startLinuxWatch(t *testing.T, p *linuxInotifyPoller, path string) *linuxWatch {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	lw := &linuxWatch{cancel: cancel, modified: make(chan struct{}, 1), done: make(chan struct{})}
	go func() {
		defer close(lw.done)
		lw.err = p.Watch(ctx, path, func() {
			select {
			case lw.modified <- struct{}{}:
			default:
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-lw.done:
		case <-time.After(linuxTestTimeout):
			t.Errorf("Watch on %s did not return within %v after cancel", path, linuxTestTimeout)
		}
	})
	return lw
}

func (lw *linuxWatch) waitDone(t *testing.T, what string) error {
	t.Helper()
	select {
	case <-lw.done:
		return lw.err
	case <-time.After(linuxTestTimeout):
		t.Fatalf("Watch did not return within %v %s", linuxTestTimeout, what)
		return nil
	}
}

// writeUntilModified menulis ulang path hingga poller melaporkan modifikasi. Penulisan sebelum inotify_add_watch
// tidak menghasilkan event, sehingga penulisan diulang alih-alih diandalkan sekali.
func (lw *linuxWatch) writeUntilModified(t *testing.T, path string) {
	t.Helper()
	deadline := time.After(linuxTestTimeout)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for i := 1; ; i++ {
		overwriteInPlace(t, path, fmt.Sprintf("low 000\nhigh %03d\nmax 000\noom 000\noom_kill 000\n", i%1000))
		select {
		case <-lw.modified:
			return
		case <-lw.done:
			t.Fatalf("Watch returned %v before reporting a modification of %s", lw.err, path)
		case <-deadline:
			t.Fatalf("no modification of %s reported within %v", path, linuxTestTimeout)
		case <-ticker.C:
		}
	}
}

// replaceKeepingOldInode meniru cgroupfs (kernfs) yang tidak mengirim IN_DELETE_SELF/IN_IGNORED saat cgroup
// dihapus: hard link kedua menjaga inode lama tetap hidup sehingga unlink hanya memicu IN_ATTRIB, lalu path
// dibuat ulang sebagai inode baru yang tidak pernah dilihat watch lama.
func replaceKeepingOldInode(t *testing.T, path string) {
	t.Helper()
	if err := os.Link(path, path+".pinned"); err != nil {
		t.Fatalf("link %s: %v", path, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
	writeFixture(t, path, paddedZeroEvents)
}

func TestLinuxInotifyPoller_ModifyThenDeleteReturnsErrWatchGone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.events")
	writeFixture(t, path, paddedZeroEvents)
	// Cek identitas path praktis dimatikan: hanya event inotify yang boleh mengakhiri watch di test ini
	lw := startLinuxWatch(t, newTestLinuxPoller(time.Hour), path)

	lw.writeUntilModified(t, path)

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
	if err := lw.waitDone(t, "after the watched file was deleted"); !errors.Is(err, ErrWatchGone) {
		t.Fatalf("Watch returned %v after the watched file was deleted, want ErrWatchGone", err)
	}
}

func TestLinuxInotifyPoller_PathReplacedWithoutDeleteEvent(t *testing.T) {
	t.Run("stale watch stays silent without the identity check", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "memory.events")
		writeFixture(t, path, paddedZeroEvents)
		lw := startLinuxWatch(t, newTestLinuxPoller(time.Hour), path)
		lw.writeUntilModified(t, path)

		replaceKeepingOldInode(t, path)

		select {
		case <-lw.done:
			t.Fatalf("Watch returned %v on its own; this setup must reproduce a watch the kernel never drops", lw.err)
		case <-time.After(150 * time.Millisecond):
		}
	})

	t.Run("identity check reports ErrWatchGone", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "memory.events")
		writeFixture(t, path, paddedZeroEvents)
		lw := startLinuxWatch(t, newTestLinuxPoller(20*time.Millisecond), path)
		lw.writeUntilModified(t, path)

		replaceKeepingOldInode(t, path)

		if err := lw.waitDone(t, "after the path was replaced by a new inode"); !errors.Is(err, ErrWatchGone) {
			t.Fatalf("Watch returned %v after the path was replaced by a new inode, want ErrWatchGone", err)
		}
	})
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

func TestLinuxInotifyPoller_ClosesInotifyFDOnEveryExitPath(t *testing.T) {
	dir := t.TempDir()
	scenarios := []struct {
		name string
		run  func(t *testing.T, path string)
	}{
		{
			name: "watched file missing",
			run: func(t *testing.T, path string) {
				err := newTestLinuxPoller(time.Hour).Watch(context.Background(), path+".missing", func() {})
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("Watch on a missing file returned %v, want an error wrapping ENOENT", err)
				}
			},
		},
		{
			name: "context cancelled",
			run: func(t *testing.T, path string) {
				lw := startLinuxWatch(t, newTestLinuxPoller(time.Hour), path)
				lw.writeUntilModified(t, path)
				lw.cancel()
				if err := lw.waitDone(t, "after cancel"); err != nil {
					t.Fatalf("Watch returned %v after cancel, want nil", err)
				}
			},
		},
		{
			name: "watched file deleted",
			run: func(t *testing.T, path string) {
				lw := startLinuxWatch(t, newTestLinuxPoller(time.Hour), path)
				lw.writeUntilModified(t, path)
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove %s: %v", path, err)
				}
				if err := lw.waitDone(t, "after delete"); !errors.Is(err, ErrWatchGone) {
					t.Fatalf("Watch returned %v after delete, want ErrWatchGone", err)
				}
			},
		},
		{
			name: "path replaced",
			run: func(t *testing.T, path string) {
				lw := startLinuxWatch(t, newTestLinuxPoller(20*time.Millisecond), path)
				lw.writeUntilModified(t, path)
				replaceKeepingOldInode(t, path)
				if err := lw.waitDone(t, "after replace"); !errors.Is(err, ErrWatchGone) {
					t.Fatalf("Watch returned %v after replace, want ErrWatchGone", err)
				}
			},
		},
	}
	runRound := func(round int) {
		for i, sc := range scenarios {
			path := filepath.Join(dir, fmt.Sprintf("memory.events.%d.%d", round, i))
			writeFixture(t, path, paddedZeroEvents)
			sc.run(t, path)
		}
	}

	runRound(0) // pemanasan: fd yang dibuka sekali oleh runtime tidak dihitung sebagai kebocoran
	before := countOpenFDs(t)
	for round := 1; round <= 3; round++ {
		runRound(round)
	}
	if after := countOpenFDs(t); after != before {
		t.Fatalf("open fds went from %d to %d after 3 rounds of %d Watch exit paths (fd leak)", before, after, len(scenarios))
	}
}

// writeUntilDelta menimpa path dengan content(i) secara berkala hingga watcher mengirim EventsDelta.
func writeUntilDelta(t *testing.T, run *watchRun, out <-chan EventsDelta, path string, content func(i int) string) EventsDelta {
	t.Helper()
	deadline := time.After(linuxTestTimeout)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for i := 0; ; i++ {
		overwriteInPlace(t, path, content(i))
		select {
		case d := <-out:
			return d
		case <-run.done:
			t.Fatalf("WatchTarget exited (err=%v) before emitting a delta for %s", run.err, path)
		case <-deadline:
			t.Fatalf("no EventsDelta for %s within %v", path, linuxTestTimeout)
		case <-ticker.C:
		}
	}
}

func drainDeltas(out <-chan EventsDelta) []EventsDelta {
	var got []EventsDelta
	for {
		select {
		case d := <-out:
			got = append(got, d)
		default:
			return got
		}
	}
}

func TestEventsWatcher_RealInotifyRearmsWhenFileIsRecreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory.events")
	writeFixture(t, path, "low 000\nhigh 007\nmax 003\noom 001\noom_kill 001\n")

	rearms := make(chan string, 4)
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:                  kernelfs.NewOSFS(),
		Poller:              newTestLinuxPoller(50 * time.Millisecond),
		OnRearm:             func(cg string) { rearms <- cg },
		RearmBackoffInitial: 5 * time.Millisecond,
		RearmBackoffMax:     20 * time.Millisecond,
	})
	out := make(chan EventsDelta, 64)
	run := startWatch(t, w, testCgroup, path, out)

	// 1. Watch awal aktif. Nilai max terus dinaikkan agar penulisan yang mendahului pembacaan baseline tidak
	//    membuat test menunggu selamanya.
	first := writeUntilDelta(t, run, out, path, func(i int) string {
		return fmt.Sprintf("low 000\nhigh 007\nmax %03d\noom 001\noom_kill 001\n", 4+i)
	})
	if first.Delta.Max == 0 || first.Delta.High != 0 || first.Delta.OOMKill != 0 {
		t.Fatalf("first delta = %+v, want only a max increment", first.Delta)
	}

	// 2. Unit di-restart: berkas dihapus lalu dibuat ulang dengan seluruh counter dimulai dari 0
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
	time.Sleep(30 * time.Millisecond)
	writeFixture(t, path, paddedZeroEvents)
	expectRearm(t, rearms, testCgroup)

	// Delta yang masih tertahan hanya boleh berasal dari berkas lama (high 7), bukan dari reset counter
	for _, d := range drainDeltas(out) {
		if d.Current.High != 7 {
			t.Fatalf("delta %+v (current %+v) emitted for the counter reset", d.Delta, d.Current)
		}
	}

	// 3. Satu oom_kill pada berkas baru dilaporkan sebagai delta 1 terhadap baseline baru
	got := writeUntilDelta(t, run, out, path, func(int) string {
		return "low 000\nhigh 000\nmax 000\noom 000\noom_kill 001\n"
	})
	if got.Delta != (MemoryEvents{OOMKill: 1}) || got.Current != (MemoryEvents{OOMKill: 1}) {
		t.Fatalf("got delta=%+v current=%+v after re-arm, want delta and current of only oom_kill 1", got.Delta, got.Current)
	}

	if err := run.stop(t); err != nil {
		t.Errorf("WatchTarget returned %v after cancel, want nil", err)
	}
}
