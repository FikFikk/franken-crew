package cgroup

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

const (
	testCgroup     = "/franken.slice/haunted-api.service"
	testEventsPath = "/sys/fs/cgroup/franken.slice/haunted-api.service/memory.events"
	// Backoff pendek agar skenario re-arm dengan poller palsu selesai dalam hitungan milidetik.
	testBackoffInitial = time.Millisecond
	testBackoffMax     = 4 * time.Millisecond
	testWaitTimeout    = 2 * time.Second
	zeroEvents         = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n"
)

// scriptedArm merepresentasikan satu pemanggilan Watch yang sedang aktif pada scriptedPoller.
type scriptedArm struct {
	path     string
	onChange func()
	gone     chan struct{}
}

// end membuat Watch terkait kembali dengan ErrWatchGone, seperti kernel yang melepas watch (IN_IGNORED).
func (a *scriptedArm) end() { close(a.gone) }

// scriptedPoller adalah InotifyPoller palsu: setiap Watch diserahkan ke test lewat channel arms, lalu memblokir
// hingga ctx dibatalkan (nil) atau test memanggil end (ErrWatchGone).
type scriptedPoller struct {
	arms   chan *scriptedArm
	active atomic.Int32
}

func newScriptedPoller() *scriptedPoller {
	return &scriptedPoller{arms: make(chan *scriptedArm)}
}

func (p *scriptedPoller) Watch(ctx context.Context, targetPath string, onChange func()) error {
	p.active.Add(1)
	defer p.active.Add(-1)

	arm := &scriptedArm{path: targetPath, onChange: onChange, gone: make(chan struct{})}
	select {
	case p.arms <- arm:
	case <-ctx.Done():
		return nil
	}
	select {
	case <-ctx.Done():
		return nil
	case <-arm.gone:
		return ErrWatchGone
	}
}

// failingPoller menyimulasikan watch yang tidak pernah berhasil dipasang (mis. batas instance inotify habis).
type failingPoller struct {
	err   error
	calls atomic.Int32
}

func (p *failingPoller) Watch(context.Context, string, func()) error {
	p.calls.Add(1)
	return p.err
}

// probeFS membungkus MemFS untuk menghitung pembacaan memory.events, sehingga test dapat memastikan watcher
// terus mencoba ulang alih-alih menyerah.
type probeFS struct {
	*kernelfs.MemFS
	reads    atomic.Int32 // jumlah ReadFile, berhasil maupun gagal
	failures atomic.Int32 // jumlah Stat/ReadFile yang gagal
}

func newProbeFS() *probeFS {
	return &probeFS{MemFS: kernelfs.NewMemFS()}
}

func (p *probeFS) Stat(filePath string) (fs.FileInfo, error) {
	info, err := p.MemFS.Stat(filePath)
	if err != nil {
		p.failures.Add(1)
	}
	return info, err
}

func (p *probeFS) ReadFile(filePath string) ([]byte, error) {
	p.reads.Add(1)
	data, err := p.MemFS.ReadFile(filePath)
	if err != nil {
		p.failures.Add(1)
	}
	return data, err
}

// watchRun melacak satu WatchTarget yang berjalan di goroutine terpisah.
type watchRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error // hanya valid setelah done ditutup
}

// startWatch menjalankan WatchTarget di goroutine terpisah; cleanup memastikan goroutine tersebut selalu berhenti.
func startWatch(t *testing.T, w *EventsWatcher, cgroup, eventsPath string, out chan<- EventsDelta) *watchRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	run := &watchRun{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(run.done)
		run.err = w.WatchTarget(ctx, cgroup, eventsPath, out)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-run.done:
		case <-time.After(testWaitTimeout):
			t.Errorf("WatchTarget did not return within %v after its context was cancelled", testWaitTimeout)
		}
	})
	return run
}

// stop membatalkan ctx, menunggu WatchTarget kembali, lalu mengembalikan error-nya.
func (r *watchRun) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case <-r.done:
		return r.err
	case <-time.After(testWaitTimeout):
		t.Fatalf("WatchTarget did not return within %v after its context was cancelled", testWaitTimeout)
		return nil
	}
}

// nextArm menunggu pemanggilan Watch berikutnya dan gagal dengan pesan jelas bila WatchTarget keluar lebih dulu.
func (r *watchRun) nextArm(t *testing.T, p *scriptedPoller, what string) *scriptedArm {
	t.Helper()
	select {
	case arm := <-p.arms:
		return arm
	case <-r.done:
		t.Fatalf("WatchTarget exited (err=%v) while waiting for %s", r.err, what)
	case <-time.After(testWaitTimeout):
		t.Fatalf("timed out after %v waiting for %s", testWaitTimeout, what)
	}
	return nil
}

// waitUntil mem-polling cond hingga terpenuhi; WatchTarget yang keluar lebih dulu dilaporkan sebagai kegagalan.
func (r *watchRun) waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testWaitTimeout)
	for !cond() {
		select {
		case <-r.done:
			t.Fatalf("WatchTarget exited (err=%v) while waiting for %s", r.err, what)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", testWaitTimeout, what)
		}
		time.Sleep(time.Millisecond)
	}
}

func expectRearm(t *testing.T, rearms <-chan string, want string) {
	t.Helper()
	select {
	case got := <-rearms:
		if got != want {
			t.Errorf("OnRearm called with cgroup %q, want %q", got, want)
		}
	case <-time.After(testWaitTimeout):
		t.Fatalf("OnRearm was not called within %v after the watch was re-armed", testWaitTimeout)
	}
}

func recvDelta(t *testing.T, out <-chan EventsDelta, what string) EventsDelta {
	t.Helper()
	select {
	case d := <-out:
		return d
	case <-time.After(testWaitTimeout):
		t.Fatalf("timed out after %v waiting for EventsDelta: %s", testWaitTimeout, what)
		return EventsDelta{}
	}
}

func assertNoDelta(t *testing.T, out <-chan EventsDelta, when string) {
	t.Helper()
	select {
	case d := <-out:
		t.Fatalf("unexpected EventsDelta %s: delta=%+v current=%+v", when, d.Delta, d.Current)
	case <-time.After(20 * time.Millisecond):
	}
}

// sleepRecorder menggantikan EventsWatcher.sleep: setiap jeda backoff dilaporkan ke test dan baru berakhir
// setelah test melepasnya, sehingga jadwal backoff dapat diperiksa tanpa menunggu waktu sungguhan.
type sleepRecorder struct {
	requests chan time.Duration
	release  chan struct{}
}

func newSleepRecorder(w *EventsWatcher) *sleepRecorder {
	r := &sleepRecorder{requests: make(chan time.Duration), release: make(chan struct{})}
	w.sleep = func(ctx context.Context, d time.Duration) bool {
		select {
		case r.requests <- d:
		case <-ctx.Done():
			return false
		}
		select {
		case <-r.release:
			return true
		case <-ctx.Done():
			return false
		}
	}
	return r
}

// await menunggu permintaan jeda berikutnya dan memeriksa durasinya. Watcher tetap tertahan di jeda itu hingga
// resume dipanggil, sehingga test dapat mengubah fixture tanpa balapan dengan percobaan berikutnya.
func (r *sleepRecorder) await(t *testing.T, run *watchRun, want time.Duration) {
	t.Helper()
	select {
	case got := <-r.requests:
		if got != want {
			t.Fatalf("backoff delay = %v, want %v", got, want)
		}
	case <-run.done:
		t.Fatalf("WatchTarget exited (err=%v) while waiting for a %v backoff", run.err, want)
	case <-time.After(testWaitTimeout):
		t.Fatalf("timed out after %v waiting for a %v backoff", testWaitTimeout, want)
	}
}

// resume melepas jeda yang sedang ditahan await.
func (r *sleepRecorder) resume(t *testing.T, run *watchRun) {
	t.Helper()
	select {
	case r.release <- struct{}{}:
	case <-run.done:
		t.Fatalf("WatchTarget exited (err=%v) during a backoff", run.err)
	case <-time.After(testWaitTimeout):
		t.Fatalf("timed out after %v releasing a backoff", testWaitTimeout)
	}
}

// expect memeriksa jeda berikutnya lalu langsung melepasnya.
func (r *sleepRecorder) expect(t *testing.T, run *watchRun, want time.Duration) {
	t.Helper()
	r.await(t, run, want)
	r.resume(t, run)
}

func TestEventsWatcher_RearmsAfterWatchGoneWhenCgroupIsRecreated(t *testing.T) {
	pfs := newProbeFS()
	// Total seumur hidup cgroup lama: tidak boleh pernah dilaporkan ulang setelah cgroup dibuat ulang
	pfs.SetFile(testEventsPath, "low 0\nhigh 7\nmax 3\noom 1\noom_kill 1\n")

	poller := newScriptedPoller()
	rearms := make(chan string, 4)
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:                  pfs,
		Poller:              poller,
		OnRearm:             func(cg string) { rearms <- cg },
		RearmBackoffInitial: testBackoffInitial,
		RearmBackoffMax:     testBackoffMax,
	})
	out := make(chan EventsDelta, 8)
	run := startWatch(t, w, testCgroup, testEventsPath, out)

	first := run.nextArm(t, poller, "the initial watch on memory.events")

	// systemd me-restart unit: direktori cgroup dihapus dan kernel melepas watch
	pfs.Remove(testEventsPath)
	first.end()

	run.waitUntil(t, "repeated attempts while memory.events is missing", func() bool {
		return pfs.failures.Load() >= 2
	})
	if n := len(rearms); n != 0 {
		t.Fatalf("OnRearm called %d times before memory.events existed again", n)
	}

	// cgroup dibuat ulang dengan seluruh counter dimulai lagi dari 0
	pfs.SetFile(testEventsPath, zeroEvents)
	second := run.nextArm(t, poller, "a re-arm after the cgroup was recreated")
	if second.path != testEventsPath {
		t.Errorf("re-armed watch on %q, want %q", second.path, testEventsPath)
	}
	expectRearm(t, rearms, testCgroup)

	// Notifikasi tanpa kenaikan counter tidak boleh melaporkan reset sebagai delta
	second.onChange()
	assertNoDelta(t, out, "after re-arming on counters that restarted at 0")

	// Satu oom_kill sungguhan pada cgroup baru dihitung terhadap baseline baru (0), bukan total cgroup lama
	pfs.SetFile(testEventsPath, "low 0\nhigh 0\nmax 0\noom 0\noom_kill 1\n")
	second.onChange()
	got := recvDelta(t, out, "the oom_kill increment on the recreated cgroup")
	if got.Delta != (MemoryEvents{OOMKill: 1}) {
		t.Errorf("delta = %+v, want only oom_kill 1", got.Delta)
	}
	if got.Current != (MemoryEvents{OOMKill: 1}) {
		t.Errorf("current = %+v, want only oom_kill 1", got.Current)
	}
	if got.Cgroup != testCgroup || got.EventsPath != testEventsPath {
		t.Errorf("delta labelled %q/%q, want %q/%q", got.Cgroup, got.EventsPath, testCgroup, testEventsPath)
	}
	assertNoDelta(t, out, "after the single oom_kill increment")

	if err := run.stop(t); err != nil {
		t.Errorf("WatchTarget returned %v after cancel, want nil", err)
	}
	if n := len(rearms); n != 0 {
		t.Errorf("OnRearm called %d extra times for a single re-arm", n)
	}
	if n := poller.active.Load(); n != 0 {
		t.Errorf("%d Watch calls still running after WatchTarget returned", n)
	}
}

func TestEventsWatcher_RearmRebaselinesEvenWhenNewCountersAreHigher(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	mfs.SetFile(testEventsPath, "low 0\nhigh 1\nmax 1\noom 0\noom_kill 0\n")
	poller := newScriptedPoller()
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:                  mfs,
		Poller:              poller,
		RearmBackoffInitial: testBackoffInitial,
		RearmBackoffMax:     testBackoffMax,
	})
	out := make(chan EventsDelta, 4)
	run := startWatch(t, w, testCgroup, testEventsPath, out)
	first := run.nextArm(t, poller, "the initial watch on memory.events")

	// cgroup baru sudah mencatat event sebelum watch dipasang ulang; semua counter >= baseline lama sehingga
	// deteksi reset tidak membantu, dan hanya baseline baru yang mencegah delta palsu.
	mfs.SetFile(testEventsPath, "low 0\nhigh 4\nmax 2\noom 1\noom_kill 1\n")
	first.end()
	second := run.nextArm(t, poller, "a re-arm after ErrWatchGone")

	second.onChange()
	assertNoDelta(t, out, "for counters that were already present when the watch was re-armed")

	mfs.SetFile(testEventsPath, "low 0\nhigh 4\nmax 2\noom 1\noom_kill 2\n")
	second.onChange()
	got := recvDelta(t, out, "the oom_kill increment after the re-arm")
	if got.Delta != (MemoryEvents{OOMKill: 1}) {
		t.Errorf("delta = %+v, want only oom_kill 1", got.Delta)
	}
}

func TestEventsWatcher_RecoversWhenInitialReadFails(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(p *probeFS)
		retried func(p *probeFS) bool
	}{
		{
			name:    "memory.events missing",
			setup:   func(*probeFS) {},
			retried: func(p *probeFS) bool { return p.failures.Load() >= 2 },
		},
		{
			name:    "memory.events malformed",
			setup:   func(p *probeFS) { p.SetFile(testEventsPath, "low 0\nhigh\n") },
			retried: func(p *probeFS) bool { return p.reads.Load() >= 2 },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pfs := newProbeFS()
			tc.setup(pfs)
			poller := newScriptedPoller()
			rearms := make(chan string, 4)
			w := NewEventsWatcher(EventsWatcherConfig{
				FS:                  pfs,
				Poller:              poller,
				OnRearm:             func(cg string) { rearms <- cg },
				RearmBackoffInitial: testBackoffInitial,
				RearmBackoffMax:     testBackoffMax,
			})
			out := make(chan EventsDelta, 4)
			run := startWatch(t, w, testCgroup, testEventsPath, out)

			run.waitUntil(t, "repeated attempts to read memory.events", func() bool { return tc.retried(pfs) })

			pfs.SetFile(testEventsPath, "low 0\nhigh 1\nmax 0\noom 0\noom_kill 0\n")
			arm := run.nextArm(t, poller, "a watch once memory.events became readable")
			expectRearm(t, rearms, testCgroup)

			pfs.SetFile(testEventsPath, "low 0\nhigh 2\nmax 0\noom 0\noom_kill 0\n")
			arm.onChange()
			got := recvDelta(t, out, "the memory.high increment after recovery")
			if got.Delta != (MemoryEvents{High: 1}) || got.Current != (MemoryEvents{High: 2}) {
				t.Errorf("got delta=%+v current=%+v, want delta high 1 and current high 2", got.Delta, got.Current)
			}
		})
	}
}

func TestEventsWatcher_ReadFailureDuringWatchRearms(t *testing.T) {
	pfs := newProbeFS()
	pfs.SetFile(testEventsPath, "low 0\nhigh 4\nmax 2\noom 0\noom_kill 0\n")
	poller := newScriptedPoller()
	rearms := make(chan string, 4)
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:                  pfs,
		Poller:              poller,
		OnRearm:             func(cg string) { rearms <- cg },
		RearmBackoffInitial: testBackoffInitial,
		RearmBackoffMax:     testBackoffMax,
	})
	out := make(chan EventsDelta, 4)
	run := startWatch(t, w, testCgroup, testEventsPath, out)

	first := run.nextArm(t, poller, "the initial watch on memory.events")

	// Kernel sempat mengirim IN_MODIFY saat cgroup dihapus, tetapi pembacaan ulang gagal karena berkas hilang
	pfs.Remove(testEventsPath)
	first.onChange()

	pfs.SetFile(testEventsPath, zeroEvents)
	run.nextArm(t, poller, "a re-arm after memory.events could not be re-read")
	expectRearm(t, rearms, testCgroup)
	assertNoDelta(t, out, "after re-arming on the recreated cgroup")
}

func TestEventsWatcher_CountersBelowBaselineNeverEmitDelta(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	mfs.SetFile(testEventsPath, "low 0\nhigh 5\nmax 3\noom 2\noom_kill 1\n")
	poller := newScriptedPoller()
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:                  mfs,
		Poller:              poller,
		RearmBackoffInitial: testBackoffInitial,
		RearmBackoffMax:     testBackoffMax,
	})
	out := make(chan EventsDelta, 4)
	run := startWatch(t, w, testCgroup, testEventsPath, out)
	arm := run.nextArm(t, poller, "the initial watch on memory.events")

	// high naik 4, tetapi max/oom/oom_kill turun: tanda cgroup dibuat ulang, bukan kenaikan sungguhan
	mfs.SetFile(testEventsPath, "low 0\nhigh 9\nmax 0\noom 0\noom_kill 0\n")
	arm.onChange()
	assertNoDelta(t, out, "when max, oom and oom_kill dropped below the baseline")

	// Kenaikan berikutnya dihitung dari baseline hasil reset (high 9, oom_kill 0)
	mfs.SetFile(testEventsPath, "low 0\nhigh 10\nmax 0\noom 0\noom_kill 1\n")
	arm.onChange()
	got := recvDelta(t, out, "increments after the counter reset")
	if got.Delta != (MemoryEvents{High: 1, OOMKill: 1}) {
		t.Errorf("delta = %+v, want high 1 and oom_kill 1", got.Delta)
	}
	if got.Current != (MemoryEvents{High: 10, OOMKill: 1}) {
		t.Errorf("current = %+v, want high 10 and oom_kill 1", got.Current)
	}
}

func TestComputeDelta(t *testing.T) {
	const maxCounter = ^uint64(0)
	cases := []struct {
		name      string
		prev, cur MemoryEvents
		want      MemoryEvents
		wantReset bool
	}{
		{
			name: "unchanged counters",
			prev: MemoryEvents{High: 2, Max: 1},
			cur:  MemoryEvents{High: 2, Max: 1},
		},
		{
			name: "every counter increments",
			prev: MemoryEvents{Low: 1, High: 2, Max: 3, OOM: 4, OOMKill: 5},
			cur:  MemoryEvents{Low: 2, High: 4, Max: 6, OOM: 8, OOMKill: 10},
			want: MemoryEvents{Low: 1, High: 2, Max: 3, OOM: 4, OOMKill: 5},
		},
		{
			name:      "one counter below baseline is a reset",
			prev:      MemoryEvents{Max: 3, OOMKill: 1},
			cur:       MemoryEvents{Max: 4, OOMKill: 0},
			wantReset: true,
		},
		{
			name:      "recreated cgroup restarts at zero",
			prev:      MemoryEvents{High: 7, Max: 3, OOM: 1, OOMKill: 1},
			cur:       MemoryEvents{},
			wantReset: true,
		},
		{
			name:      "huge baseline never underflows",
			prev:      MemoryEvents{Low: maxCounter},
			cur:       MemoryEvents{Low: 0, OOMKill: 1},
			wantReset: true,
		},
		{
			name: "increment at the top of the counter range",
			prev: MemoryEvents{High: maxCounter - 1},
			cur:  MemoryEvents{High: maxCounter},
			want: MemoryEvents{High: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reset := computeDelta(tc.prev, tc.cur)
			if got != tc.want || reset != tc.wantReset {
				t.Errorf("computeDelta(%+v, %+v) = %+v, reset=%t; want %+v, reset=%t",
					tc.prev, tc.cur, got, reset, tc.want, tc.wantReset)
			}
		})
	}
}

func TestEventsWatcher_CancelDuringBackoffReturnsPromptly(t *testing.T) {
	pfs := newProbeFS() // memory.events belum ada sehingga watcher langsung masuk jeda backoff
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:                  pfs,
		Poller:              newScriptedPoller(),
		RearmBackoffInitial: 10 * time.Second,
		RearmBackoffMax:     10 * time.Second,
	})
	run := startWatch(t, w, testCgroup, testEventsPath, make(chan EventsDelta, 1))

	run.waitUntil(t, "the first failed read of memory.events", func() bool { return pfs.failures.Load() >= 1 })
	time.Sleep(20 * time.Millisecond)
	select {
	case <-run.done:
		t.Fatalf("WatchTarget exited (err=%v) before its context was cancelled", run.err)
	default:
	}

	start := time.Now()
	err := run.stop(t)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("WatchTarget took %v to return after cancel during a 10s backoff, want < 200ms", elapsed)
	}
	if err != nil {
		t.Errorf("WatchTarget returned %v after cancel, want nil", err)
	}
}

func TestEventsWatcher_LeavesNoGoroutineBehind(t *testing.T) {
	before := runtime.NumGoroutine()

	mfs := kernelfs.NewMemFS()
	mfs.SetFile(testEventsPath, zeroEvents)
	poller := newScriptedPoller()
	// OnRearm sengaja nil: re-arm di bawah sekaligus membuktikan callback tersebut opsional
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:                  mfs,
		Poller:              poller,
		RearmBackoffInitial: testBackoffInitial,
		RearmBackoffMax:     testBackoffMax,
	})
	out := make(chan EventsDelta) // tanpa pembaca: pengiriman delta akan memblokir
	run := startWatch(t, w, testCgroup, testEventsPath, out)

	run.nextArm(t, poller, "the initial watch on memory.events").end()
	second := run.nextArm(t, poller, "a re-arm after ErrWatchGone")

	mfs.SetFile(testEventsPath, "low 0\nhigh 0\nmax 1\noom 0\noom_kill 0\n")
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		second.onChange() // memblokir pada channel out hingga ctx dibatalkan
	}()
	time.Sleep(10 * time.Millisecond)

	if err := run.stop(t); err != nil {
		t.Errorf("WatchTarget returned %v after cancel, want nil", err)
	}
	select {
	case <-handlerDone:
	case <-time.After(testWaitTimeout):
		t.Fatalf("onChange stayed blocked on the output channel after the context was cancelled")
	}
	if n := poller.active.Load(); n != 0 {
		t.Errorf("%d Watch calls still running after WatchTarget returned", n)
	}

	deadline := time.Now().Add(testWaitTimeout)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: %d goroutines before WatchTarget, %d after it returned", before, runtime.NumGoroutine())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEventsWatcher_BackoffDoublesWhileMissingAndRestartsAfterRearm(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	mfs.SetFile(testEventsPath, zeroEvents)
	poller := newScriptedPoller()
	w := NewEventsWatcher(EventsWatcherConfig{FS: mfs, Poller: poller}) // backoff default
	sleeps := newSleepRecorder(w)
	run := startWatch(t, w, testCgroup, testEventsPath, make(chan EventsDelta, 1))

	first := run.nextArm(t, poller, "the initial watch on memory.events")
	mfs.Remove(testEventsPath)
	first.end()

	// Jeda dimulai dari 250 ms lalu digandakan selama memory.events masih hilang, dibatasi 5 detik
	for _, want := range []time.Duration{
		250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second,
	} {
		sleeps.expect(t, run, want)
	}
	// memory.events muncul kembali selagi watcher tertahan di jeda 5 detik berikutnya
	sleeps.await(t, run, 5*time.Second)
	mfs.SetFile(testEventsPath, zeroEvents)
	sleeps.resume(t, run)
	second := run.nextArm(t, poller, "a re-arm after memory.events reappeared")

	// Setelah re-arm berhasil, kegagalan berikutnya kembali menunggu 250 ms, bukan melanjutkan dari 5 detik
	second.end()
	sleeps.expect(t, run, 250*time.Millisecond)
}

func TestEventsWatcher_WatchThatNeverArmsKeepsBackingOffWithoutOnRearm(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	mfs.SetFile(testEventsPath, zeroEvents)
	poller := &failingPoller{err: errors.New("inotify_init1: too many open files")}
	var rearms atomic.Int32
	w := NewEventsWatcher(EventsWatcherConfig{
		FS:      mfs,
		Poller:  poller,
		OnRearm: func(string) { rearms.Add(1) },
	})
	sleeps := newSleepRecorder(w)
	run := startWatch(t, w, testCgroup, testEventsPath, make(chan EventsDelta, 1))

	// memory.events selalu terbaca, tetapi watch tidak pernah terpasang: jeda terus digandakan, tidak direset
	for _, want := range []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second} {
		sleeps.expect(t, run, want)
	}
	if n := rearms.Load(); n != 0 {
		t.Errorf("OnRearm called %d times although the watch never armed", n)
	}
	if n := poller.calls.Load(); n < 4 {
		t.Errorf("Watch attempted %d times, want at least 4", n)
	}
}
