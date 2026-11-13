package cgroup

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

const (
	// DefaultRearmBackoffInitial adalah jeda pertama sebelum watch memory.events dicoba dipasang ulang (250 ms).
	DefaultRearmBackoffInitial = 250 * time.Millisecond
	// DefaultRearmBackoffMax adalah batas atas jeda backoff pemasangan ulang watch (5 detik).
	DefaultRearmBackoffMax = 5 * time.Second
)

var (
	// ErrEventsFileNotFound dikembalikan jika berkas memory.events tidak ditemukan pada target cgroup.
	ErrEventsFileNotFound = errors.New("cgroup: memory.events file not found")
	// ErrWatchGone dikembalikan InotifyPoller (boleh dibungkus) ketika watch tidak lagi memantau berkas pada
	// targetPath: kernel mengirim IN_IGNORED/IN_DELETE_SELF/IN_UNMOUNT, atau path kini menunjuk inode lain
	// karena cgroup dihapus lalu dibuat ulang.
	ErrWatchGone = errors.New("cgroup: memory.events watch is gone")
)

// MemoryEvents menyimpan nilai counter kumulatif dari berkas memory.events cgroup v2.
type MemoryEvents struct {
	Low     uint64 `json:"low"`
	High    uint64 `json:"high"`
	Max     uint64 `json:"max"`
	OOM     uint64 `json:"oom"`
	OOMKill uint64 `json:"oom_kill"`
}

// EventsDelta merepresentasikan selisih kenaikan nilai counter memory.events antar-kejadian.
type EventsDelta struct {
	Cgroup     string       `json:"cgroup"`
	EventsPath string       `json:"events_path"`
	Current    MemoryEvents `json:"current"`
	Delta      MemoryEvents `json:"delta"`
	At         time.Time    `json:"at"`
}

// InotifyPoller mengabstraksikan notifikasi modifikasi berkas berbasis inotify (atau mock untuk test).
type InotifyPoller interface {
	// Watch memantau targetPath dan memanggil onChange setiap kali berkas perlu dibaca ulang. Watch kembali dengan
	// nil setelah ctx dibatalkan, dengan ErrWatchGone (boleh dibungkus) bila watch mati, atau dengan error lain
	// bila watch gagal dipasang.
	Watch(ctx context.Context, targetPath string, onChange func()) error
}

// EventsWatcherConfig menyimpan konfigurasi pemantauan berkas memory.events.
type EventsWatcherConfig struct {
	FS     kernelfs.FS
	Poller InotifyPoller
	// OnRearm (opsional) dipanggil secara sinkron dengan nama cgroup setiap kali watch berhasil dipasang ulang
	// dengan baseline baru, setelah watch sebelumnya mati atau memory.events gagal dibaca.
	OnRearm func(cgroup string)
	// RearmBackoffInitial adalah jeda pertama sebelum mencoba memasang ulang watch; nilai <= 0 memakai 250 ms.
	RearmBackoffInitial time.Duration
	// RearmBackoffMax adalah batas atas jeda yang digandakan setiap percobaan gagal; nilai <= 0 memakai 5 detik.
	RearmBackoffMax time.Duration
}

// EventsWatcher membaca delta memory.events dalam < 100 ms saat kernel memodifikasi berkas, dan memasang ulang
// watch ketika cgroup target dihapus lalu dibuat ulang (misalnya saat systemd me-restart unit).
type EventsWatcher struct {
	fs             kernelfs.FS
	poller         InotifyPoller
	onRearm        func(cgroup string)
	backoffInitial time.Duration
	backoffMax     time.Duration
	// sleep menunggu selama d dan mengembalikan false bila ctx dibatalkan lebih dulu; test dapat menggantinya
	// untuk memeriksa jadwal backoff tanpa menunggu waktu sungguhan.
	sleep func(ctx context.Context, d time.Duration) bool
}

// NewEventsWatcher membuat instance watcher baru untuk memory.events.
func NewEventsWatcher(cfg EventsWatcherConfig) *EventsWatcher {
	fsys := cfg.FS
	if fsys == nil {
		fsys = kernelfs.NewOSFS()
	}
	poller := cfg.Poller
	if poller == nil {
		poller = newOSInotifyPoller()
	}
	initial := cfg.RearmBackoffInitial
	if initial <= 0 {
		initial = DefaultRearmBackoffInitial
	}
	maxDelay := cfg.RearmBackoffMax
	if maxDelay <= 0 {
		maxDelay = DefaultRearmBackoffMax
	}
	if maxDelay < initial {
		maxDelay = initial
	}
	return &EventsWatcher{
		fs:             fsys,
		poller:         poller,
		onRearm:        cfg.OnRearm,
		backoffInitial: initial,
		backoffMax:     maxDelay,
		sleep:          sleepContext,
	}
}

// WatchTarget memantau berkas memory.events pada sebuah cgroup dan mengirimkan EventsDelta ke channel output.
//
// Watch yang mati (ErrWatchGone), kegagalan memasang watch (mis. ENOENT), dan kegagalan membaca memory.events
// (termasuk pembacaan pertama) tidak menghentikan WatchTarget: watcher menunggu dengan backoff eksponensial
// hingga memory.events terbaca lagi, lalu memasang ulang watch dengan baseline baru tanpa mengirim delta.
// WatchTarget hanya kembali, selalu dengan nil, setelah ctx dibatalkan.
func (w *EventsWatcher) WatchTarget(ctx context.Context, cgroup string, eventsPath string, out chan<- EventsDelta) error {
	backoff := newRearmBackoff(w.backoffInitial, w.backoffMax)
	// recovering bernilai true setelah pembacaan gagal atau watch yang sempat hidup berakhir, sehingga
	// pemasangan berikutnya dilaporkan sebagai re-arm.
	recovering := false

	for {
		if ctx.Err() != nil {
			return nil
		}

		baseline, err := w.readBaseline(eventsPath)
		if err != nil {
			recovering = true
			if !w.sleep(ctx, backoff.next()) {
				return nil
			}
			continue
		}
		if recovering {
			recovering = false
			if w.onRearm != nil {
				w.onRearm(cgroup)
			}
		}

		session := newWatchSession(ctx, w.fs, cgroup, eventsPath, out, baseline)
		watchErr := w.poller.Watch(session.ctx, eventsPath, session.handleChange)
		session.cancel()
		if ctx.Err() != nil {
			return nil
		}

		// Watch yang terbukti hidup (sempat mengirim notifikasi atau dilepas kernel) berarti arm sebelumnya
		// berhasil: backoff kembali ke jeda awal dan arm berikutnya dilaporkan lewat OnRearm. Watch yang gagal
		// dipasang (mis. batas instance inotify habis) terus menggandakan backoff tanpa memicu OnRearm berulang.
		if session.wasLive(watchErr) {
			backoff.reset()
			recovering = true
		}
		if !w.sleep(ctx, backoff.next()) {
			return nil
		}
	}
}

// readBaseline memastikan memory.events ada lalu membaca nilai counter terkininya sebagai baseline.
func (w *EventsWatcher) readBaseline(eventsPath string) (MemoryEvents, error) {
	if _, err := w.fs.Stat(eventsPath); err != nil {
		return MemoryEvents{}, err
	}
	return ReadMemoryEvents(w.fs, eventsPath)
}

// watchSession menyimpan baseline counter untuk satu kali pemasangan watch. Setiap re-arm membuat sesi baru,
// sehingga onChange basi dari sesi lama tidak dapat menimpa baseline sesi berikutnya.
type watchSession struct {
	ctx    context.Context
	cancel context.CancelFunc
	fs     kernelfs.FS
	cgroup string
	path   string
	out    chan<- EventsDelta

	mu   sync.Mutex
	last MemoryEvents

	// notified bernilai true setelah poller memanggil onChange, bukti bahwa watch sempat hidup.
	notified atomic.Bool
}

func newWatchSession(parent context.Context, fsys kernelfs.FS, cgroup, eventsPath string, out chan<- EventsDelta, baseline MemoryEvents) *watchSession {
	ctx, cancel := context.WithCancel(parent)
	return &watchSession{
		ctx:    ctx,
		cancel: cancel,
		fs:     fsys,
		cgroup: cgroup,
		path:   eventsPath,
		out:    out,
		last:   baseline,
	}
}

// handleChange membaca ulang memory.events dan mengirim EventsDelta bila ada counter yang bertambah.
func (s *watchSession) handleChange() {
	if s.ctx.Err() != nil {
		return
	}
	s.notified.Store(true)

	// Pembacaan dan pembaruan baseline berada di bawah lock yang sama agar notifikasi bersamaan tidak
	// menimpa baseline dengan hasil pembacaan yang lebih lama.
	s.mu.Lock()
	current, err := ReadMemoryEvents(s.fs, s.path)
	if err != nil {
		s.mu.Unlock()
		// Berkas hilang atau tidak terbaca (biasanya cgroup sedang dihapus): akhiri sesi agar WatchTarget
		// memasang ulang watch dan menetapkan baseline baru.
		s.cancel()
		return
	}
	delta, reset := computeDelta(s.last, current)
	s.last = current
	s.mu.Unlock()

	if reset || delta == (MemoryEvents{}) {
		return
	}
	select {
	case s.out <- EventsDelta{
		Cgroup:     s.cgroup,
		EventsPath: s.path,
		Current:    current,
		Delta:      delta,
		At:         time.Now(),
	}:
	case <-s.ctx.Done():
	}
}

// wasLive melaporkan apakah watch pada sesi ini terbukti sempat terpasang.
func (s *watchSession) wasLive(watchErr error) bool {
	return errors.Is(watchErr, ErrWatchGone) || s.notified.Load()
}

// ReadMemoryEvents mem-parsing berkas memory.events menjadi struktur MemoryEvents.
func ReadMemoryEvents(fsys kernelfs.FS, eventsPath string) (MemoryEvents, error) {
	kv, err := kernelfs.ReadKeyValueUint64(fsys, eventsPath)
	if err != nil {
		return MemoryEvents{}, err
	}
	return MemoryEvents{
		Low:     kv["low"],
		High:    kv["high"],
		Max:     kv["max"],
		OOM:     kv["oom"],
		OOMKill: kv["oom_kill"],
	}, nil
}

// computeDelta menghitung kenaikan counter dari prev ke current. Counter memory.events hanya naik selama cgroup
// hidup, sehingga satu counter saja yang lebih kecil dari baseline berarti cgroup dibuat ulang dan counter mulai
// lagi dari 0: hasilnya reset=true tanpa delta, dan pengurangan tidak pernah underflow.
func computeDelta(prev, current MemoryEvents) (delta MemoryEvents, reset bool) {
	if current.Low < prev.Low || current.High < prev.High || current.Max < prev.Max ||
		current.OOM < prev.OOM || current.OOMKill < prev.OOMKill {
		return MemoryEvents{}, true
	}
	return MemoryEvents{
		Low:     current.Low - prev.Low,
		High:    current.High - prev.High,
		Max:     current.Max - prev.Max,
		OOM:     current.OOM - prev.OOM,
		OOMKill: current.OOMKill - prev.OOMKill,
	}, false
}

// rearmBackoff menghasilkan jeda eksponensial antar-percobaan pemasangan ulang watch.
type rearmBackoff struct {
	initial time.Duration
	limit   time.Duration
	current time.Duration
}

func newRearmBackoff(initial, limit time.Duration) *rearmBackoff {
	return &rearmBackoff{initial: initial, limit: limit, current: initial}
}

// next mengembalikan jeda saat ini lalu menggandakannya, dibatasi limit.
func (b *rearmBackoff) next() time.Duration {
	d := b.current
	if b.current > b.limit/2 {
		b.current = b.limit
	} else {
		b.current *= 2
	}
	return d
}

// reset mengembalikan jeda ke nilai awal setelah watch terbukti berhasil dipasang.
func (b *rearmBackoff) reset() {
	b.current = b.initial
}

// sleepContext menunggu selama d dan mengembalikan false bila ctx dibatalkan lebih dulu.
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
