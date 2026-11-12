package psi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

const (
	// DefaultStallUs adalah ambang batas akumulasi stall default (150.000 mikrodetik = 150 ms).
	DefaultStallUs = 150000
	// DefaultWindowUs adalah ukuran jendela waktu pemantauan default (1.000.000 mikrodetik = 1 detik).
	DefaultWindowUs = 1000000
	// DefaultFallbackThresholdAvg10 adalah ambang batas avg10 (%) saat mode fallback polling 1 Hz aktif.
	DefaultFallbackThresholdAvg10 = 15.0
	// DefaultRediscoverDelay adalah jeda waktu re-discovery saat cgroup dihapus (POLLERR).
	DefaultRediscoverDelay = 5 * time.Second
	// DefaultFallbackPollInterval adalah interval pembacaan avg10 pada mode fallback (1 Hz).
	DefaultFallbackPollInterval = 1 * time.Second
)

var (
	// ErrCgroupGone dikembalikan ketika kernel mengirim sinyal POLLERR karena cgroup telah dihapus.
	ErrCgroupGone = errors.New("psi: target cgroup was removed (POLLERR)")
	// ErrTriggerUnsupported dikembalikan ketika penulisan trigger PSI ditolak kernel (EINVAL/EPERM).
	ErrTriggerUnsupported = errors.New("psi: kernel trigger registration rejected (EINVAL/EPERM)")
)

// Line merepresentasikan satu baris metrik tekanan PSI (some atau full).
type Line struct {
	Avg10  float64
	Avg60  float64
	Avg300 float64
	Total  uint64
}

// Metrics menyimpan pasangan metrik PSI "some" dan "full" dari berkas memory.pressure.
type Metrics struct {
	Some Line
	Full Line
}

// TriggerSpec mendefinisikan parameter pendaftaran trigger PSI ke kernel.
type TriggerSpec struct {
	Kind     string
	StallUs  int
	WindowUs int
}

// DefaultTriggerSpec mengembalikan konfigurasi trigger standar sesuai Requirement 1.1 ("some 150000 1000000").
func DefaultTriggerSpec() TriggerSpec {
	return TriggerSpec{
		Kind:     "some",
		StallUs:  DefaultStallUs,
		WindowUs: DefaultWindowUs,
	}
}

// String memformat spesifikasi trigger menjadi string perintah kernel "<some|full> <stall_us> <window_us>".
func (s TriggerSpec) String() string {
	kind := s.Kind
	if kind == "" {
		kind = "some"
	}
	stall := s.StallUs
	if stall <= 0 {
		stall = DefaultStallUs
	}
	window := s.WindowUs
	if window <= 0 {
		window = DefaultWindowUs
	}
	return fmt.Sprintf("%s %d %d", kind, stall, window)
}

// Bytes mengembalikan payload byte trigger yang siap ditulis ke file descriptor memory.pressure.
func (s TriggerSpec) Bytes() []byte {
	return []byte(s.String())
}

// PressureEvent merepresentasikan kejadian lonjakan tekanan memori yang terdeteksi oleh Watcher.
type PressureEvent struct {
	Cgroup       string
	PressurePath string
	Metrics      Metrics
	DegradedMode bool
	At           time.Time
}

// TriggerPoller adalah abstraksi untuk memantau file descriptor PSI via poll(POLLPRI) atau mock pengujian.
type TriggerPoller interface {
	// Watch mendaftarkan trigger PSI pada pressurePath dan memanggil onEvent setiap kali POLLPRI aktif.
	Watch(ctx context.Context, pressurePath string, spec TriggerSpec, onEvent func()) error
}

// WatcherConfig menyimpan konfigurasi operasional untuk Watcher PSI.
type WatcherConfig struct {
	FS                     kernelfs.FS
	Poller                 TriggerPoller
	Spec                   TriggerSpec
	FallbackPollInterval   time.Duration
	FallbackThresholdAvg10 float64
	RediscoverDelay        time.Duration
	OnDegradedAlert        func(cgroup string, reason error)
}

// Watcher mengelola pemantauan PSI berbasis event (POLLPRI) beserta mekanisme fallback 1 Hz dan re-discovery.
type Watcher struct {
	cfg          WatcherConfig
	degraded     atomic.Bool
	alertedMu    sync.Mutex
	alertedNodes map[string]bool
}

// NewWatcher membuat instance Watcher baru dengan nilai default yang aman jika belum diisi.
func NewWatcher(cfg WatcherConfig) *Watcher {
	if cfg.FS == nil {
		cfg.FS = kernelfs.NewOSFS()
	}
	if cfg.Poller == nil {
		cfg.Poller = newOSTriggerPoller()
	}
	if cfg.Spec.StallUs <= 0 || cfg.Spec.WindowUs <= 0 {
		cfg.Spec = DefaultTriggerSpec()
	}
	if cfg.FallbackPollInterval <= 0 {
		cfg.FallbackPollInterval = DefaultFallbackPollInterval
	}
	if cfg.FallbackThresholdAvg10 <= 0 {
		cfg.FallbackThresholdAvg10 = DefaultFallbackThresholdAvg10
	}
	if cfg.RediscoverDelay <= 0 {
		cfg.RediscoverDelay = DefaultRediscoverDelay
	}
	return &Watcher{
		cfg:          cfg,
		alertedNodes: make(map[string]bool),
	}
}

// IsDegraded mengembalikan true apabila minimal satu target terpaksa berjalan dalam mode fallback 1 Hz.
func (w *Watcher) IsDegraded() bool {
	return w.degraded.Load()
}

// WatchTarget memantau berkas memory.pressure untuk satu cgroup atau host (/proc/pressure/memory).
// Menangani POLLERR dengan menunggu RediscoverDelay (5 detik) dan menangani EINVAL/EPERM dengan fallback polling 1 Hz.
func (w *Watcher) WatchTarget(ctx context.Context, cgroup string, pressurePath string, out chan<- PressureEvent) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		// Pastikan berkas pressure tersedia sebelum memasang watcher
		if _, err := w.cfg.FS.Stat(pressurePath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if !sleepContext(ctx, w.cfg.RediscoverDelay) {
					return nil
				}
				continue
			}
			return fmt.Errorf("stat pressure file %s: %w", pressurePath, err)
		}

		err := w.cfg.Poller.Watch(ctx, pressurePath, w.cfg.Spec, func() {
			metrics, readErr := ReadMetrics(w.cfg.FS, pressurePath)
			if readErr != nil {
				// Tetap kirim event meskipun pembacaan detail metrik gagal sesaat
				metrics = Metrics{}
			}
			emitEvent(ctx, out, PressureEvent{
				Cgroup:       cgroup,
				PressurePath: pressurePath,
				Metrics:      metrics,
				DegradedMode: false,
				At:           time.Now(),
			})
		})

		if ctx.Err() != nil || err == nil {
			return nil
		}

		// Jika cgroup dihapus (POLLERR), tutup watcher saat ini dan coba re-discover setelah 5 detik
		if errors.Is(err, ErrCgroupGone) {
			if !sleepContext(ctx, w.cfg.RediscoverDelay) {
				return nil
			}
			continue
		}

		// Jika pendaftaran trigger gagal karena EINVAL/EPERM, beralih ke fallback polling 1 Hz avg10
		if errors.Is(err, ErrTriggerUnsupported) {
			w.markDegradedAndAlertOnce(cgroup, err)
			if fbErr := w.runFallbackPolling(ctx, cgroup, pressurePath, out); fbErr != nil {
				if errors.Is(fbErr, ErrCgroupGone) {
					if !sleepContext(ctx, w.cfg.RediscoverDelay) {
						return nil
					}
					continue
				}
				return fbErr
			}
			return nil
		}

		return fmt.Errorf("watch psi on %s: %w", pressurePath, err)
	}
}

// markDegradedAndAlertOnce menandai status capability degraded dan memanggil callback alert tepat satu kali per target.
func (w *Watcher) markDegradedAndAlertOnce(cgroup string, reason error) {
	w.degraded.Store(true)
	if w.cfg.OnDegradedAlert == nil {
		return
	}
	w.alertedMu.Lock()
	alreadyAlerted := w.alertedNodes[cgroup]
	if !alreadyAlerted {
		w.alertedNodes[cgroup] = true
	}
	w.alertedMu.Unlock()

	if !alreadyAlerted {
		w.cfg.OnDegradedAlert(cgroup, reason)
	}
}

// runFallbackPolling memantau nilai avg10 pada interval 1 Hz ketika trigger POLLPRI tidak didukung.
func (w *Watcher) runFallbackPolling(ctx context.Context, cgroup string, pressurePath string, out chan<- PressureEvent) error {
	ticker := time.NewTicker(w.cfg.FallbackPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			metrics, err := ReadMetrics(w.cfg.FS, pressurePath)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return ErrCgroupGone
				}
				return fmt.Errorf("fallback read psi %s: %w", pressurePath, err)
			}
			if metrics.Some.Avg10 >= w.cfg.FallbackThresholdAvg10 || metrics.Full.Avg10 > 0 {
				emitEvent(ctx, out, PressureEvent{
					Cgroup:       cgroup,
					PressurePath: pressurePath,
					Metrics:      metrics,
					DegradedMode: true,
					At:           time.Now(),
				})
			}
		}
	}
}

// emitEvent mengirim PressureEvent ke channel output secara aman terhadap pembatalan context.
func emitEvent(ctx context.Context, out chan<- PressureEvent, evt PressureEvent) {
	select {
	case out <- evt:
	case <-ctx.Done():
	}
}

// sleepContext menunggu selama durasi d atau berhenti lebih awal jika context dibatalkan.
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

// ReadMetrics membaca dan mem-parsing berkas memory.pressure melalui abstraksi kernelfs.FS.
func ReadMetrics(fsys kernelfs.FS, pressurePath string) (Metrics, error) {
	raw, err := fsys.ReadFile(pressurePath)
	if err != nil {
		return Metrics{}, err
	}
	return ParseMetrics(string(raw))
}

// ParseMetrics mem-parsing teks keluaran standar PSI ("some avg10=... avg60=... avg300=... total=...").
func ParseMetrics(content string) (Metrics, error) {
	var m Metrics
	var hasSome bool

	lines := strings.Split(strings.TrimSpace(content), "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return Metrics{}, fmt.Errorf("malformed psi line: %q", line)
		}

		kind := fields[0]
		parsedLine, err := parsePSIFields(fields[1:])
		if err != nil {
			return Metrics{}, fmt.Errorf("parse psi %q line: %w", kind, err)
		}

		switch kind {
		case "some":
			m.Some = parsedLine
			hasSome = true
		case "full":
			m.Full = parsedLine
		default:
			return Metrics{}, fmt.Errorf("unknown psi line kind %q", kind)
		}
	}

	if !hasSome {
		return Metrics{}, errors.New("missing 'some' line in psi metrics")
	}
	return m, nil
}

// parsePSIFields mem-parsing pasangan key=value pada satu baris PSI.
func parsePSIFields(fields []string) (Line, error) {
	var out Line
	for _, kv := range fields {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return Line{}, fmt.Errorf("invalid token %q", kv)
		}
		key, valStr := parts[0], parts[1]
		switch key {
		case "avg10":
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				return Line{}, fmt.Errorf("parse avg10: %w", err)
			}
			out.Avg10 = v
		case "avg60":
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				return Line{}, fmt.Errorf("parse avg60: %w", err)
			}
			out.Avg60 = v
		case "avg300":
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				return Line{}, fmt.Errorf("parse avg300: %w", err)
			}
			out.Avg300 = v
		case "total":
			v, err := strconv.ParseUint(valStr, 10, 64)
			if err != nil {
				return Line{}, fmt.Errorf("parse total: %w", err)
			}
			out.Total = v
		}
	}
	return out, nil
}

