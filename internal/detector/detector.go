package detector

import (
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	// DefaultAlpha adalah bobot peluruhan EWMA standar sesuai spesifikasi desain (0.3).
	DefaultAlpha = 0.3
	// DefaultHostReserveBytes adalah cadangan RAM host (64 MiB) saat cgroup tidak memiliki batas memory.max.
	DefaultHostReserveBytes uint64 = 64 * 1024 * 1024
	// MinSlopeBytesPerSec adalah batas bawah penyebut slope (1 KiB/s) untuk perhitungan TTO.
	MinSlopeBytesPerSec = 1024.0

	// Ambang batas klasifikasi severity sesuai Requirement 2 dan Blueprint A.4.
	DefaultP1TTOSeconds       = 30.0
	DefaultP2TTOSeconds       = 120.0
	DefaultP3TTOSeconds       = 300.0
	DefaultP2PSISomeAvg10     = 25.0
	DefaultP2PSIFullAvg10     = 5.0
	DefaultP3PSISomeAvg10     = 10.0
	DefaultP3SustainDuration  = 30 * time.Second
	DefaultHysteresisDuration = 120 * time.Second
	DefaultDebounceDuration   = 5 * time.Minute
)

// Severity merepresentasikan tingkat keparahan insiden memori.
type Severity string

const (
	SeverityNone    Severity = "NONE"
	SeverityP3      Severity = "P3"
	SeverityP2      Severity = "P2"
	SeverityP1      Severity = "P1"
	SeverityPostOOM Severity = "POST_OOM"
)

// Rank mengembalikan urutan numerik tingkat keparahan untuk perbandingan eskalasi.
func (s Severity) Rank() int {
	switch s {
	case SeverityPostOOM:
		return 4
	case SeverityP1:
		return 3
	case SeverityP2:
		return 2
	case SeverityP3:
		return 1
	default:
		return 0
	}
}

// MemoryEvents menyimpan nilai kumulatif counter dari berkas cgroup memory.events.
type MemoryEvents struct {
	Low     uint64
	High    uint64
	Max     uint64
	OOM     uint64
	OOMKill uint64
}

// Sample merepresentasikan satu titik pembacaan telemetri memori untuk sebuah cgroup.
type Sample struct {
	Cgroup        string
	MemoryCurrent uint64
	MemoryMax     uint64 // 0 menandakan "max" (tidak dibatasi pada level cgroup)
	PSISomeAvg10  float64
	PSIFullAvg10  float64
	Events        MemoryEvents
	At            time.Time
}

// Evaluation merepresentasikan hasil analisis Detector untuk satu sampel cgroup.
type Evaluation struct {
	Cgroup         string
	Severity       Severity
	RawSeverity    Severity
	SlopeBytesPerS float64
	TTOSeconds     *float64
	LimitBytes     uint64
	IncidentOpen   bool
	IncidentClosed bool
	Reopened       bool
	IncidentID     string
	At             time.Time
}

// Config menyimpan parameter kerja Detector.
type Config struct {
	NodeName           string
	HostMemTotalBytes  uint64
	HostReserveBytes   uint64
	Alpha              float64
	HysteresisDuration time.Duration
	DebounceDuration   time.Duration
	P3SustainDuration  time.Duration
}

// cgroupState menyimpan histori telemetri dan status insiden per cgroup.
type cgroupState struct {
	initialized    bool
	lastBytes      uint64
	lastAt         time.Time
	hasSlope       bool
	ewmaSlope      float64
	lastEvents     MemoryEvents
	p3SomeSince    time.Time
	incidentOpen   bool
	activeSeverity Severity
	activeID       string
	healthySince   time.Time
	lastClosedAt   time.Time
	lastClosedID   string
}

// Detector menghitung EWMA slope, memprediksi Time-To-OOM (TTO), serta mengelola klasifikasi severity, hysteresis, dan debounce.
type Detector struct {
	mu     sync.Mutex
	cfg    Config
	states map[string]*cgroupState
	seq    uint64
}

// NewDetector membuat instance Detector baru dengan konfigurasi yang telah divalidasi.
func NewDetector(cfg Config) *Detector {
	if cfg.NodeName == "" {
		cfg.NodeName = "node01"
	}
	if cfg.HostReserveBytes == 0 {
		cfg.HostReserveBytes = DefaultHostReserveBytes
	}
	if cfg.Alpha <= 0 || cfg.Alpha > 1.0 {
		cfg.Alpha = DefaultAlpha
	}
	if cfg.HysteresisDuration <= 0 {
		cfg.HysteresisDuration = DefaultHysteresisDuration
	}
	if cfg.DebounceDuration <= 0 {
		cfg.DebounceDuration = DefaultDebounceDuration
	}
	if cfg.P3SustainDuration <= 0 {
		cfg.P3SustainDuration = DefaultP3SustainDuration
	}
	return &Detector{
		cfg:    cfg,
		states: make(map[string]*cgroupState),
	}
}

// Evaluate memproses satu sampel telemetri cgroup dan mengembalikan hasil deteksi terbaru.
func (d *Detector) Evaluate(s Sample) Evaluation {
	d.mu.Lock()
	defer d.mu.Unlock()

	if s.At.IsZero() {
		s.At = time.Now()
	}

	st, exists := d.states[s.Cgroup]
	if !exists {
		st = &cgroupState{}
		d.states[s.Cgroup] = st
	}

	var deltaMax, deltaOOM, deltaOOMKill uint64
	if !st.initialized {
		st.initialized = true
		st.lastBytes = s.MemoryCurrent
		st.lastAt = s.At
		st.lastEvents = s.Events
	} else {
		dt := s.At.Sub(st.lastAt).Seconds()
		if dt > 0 {
			diffBytes := float64(s.MemoryCurrent) - float64(st.lastBytes)
			instSlope := diffBytes / dt
			if !st.hasSlope {
				st.ewmaSlope = instSlope
				st.hasSlope = true
			} else {
				st.ewmaSlope = d.cfg.Alpha*instSlope + (1.0-d.cfg.Alpha)*st.ewmaSlope
			}
			st.lastBytes = s.MemoryCurrent
			st.lastAt = s.At
		}

		if s.Events.Max > st.lastEvents.Max {
			deltaMax = s.Events.Max - st.lastEvents.Max
		}
		if s.Events.OOM > st.lastEvents.OOM {
			deltaOOM = s.Events.OOM - st.lastEvents.OOM
		}
		if s.Events.OOMKill > st.lastEvents.OOMKill {
			deltaOOMKill = s.Events.OOMKill - st.lastEvents.OOMKill
		}
		st.lastEvents = s.Events
	}

	limit := d.effectiveLimit(s.MemoryMax)
	tto := computeTTO(s.MemoryCurrent, limit, st.hasSlope, st.ewmaSlope)

	// Lacak durasi PSI some avg10 >= 10% untuk klasifikasi P3
	if s.PSISomeAvg10 >= DefaultP3PSISomeAvg10 {
		if st.p3SomeSince.IsZero() {
			st.p3SomeSince = s.At
		}
	} else {
		st.p3SomeSince = time.Time{}
	}
	p3Sustained := !st.p3SomeSince.IsZero() && s.At.Sub(st.p3SomeSince) >= d.cfg.P3SustainDuration

	rawSeverity := classifyRawSeverity(tto, s.PSISomeAvg10, s.PSIFullAvg10, p3Sustained, deltaMax, deltaOOM, deltaOOMKill)

	eval := Evaluation{
		Cgroup:         s.Cgroup,
		Severity:       rawSeverity,
		RawSeverity:    rawSeverity,
		SlopeBytesPerS: st.ewmaSlope,
		TTOSeconds:     tto,
		LimitBytes:     limit,
		At:             s.At,
	}

	// Kelola siklus hidup insiden (P2, P1, POST_OOM) beserta hysteresis dan debounce
	if !st.incidentOpen {
		if rawSeverity.Rank() >= SeverityP2.Rank() {
			st.incidentOpen = true
			st.activeSeverity = rawSeverity
			st.healthySince = time.Time{}

			if !st.lastClosedAt.IsZero() && s.At.Sub(st.lastClosedAt) < d.cfg.DebounceDuration && st.lastClosedID != "" {
				// Debounce aktif: gunakan kembali ID insiden sebelumnya
				st.activeID = st.lastClosedID
				eval.Reopened = true
			} else {
				st.activeID = d.nextIncidentID(s.At)
				eval.Reopened = false
			}
			eval.IncidentOpen = true
			eval.IncidentID = st.activeID
			eval.Severity = st.activeSeverity
		}
		return eval
	}

	// Insiden sedang aktif: periksa eskalasi severity
	if rawSeverity.Rank() > st.activeSeverity.Rank() {
		st.activeSeverity = rawSeverity
	}

	// Periksa apakah syarat pemulihan setengah ambang batas (half-threshold) terpenuhi
	if isHalfThresholdHealthy(tto, s.PSISomeAvg10, s.PSIFullAvg10, deltaMax, deltaOOM, deltaOOMKill) {
		if st.healthySince.IsZero() {
			st.healthySince = s.At
		}
		if s.At.Sub(st.healthySince) >= d.cfg.HysteresisDuration {
			// Hysteresis 120 detik terpenuhi: tutup insiden
			closedID := st.activeID
			st.incidentOpen = false
			st.activeSeverity = SeverityNone
			st.activeID = ""
			st.healthySince = time.Time{}
			st.lastClosedAt = s.At
			st.lastClosedID = closedID

			eval.Severity = SeverityNone
			eval.IncidentOpen = false
			eval.IncidentClosed = true
			eval.IncidentID = closedID
			return eval
		}
	} else {
		// Tekanan kembali naik sebelum jendela hysteresis selesai: reset timer pemulihan
		st.healthySince = time.Time{}
	}

	eval.Severity = st.activeSeverity
	eval.IncidentOpen = true
	eval.IncidentID = st.activeID
	return eval
}

// effectiveLimit menentukan batas memori efektif dari memory.max cgroup atau MemTotal host dikurangi cadangan.
func (d *Detector) effectiveLimit(cgroupMax uint64) uint64 {
	if cgroupMax > 0 {
		return cgroupMax
	}
	if d.cfg.HostMemTotalBytes > d.cfg.HostReserveBytes {
		return d.cfg.HostMemTotalBytes - d.cfg.HostReserveBytes
	}
	return d.cfg.HostMemTotalBytes
}

// nextIncidentID menghasilkan ID insiden berformat INC-<yyyymmdd>-<hhmm>-<node>.
func (d *Detector) nextIncidentID(at time.Time) string {
	d.seq++
	utc := at.UTC()
	base := fmt.Sprintf("INC-%s-%s-%s", utc.Format("20060102"), utc.Format("1504"), d.cfg.NodeName)
	if d.seq == 1 {
		return base
	}
	return fmt.Sprintf("%s-%02d", base, d.seq)
}

// computeTTO menghitung prediksi waktu menuju OOM dalam satuan detik; mengembalikan nil jika slope <= 0.
func computeTTO(currentBytes, limitBytes uint64, hasSlope bool, ewmaSlope float64) *float64 {
	if !hasSlope || ewmaSlope <= 0 || limitBytes == 0 {
		return nil
	}
	if currentBytes >= limitBytes {
		zero := 0.0
		return &zero
	}
	denom := math.Max(ewmaSlope, MinSlopeBytesPerSec)
	tto := float64(limitBytes-currentBytes) / denom
	return &tto
}

// classifyRawSeverity mengklasifikasikan tingkat keparahan seketika berdasarkan TTO, PSI, dan delta memory.events.
func classifyRawSeverity(
	tto *float64,
	psiSomeAvg10 float64,
	psiFullAvg10 float64,
	p3Sustained bool,
	deltaMax uint64,
	deltaOOM uint64,
	deltaOOMKill uint64,
) Severity {
	// Requirement 2.4: kenaikan oom_kill langsung memicu POST_OOM
	if deltaOOMKill > 0 {
		return SeverityPostOOM
	}
	// Requirement 2.3: TTO < 30 detik atau kenaikan counter max/oom memicu P1
	if (tto != nil && *tto < DefaultP1TTOSeconds) || deltaMax > 0 || deltaOOM > 0 {
		return SeverityP1
	}
	// Requirement 2.2: TTO < 120 detik atau PSI some >= 25 atau PSI full >= 5 memicu P2
	if (tto != nil && *tto < DefaultP2TTOSeconds) || psiSomeAvg10 >= DefaultP2PSISomeAvg10 || psiFullAvg10 >= DefaultP2PSIFullAvg10 {
		return SeverityP2
	}
	// Blueprint A.4: TTO < 300 detik atau PSI some >= 10 selama 30 detik memicu P3
	if (tto != nil && *tto < DefaultP3TTOSeconds) || p3Sustained {
		return SeverityP3
	}
	return SeverityNone
}

// isHalfThresholdHealthy memeriksa apakah metrik berada di bawah setengah ambang batas P2 untuk hysteresis penutupan insiden.
func isHalfThresholdHealthy(
	tto *float64,
	psiSomeAvg10 float64,
	psiFullAvg10 float64,
	deltaMax uint64,
	deltaOOM uint64,
	deltaOOMKill uint64,
) bool {
	if deltaMax > 0 || deltaOOM > 0 || deltaOOMKill > 0 {
		return false
	}
	if psiSomeAvg10 >= (DefaultP2PSISomeAvg10 / 2.0) {
		return false
	}
	if psiFullAvg10 >= (DefaultP2PSIFullAvg10 / 2.0) {
		return false
	}
	if tto != nil && *tto < (DefaultP2TTOSeconds*2.0) {
		return false
	}
	return true
}

