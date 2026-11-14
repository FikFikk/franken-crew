package detector

import (
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	// DefaultAlpha adalah bobot peluruhan EWMA standar sesuai spesifikasi desain (0.3) untuk satu sampel
	// yang berjarak tepat satu ReferenceInterval dari pembaruan slope sebelumnya.
	DefaultAlpha = 0.3
	// DefaultReferenceInterval adalah jarak sampel acuan tempat Alpha berlaku apa adanya (1 detik, sesuai sampling 1 Hz).
	DefaultReferenceInterval = 1 * time.Second
	// DefaultMinSlopeInterval adalah rentang minimum sejak anchor slope sebelum slope boleh diperbarui (250 ms).
	DefaultMinSlopeInterval = 250 * time.Millisecond
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
	NodeName          string
	HostMemTotalBytes uint64
	HostReserveBytes  uint64
	// Alpha adalah bobot EWMA untuk satu sampel yang diambil tepat satu ReferenceInterval setelah pembaruan slope
	// sebelumnya; untuk rentang lain bobotnya menjadi 1 - (1-Alpha)^(rentang/ReferenceInterval).
	Alpha              float64
	HysteresisDuration time.Duration
	DebounceDuration   time.Duration
	P3SustainDuration  time.Duration
	// ReferenceInterval adalah jarak sampel acuan untuk Alpha sekaligus rentang minimum slope pertama (default 1 detik).
	ReferenceInterval time.Duration
	// MinSlopeInterval adalah rentang minimum sejak anchor slope sebelum slope diperbarui (default 250 ms). Sampel yang
	// lebih rapat tetap dievaluasi untuk severity, namun tidak mengubah slope maupun anchor.
	MinSlopeInterval time.Duration
}

// cgroupState menyimpan histori telemetri dan status insiden per cgroup.
type cgroupState struct {
	initialized bool
	// lastAt adalah waktu sampel in-order terbaru; sampel dengan At lebih awal dianggap basi.
	lastAt time.Time
	// anchorBytes dan anchorAt adalah titik acuan slope; hanya bergeser saat slope diperbarui atau counter di-reset.
	anchorBytes    uint64
	anchorAt       time.Time
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
	if cfg.ReferenceInterval <= 0 {
		cfg.ReferenceInterval = DefaultReferenceInterval
	}
	if cfg.MinSlopeInterval <= 0 {
		cfg.MinSlopeInterval = DefaultMinSlopeInterval
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

	limit := d.effectiveLimit(s.MemoryMax)

	// Sampel yang lebih tua dari sampel terakhir yang diproses (out-of-order) tidak boleh mengubah state apa pun.
	// Sampel dengan At sama tetap in-order karena counter memory.events monoton.
	if st.initialized && s.At.Before(st.lastAt) {
		return d.evaluateStale(st, s, limit)
	}

	var deltaMax, deltaOOM, deltaOOMKill uint64
	switch {
	case !st.initialized:
		st.initialized = true
		st.lastEvents = s.Events
		st.resetSlopeAnchor(s)
	case eventsCounterReset(s.Events, st.lastEvents):
		// Counter turun berarti cgroup dihapus lalu dibuat ulang (misalnya restart unit): rebaseline seluruh counter
		// tanpa delta, dan mulai slope dari nol karena memori cgroup baru tidak kontinu dengan cgroup lama.
		st.lastEvents = s.Events
		st.resetSlopeAnchor(s)
	default:
		// Tidak ada counter yang turun, sehingga pengurangan di bawah aman dari underflow
		deltaMax = s.Events.Max - st.lastEvents.Max
		deltaOOM = s.Events.OOM - st.lastEvents.OOM
		deltaOOMKill = s.Events.OOMKill - st.lastEvents.OOMKill
		st.lastEvents = s.Events
		d.updateSlope(st, s)
	}
	st.lastAt = s.At

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
		d.applyOpenOrReopen(st, rawSeverity, s.At, &eval)
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

// applyOpenOrReopen membuka atau me-reopen insiden pada state cgroup bila tingkat keparahan mencapai minimal P2.
func (d *Detector) applyOpenOrReopen(st *cgroupState, rawSeverity Severity, at time.Time, eval *Evaluation) {
	if rawSeverity.Rank() < SeverityP2.Rank() {
		return
	}
	st.incidentOpen = true
	st.activeSeverity = rawSeverity
	st.healthySince = time.Time{}

	if !st.lastClosedAt.IsZero() && at.Sub(st.lastClosedAt) < d.cfg.DebounceDuration && st.lastClosedID != "" {
		// Debounce aktif: gunakan kembali ID insiden sebelumnya
		st.activeID = st.lastClosedID
		eval.Reopened = true
	} else {
		st.activeID = d.nextIncidentID(at)
		eval.Reopened = false
	}
	eval.IncidentOpen = true
	eval.IncidentID = st.activeID
	eval.Severity = st.activeSeverity
}

// ForgetCgroup menghapus seluruh state deteksi cgroup yang sudah hilang dari kernel agar kemunculan kembali
// unit transien/baru tidak tertelan oleh status incidentOpen lama.
func (d *Detector) ForgetCgroup(cgroup string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.states[cgroup]
	if !ok {
		return false
	}
	wasOpen := st.incidentOpen
	delete(d.states, cgroup)
	return wasOpen
}

// RestoreOpenIncident memulihkan status insiden terbuka dari SQLite setelah daemon restart untuk target hidup
// agar Evaluator tidak membuka insiden duplikat bagi insiden yang masih berlangsung.
func (d *Detector) RestoreOpenIncident(cgroup, incidentID string, severity Severity) {
	if cgroup == "" || incidentID == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.states[cgroup]
	if !ok {
		st = &cgroupState{}
		d.states[cgroup] = st
	}
	st.incidentOpen = true
	st.activeID = incidentID
	if severity.Rank() > st.activeSeverity.Rank() {
		st.activeSeverity = severity
	}
	st.healthySince = time.Time{}
}

// ObserveDelta mengevaluasi kenaikan delta memory.events secara langsung (misalnya ketika inotify/journal mendeteksi
// OOM kill tepat sebelum systemd menghapus direktori cgroup unit transien).
func (d *Detector) ObserveDelta(cgroup string, current, delta MemoryEvents, limitBytes uint64, at time.Time) Evaluation {
	d.mu.Lock()
	defer d.mu.Unlock()

	if at.IsZero() {
		at = time.Now()
	}
	st, ok := d.states[cgroup]
	if !ok {
		st = &cgroupState{}
		d.states[cgroup] = st
	}
	if !st.initialized {
		st.initialized = true
	}
	if at.After(st.lastAt) {
		st.lastAt = at
	}
	st.lastEvents = current

	rawSeverity := classifyRawSeverity(nil, 0, 0, false, delta.Max, delta.OOM, delta.OOMKill)
	limit := d.effectiveLimit(limitBytes)
	eval := Evaluation{
		Cgroup:         cgroup,
		Severity:       rawSeverity,
		RawSeverity:    rawSeverity,
		SlopeBytesPerS: st.ewmaSlope,
		LimitBytes:     limit,
		At:             at,
	}

	if !st.incidentOpen {
		d.applyOpenOrReopen(st, rawSeverity, at, &eval)
		return eval
	}
	if rawSeverity.Rank() > st.activeSeverity.Rank() {
		st.activeSeverity = rawSeverity
	}
	eval.Severity = st.activeSeverity
	eval.IncidentOpen = true
	eval.IncidentID = st.activeID
	return eval
}

// evaluateStale menilai sampel basi secara read-only: RawSeverity dihitung dari PSI/TTO sampel tersebut tanpa delta
// memory.events, sedangkan status insiden yang dilaporkan adalah insiden aktif saat ini tanpa dibuka, ditutup, atau
// dieskalasi.
func (d *Detector) evaluateStale(st *cgroupState, s Sample, limit uint64) Evaluation {
	tto := computeTTO(s.MemoryCurrent, limit, st.hasSlope, st.ewmaSlope)
	p3Sustained := s.PSISomeAvg10 >= DefaultP3PSISomeAvg10 &&
		!st.p3SomeSince.IsZero() && s.At.Sub(st.p3SomeSince) >= d.cfg.P3SustainDuration

	eval := Evaluation{
		Cgroup:         s.Cgroup,
		Severity:       SeverityNone,
		RawSeverity:    classifyRawSeverity(tto, s.PSISomeAvg10, s.PSIFullAvg10, p3Sustained, 0, 0, 0),
		SlopeBytesPerS: st.ewmaSlope,
		TTOSeconds:     tto,
		LimitBytes:     limit,
		At:             s.At,
	}
	if st.incidentOpen {
		eval.Severity = st.activeSeverity
		eval.IncidentOpen = true
		eval.IncidentID = st.activeID
	}
	return eval
}

// resetSlopeAnchor menjadikan sampel s sebagai anchor slope baru dan menghapus slope lama.
func (st *cgroupState) resetSlopeAnchor(s Sample) {
	st.anchorBytes = s.MemoryCurrent
	st.anchorAt = s.At
	st.hasSlope = false
	st.ewmaSlope = 0
}

// updateSlope memperbarui EWMA slope dari rentang penuh sejak anchor dengan bobot yang disesuaikan terhadap panjang
// rentang, sehingga sampel jalur cepat tidak menggelembungkan slope dan sampling 1 Hz berperilaku seperti sebelumnya.
func (d *Detector) updateSlope(st *cgroupState, s Sample) {
	span := s.At.Sub(st.anchorAt)
	if span < d.cfg.MinSlopeInterval {
		// Rentang terlalu pendek (misalnya sampel jalur cepat atau At identik): pertahankan slope dan anchor agar
		// pembaruan berikutnya memakai rentang penuh sejak anchor.
		return
	}
	if !st.hasSlope && span < d.cfg.ReferenceInterval {
		// Slope pertama baru ditetapkan setelah rentang sejak anchor pertama mencapai ReferenceInterval
		return
	}

	instSlope := (float64(s.MemoryCurrent) - float64(st.anchorBytes)) / span.Seconds()
	if st.hasSlope {
		alpha := effectiveAlpha(d.cfg.Alpha, span, d.cfg.ReferenceInterval)
		st.ewmaSlope = alpha*instSlope + (1.0-alpha)*st.ewmaSlope
	} else {
		st.ewmaSlope = instSlope
		st.hasSlope = true
	}
	st.anchorBytes = s.MemoryCurrent
	st.anchorAt = s.At
}

// effectiveAlpha menghitung bobot EWMA untuk satu pembaruan sepanjang span: 1 - (1-alpha)^(span/ref).
// Bentuk -Expm1(x*Log1p(-alpha)) identik secara matematis namun tetap presisi untuk alpha atau rentang yang kecil.
func effectiveAlpha(alpha float64, span, ref time.Duration) float64 {
	x := span.Seconds() / ref.Seconds()
	weight := -math.Expm1(x * math.Log1p(-alpha))
	// Jaga bobot tetap di (0, 1] walau terjadi underflow numerik
	return math.Min(1, math.Max(weight, math.SmallestNonzeroFloat64))
}

// eventsCounterReset melaporkan apakah ada counter memory.events yang lebih kecil dari baseline. Counter kernel
// bersifat monoton selama umur cgroup, sehingga penurunan berarti cgroup telah dibuat ulang.
func eventsCounterReset(cur, base MemoryEvents) bool {
	return cur.Low < base.Low ||
		cur.High < base.High ||
		cur.Max < base.Max ||
		cur.OOM < base.OOM ||
		cur.OOMKill < base.OOMKill
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
