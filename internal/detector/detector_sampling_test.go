package detector

import (
	"fmt"
	"math"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// samplingT0 adalah waktu awal bersama untuk skenario uji urutan dan kerapatan sampel.
var samplingT0 = time.Date(2026, 11, 12, 3, 17, 0, 0, time.UTC)

const samplingCgroup = "/franken.slice/haunted-api.service"

// evalAt mengevaluasi sampel s untuk cgroup uji pada waktu samplingT0+offset.
func evalAt(det *Detector, offset time.Duration, s Sample) Evaluation {
	s.Cgroup = samplingCgroup
	s.At = samplingT0.Add(offset)
	return det.Evaluate(s)
}

// fmtTTO memformat TTO untuk pesan kegagalan; nil berarti tidak ada proyeksi OOM.
func fmtTTO(tto *float64) string {
	if tto == nil {
		return "nil"
	}
	return fmt.Sprintf("%.2fs", *tto)
}

// describeEval meringkas Evaluation tanpa alamat pointer agar pesan kegagalan mudah dibaca.
func describeEval(e Evaluation) string {
	return fmt.Sprintf("severity=%s raw=%s slope=%.1fB/s tto=%s open=%v closed=%v reopened=%v id=%q",
		e.Severity, e.RawSeverity, e.SlopeBytesPerS, fmtTTO(e.TTOSeconds), e.IncidentOpen, e.IncidentClosed, e.Reopened, e.IncidentID)
}

// assertSlope memastikan slope EWMA sama dengan nilai yang diturunkan manual (toleransi 1 B/s).
func assertSlope(t *testing.T, step string, got Evaluation, wantBytesPerSec float64) {
	t.Helper()
	if math.Abs(got.SlopeBytesPerS-wantBytesPerSec) > 1.0 {
		t.Fatalf("%s: slope = %.4f MiB/s, want %.4f MiB/s (%s)", step, got.SlopeBytesPerS/mib, wantBytesPerSec/mib, describeEval(got))
	}
}

// assertTTO memastikan TTO terdefinisi dan sama dengan nilai yang diturunkan manual (toleransi 0.01 detik).
func assertTTO(t *testing.T, step string, got Evaluation, wantSeconds float64) {
	t.Helper()
	if got.TTOSeconds == nil || math.Abs(*got.TTOSeconds-wantSeconds) > 0.01 {
		t.Fatalf("%s: TTO = %s, want %.2fs (%s)", step, fmtTTO(got.TTOSeconds), wantSeconds, describeEval(got))
	}
}

func TestDetector_QuantizedGrowthSampledFastStaysNearTrueRate(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 8 * gib})

	// Pertumbuhan sebenarnya 2 MiB/s, namun kernel menagih memori per batch per-CPU 512 KiB tiap 250 ms,
	// sementara sampel datang tiap 100 ms (tick 1 Hz ditambah event jalur cepat).
	const (
		trueRate    = 2.0 * mib
		chargeBatch = 512 * 1024
		batchEvery  = 250 * time.Millisecond
		sampleEvery = 100 * time.Millisecond
		duration    = 60 * time.Second
		settleAfter = 30 * time.Second
	)
	minSlope, maxSlope := math.Inf(1), math.Inf(-1)
	for at := time.Duration(0); at <= duration; at += sampleEvery {
		current := uint64(100*mib) + uint64(at/batchEvery)*chargeBatch
		eval := evalAt(det, at, Sample{MemoryCurrent: current, MemoryMax: 4 * gib})
		if at < settleAfter {
			continue
		}
		minSlope = math.Min(minSlope, eval.SlopeBytesPerS)
		maxSlope = math.Max(maxSlope, eval.SlopeBytesPerS)
	}
	if minSlope < 0.7*trueRate || maxSlope > 1.3*trueRate {
		t.Fatalf("EWMA slope over the last 30 s ranged %.3f..%.3f MiB/s, want within ±30%% of %.1f MiB/s (%.2f..%.2f)",
			minSlope/mib, maxSlope/mib, trueRate/mib, 0.7*trueRate/mib, 1.3*trueRate/mib)
	}
}

func TestDetector_FastSampleAfterTickDoesNotSpikeSlope(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	const (
		limit   = 512 * mib
		current = limit - 300*mib // sisa ruang 300 MiB sebelum limit
	)

	// 30 detik memori datar pada 1 Hz
	for sec := 0; sec <= 30; sec++ {
		eval := evalAt(det, time.Duration(sec)*time.Second, Sample{MemoryCurrent: current, MemoryMax: limit})
		if eval.RawSeverity != SeverityNone {
			t.Fatalf("flat memory at +%ds: %s, want raw NONE", sec, describeEval(eval))
		}
	}

	// Sampel jalur cepat 10 ms setelah tick membawa satu batch charge +1 MiB
	eval := evalAt(det, 30*time.Second+10*time.Millisecond, Sample{MemoryCurrent: current + 1*mib, MemoryMax: limit})
	if eval.Severity != SeverityNone || eval.RawSeverity != SeverityNone {
		t.Fatalf("fast sample 10 ms after a tick: %s, want severity and raw NONE", describeEval(eval))
	}
	if eval.TTOSeconds != nil && *eval.TTOSeconds < 120 {
		t.Fatalf("fast sample 10 ms after a tick: TTO %s dropped below 120s (%s)", fmtTTO(eval.TTOSeconds), describeEval(eval))
	}
}

func TestDetector_ShortSpanSampleKeepsAnchorForNextUpdate(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 8 * gib})
	limit := uint64(4 * gib)

	evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit})
	assertSlope(t, "+1s", evalAt(det, time.Second, Sample{MemoryCurrent: 101 * mib, MemoryMax: limit}), 1*mib)

	// +1.1s: rentang 100 ms sejak anchor < 250 ms, sehingga slope dan anchor tidak berubah
	assertSlope(t, "+1.1s", evalAt(det, 1100*time.Millisecond, Sample{MemoryCurrent: 105 * mib, MemoryMax: limit}), 1*mib)

	// +2s: rentang penuh sejak anchor +1s: inst = (112-101)/1 = 11 MiB/s -> 0.3*11 + 0.7*1 = 4 MiB/s
	assertSlope(t, "+2s", evalAt(det, 2*time.Second, Sample{MemoryCurrent: 112 * mib, MemoryMax: limit}), 4*mib)
}

func TestDetector_SlopeUpdateWeightScalesWithSpan(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 8 * gib, Alpha: 0.3})
	limit := uint64(4 * gib)

	evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit})
	assertSlope(t, "+1s", evalAt(det, time.Second, Sample{MemoryCurrent: 110 * mib, MemoryMax: limit}), 10*mib)

	// Rentang 2 detik: bobot = 1 - 0.7^2 = 0.51; inst = 40/2 = 20 MiB/s -> 0.51*20 + 0.49*10 = 15.1 MiB/s
	assertSlope(t, "+3s", evalAt(det, 3*time.Second, Sample{MemoryCurrent: 150 * mib, MemoryMax: limit}), 15.1*mib)

	// Rentang 0.5 detik: bobot = 1 - sqrt(0.7); inst = 5/0.5 = 10 MiB/s
	halfSpanWeight := 1 - math.Sqrt(0.7)
	assertSlope(t, "+3.5s", evalAt(det, 3500*time.Millisecond, Sample{MemoryCurrent: 155 * mib, MemoryMax: limit}),
		(halfSpanWeight*10+(1-halfSpanWeight)*15.1)*mib)
}

func TestDetector_FirstSlopeNeedsReferenceSpan(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	limit := uint64(1 * gib)

	evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit})

	// +10 ms: +1 MiB tidak boleh menetapkan slope pertama
	eval := evalAt(det, 10*time.Millisecond, Sample{MemoryCurrent: 101 * mib, MemoryMax: limit})
	if eval.TTOSeconds != nil || eval.RawSeverity != SeverityNone {
		t.Fatalf("+10ms: %s, want TTO nil and raw NONE before a full reference span", describeEval(eval))
	}

	// +500 ms: rentang sudah >= MinSlopeInterval namun masih < ReferenceInterval
	eval = evalAt(det, 500*time.Millisecond, Sample{MemoryCurrent: 101*mib + 256*1024, MemoryMax: limit})
	if eval.TTOSeconds != nil {
		t.Fatalf("+500ms: %s, want TTO nil before a full reference span", describeEval(eval))
	}

	// +1s: slope pertama dari seluruh rentang sejak baseline: (102-100) MiB / 1 s = 2 MiB/s
	eval = evalAt(det, time.Second, Sample{MemoryCurrent: 102 * mib, MemoryMax: limit})
	assertSlope(t, "+1s", eval, 2*mib)
	assertTTO(t, "+1s", eval, (1024.0-102.0)/2.0)
}

func TestDetector_CustomReferenceAndMinSlopeInterval(t *testing.T) {
	det := NewDetector(Config{
		NodeName:          "pi01",
		HostMemTotalBytes: 8 * gib,
		ReferenceInterval: 2 * time.Second,
		MinSlopeInterval:  time.Second,
	})
	limit := uint64(4 * gib)

	evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit})

	// +1s: rentang 1 s < ReferenceInterval 2 s, slope pertama belum ada
	if eval := evalAt(det, time.Second, Sample{MemoryCurrent: 102 * mib, MemoryMax: limit}); eval.TTOSeconds != nil {
		t.Fatalf("+1s: %s, want TTO nil before the 2s reference span", describeEval(eval))
	}

	// +2s: slope pertama = (104-100) MiB / 2 s = 2 MiB/s
	assertSlope(t, "+2s", evalAt(det, 2*time.Second, Sample{MemoryCurrent: 104 * mib, MemoryMax: limit}), 2*mib)

	// +2.5s: rentang 0.5 s < MinSlopeInterval 1 s, slope tetap
	assertSlope(t, "+2.5s", evalAt(det, 2500*time.Millisecond, Sample{MemoryCurrent: 110 * mib, MemoryMax: limit}), 2*mib)

	// +3s: rentang 1 s = setengah ReferenceInterval: bobot = 1 - 0.7^(1/2); inst = (112-104)/1 = 8 MiB/s
	halfRefWeight := 1 - math.Sqrt(0.7)
	assertSlope(t, "+3s", evalAt(det, 3*time.Second, Sample{MemoryCurrent: 112 * mib, MemoryMax: limit}),
		(halfRefWeight*8+(1-halfRefWeight)*2)*mib)
}

func TestDetector_EqualTimestampStillCountsEvents(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	limit := uint64(1 * gib)

	// Pemanggil dengan clock palsu sering mengirim beberapa sampel dengan At identik
	evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit, Events: MemoryEvents{OOMKill: 0}})
	eval := evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit, Events: MemoryEvents{OOMKill: 1}})
	if eval.RawSeverity != SeverityPostOOM || eval.Severity != SeverityPostOOM || !eval.IncidentOpen {
		t.Fatalf("equal-timestamp sample with oom_kill 0->1: %s, want open POST_OOM incident", describeEval(eval))
	}
}

func TestDetector_EqualTimestampDoesNotUpdateSlope(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 8 * gib})
	limit := uint64(4 * gib)

	evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit})
	assertSlope(t, "+1s", evalAt(det, time.Second, Sample{MemoryCurrent: 110 * mib, MemoryMax: limit}), 10*mib)

	// At identik (dt = 0): slope dan anchor tidak boleh berubah
	assertSlope(t, "+1s duplicate", evalAt(det, time.Second, Sample{MemoryCurrent: 150 * mib, MemoryMax: limit}), 10*mib)

	// +2s: rentang dihitung dari anchor +1s (110 MiB), bukan dari sampel duplikat: inst = 10 MiB/s
	assertSlope(t, "+2s", evalAt(det, 2*time.Second, Sample{MemoryCurrent: 120 * mib, MemoryMax: limit}), 10*mib)
}

func TestDetector_StaleSampleDoesNotDoubleCountEvents(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	limit := uint64(1 * gib)
	withOOMKill := func(n uint64) Sample {
		return Sample{MemoryCurrent: 200 * mib, MemoryMax: limit, Events: MemoryEvents{OOMKill: n}}
	}

	evalAt(det, 1*time.Second, withOOMKill(0))
	if got := evalAt(det, 2*time.Second, withOOMKill(1)); got.RawSeverity != SeverityPostOOM {
		t.Fatalf("+2s: %s, want raw POST_OOM for oom_kill 0->1", describeEval(got))
	}

	// Sampel basi (+1.5s, lebih tua dari +2s) membawa counter lama dan tidak boleh menggeser baseline mundur
	evalAt(det, 1500*time.Millisecond, withOOMKill(0))

	if got := evalAt(det, 3*time.Second, withOOMKill(1)); got.RawSeverity == SeverityPostOOM {
		t.Fatalf("+3s: %s; the oom_kill already reported at +2s was counted again", describeEval(got))
	}
}

func TestDetector_StaleSampleNeverReportsEventDeltas(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	withOOMKill := func(n uint64) Sample {
		return Sample{MemoryCurrent: 200 * mib, MemoryMax: 1 * gib, Events: MemoryEvents{OOMKill: n}}
	}

	evalAt(det, 1*time.Second, withOOMKill(0))
	evalAt(det, 2*time.Second, withOOMKill(0))

	// Sampel basi dapat membawa counter yang lebih baru bila dua goroutine pemanggil memberi stempel waktu yang tidak
	// searah dengan urutan pembacaan berkas. Deltanya tidak dilaporkan oleh sampel basi, melainkan oleh sampel in-order
	// berikutnya karena baseline tidak bergeser.
	stale := evalAt(det, 1500*time.Millisecond, withOOMKill(1))
	if stale.RawSeverity == SeverityPostOOM || stale.IncidentOpen {
		t.Fatalf("stale sample with oom_kill 0->1: %s, want zero event deltas and no incident", describeEval(stale))
	}
	if got := evalAt(det, 3*time.Second, withOOMKill(1)); got.RawSeverity != SeverityPostOOM || !got.IncidentOpen {
		t.Fatalf("+3s: %s, want the deferred oom_kill 0->1 reported as an open POST_OOM incident", describeEval(got))
	}
}

func TestDetector_StaleSampleDoesNotOpenIncident(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	calm := Sample{MemoryCurrent: 100 * mib, MemoryMax: 512 * mib, PSISomeAvg10: 1}

	evalAt(det, 0, calm)
	evalAt(det, 2*time.Second, calm)

	// Sampel basi +1s dengan PSI some 30 (P2 mentah) tidak boleh membuka insiden
	stale := evalAt(det, time.Second, Sample{MemoryCurrent: 100 * mib, MemoryMax: 512 * mib, PSISomeAvg10: 30})
	if stale.IncidentOpen || stale.IncidentID != "" || stale.Severity != SeverityNone {
		t.Fatalf("stale sample: %s, want no incident and severity NONE", describeEval(stale))
	}
	if stale.RawSeverity != SeverityP2 {
		t.Fatalf("stale sample: %s, want raw P2 from its own PSI some avg10=30", describeEval(stale))
	}

	if next := evalAt(det, 3*time.Second, calm); next.IncidentOpen {
		t.Fatalf("+3s: %s; an incident was opened by a stale sample", describeEval(next))
	}
}

func TestDetector_StaleSampleReportsActiveIncidentWithoutEscalating(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	limit := uint64(512 * mib)

	evalAt(det, 0, Sample{MemoryCurrent: 100 * mib, MemoryMax: limit})
	// +1s: slope 10 MiB/s, TTO = (512-110)/10 = 40.2s -> insiden P2 dibuka
	opened := evalAt(det, time.Second, Sample{MemoryCurrent: 110 * mib, MemoryMax: limit})
	if !opened.IncidentOpen || opened.Severity != SeverityP2 {
		t.Fatalf("+1s: %s, want open P2 incident", describeEval(opened))
	}
	evalAt(det, 2*time.Second, Sample{MemoryCurrent: 120 * mib, MemoryMax: limit})

	// Sampel basi +1.5s dengan 330 MiB: TTO = (512-330)/10 = 18.2s (P1 mentah), namun insiden tidak boleh tereskalasi
	stale := evalAt(det, 1500*time.Millisecond, Sample{MemoryCurrent: 330 * mib, MemoryMax: limit})
	if !stale.IncidentOpen || stale.IncidentID != opened.IncidentID || stale.Severity != SeverityP2 {
		t.Fatalf("stale sample: %s, want the active P2 incident %q reported unchanged", describeEval(stale), opened.IncidentID)
	}
	if stale.IncidentClosed || stale.Reopened {
		t.Fatalf("stale sample: %s, want neither closed nor reopened", describeEval(stale))
	}
	if stale.RawSeverity != SeverityP1 {
		t.Fatalf("stale sample: %s, want raw P1 from its own TTO", describeEval(stale))
	}
	assertTTO(t, "stale +1.5s", stale, 18.2)
	assertSlope(t, "stale +1.5s", stale, 10*mib)

	// +3s: anchor tetap di +2s (120 MiB) -> slope 10 MiB/s, TTO 38.2s (P2); severity aktif tetap P2
	next := evalAt(det, 3*time.Second, Sample{MemoryCurrent: 130 * mib, MemoryMax: limit})
	if !next.IncidentOpen || next.Severity != SeverityP2 {
		t.Fatalf("+3s: %s, want the incident still open at P2", describeEval(next))
	}
	assertSlope(t, "+3s", next, 10*mib)
}

func TestDetector_StaleSampleDoesNotResetHysteresisTimer(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib, HysteresisDuration: 120 * time.Second})
	withPSI := func(some float64) Sample {
		return Sample{MemoryCurrent: 100 * mib, MemoryMax: 512 * mib, PSISomeAvg10: some}
	}

	if open := evalAt(det, 0, withPSI(30)); !open.IncidentOpen {
		t.Fatalf("+0s: %s, want open P2 incident", describeEval(open))
	}
	evalAt(det, 10*time.Second, withPSI(2)) // pemulihan setengah ambang dimulai
	evalAt(det, 60*time.Second, withPSI(2))

	// Sampel basi +50s dengan PSI tinggi tidak boleh me-reset timer hysteresis yang berjalan sejak +10s
	evalAt(det, 50*time.Second, withPSI(30))

	if closed := evalAt(det, 130*time.Second, withPSI(1)); !closed.IncidentClosed || closed.IncidentOpen {
		t.Fatalf("+130s: %s, want the incident closed after 120s of recovery since +10s", describeEval(closed))
	}
}

func TestDetector_StaleSampleDoesNotResetP3SustainTimer(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib, P3SustainDuration: 30 * time.Second})
	withPSI := func(some float64) Sample {
		return Sample{MemoryCurrent: 100 * mib, MemoryMax: 1 * gib, PSISomeAvg10: some}
	}

	for sec := 0; sec <= 20; sec++ {
		evalAt(det, time.Duration(sec)*time.Second, withPSI(15))
	}
	// Sampel basi +19.5s dengan PSI rendah tidak boleh menghapus awal jendela P3 (+0s)
	evalAt(det, 19500*time.Millisecond, withPSI(2))

	if got := evalAt(det, 31*time.Second, withPSI(15)); got.RawSeverity != SeverityP3 {
		t.Fatalf("+31s: %s, want raw P3 after PSI some >= 10 sustained since +0s", describeEval(got))
	}
	// Sampel basi di dalam jendela yang sudah bertahan 30 detik melaporkan P3 dari PSI-nya sendiri
	if got := evalAt(det, 30500*time.Millisecond, withPSI(15)); got.RawSeverity != SeverityP3 {
		t.Fatalf("stale +30.5s: %s, want raw P3", describeEval(got))
	}
	if got := evalAt(det, 32*time.Second, withPSI(15)); got.RawSeverity != SeverityP3 {
		t.Fatalf("+32s: %s, want raw P3", describeEval(got))
	}
}

func TestDetector_CounterResetIsNotADelta(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	withOOMKill := func(n uint64) Sample {
		return Sample{MemoryCurrent: 200 * mib, MemoryMax: 1 * gib, Events: MemoryEvents{OOMKill: n}}
	}

	evalAt(det, 0, withOOMKill(5))
	// cgroup dihapus lalu dibuat ulang (restart unit): counter memory.events mulai lagi dari 0
	if got := evalAt(det, time.Second, withOOMKill(0)); got.RawSeverity == SeverityPostOOM {
		t.Fatalf("+1s counter reset 5->0: %s, want no POST_OOM", describeEval(got))
	}
	if got := evalAt(det, 2*time.Second, withOOMKill(1)); got.RawSeverity != SeverityPostOOM {
		t.Fatalf("+2s oom_kill 0->1 after reset: %s, want raw POST_OOM", describeEval(got))
	}
}

func TestDetector_CounterResetSampleReportsNoDeltas(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	limit := uint64(1 * gib)

	// cgroup lama: throttling memory.high berat tanpa OOM
	evalAt(det, 0, Sample{MemoryCurrent: 450 * mib, MemoryMax: limit, Events: MemoryEvents{High: 250, Max: 12}})

	// Unit di-restart dan cgroup baru sudah terkena satu OOM kill sebelum sampel pertamanya. high turun 250 -> 3
	// menandakan reset, jadi seluruh counter di-rebaseline tanpa delta walau oom/oom_kill lebih besar dari baseline lama.
	recreated := MemoryEvents{High: 3, Max: 1, OOM: 1, OOMKill: 1}
	if got := evalAt(det, time.Second, Sample{MemoryCurrent: 30 * mib, MemoryMax: limit, Events: recreated}); got.RawSeverity != SeverityNone {
		t.Fatalf("+1s reset sample: %s, want raw NONE (zero deltas)", describeEval(got))
	}

	// Baseline kini counter cgroup baru, sehingga nilai yang sama tidak menghasilkan delta
	if got := evalAt(det, 2*time.Second, Sample{MemoryCurrent: 30 * mib, MemoryMax: limit, Events: recreated}); got.RawSeverity != SeverityNone {
		t.Fatalf("+2s unchanged counters: %s, want raw NONE", describeEval(got))
	}

	// Kenaikan oom_kill berikutnya pada cgroup baru tetap terdeteksi
	next := MemoryEvents{High: 3, Max: 1, OOM: 2, OOMKill: 2}
	if got := evalAt(det, 3*time.Second, Sample{MemoryCurrent: 30 * mib, MemoryMax: limit, Events: next}); got.RawSeverity != SeverityPostOOM {
		t.Fatalf("+3s oom_kill 1->2: %s, want raw POST_OOM", describeEval(got))
	}
}

func TestDetector_AnyCounterDecreaseIsAReset(t *testing.T) {
	tests := []struct {
		name     string
		baseline MemoryEvents
	}{
		{name: "low", baseline: MemoryEvents{Low: 5}},
		{name: "high", baseline: MemoryEvents{High: 5}},
		{name: "max", baseline: MemoryEvents{Max: 5}},
		{name: "oom", baseline: MemoryEvents{OOM: 5}},
		{name: "oom_kill", baseline: MemoryEvents{OOMKill: 5}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
			limit := uint64(1 * gib)

			evalAt(det, 0, Sample{MemoryCurrent: 400 * mib, MemoryMax: limit, Events: tc.baseline})
			assertSlope(t, "+1s", evalAt(det, time.Second, Sample{MemoryCurrent: 402 * mib, MemoryMax: limit, Events: tc.baseline}), 2*mib)

			// Hanya counter ini yang turun ke 0 (memori tetap); itu cukup untuk menandai cgroup yang dibuat ulang
			reset := evalAt(det, 2*time.Second, Sample{MemoryCurrent: 402 * mib, MemoryMax: limit})
			if reset.SlopeBytesPerS != 0 || reset.TTOSeconds != nil {
				t.Fatalf("+2s %s 5->0: %s, want slope cleared and TTO nil", tc.name, describeEval(reset))
			}
		})
	}
}

func TestDetector_CounterResetRestartsSlope(t *testing.T) {
	det := NewDetector(Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib})
	limit := uint64(1 * gib)

	evalAt(det, 0, Sample{MemoryCurrent: 400 * mib, MemoryMax: limit, Events: MemoryEvents{High: 9}})
	assertSlope(t, "+1s", evalAt(det, time.Second, Sample{MemoryCurrent: 402 * mib, MemoryMax: limit, Events: MemoryEvents{High: 9}}), 2*mib)

	// +2s: cgroup dibuat ulang (high 9 -> 0) pada 20 MiB; memorinya tidak kontinu dengan cgroup lama
	reset := evalAt(det, 2*time.Second, Sample{MemoryCurrent: 20 * mib, MemoryMax: limit})
	if reset.TTOSeconds != nil || reset.SlopeBytesPerS != 0 {
		t.Fatalf("+2s reset sample: %s, want slope cleared (0 B/s) and TTO nil", describeEval(reset))
	}

	// +2.5s: slope pertama cgroup baru menunggu rentang referensi penuh sejak anchor reset
	if half := evalAt(det, 2500*time.Millisecond, Sample{MemoryCurrent: 25 * mib, MemoryMax: limit}); half.TTOSeconds != nil {
		t.Fatalf("+2.5s: %s, want TTO nil before a full reference span since the reset", describeEval(half))
	}

	// +3s: slope pertama dari anchor reset: (30-20) MiB / 1 s = 10 MiB/s; TTO = (1024-30)/10 = 99.4s -> P2
	next := evalAt(det, 3*time.Second, Sample{MemoryCurrent: 30 * mib, MemoryMax: limit})
	assertSlope(t, "+3s", next, 10*mib)
	assertTTO(t, "+3s", next, 99.4)
	if next.RawSeverity != SeverityP2 {
		t.Fatalf("+3s: %s, want raw P2 for the recreated cgroup leaking 10 MiB/s", describeEval(next))
	}
}

// sameEvaluation membandingkan dua Evaluation berdasarkan nilai, termasuk nilai TTO di balik pointer.
func sameEvaluation(a, b Evaluation) bool {
	if (a.TTOSeconds == nil) != (b.TTOSeconds == nil) {
		return false
	}
	if a.TTOSeconds != nil && *a.TTOSeconds != *b.TTOSeconds {
		return false
	}
	a.TTOSeconds, b.TTOSeconds = nil, nil
	return a == b
}

func TestDetector_Property_StaleSamplesNeverChangeInOrderEvaluations(t *testing.T) {
	gaps := []time.Duration{0, 10 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond,
		time.Second, time.Second, time.Second, 2 * time.Second, 15 * time.Second}
	psiSomeLevels := []float64{0, 5, 11, 13, 30}
	psiFullLevels := []float64{0, 1, 3, 6}
	limit := uint64(512 * mib)

	rapid.Check(t, func(rt *rapid.T) {
		cfg := Config{NodeName: "pi01", HostMemTotalBytes: 2 * gib}
		// reference hanya menerima sampel in-order; withStale menerima sampel yang sama diselingi sampel basi
		reference := NewDetector(cfg)
		withStale := NewDetector(cfg)

		at := samplingT0
		currentMiB := rapid.IntRange(16, 480).Draw(rt, "startMiB")
		var events MemoryEvents
		var psiSome, psiFull float64
		n := rapid.IntRange(2, 150).Draw(rt, "samples")
		for i := 0; i < n; i++ {
			if i > 0 {
				// Sisipkan 0-2 sampel basi yang lebih tua dari sampel in-order terakhir yang diproses
				for k := rapid.IntRange(0, 2).Draw(rt, "staleCount"); k > 0; k-- {
					back := time.Duration(rapid.IntRange(1, 20_000).Draw(rt, "staleBackMs")) * time.Millisecond
					withStale.Evaluate(Sample{
						Cgroup:        samplingCgroup,
						MemoryCurrent: uint64(rapid.IntRange(1, 600).Draw(rt, "staleMiB")) * mib,
						MemoryMax:     limit,
						PSISomeAvg10:  rapid.SampledFrom(psiSomeLevels).Draw(rt, "stalePSISome"),
						PSIFullAvg10:  rapid.SampledFrom(psiFullLevels).Draw(rt, "stalePSIFull"),
						Events: MemoryEvents{
							High:    uint64(rapid.IntRange(0, 5).Draw(rt, "staleHigh")),
							Max:     uint64(rapid.IntRange(0, 5).Draw(rt, "staleMax")),
							OOM:     uint64(rapid.IntRange(0, 5).Draw(rt, "staleOOM")),
							OOMKill: uint64(rapid.IntRange(0, 5).Draw(rt, "staleOOMKill")),
						},
						At: at.Add(-back),
					})
				}
				at = at.Add(rapid.SampledFrom(gaps).Draw(rt, "gap"))
			}

			// Sampel in-order: memori acak berjalan, counter monoton dengan sesekali reset, PSI berganti rezim
			currentMiB = min(max(currentMiB+rapid.IntRange(-6, 14).Draw(rt, "deltaMiB"), 8), 560)
			switch rapid.IntRange(0, 39).Draw(rt, "eventChange") {
			case 0:
				events = MemoryEvents{}
			case 1, 2:
				events.Max++
			case 3:
				events.OOM++
			case 4:
				events.OOMKill++
			case 5, 6, 7:
				events.High++
			}
			if rapid.IntRange(0, 9).Draw(rt, "psiRegimeChange") == 0 {
				psiSome = rapid.SampledFrom(psiSomeLevels).Draw(rt, "psiSome")
				psiFull = rapid.SampledFrom(psiFullLevels).Draw(rt, "psiFull")
			}
			s := Sample{
				Cgroup:        samplingCgroup,
				MemoryCurrent: uint64(currentMiB) * mib,
				MemoryMax:     limit,
				PSISomeAvg10:  psiSome,
				PSIFullAvg10:  psiFull,
				Events:        events,
				At:            at,
			}

			want := reference.Evaluate(s)
			got := withStale.Evaluate(s)
			if !sameEvaluation(want, got) {
				rt.Fatalf("in-order sample #%d at +%v diverged after stale samples:\n got  %s\n want %s",
					i, at.Sub(samplingT0), describeEval(got), describeEval(want))
			}
		}
	})
}
