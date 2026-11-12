package detector

import (
	"math"
	"strings"
	"testing"
	"time"
)

const (
	mib = 1024 * 1024
	gib = 1024 * mib
)

func TestDetector_EWMASlopeAndTTOComputation(t *testing.T) {
	det := NewDetector(Config{
		NodeName:          "pi01",
		HostMemTotalBytes: 2 * gib,
		Alpha:             0.3,
	})

	baseTime := time.Date(2026, 11, 12, 3, 17, 0, 0, time.UTC)
	cgroup := "/franken.slice/haunted-api.service"
	limit := uint64(500 * mib)

	// Sampel 1: inisialisasi baseline (belum ada slope)
	eval1 := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 200 * mib,
		MemoryMax:     limit,
		At:            baseTime,
	})
	if eval1.TTOSeconds != nil {
		t.Fatalf("expected nil TTO on initial sample, got %v", *eval1.TTOSeconds)
	}
	if eval1.Severity != SeverityNone {
		t.Fatalf("expected SeverityNone on initial sample, got %s", eval1.Severity)
	}

	// Sampel 2 (+1 detik): naik 10 MiB -> slope = 10 MiB/s, sisa = 290 MiB -> TTO = 29.0 detik (P1)
	eval2 := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 210 * mib,
		MemoryMax:     limit,
		At:            baseTime.Add(1 * time.Second),
	})
	if eval2.TTOSeconds == nil {
		t.Fatalf("expected non-nil TTO on second sample")
	}
	if math.Abs(*eval2.TTOSeconds-29.0) > 0.01 {
		t.Errorf("expected TTO=29.0s, got %.2fs", *eval2.TTOSeconds)
	}
	if eval2.Severity != SeverityP1 {
		t.Errorf("expected SeverityP1 when TTO=29s (<30s), got %s", eval2.Severity)
	}

	// Sampel 3 (+2 detik): naik 20 MiB dalam 1 detik -> instSlope = 20 MiB/s
	// EWMA = 0.3 * 20 + 0.7 * 10 = 13.0 MiB/s; sisa = 270 MiB -> TTO = 270 / 13 = 20.769 detik
	eval3 := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 230 * mib,
		MemoryMax:     limit,
		At:            baseTime.Add(2 * time.Second),
	})
	expectedSlope := 13.0 * float64(mib)
	if math.Abs(eval3.SlopeBytesPerS-expectedSlope) > 1.0 {
		t.Errorf("expected EWMA slope %.0f B/s, got %.0f B/s", expectedSlope, eval3.SlopeBytesPerS)
	}
	expectedTTO := 270.0 / 13.0
	if eval3.TTOSeconds == nil || math.Abs(*eval3.TTOSeconds-expectedTTO) > 0.05 {
		t.Errorf("expected TTO=%.2fs, got %v", expectedTTO, eval3.TTOSeconds)
	}
}

func TestDetector_TableDrivenSeverityClassification(t *testing.T) {
	baseTime := time.Date(2026, 11, 12, 3, 17, 0, 0, time.UTC)

	tests := []struct {
		name         string
		initialBytes uint64
		secondBytes  uint64
		limitBytes   uint64
		psiSome      float64
		psiFull      float64
		initialEv    MemoryEvents
		secondEv     MemoryEvents
		wantSeverity Severity
	}{
		{
			name:         "Stable memory and low PSI returns NONE",
			initialBytes: 100 * mib,
			secondBytes:  100 * mib,
			limitBytes:   512 * mib,
			psiSome:      1.2,
			psiFull:      0.0,
			wantSeverity: SeverityNone,
		},
		{
			name:         "Moderate leak with TTO 200s returns P3",
			initialBytes: 100 * mib,
			secondBytes:  102 * mib, // 2 MiB/s -> sisa 400 MiB -> TTO = 200s (<300s)
			limitBytes:   502 * mib,
			wantSeverity: SeverityP3,
		},
		{
			name:         "Leak with TTO 80s returns P2",
			initialBytes: 100 * mib,
			secondBytes:  105 * mib, // 5 MiB/s -> sisa 400 MiB -> TTO = 80s (<120s)
			limitBytes:   505 * mib,
			wantSeverity: SeverityP2,
		},
		{
			name:         "PSI some avg10 >= 25 returns P2 even without memory growth",
			initialBytes: 100 * mib,
			secondBytes:  100 * mib,
			limitBytes:   512 * mib,
			psiSome:      27.5,
			wantSeverity: SeverityP2,
		},
		{
			name:         "PSI full avg10 >= 5 returns P2",
			initialBytes: 100 * mib,
			secondBytes:  100 * mib,
			limitBytes:   512 * mib,
			psiFull:      5.2,
			wantSeverity: SeverityP2,
		},
		{
			name:         "Memory events max counter increase returns P1",
			initialBytes: 400 * mib,
			secondBytes:  400 * mib,
			limitBytes:   512 * mib,
			initialEv:    MemoryEvents{Max: 2},
			secondEv:     MemoryEvents{Max: 3},
			wantSeverity: SeverityP1,
		},
		{
			name:         "OOM kill counter increase returns POST_OOM",
			initialBytes: 500 * mib,
			secondBytes:  120 * mib,
			limitBytes:   512 * mib,
			initialEv:    MemoryEvents{OOMKill: 0},
			secondEv:     MemoryEvents{OOMKill: 1},
			wantSeverity: SeverityPostOOM,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			det := NewDetector(Config{
				NodeName:          "pi01",
				HostMemTotalBytes: 2 * gib,
			})
			det.Evaluate(Sample{
				Cgroup:        "/app.service",
				MemoryCurrent: tc.initialBytes,
				MemoryMax:     tc.limitBytes,
				Events:        tc.initialEv,
				At:            baseTime,
			})
			got := det.Evaluate(Sample{
				Cgroup:        "/app.service",
				MemoryCurrent: tc.secondBytes,
				MemoryMax:     tc.limitBytes,
				PSISomeAvg10:  tc.psiSome,
				PSIFullAvg10:  tc.psiFull,
				Events:        tc.secondEv,
				At:            baseTime.Add(1 * time.Second),
			})
			if got.Severity != tc.wantSeverity {
				t.Errorf("expected severity %s, got %s (TTO=%v)", tc.wantSeverity, got.Severity, got.TTOSeconds)
			}
		})
	}
}

func TestDetector_Hysteresis120sAndDebounce5Min(t *testing.T) {
	det := NewDetector(Config{
		NodeName:           "pi01",
		HostMemTotalBytes:  2 * gib,
		HysteresisDuration: 120 * time.Second,
		DebounceDuration:   5 * time.Minute,
	})

	t0 := time.Date(2026, 11, 12, 3, 17, 0, 0, time.UTC)
	cgroup := "/franken.slice/haunted-api.service"

	// 1. Buka insiden P2 lewat lonjakan PSI some avg10 = 30.0
	evalOpen := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 300 * mib,
		MemoryMax:     512 * mib,
		PSISomeAvg10:  30.0,
		At:            t0,
	})
	if !evalOpen.IncidentOpen || evalOpen.Severity != SeverityP2 {
		t.Fatalf("expected open P2 incident, got open=%v severity=%s", evalOpen.IncidentOpen, evalOpen.Severity)
	}
	if !strings.HasPrefix(evalOpen.IncidentID, "INC-20261112-0317-pi01") {
		t.Errorf("unexpected incident ID format: %s", evalOpen.IncidentID)
	}
	firstIncidentID := evalOpen.IncidentID

	// 2. Pada t0 + 10s, metrik turun ke bawah setengah ambang batas (PSI some = 2.0 < 12.5)
	evalRecoveringStart := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 250 * mib,
		MemoryMax:     512 * mib,
		PSISomeAvg10:  2.0,
		At:            t0.Add(10 * time.Second),
	})
	if !evalRecoveringStart.IncidentOpen || evalRecoveringStart.IncidentClosed {
		t.Fatalf("incident must remain open when recovery just started")
	}

	// 3. Pada t0 + 100s (baru 90 detik sehat < 120 detik), insiden masih harus tetap terbuka
	evalMidRecovery := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 250 * mib,
		MemoryMax:     512 * mib,
		PSISomeAvg10:  1.5,
		At:            t0.Add(100 * time.Second),
	})
	if !evalMidRecovery.IncidentOpen || evalMidRecovery.IncidentClosed {
		t.Fatalf("incident must remain open at 90s of recovery (<120s hysteresis)")
	}

	// 4. Pada t0 + 130s (genap 120 detik sehat sejak t0 + 10s), insiden harus tertutup
	evalClosed := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 245 * mib,
		MemoryMax:     512 * mib,
		PSISomeAvg10:  0.5,
		At:            t0.Add(130 * time.Second),
	})
	if evalClosed.IncidentOpen || !evalClosed.IncidentClosed || evalClosed.Severity != SeverityNone {
		t.Fatalf("expected incident to close after 120s hysteresis, got %+v", evalClosed)
	}

	// 5. Pada t0 + 250s (2 menit setelah ditutup < 5 menit debounce), terjadi lonjakan baru -> harus me-reopen ID lama
	evalReopen := det.Evaluate(Sample{
		Cgroup:        cgroup,
		MemoryCurrent: 350 * mib,
		MemoryMax:     512 * mib,
		PSISomeAvg10:  28.0,
		At:            t0.Add(250 * time.Second),
	})
	if !evalReopen.IncidentOpen || !evalReopen.Reopened {
		t.Fatalf("expected incident to be reopened within 5m debounce window, got %+v", evalReopen)
	}
	if evalReopen.IncidentID != firstIncidentID {
		t.Errorf("expected reopened incident to reuse ID %s, got %s", firstIncidentID, evalReopen.IncidentID)
	}
}

func TestDetector_HostLimitFallbackWhenMemoryMaxUnset(t *testing.T) {
	det := NewDetector(Config{
		NodeName:          "pi01",
		HostMemTotalBytes: 1024 * mib,
		HostReserveBytes:  64 * mib,
	})

	eval := det.Evaluate(Sample{
		Cgroup:        "/system.slice/app.service",
		MemoryCurrent: 200 * mib,
		MemoryMax:     0, // Tidak dibatasi ("max")
		At:            time.Now(),
	})

	expectedLimit := uint64((1024 - 64) * mib)
	if eval.LimitBytes != expectedLimit {
		t.Errorf("expected fallback host limit %d, got %d", expectedLimit, eval.LimitBytes)
	}
}

