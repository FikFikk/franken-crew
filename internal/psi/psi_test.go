package psi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

// mockTriggerPoller menyimulasikan pemicuan event POLLPRI, POLLERR, dan kegagalan registrasi trigger untuk pengujian unit.
type mockTriggerPoller struct {
	fn func(ctx context.Context, pressurePath string, spec TriggerSpec, onEvent func()) error
}

func (m *mockTriggerPoller) Watch(ctx context.Context, pressurePath string, spec TriggerSpec, onEvent func()) error {
	return m.fn(ctx, pressurePath, spec, onEvent)
}

func TestParseMetrics_ValidAndInvalid(t *testing.T) {
	raw := "some avg10=28.45 avg60=12.10 avg300=4.05 total=981234\nfull avg10=6.20 avg60=2.00 avg300=0.50 total=210000\n"
	m, err := ParseMetrics(raw)
	if err != nil {
		t.Fatalf("expected valid parse, got error: %v", err)
	}
	if m.Some.Avg10 != 28.45 || m.Some.Avg60 != 12.10 || m.Some.Total != 981234 {
		t.Errorf("unexpected 'some' metrics: %+v", m.Some)
	}
	if m.Full.Avg10 != 6.20 || m.Full.Total != 210000 {
		t.Errorf("unexpected 'full' metrics: %+v", m.Full)
	}

	// Uji input tidak valid (tanpa baris 'some')
	if _, err := ParseMetrics("full avg10=1.00 avg60=1.00 avg300=1.00 total=10\n"); err == nil {
		t.Errorf("expected error when 'some' line is missing")
	}
}

func TestDefaultTriggerSpec_Format(t *testing.T) {
	spec := DefaultTriggerSpec()
	if got := spec.String(); got != "some 150000 1000000" {
		t.Fatalf("expected 'some 150000 1000000', got %q", got)
	}
}

func TestWatcher_POLLPRI_ProducesEventUnder100ms(t *testing.T) {
	// Siapkan fixture cgroup dengan berkas memory.pressure
	mfs := kernelfs.NewMemFS()
	pressurePath := "/sys/fs/cgroup/franken.slice/haunted-api.service/memory.pressure"
	mfs.SetFile(pressurePath, "some avg10=32.10 avg60=10.00 avg300=2.00 total=550000\nfull avg10=5.50 avg60=1.00 avg300=0.10 total=120000\n")

	var registeredSpec string
	poller := &mockTriggerPoller{
		fn: func(ctx context.Context, path string, spec TriggerSpec, onEvent func()) error {
			registeredSpec = spec.String()
			// Simulasikan kernel membangunkan poller via POLLPRI
			onEvent()
			<-ctx.Done()
			return nil
		},
	}

	watcher := NewWatcher(WatcherConfig{
		FS:     mfs,
		Poller: poller,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan PressureEvent, 4)
	start := time.Now()
	go func() {
		_ = watcher.WatchTarget(ctx, "/franken.slice/haunted-api.service", pressurePath, out)
	}()

	select {
	case evt := <-out:
		elapsed := time.Since(start)
		// Sesuai Requirement 1.2, event harus dihasilkan dalam < 100 ms
		if elapsed > 100*time.Millisecond {
			t.Errorf("expected event within 100ms, took %v", elapsed)
		}
		if registeredSpec != "some 150000 1000000" {
			t.Errorf("expected trigger spec 'some 150000 1000000', got %q", registeredSpec)
		}
		if evt.DegradedMode {
			t.Errorf("expected DegradedMode=false on POLLPRI event")
		}
		if evt.Metrics.Some.Avg10 != 32.10 || evt.Metrics.Full.Avg10 != 5.50 {
			t.Errorf("unexpected event metrics: %+v", evt.Metrics)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timed out waiting for POLLPRI pressure event within 100ms")
	}
}

func TestWatcher_TriggerRejected_FallsBackToPollingAndAlertsOnce(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	pressurePath := "/sys/fs/cgroup/app.service/memory.pressure"
	mfs.SetFile(pressurePath, "some avg10=26.00 avg60=14.00 avg300=3.00 total=400000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

	var alertCount atomic.Int32
	poller := &mockTriggerPoller{
		fn: func(_ context.Context, _ string, _ TriggerSpec, _ func()) error {
			// Simulasikan penolakan penulisan trigger oleh kernel (EINVAL/EPERM)
			return ErrTriggerUnsupported
		},
	}

	watcher := NewWatcher(WatcherConfig{
		FS:                     mfs,
		Poller:                 poller,
		FallbackPollInterval:   15 * time.Millisecond,
		FallbackThresholdAvg10: 15.0,
		OnDegradedAlert: func(_ string, _ error) {
			alertCount.Add(1)
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan PressureEvent, 4)
	go func() {
		_ = watcher.WatchTarget(ctx, "/app.service", pressurePath, out)
	}()

	select {
	case evt := <-out:
		if !evt.DegradedMode {
			t.Errorf("expected DegradedMode=true when running in fallback polling")
		}
		if !watcher.IsDegraded() {
			t.Errorf("expected watcher.IsDegraded() to be true")
		}
		if alertCount.Load() != 1 {
			t.Errorf("expected degraded alert to fire exactly once, got %d", alertCount.Load())
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected fallback polling event, timed out")
	}
}

func TestWatcher_POLLERR_RediscoversCgroup(t *testing.T) {
	mfs := kernelfs.NewMemFS()
	pressurePath := "/sys/fs/cgroup/transient.service/memory.pressure"
	mfs.SetFile(pressurePath, "some avg10=20.00 avg60=5.00 avg300=1.00 total=10000\nfull avg10=1.00 avg60=0.00 avg300=0.00 total=1000\n")

	var attempts atomic.Int32
	poller := &mockTriggerPoller{
		fn: func(ctx context.Context, _ string, _ TriggerSpec, onEvent func()) error {
			attempt := attempts.Add(1)
			if attempt == 1 {
				// Percobaan pertama menyimulasikan cgroup terhapus (POLLERR)
				return ErrCgroupGone
			}
			// Percobaan kedua setelah re-discovery berhasil mengirim event
			onEvent()
			<-ctx.Done()
			return nil
		},
	}

	watcher := NewWatcher(WatcherConfig{
		FS:              mfs,
		Poller:          poller,
		RediscoverDelay: 20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan PressureEvent, 2)
	go func() {
		err := watcher.WatchTarget(ctx, "/transient.service", pressurePath, out)
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected WatchTarget error: %v", err)
		}
	}()

	select {
	case <-out:
		if attempts.Load() < 2 {
			t.Errorf("expected at least 2 watch attempts across POLLERR rediscovery, got %d", attempts.Load())
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("timed out waiting for event after POLLERR rediscovery")
	}
}

