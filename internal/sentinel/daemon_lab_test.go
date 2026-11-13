package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/cgroup"
	"github.com/FikFikk/franken-crew/internal/detector"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/psi"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

// labClock adalah jam simulasi yang aman dipakai bersama goroutine daemon.
type labClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *labClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *labClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

type labDaemon struct {
	d     *Daemon
	store *incident.Store
	srv   *mcpserver.Server
	clock *labClock
}

func newLabDaemon(t *testing.T, mfs *kernelfs.MemFS, mutate func(*Config)) *labDaemon {
	t.Helper()
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "sentinel_lab.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	clock := &labClock{now: time.Date(2026, 11, 13, 3, 17, 0, 0, time.UTC)}
	store.SetClock(clock.Now)

	cat := loadTestCatalog(t)
	eng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    newSpyPropDriver(),
		AdmissionDriver:   reflex.NewFSAdmissionDriver(t.TempDir()),
		HostMemTotalBytes: 4 * 1024 * 1024 * 1024,
		Clock:             clock.Now,
	})
	if err != nil {
		t.Fatalf("reflex.NewEngine: %v", err)
	}
	srv, err := mcpserver.New(mcpserver.Config{NodeName: "pi01-sim", Store: store, Catalog: cat, Reflex: eng, FS: mfs, Clock: clock.Now})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}
	t.Cleanup(srv.Close)

	cfg := Config{
		NodeName:  "pi01-sim",
		FS:        mfs,
		Store:     store,
		Catalog:   cat,
		Reflex:    eng,
		MCPServer: srv,
		Clock:     clock.Now,
		Detector:  detector.NewDetector(detector.Config{NodeName: "pi01-sim", HostMemTotalBytes: 4 * 1024 * 1024 * 1024}),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}
	return &labDaemon{d: d, store: store, srv: srv, clock: clock}
}

const labCgroup = "/sys/fs/cgroup/franken.slice/haunted-api.service"
const labRel = "/franken.slice/haunted-api.service"

// spikeToP1 menulis lonjakan memori (TTO < 30 s) agar evaluasi berikutnya membuka insiden P1 dengan dua refleks.
func spikeToP1(mfs *kernelfs.MemFS) {
	mfs.SetFile(labCgroup+"/memory.current", "490000000\n")
	mfs.SetFile(labCgroup+"/memory.pressure", "some avg10=42.50 avg60=18.00 avg300=4.00 total=900\nfull avg10=8.10 avg60=2.00 avg300=0.40 total=150\n")
}

type latencyPayload struct {
	ReflexID  string   `json:"reflex_id"`
	Action    string   `json:"action"`
	LatencyMS *float64 `json:"latency_ms"`
	Trigger   string   `json:"trigger"`
}

func reflexLatencyRows(t *testing.T, store *incident.Store, incID string) []latencyPayload {
	t.Helper()
	audit, err := store.GetAuditTrail(context.Background(), incID)
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	var out []latencyPayload
	for _, a := range audit {
		if a.EventType != "REFLEX_LATENCY" {
			continue
		}
		var p latencyPayload
		if err := json.Unmarshal([]byte(a.PayloadJSON), &p); err != nil {
			t.Fatalf("REFLEX_LATENCY payload is not JSON: %q (%v)", a.PayloadJSON, err)
		}
		if a.Actor != "sentinel" {
			t.Fatalf("REFLEX_LATENCY actor = %q, want sentinel", a.Actor)
		}
		out = append(out, p)
	}
	return out
}

func TestDaemon_RecordsReflexLatencyForSampleTrigger(t *testing.T) {
	mfs := setupHealthyMemFS()
	ld := newLabDaemon(t, mfs, func(c *Config) {
		c.IDSource = bytes.NewReader(bytes.Repeat([]byte{0x33}, 64))
	})
	subID, events, _ := ld.srv.Broker().Subscribe(0)
	defer ld.srv.Broker().Unsubscribe(subID)

	ctx := context.Background()
	if _, err := ld.d.EvaluateOnce(ctx, labCgroup); err != nil {
		t.Fatalf("baseline EvaluateOnce: %v", err)
	}
	ld.clock.Set(ld.clock.Now().Add(time.Second))
	spikeToP1(mfs)
	eval, err := ld.d.EvaluateOnce(ctx, labCgroup)
	if err != nil || !eval.IncidentOpen {
		t.Fatalf("expected an open incident, got %+v err=%v", eval, err)
	}

	rows := reflexLatencyRows(t, ld.store, eval.IncidentID)
	reflexes, _ := ld.store.GetReflexActionsByIncident(ctx, eval.IncidentID)
	if len(rows) != 2 || len(reflexes) != 2 {
		t.Fatalf("expected REFLEX_LATENCY for both reflexes (reclaim + throttle), got rows=%d reflexes=%d", len(rows), len(reflexes))
	}
	for i, row := range rows {
		if row.ReflexID != reflexes[i].ID || row.Action != reflexes[i].Action || row.Trigger != "sample" {
			t.Errorf("REFLEX_LATENCY[%d] = %+v, want reflex %s (%s) with trigger sample", i, row, reflexes[i].ID, reflexes[i].Action)
		}
		if row.LatencyMS == nil || *row.LatencyMS < 0 {
			t.Errorf("REFLEX_LATENCY[%d] latency_ms must be >= 0, got %v", i, row.LatencyMS)
		}
	}

	// SSE reflex.applied membawa latency_ms dan trigger
	seen := 0
	deadline := time.After(2 * time.Second)
	for seen < 2 {
		select {
		case ev := <-events:
			if ev.Type != "reflex.applied" {
				continue
			}
			if _, ok := ev.Data["latency_ms"].(float64); !ok || ev.Data["trigger"] != "sample" {
				t.Fatalf("reflex.applied must carry latency_ms and trigger, got %+v", ev.Data)
			}
			seen++
		case <-deadline:
			t.Fatalf("timed out waiting for reflex.applied events (seen %d)", seen)
		}
	}

	// Evidence pembuka memakai ID dari IDSource dan stempel waktu jam daemon, bukan jam dinding sampler
	evs, _ := ld.store.GetEvidenceByIncident(ctx, eval.IncidentID)
	if len(evs) != 1 || evs[0].ID != "EVD-333333333333" || evs[0].Kind != "telemetry_sample" {
		t.Fatalf("unexpected opening evidence: %+v", evs)
	}
	var sample cgroup.Sample
	if err := json.Unmarshal([]byte(evs[0].RedactedData), &sample); err != nil {
		t.Fatalf("telemetry_sample evidence is not JSON: %v", err)
	}
	if !sample.At.Equal(ld.clock.Now()) {
		t.Fatalf("telemetry_sample at = %s, want daemon clock %s", sample.At, ld.clock.Now())
	}
}

func TestDaemon_ReflexLatencyUsesMonotonicSourceAndFastTriggers(t *testing.T) {
	cases := []struct {
		name    string
		trigger string
		fire    func(d *Daemon, ctx context.Context)
	}{
		{"psi wakeup", "psi", func(d *Daemon, ctx context.Context) {
			d.handlePSIEvent(ctx, psi.PressureEvent{Cgroup: labRel, At: time.Now()})
		}},
		{"memory.events delta", "memory_events", func(d *Daemon, ctx context.Context) {
			d.handleEventsDelta(ctx, cgroup.EventsDelta{Cgroup: labRel, At: time.Now()})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mfs := setupHealthyMemFS()
			var monoMu sync.Mutex
			mono := time.Unix(0, 0)
			ld := newLabDaemon(t, mfs, func(c *Config) {
				// Jam monotonik injeksi maju 250 µs setiap kali dibaca sehingga latensi dapat diprediksi
				c.Monotonic = func() time.Time {
					monoMu.Lock()
					defer monoMu.Unlock()
					mono = mono.Add(250 * time.Microsecond)
					return mono
				}
			})
			ctx := context.Background()
			setLiveTargets(ld.d, labCgroup)
			if _, err := ld.d.EvaluateOnce(ctx, labCgroup); err != nil {
				t.Fatalf("baseline EvaluateOnce: %v", err)
			}
			ld.clock.Set(ld.clock.Now().Add(time.Second))
			spikeToP1(mfs)
			tc.fire(ld.d, ctx)

			incs, _ := ld.store.ListIncidents(ctx, "", 5)
			if len(incs) != 1 {
				t.Fatalf("expected one incident opened by the fast path, got %d", len(incs))
			}
			rows := reflexLatencyRows(t, ld.store, incs[0].ID)
			if len(rows) != 2 {
				t.Fatalf("expected two REFLEX_LATENCY rows, got %+v", rows)
			}
			for i, row := range rows {
				want := 0.25 * float64(i+1)
				if row.Trigger != tc.trigger || row.LatencyMS == nil || *row.LatencyMS != want {
					t.Errorf("row %d = trigger %q latency %v, want trigger %q latency %.2f ms from the monotonic source", i, row.Trigger, row.LatencyMS, tc.trigger, want)
				}
			}
		})
	}
}

func TestDaemon_ThrottlesFastPathRingWrites(t *testing.T) {
	mfs := setupHealthyMemFS()
	ld := newLabDaemon(t, mfs, nil)
	setLiveTargets(ld.d, labCgroup)
	ctx := context.Background()
	base := ld.clock.Now()

	// inotify memory.events dapat menembak ~100x/detik saat throttling memory.high: 200 event dalam 2 detik
	for i := 0; i < 200; i++ {
		ld.clock.Set(base.Add(time.Duration(i) * 10 * time.Millisecond))
		if i%2 == 0 {
			ld.d.handlePSIEvent(ctx, psi.PressureEvent{Cgroup: labRel, At: ld.clock.Now()})
		} else {
			ld.d.handleEventsDelta(ctx, cgroup.EventsDelta{Cgroup: labRel, At: ld.clock.Now()})
		}
	}
	end := base.Add(2 * time.Second)
	got := len(ld.srv.PSIRing().Window(labRel, base.Add(-time.Second), end))
	if got > 5 || got < 4 {
		t.Fatalf("200 fast events in 2s must add between 4 and 5 daemon ring points (one per 500 ms), got %d", got)
	}

	// Sampling 1 Hz tetap mencatat setiap detik
	before := got
	for i := 1; i <= 5; i++ {
		ld.clock.Set(end.Add(time.Duration(i) * time.Second))
		if _, err := ld.d.EvaluateOnce(ctx, labCgroup); err != nil {
			t.Fatalf("EvaluateOnce: %v", err)
		}
	}
	if after := len(ld.srv.PSIRing().Window(labRel, base.Add(-time.Second), end.Add(10*time.Second))); after != before+5 {
		t.Fatalf("1 Hz samples must not be throttled: %d -> %d points", before, after)
	}

	// Interval negatif menonaktifkan throttle (dipakai harness yang menghitung evaluasi lewat ring)
	unthrottled := newLabDaemon(t, setupHealthyMemFS(), func(c *Config) { c.RingWriteInterval = -1 })
	for i := 0; i < 3; i++ {
		if _, err := unthrottled.d.EvaluateOnce(ctx, labCgroup); err != nil {
			t.Fatalf("EvaluateOnce: %v", err)
		}
	}
	if n := len(unthrottled.srv.PSIRing().Query(labRel, 10, unthrottled.clock.Now())); n != 3 {
		t.Fatalf("RingWriteInterval < 0 must disable the throttle, got %d points", n)
	}
}

func TestDaemon_RecoveryCloseSavesTelemetrySeries(t *testing.T) {
	mfs := setupHealthyMemFS()
	ld := newLabDaemon(t, mfs, nil)
	ctx := context.Background()
	if _, err := ld.d.EvaluateOnce(ctx, labCgroup); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	ld.clock.Set(ld.clock.Now().Add(time.Second))
	mfs.SetFile(labCgroup+"/memory.pressure", "some avg10=30.00 avg60=10.00 avg300=2.00 total=900\nfull avg10=1.00 avg60=0.50 avg300=0.10 total=150\n")
	eval, err := ld.d.EvaluateOnce(ctx, labCgroup)
	if err != nil || !eval.IncidentOpen {
		t.Fatalf("expected P2 incident on PSI, got %+v err=%v", eval, err)
	}

	mfs.SetFile(labCgroup+"/memory.pressure", "some avg10=1.00 avg60=1.00 avg300=1.00 total=950\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=150\n")
	for i := 0; i < 130; i++ {
		ld.clock.Set(ld.clock.Now().Add(time.Second))
		if _, err := ld.d.EvaluateOnce(ctx, labCgroup); err != nil {
			t.Fatalf("EvaluateOnce %d: %v", i, err)
		}
	}
	inc, err := ld.store.GetIncident(ctx, eval.IncidentID)
	if err != nil || inc.State != incident.StateResolved {
		t.Fatalf("expected the daemon to auto-resolve after hysteresis, got %+v err=%v", inc, err)
	}
	evs, _ := ld.store.GetEvidenceByIncident(ctx, inc.ID)
	count := 0
	for _, ev := range evs {
		if ev.Kind == mcpserver.TelemetrySeriesKind {
			count++
			var series mcpserver.TelemetrySeries
			if err := json.Unmarshal([]byte(ev.RedactedData), &series); err != nil || len(series.Points) < 100 {
				t.Fatalf("recovery series must decode with the recorded samples, got %d points err=%v", len(series.Points), err)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one telemetry_series after closeIncidentOnRecovery, got %d", count)
	}
}

// setLiveTargets mengisi set target hidup tanpa menjalankan Run sehingga jalur cepat dapat diuji langsung.
func setLiveTargets(d *Daemon, targets ...string) {
	d.targetsMu.Lock()
	d.targetOrder = append([]string(nil), targets...)
	d.targetsMu.Unlock()
}
