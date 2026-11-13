package reflex

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/policy"
	"pgregory.net/rapid"
)

// spyPropertyDriver merekam setiap perubahan properti unit untuk memverifikasi rollback dan ketepatan nilai.
type spyPropertyDriver struct {
	mu            sync.Mutex
	current       map[string]UnitProperties
	setCalls      []UnitProperties
	setCount      map[string]int
	revertCount   atomic.Int32
	failNextSet   bool
	failRemaining int
}

func newSpyPropertyDriver() *spyPropertyDriver {
	return &spyPropertyDriver{
		current:  make(map[string]UnitProperties),
		setCount: make(map[string]int),
	}
}

func (s *spyPropertyDriver) GetProperties(_ context.Context, unit string) (UnitProperties, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.current[unit]; ok {
		return p, nil
	}
	return UnitProperties{MemoryHigh: "infinity", CPUQuota: "", IOWeight: "100"}, nil
}

func (s *spyPropertyDriver) SetProperties(_ context.Context, unit string, props UnitProperties) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNextSet {
		s.failNextSet = false
		return errors.New("simulated systemd dbus error")
	}
	if s.failRemaining > 0 {
		s.failRemaining--
		return errors.New("simulated transient systemd dbus error")
	}
	updated := UnitProperties{MemoryHigh: "infinity", IOWeight: "100"}
	if cur, ok := s.current[unit]; ok {
		updated = cur
	}
	if props.MemoryHigh != "" {
		updated.MemoryHigh = props.MemoryHigh
	}
	if props.ResetCPUQuota {
		updated.CPUQuota = ""
	} else if props.CPUQuota != "" {
		updated.CPUQuota = props.CPUQuota
	}
	if props.IOWeight != "" {
		updated.IOWeight = props.IOWeight
	}
	s.current[unit] = updated
	s.setCalls = append(s.setCalls, props)
	s.setCount[unit]++
	if props.MemoryHigh == "infinity" || props.MemoryHigh == "max" {
		s.revertCount.Add(1)
	}
	return nil
}

func setupReflexTestEnv(t *testing.T, clockFn func() time.Time) (*Engine, *incident.Store, *kernelfs.MemFS, *spyPropertyDriver, string) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "reflex_test.db")
	store, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open incident store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	incID := "INC-20261113-0317-pi01"
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID:       incID,
		Node:     "pi01",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P2",
		State:    incident.StateDetected,
	}); err != nil {
		t.Fatalf("failed to create test incident: %v", err)
	}

	catalogPath := filepath.Join("..", "..", "policy", "actions.yaml")
	cat, err := policy.LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("failed loading actions catalog: %v", err)
	}

	mfs := kernelfs.NewMemFS()
	cgPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	mfs.SetFile(cgPath+"/memory.current", "209715200\n") // 200 MiB
	mfs.SetFile(cgPath+"/memory.reclaim", "")

	spyProp := newSpyPropertyDriver()
	admDir := filepath.Join(tmpDir, "run-franken")

	eng, err := NewEngine(EngineConfig{
		Store:             store,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    spyProp,
		AdmissionDriver:   NewFSAdmissionDriver(admDir),
		HostMemTotalBytes: 2 * 1024 * 1024 * 1024, // 2 GiB
		Clock:             clockFn,
	})
	if err != nil {
		t.Fatalf("failed creating reflex engine: %v", err)
	}

	return eng, store, mfs, spyProp, incID
}

func TestReflex_AllThreeL1ActionsAndRollback(t *testing.T) {
	now := time.Date(2026, 11, 13, 3, 17, 0, 0, time.UTC)
	eng, store, mfs, spyProp, incID := setupReflexTestEnv(t, func() time.Time { return now })
	ctx := context.Background()
	cgPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"

	// 1. Uji cgroup_reclaim (target 20 MiB <= 25% dari 200 MiB = 50 MiB)
	reclaimAct, err := eng.ApplyReclaim(ctx, ReclaimRequest{
		IncidentID: incID,
		CgroupPath: cgPath,
		Bytes:      20 * 1024 * 1024,
		TTLSeconds: 90,
	})
	if err != nil {
		t.Fatalf("ApplyReclaim failed: %v", err)
	}
	reclaimData, _ := mfs.ReadFile(cgPath + "/memory.reclaim")
	if strings.TrimSpace(string(reclaimData)) != "20971520" {
		t.Errorf("expected 20971520 written to memory.reclaim, got %q", string(reclaimData))
	}

	// 2. Uji cgroup_throttle (dengan MemoryHigh + CPUQuota + IOWeight)
	throttleAct, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID:      incID,
		Unit:            "haunted-api.service",
		CgroupPath:      cgPath,
		MemoryHighBytes: 220 * 1024 * 1024,
		CPUQuota:        "50%",
		IOWeight:        "50",
		TTLSeconds:      120,
	})
	if err != nil {
		t.Fatalf("ApplyThrottle failed: %v", err)
	}
	propsAfter, _ := spyProp.GetProperties(ctx, "haunted-api.service")
	if propsAfter.MemoryHigh != "230686720" || propsAfter.CPUQuota != "50%" || propsAfter.IOWeight != "50" {
		t.Errorf("unexpected applied unit properties: %+v", propsAfter)
	}

	// 3. Uji admission_close
	admAct, err := eng.ApplyAdmissionClose(ctx, AdmissionRequest{
		IncidentID: incID,
		App:        "haunted-api",
		TTLSeconds: 120,
	})
	if err != nil {
		t.Fatalf("ApplyAdmissionClose failed: %v", err)
	}
	admState, _ := eng.admDriver.ReadState(ctx, "haunted-api")
	if !strings.HasPrefix(admState, "closed ") {
		t.Errorf("expected admission file to start with 'closed ', got %q", admState)
	}

	// 4. Uji batas maksimal 3 aksi L1 per insiden (aksi ke-4 wajib ditolak)
	_, err = eng.ApplyReclaim(ctx, ReclaimRequest{
		IncidentID: incID,
		CgroupPath: cgPath,
		Bytes:      10 * 1024 * 1024,
	})
	if !errors.Is(err, ErrMaxReflexReached) {
		t.Fatalf("expected ErrMaxReflexReached on 4th reflex action, got: %v", err)
	}

	// 5. Uji Rollback seluruh insiden -> memulihkan unit property dan admission file
	count, err := eng.RollbackIncident(ctx, incID)
	if err != nil {
		t.Fatalf("RollbackIncident failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 rolled back actions, got %d", count)
	}

	propsReverted, _ := spyProp.GetProperties(ctx, "haunted-api.service")
	if propsReverted.MemoryHigh != "infinity" || propsReverted.CPUQuota != "" || propsReverted.IOWeight != "100" {
		t.Errorf("unit properties were not reverted to original state: %+v", propsReverted)
	}
	spyProp.mu.Lock()
	lastCall := spyProp.setCalls[len(spyProp.setCalls)-1]
	spyProp.mu.Unlock()
	if !lastCall.ResetCPUQuota {
		t.Errorf("expected rollback SetProperties call to set ResetCPUQuota=true, got %+v", lastCall)
	}
	admReverted, _ := eng.admDriver.ReadState(ctx, "haunted-api")
	if strings.TrimSpace(admReverted) != "open" {
		t.Errorf("expected admission reverted to 'open', got %q", admReverted)
	}

	// Pastikan status ketiga aksi di SQLite berubah menjadi ROLLED_BACK
	for _, id := range []string{reclaimAct.ID, throttleAct.ID, admAct.ID} {
		rec, err := store.GetReflexAction(ctx, id)
		if err != nil || rec.Status != "ROLLED_BACK" {
			t.Errorf("expected action %s status ROLLED_BACK, got %+v (err=%v)", id, rec, err)
		}
	}
}

func TestReflex_SafetyGuardrails(t *testing.T) {
	now := time.Now()
	eng, _, _, _, incID := setupReflexTestEnv(t, func() time.Time { return now })
	ctx := context.Background()
	cgPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"

	// Tolak reclaim melebihi 25% dari 200 MiB (> 50 MiB)
	if _, err := eng.ApplyReclaim(ctx, ReclaimRequest{
		IncidentID: incID,
		CgroupPath: cgPath,
		Bytes:      60 * 1024 * 1024,
	}); !errors.Is(err, ErrReclaimExceedsCap) {
		t.Errorf("expected ErrReclaimExceedsCap, got: %v", err)
	}

	// Tolak MemoryHigh di bawah memory.current (150 MiB < 200 MiB)
	if _, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID:      incID,
		Unit:            "haunted-api.service",
		CgroupPath:      cgPath,
		MemoryHighBytes: 150 * 1024 * 1024,
	}); !errors.Is(err, ErrMemoryHighBelowUsage) {
		t.Errorf("expected ErrMemoryHighBelowUsage, got: %v", err)
	}

	// Tolak MemoryHigh di atas 95% host RAM (1.95 GiB > 1.90 GiB)
	if _, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID: incID,
		Unit:       "haunted-api.service",
		CgroupPath: cgPath,
		// 2000 MiB > 1945.6 MiB (95% dari 2 GiB)
		MemoryHighBytes: 2000 * 1024 * 1024,
	}); !errors.Is(err, ErrMemoryHighAboveHostCap) {
		t.Errorf("expected ErrMemoryHighAboveHostCap, got: %v", err)
	}

	// Tolak TTL > 15 menit (901 detik)
	if _, err := eng.ApplyAdmissionClose(ctx, AdmissionRequest{
		IncidentID: incID,
		App:        "haunted-api",
		TTLSeconds: 901,
	}); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("expected ErrInvalidTTL, got: %v", err)
	}

	// Tolak unit yang dilindungi (sshd.service)
	if _, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID: incID,
		Unit:       "sshd.service",
		CgroupPath: cgPath,
	}); !errors.Is(err, ErrProtectedTarget) {
		t.Errorf("expected ErrProtectedTarget for sshd.service, got: %v", err)
	}
}

func TestReflex_TTLSchedulerSurvivesSentinelRestart(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "persist_restart.db")
	catalogPath := filepath.Join("..", "..", "policy", "actions.yaml")
	cat, err := policy.LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("failed loading catalog: %v", err)
	}

	mfs := kernelfs.NewMemFS()
	cgPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	mfs.SetFile(cgPath+"/memory.current", "104857600\n") // 100 MiB

	spyProp := newSpyPropertyDriver()
	t0 := time.Date(2026, 11, 13, 3, 20, 0, 0, time.UTC)

	// === FASE 1: Sentinel pertama menerapkan aksi refleks dengan TTL 90 detik ===
	store1, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("open store1: %v", err)
	}
	ctx := context.Background()
	incID := "INC-20261113-0320-pi01"
	_ = store1.CreateIncident(ctx, &incident.Incident{
		ID:       incID,
		Node:     "pi01",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P2",
		State:    incident.StateDetected,
	})

	eng1, err := NewEngine(EngineConfig{
		Store:             store1,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    spyProp,
		HostMemTotalBytes: 2 * 1024 * 1024 * 1024,
		Clock:             func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatalf("create eng1: %v", err)
	}

	act, err := eng1.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID:      incID,
		Unit:            "haunted-api.service",
		CgroupPath:      cgPath,
		MemoryHighBytes: 120 * 1024 * 1024,
		TTLSeconds:      90,
	})
	if err != nil {
		t.Fatalf("ApplyThrottle failed: %v", err)
	}

	// Simulasikan Sentinel restart dengan menutup database & membuang instance engine1
	_ = store1.Close()

	// === FASE 2: Sentinel bangkit kembali pada t0 + 95 detik (melewati batas TTL 90 detik) ===
	store2, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("open store2 after restart: %v", err)
	}
	defer store2.Close()

	eng2, err := NewEngine(EngineConfig{
		Store:             store2,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    spyProp,
		HostMemTotalBytes: 2 * 1024 * 1024 * 1024,
		Clock:             func() time.Time { return t0.Add(95 * time.Second) },
	})
	if err != nil {
		t.Fatalf("create eng2: %v", err)
	}

	swept, err := eng2.SweepExpired(ctx)
	if err != nil {
		t.Fatalf("SweepExpired failed: %v", err)
	}
	if swept != 1 {
		t.Fatalf("expected 1 expired reflex swept after restart, got %d", swept)
	}

	// Verifikasi properti unit dikembalikan ke nilai awal dan status di SQLite menjadi EXPIRED_ROLLED_BACK
	propsRestored, _ := spyProp.GetProperties(ctx, "haunted-api.service")
	if propsRestored.MemoryHigh != "infinity" {
		t.Errorf("expected MemoryHigh restored to 'infinity', got %q", propsRestored.MemoryHigh)
	}
	rec, err := store2.GetReflexAction(ctx, act.ID)
	if err != nil || rec.Status != "EXPIRED_ROLLED_BACK" {
		t.Errorf("expected EXPIRED_ROLLED_BACK after TTL sweep, got %+v (err=%v)", rec, err)
	}
}

// Property test P3: Setiap aksi L1 yang diterapkan hanya di-rollback tepat satu kali,
// meskipun Rollback, RollbackIncident, dan SweepExpired dipanggil berulang kali secara paralel.
func TestReflex_Property_P3_AppliedActionRolledBackExactlyOnce(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		tmpDir := t.TempDir()
		store, err := incident.NewStore(filepath.Join(tmpDir, "p3.db"))
		if err != nil {
			rt.Fatalf("store init: %v", err)
		}
		defer store.Close()

		ctx := context.Background()
		incID := "INC-20261113-0001-p3"
		_ = store.CreateIncident(ctx, &incident.Incident{
			ID: incID, Node: "pi01", Cgroup: "/app.service", Severity: "P2", State: incident.StateDetected,
		})

		mfs := kernelfs.NewMemFS()
		cgPath := "/sys/fs/cgroup/app.service"
		mfs.SetFile(cgPath+"/memory.current", "104857600\n")

		spyProp := newSpyPropertyDriver()
		now := time.Date(2026, 11, 13, 4, 0, 0, 0, time.UTC)
		var curTimeMu sync.Mutex
		curTime := now

		eng, err := NewEngine(EngineConfig{
			Store:             store,
			FS:                mfs,
			PropertyDriver:    spyProp,
			HostMemTotalBytes: 2 * 1024 * 1024 * 1024,
			Clock: func() time.Time {
				curTimeMu.Lock()
				defer curTimeMu.Unlock()
				return curTime
			},
		})
		if err != nil {
			rt.Fatalf("engine init: %v", err)
		}

		// Terapkan antara 1 sampai 3 aksi throttle secara acak
		numActions := rapid.IntRange(1, 3).Draw(rt, "numActions")
		var ids []string
		for i := 0; i < numActions; i++ {
			act, err := eng.ApplyThrottle(ctx, ThrottleRequest{
				IncidentID:      incID,
				Unit:            "app.service",
				CgroupPath:      cgPath,
				MemoryHighBytes: 120 * 1024 * 1024,
				TTLSeconds:      60,
			})
			if err != nil {
				rt.Fatalf("apply %d failed: %v", i, err)
			}
			ids = append(ids, act.ID)
		}

		// Majukan waktu melewati TTL sehingga SweepExpired juga berhak memicu rollback
		curTimeMu.Lock()
		curTime = now.Add(120 * time.Second)
		curTimeMu.Unlock()

		// Jalankan rollback berulang kali secara paralel (SweepExpired + Rollback langsung + RollbackIncident)
		var wg sync.WaitGroup
		calls := rapid.IntRange(2, 6).Draw(rt, "concurrentCalls")
		for c := 0; c < calls; c++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				switch idx % 3 {
				case 0:
					_, _ = eng.SweepExpired(ctx)
				case 1:
					_, _ = eng.RollbackIncident(ctx, incID)
				case 2:
					for _, id := range ids {
						_, _ = eng.Rollback(ctx, id, false)
					}
				}
			}(c)
		}
		wg.Wait()

		// Verifikasi bahwa jumlah revert driver == jumlah aksi yang diterapkan (tepat satu kali per aksi)
		if got := int(spyProp.revertCount.Load()); got != numActions {
			rt.Fatalf("invariant P3 violated: applied=%d actions, but reverted %d times", numActions, got)
		}
	})
}

// Property test P4: MemoryHigh yang ditetapkan oleh aksi refleks selalu >= memory.current saat diterapkan
// dan <= 95% total RAM host.
func TestReflex_Property_P4_MemoryHighAlwaysGECurrentUsage(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		tmpDir := t.TempDir()
		store, err := incident.NewStore(filepath.Join(tmpDir, "p4.db"))
		if err != nil {
			rt.Fatalf("store init: %v", err)
		}
		defer store.Close()

		ctx := context.Background()
		incID := "INC-20261113-0002-p4"
		_ = store.CreateIncident(ctx, &incident.Incident{
			ID: incID, Node: "pi01", Cgroup: "/app.service", Severity: "P2", State: incident.StateDetected,
		})

		hostRAM := rapid.Uint64Range(512*1024*1024, 4*1024*1024*1024).Draw(rt, "hostRAM")
		currentMem := rapid.Uint64Range(10*1024*1024, hostRAM).Draw(rt, "currentMem")
		proposedHigh := rapid.Uint64Range(0, hostRAM).Draw(rt, "proposedHigh")

		mfs := kernelfs.NewMemFS()
		cgPath := "/sys/fs/cgroup/app.service"
		mfs.SetFile(cgPath+"/memory.current", strconv.FormatUint(currentMem, 10)+"\n")

		spyProp := newSpyPropertyDriver()
		eng, err := NewEngine(EngineConfig{
			Store:             store,
			FS:                mfs,
			PropertyDriver:    spyProp,
			HostMemTotalBytes: hostRAM,
		})
		if err != nil {
			rt.Fatalf("engine init: %v", err)
		}

		_, applyErr := eng.ApplyThrottle(ctx, ThrottleRequest{
			IncidentID:      incID,
			Unit:            "app.service",
			CgroupPath:      cgPath,
			MemoryHighBytes: proposedHigh,
		})

		if applyErr == nil {
			props, _ := spyProp.GetProperties(ctx, "app.service")
			appliedVal, parseErr := strconv.ParseUint(props.MemoryHigh, 10, 64)
			if parseErr != nil {
				rt.Fatalf("applied MemoryHigh %q is not uint64: %v", props.MemoryHigh, parseErr)
			}
			if appliedVal < currentMem {
				rt.Fatalf("invariant P4 violated: applied MemoryHigh=%d < currentMem=%d", appliedVal, currentMem)
			}
			hostCap := uint64(float64(hostRAM) * MaxHostRAMRatio)
			if appliedVal > hostCap {
				rt.Fatalf("invariant violated: applied MemoryHigh=%d > 95%% hostRAM=%d", appliedVal, hostCap)
			}
		}
	})
}

func TestExecutorPropertyDriver_BuildSetPropertyArgs_CPUQuotaReset(t *testing.T) {
	// 1. Saat ResetCPUQuota aktif atau nilai sebelumnya masih berupa sentinel "infinity"/"[not set]", kirim "CPUQuota=".
	for _, props := range []UnitProperties{
		{MemoryHigh: "infinity", ResetCPUQuota: true},
		{MemoryHigh: "infinity", CPUQuota: "infinity"},
		{CPUQuota: "[not set]"},
	} {
		args, err := buildSetPropertyArgs("haunted-api.service", props)
		if err != nil {
			t.Fatalf("buildSetPropertyArgs(%+v) returned error: %v", props, err)
		}
		var hasReset bool
		for _, a := range args {
			if a == "CPUQuota=infinity" || a == "CPUQuota=[not set]" {
				t.Fatalf("systemctl arg must never contain %q (args=%v)", a, args)
			}
			if a == "CPUQuota=" {
				hasReset = true
			}
		}
		if !hasReset {
			t.Fatalf("expected 'CPUQuota=' reset arg for %+v, got %v", props, args)
		}
	}

	// 2. Saat unit sebelumnya memiliki kuota spesifik (mis. "75%"), rollback wajib mempertahankan nilai tersebut.
	args, err := buildSetPropertyArgs("haunted-api.service", UnitProperties{MemoryHigh: "infinity", CPUQuota: "75%"})
	if err != nil {
		t.Fatalf("buildSetPropertyArgs explicit quota: %v", err)
	}
	want := []string{"set-property", "--runtime", "haunted-api.service", "MemoryHigh=infinity", "CPUQuota=75%"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("expected args %v, got %v", want, args)
	}
}

func TestReflex_CPUQuotaBaselineInheritedAndResetWithoutInfinity(t *testing.T) {
	now := time.Date(2026, 11, 13, 5, 0, 0, 0, time.UTC)
	eng, _, _, spyProp, incID := setupReflexTestEnv(t, func() time.Time { return now })
	ctx := context.Background()
	cgPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"

	// Terapkan 2 throttle beruntun: keduanya mengubah CPUQuota dari kondisi awal unset.
	if _, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID:      incID,
		Unit:            "haunted-api.service",
		CgroupPath:      cgPath,
		MemoryHighBytes: 220 * 1024 * 1024,
		CPUQuota:        "50%",
		TTLSeconds:      120,
	}); err != nil {
		t.Fatalf("first ApplyThrottle: %v", err)
	}
	if _, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID:      incID,
		Unit:            "haunted-api.service",
		CgroupPath:      cgPath,
		MemoryHighBytes: 230 * 1024 * 1024,
		CPUQuota:        "25%",
		TTLSeconds:      120,
	}); err != nil {
		t.Fatalf("second ApplyThrottle: %v", err)
	}

	if _, err := eng.RollbackIncident(ctx, incID); err != nil {
		t.Fatalf("RollbackIncident: %v", err)
	}

	props, _ := spyProp.GetProperties(ctx, "haunted-api.service")
	if props.CPUQuota != "" {
		t.Fatalf("expected CPUQuota restored to unset empty string, got %q", props.CPUQuota)
	}
}

func TestReflex_RollbackRetryWithBackoffAndEscalation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "retry_test.db")
	store, err := incident.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	mfs := kernelfs.NewMemFS()
	cgPath := "/sys/fs/cgroup/franken.slice/haunted-api.service"
	mfs.SetFile(cgPath+"/memory.current", "104857600\n")

	ctx := context.Background()
	incID := "INC-RETRY-01"
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID:       incID,
		Node:     "pi01",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P1",
		State:    incident.StateDetected,
	}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	t0 := time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)
	var curMu sync.Mutex
	curNow := t0
	clockFn := func() time.Time {
		curMu.Lock()
		defer curMu.Unlock()
		return curNow
	}
	setTime := func(ts time.Time) {
		curMu.Lock()
		curNow = ts
		curMu.Unlock()
	}

	spyProp := newSpyPropertyDriver()
	var escalatedCount atomic.Int32
	eng, err := NewEngine(EngineConfig{
		Store:                  store,
		FS:                     mfs,
		Catalog:                cat,
		PropertyDriver:         spyProp,
		HostMemTotalBytes:      2 * 1024 * 1024 * 1024,
		Clock:                  clockFn,
		RollbackMaxAttempts:    3,
		RollbackInitialBackoff: 5 * time.Second,
		RollbackMaxBackoff:     30 * time.Second,
		OnRollbackEscalated: func(_ incident.ReflexAction, _ error) {
			escalatedCount.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// === Bagian A: Kegagalan transien (2x gagal lalu berhasil di percobaan ke-3) ===
	act1, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID:      incID,
		Unit:            "haunted-api.service",
		CgroupPath:      cgPath,
		MemoryHighBytes: 120 * 1024 * 1024,
		CPUQuota:        "50%",
		TTLSeconds:      60,
	})
	if err != nil {
		t.Fatalf("ApplyThrottle 1: %v", err)
	}

	// Simulasikan 2 kegagalan SetProperties saat TTL habis pada t0 + 60s
	spyProp.mu.Lock()
	spyProp.failRemaining = 2
	spyProp.mu.Unlock()

	setTime(t0.Add(60 * time.Second))
	swept, sweepErr := eng.SweepExpired(ctx)
	if sweepErr == nil || swept != 0 {
		t.Fatalf("expected attempt 1 failure (swept=0), got swept=%d err=%v", swept, sweepErr)
	}
	rec1, _ := store.GetReflexAction(ctx, act1.ID)
	if rec1.Status != "APPLIED" {
		t.Fatalf("expected status to stay APPLIED for retry instead of premature FAILED_ROLLBACK, got %s", rec1.Status)
	}

	// Pada t0 + 63s (baru +3s < initial backoff 5s), SweepExpired wajib menunda pemanggilan driver
	spyProp.mu.Lock()
	callsAfterAttempt1 := spyProp.setCount["haunted-api.service"]
	spyProp.mu.Unlock()

	setTime(t0.Add(63 * time.Second))
	_, _ = eng.SweepExpired(ctx)
	spyProp.mu.Lock()
	if spyProp.setCount["haunted-api.service"] != callsAfterAttempt1 {
		t.Fatalf("expected SweepExpired to respect 5s backoff before retry")
	}
	spyProp.mu.Unlock()

	// Pada t0 + 65s (+5s terpenuhi), percobaan ke-2 berjalan dan gagal -> jadwal berikutnya +10s (t0 + 75s)
	setTime(t0.Add(65 * time.Second))
	if swept, sweepErr = eng.SweepExpired(ctx); sweepErr == nil || swept != 0 {
		t.Fatalf("expected attempt 2 failure, got swept=%d err=%v", swept, sweepErr)
	}
	rec1, _ = store.GetReflexAction(ctx, act1.ID)
	if rec1.Status != "APPLIED" {
		t.Fatalf("expected status APPLIED after attempt 2 failure, got %s", rec1.Status)
	}

	// Sebelum +10s tercapai (t0 + 70s), SweepExpired kembali menunggu
	setTime(t0.Add(70 * time.Second))
	_, _ = eng.SweepExpired(ctx)
	if recCheck, _ := store.GetReflexAction(ctx, act1.ID); recCheck.Status != "APPLIED" {
		t.Fatalf("expected status APPLIED while waiting 10s backoff, got %s", recCheck.Status)
	}

	// Pada t0 + 75s (+10s terpenuhi), percobaan ke-3 sukses -> status menjadi EXPIRED_ROLLED_BACK
	setTime(t0.Add(75 * time.Second))
	swept, sweepErr = eng.SweepExpired(ctx)
	if sweepErr != nil || swept != 1 {
		t.Fatalf("expected attempt 3 to succeed (swept=1), got swept=%d err=%v", swept, sweepErr)
	}
	rec1, _ = store.GetReflexAction(ctx, act1.ID)
	if rec1.Status != "EXPIRED_ROLLED_BACK" {
		t.Fatalf("expected EXPIRED_ROLLED_BACK after retry recovery, got %s", rec1.Status)
	}
	if escalatedCount.Load() != 0 {
		t.Fatalf("expected 0 escalations when retry recovered, got %d", escalatedCount.Load())
	}

	// === Bagian B: Kegagalan persisten melampaui RollbackMaxAttempts (3) -> eskalasi FAILED_ROLLBACK ===
	act2, err := eng.ApplyThrottle(ctx, ThrottleRequest{
		IncidentID:      incID,
		Unit:            "haunted-api.service",
		CgroupPath:      cgPath,
		MemoryHighBytes: 120 * 1024 * 1024,
		TTLSeconds:      60,
	})
	if err != nil {
		t.Fatalf("ApplyThrottle 2: %v", err)
	}

	spyProp.mu.Lock()
	spyProp.failRemaining = 10
	spyProp.mu.Unlock()

	base := t0.Add(200 * time.Second)
	setTime(base)
	_, err = eng.SweepExpired(ctx) // Attempt 1 -> backoff +5s
	if err == nil || errors.Is(err, ErrRollbackEscalated) {
		t.Fatalf("attempt 1 should schedule retry without escalation, got %v", err)
	}
	setTime(base.Add(5 * time.Second))
	_, err = eng.SweepExpired(ctx) // Attempt 2 -> backoff +10s
	if err == nil || errors.Is(err, ErrRollbackEscalated) {
		t.Fatalf("attempt 2 should schedule retry without escalation, got %v", err)
	}
	setTime(base.Add(15 * time.Second))
	_, err = eng.SweepExpired(ctx) // Attempt 3 -> batas tercapai -> eskalasi
	if !errors.Is(err, ErrRollbackEscalated) {
		t.Fatalf("expected ErrRollbackEscalated on attempt 3, got %v", err)
	}

	rec2, _ := store.GetReflexAction(ctx, act2.ID)
	if rec2.Status != "FAILED_ROLLBACK" {
		t.Fatalf("expected terminal FAILED_ROLLBACK after max retries, got %s", rec2.Status)
	}
	if escalatedCount.Load() != 1 {
		t.Fatalf("expected OnRollbackEscalated callback once, got %d", escalatedCount.Load())
	}
	escAuditCount, err := store.CountAuditByEvent(ctx, incID, "REFLEX_ROLLBACK_ESCALATED")
	if err != nil || escAuditCount != 1 {
		t.Fatalf("expected 1 REFLEX_ROLLBACK_ESCALATED audit entry, got %d (err=%v)", escAuditCount, err)
	}
}
