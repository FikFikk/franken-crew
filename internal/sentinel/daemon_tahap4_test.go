package sentinel

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/journal"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
)

type tahap4PropDriver struct {
	mu       sync.Mutex
	setCalls int
}

func (p *tahap4PropDriver) GetProperties(_ context.Context, _ string) (reflex.UnitProperties, error) {
	return reflex.UnitProperties{}, nil
}

func (p *tahap4PropDriver) SetProperties(_ context.Context, _ string, _ reflex.UnitProperties) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setCalls++
	return nil
}

func (p *tahap4PropDriver) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.setCalls
}

func setupTahap4Daemon(t *testing.T, mfs *kernelfs.MemFS, cgroupPaths []string) (*Daemon, *incident.Store, *mcpserver.Server, *tahap4PropDriver) {
	t.Helper()
	tmpDir := t.TempDir()

	store, err := incident.NewStore(filepath.Join(tmpDir, "sentinel_t4.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	kp, err := approval.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	clockFn := func() time.Time { return time.Date(2026, 11, 13, 13, 0, 0, 0, time.UTC) }
	verifier, err := approval.NewVerifier(kp.PublicKey, store, clockFn)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	propDriver := &tahap4PropDriver{}
	reflexEng, err := reflex.NewEngine(reflex.EngineConfig{
		Store:             store,
		FS:                mfs,
		Catalog:           cat,
		PropertyDriver:    propDriver,
		AdmissionDriver:   reflex.NewFSAdmissionDriver(filepath.Join(tmpDir, "run-franken")),
		HostMemTotalBytes: 1024 * 1024 * 1024,
		Clock:             clockFn,
	})
	if err != nil {
		t.Fatalf("reflex.NewEngine: %v", err)
	}

	srv, err := mcpserver.New(mcpserver.Config{
		NodeName:    "pi01",
		Version:     "0.2.0",
		Store:       store,
		Catalog:     cat,
		Reflex:      reflexEng,
		Verifier:    verifier,
		FS:          mfs,
		CgroupRoot:  "/sys/fs/cgroup",
		ProcRoot:    "/proc",
		BearerToken: "test-bearer-token-tahap4",
		Clock:       clockFn,
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}
	t.Cleanup(srv.Close)

	d, err := New(Config{
		NodeName:    "pi01",
		FS:          mfs,
		CgroupRoot:  "/sys/fs/cgroup",
		ProcRoot:    "/proc",
		CgroupPaths: cgroupPaths,
		Store:       store,
		Catalog:     cat,
		Reflex:      reflexEng,
		MCPServer:   srv,
		Clock:       clockFn,
	})
	if err != nil {
		t.Fatalf("sentinel.New: %v", err)
	}
	return d, store, srv, propDriver
}

func seedBaseHostFS() *kernelfs.MemFS {
	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpu memory io pids\n")
	mfs.SetFile("/sys/fs/cgroup/memory.current", "900000000\n")
	mfs.SetFile("/sys/fs/cgroup/memory.reclaim", "")
	mfs.SetFile("/proc/meminfo", "MemTotal:        1048576 kB\nMemFree:          131072 kB\nMemAvailable:     262144 kB\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=1.00 avg60=0.50 avg300=0.20 total=100\nfull avg10=0.10 avg60=0.05 avg300=0.01 total=10\n")
	return mfs
}

func TestDaemon_CgroupDiscoverySkipsRootAndSlicesAndTargetsLeavesOnly(t *testing.T) {
	mfs := seedBaseHostFS()

	// Root slice, scope sistem, dan sesi user yang dilarang menjadi target refleks
	mfs.SetFile("/sys/fs/cgroup/init.scope/memory.current", "10485760\n")
	mfs.SetFile("/sys/fs/cgroup/user.slice/memory.current", "20971520\n")
	mfs.SetFile("/sys/fs/cgroup/user.slice/user-1000.slice/session-1.scope/memory.current", "10485760\n")
	mfs.SetFile("/sys/fs/cgroup/user.slice/user-1000.slice/app.service/memory.current", "10485760\n")
	mfs.SetFile("/sys/fs/cgroup/system.slice/memory.current", "400000000\n")
	mfs.SetFile("/sys/fs/cgroup/franken.slice/memory.current", "200000000\n")

	// Unit terlindungi harus dilewati
	mfs.SetFile("/sys/fs/cgroup/system.slice/sshd.service/memory.current", "16777216\n")
	mfs.SetFile("/sys/fs/cgroup/system.slice/systemd-journald.service/memory.current", "33554432\n")

	// Service non-leaf (memiliki sub-cgroup anak) tidak boleh dianggap target leaf
	mfs.SetFile("/sys/fs/cgroup/system.slice/delegated.service/memory.current", "125829120\n")
	mfs.SetFile("/sys/fs/cgroup/system.slice/delegated.service/child.scope/memory.current", "62914560\n")

	// Sub-slice dalam system.slice: slice-nya diabaikan, hanya leaf .service di dalamnya yang masuk
	mfs.SetFile("/sys/fs/cgroup/system.slice/custom.slice/memory.current", "90000000\n")
	mfs.SetFile("/sys/fs/cgroup/system.slice/custom.slice/custom-api.service/memory.current", "83886080\n")

	// Leaf service sah yang harus ditemukan
	mfs.SetFile("/sys/fs/cgroup/system.slice/worker.service/memory.current", "104857600\n")
	mfs.SetFile("/sys/fs/cgroup/franken.slice/haunted-api.service/memory.current", "209715200\n")

	d, _, _, _ := setupTahap4Daemon(t, mfs, nil)
	targets := d.resolveTargetCgroups()

	want := []string{
		"/sys/fs/cgroup/franken.slice/haunted-api.service",
		"/sys/fs/cgroup/system.slice/custom.slice/custom-api.service",
		"/sys/fs/cgroup/system.slice/worker.service",
	}
	slices.Sort(targets)
	slices.Sort(want)
	if !slices.Equal(targets, want) {
		t.Fatalf("resolveTargetCgroups() = %v, harap %v", targets, want)
	}

	// Saat tidak ada leaf service sama sekali, discovery tidak boleh fallback ke cgroupRoot
	emptyFS := seedBaseHostFS()
	emptyFS.SetFile("/sys/fs/cgroup/init.scope/memory.current", "10485760\n")
	emptyFS.SetFile("/sys/fs/cgroup/user.slice/memory.current", "20971520\n")
	emptyFS.SetFile("/sys/fs/cgroup/system.slice/memory.current", "400000000\n")
	dEmpty, _, _, _ := setupTahap4Daemon(t, emptyFS, nil)
	if got := dEmpty.resolveTargetCgroups(); len(got) != 0 {
		t.Fatalf("resolveTargetCgroups() pada host tanpa leaf service = %v, harap kosong (tanpa fallback ke root)", got)
	}
}

func TestDaemon_EvaluateOnceNeverMutatesSystemSliceOrNonLeafMemoryReclaim(t *testing.T) {
	mfs := seedBaseHostFS()
	sliceCg := "/sys/fs/cgroup/system.slice"
	mfs.SetFile(sliceCg+"/memory.current", "920000000\n")
	mfs.SetFile(sliceCg+"/memory.high", "max\n")
	mfs.SetFile(sliceCg+"/memory.max", "max\n")
	mfs.SetFile(sliceCg+"/memory.events", "low 0\nhigh 4\nmax 0\noom 1\noom_kill 0\n")
	mfs.SetFile(sliceCg+"/memory.pressure", "some avg10=75.00 avg60=50.00 avg300=20.00 total=9000\nfull avg10=35.00 avg60=20.00 avg300=10.00 total=4000\n")
	mfs.SetFile(sliceCg+"/memory.reclaim", "")
	mfs.SetFile(sliceCg+"/worker.service/memory.current", "500000000\n")

	d, _, _, propDriver := setupTahap4Daemon(t, mfs, []string{sliceCg})

	if _, err := d.EvaluateOnce(context.Background(), sliceCg); err != nil {
		t.Fatalf("EvaluateOnce(1): %v", err)
	}
	mfs.SetFile(sliceCg+"/memory.current", "980000000\n")
	if _, err := d.EvaluateOnce(context.Background(), sliceCg); err != nil {
		t.Fatalf("EvaluateOnce(2): %v", err)
	}

	reclaimBytes, err := mfs.ReadFile(sliceCg + "/memory.reclaim")
	if err != nil {
		t.Fatalf("ReadFile memory.reclaim: %v", err)
	}
	if string(reclaimBytes) != "" {
		t.Fatalf("memory.reclaim pada /system.slice ikut termutasi: %q", string(reclaimBytes))
	}
	highBytes, _ := mfs.ReadFile(sliceCg + "/memory.high")
	if string(highBytes) != "max\n" {
		t.Fatalf("memory.high pada /system.slice termutasi: %q", string(highBytes))
	}
	if propDriver.Calls() != 0 {
		t.Fatalf("propDriver dipanggil %d kali pada /system.slice, harap 0", propDriver.Calls())
	}
}

func TestDaemon_ConsumeJournalEventsRedactsAndIsolatesUnmatchedUnits(t *testing.T) {
	mfs := seedBaseHostFS()
	d, store, srv, _ := setupTahap4Daemon(t, mfs, []string{"/franken.slice/haunted-api.service"})

	ctx := context.Background()
	incID := "INC-20261113-1300-pi01"
	if err := store.CreateIncident(ctx, &incident.Incident{
		ID:       incID,
		Node:     "pi01",
		Cgroup:   "/franken.slice/haunted-api.service",
		Severity: "P1",
		State:    incident.StateDetected,
	}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	d.evalMu.Lock()
	d.openByCgroup["/franken.slice/haunted-api.service"] = incID
	d.evalMu.Unlock()

	handler, err := srv.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	httpSrv := httptest.NewServer(handler)
	defer httpSrv.Close()

	sseCtx, sseCancel := context.WithTimeout(ctx, 5*time.Second)
	defer sseCancel()

	req, err := http.NewRequestWithContext(sseCtx, http.MethodGet, httpSrv.URL+"/v1/events", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer test-bearer-token-tahap4")
	resp, err := httpSrv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /v1/events: %v", err)
	}
	defer resp.Body.Close()

	sseLines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data:") {
				sseLines <- line
			}
		}
	}()

	jCtx, jCancel := context.WithCancel(ctx)
	jCh := make(chan journal.JournalEvent, 4)
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		d.consumeJournalEvents(jCtx, jCh)
	}()

	jCh <- journal.JournalEvent{
		Category: journal.PatternHeapOOM,
		Unit:     "haunted-api.service",
		Message:  "JavaScript heap out of memory key=sk-proj-1234567890abcdefghijklmnop phone=0812-3456-7890 bytes=1073741824",
	}
	jCh <- journal.JournalEvent{
		Category: journal.PatternOOM,
		Unit:     "unrelated-worker.service",
		Message:  "out of memory token=sk-secret99999999999999999999",
	}

	var matchedLine string
	deadline := time.After(3 * time.Second)
	for matchedLine == "" {
		select {
		case line := <-sseLines:
			if strings.Contains(line, "journal.pattern") && strings.Contains(line, "haunted-api.service") {
				matchedLine = line
			}
		case <-deadline:
			jCancel()
			<-doneCh
			t.Fatal("timeout menunggu SSE journal.pattern terredaksi")
		}
	}

	// Beri kesempatan singkat agar event kedua ikut diproses sebelum dibatalkan
	time.Sleep(50 * time.Millisecond)
	jCancel()
	<-doneCh

	if strings.Contains(matchedLine, "sk-proj-1234567890") || strings.Contains(matchedLine, "0812-3456-7890") {
		t.Fatalf("SSE payload membocorkan rahasia: %s", matchedLine)
	}
	if !strings.Contains(matchedLine, "[REDACTED_TOKEN]") || !strings.Contains(matchedLine, "[REDACTED_PHONE]") || !strings.Contains(matchedLine, "1073741824") {
		t.Fatalf("SSE payload tidak terredaksi sesuai harapan: %s", matchedLine)
	}

	evList, err := store.GetEvidenceByIncident(ctx, incID)
	if err != nil {
		t.Fatalf("GetEvidenceByIncident: %v", err)
	}
	if len(evList) != 1 {
		t.Fatalf("expected tepat 1 evidence untuk haunted-api.service (unmatched unit tidak boleh menempel), dapat %d", len(evList))
	}
	for _, field := range []string{evList[0].RawData, evList[0].RedactedData} {
		if strings.Contains(field, "sk-proj-1234567890") || strings.Contains(field, "0812-3456-7890") {
			t.Fatalf("DB evidence masih menyimpan rahasia mentah: %s", field)
		}
		if !strings.Contains(field, "[REDACTED_TOKEN]") || !strings.Contains(field, "[REDACTED_PHONE]") || !strings.Contains(field, "1073741824") {
			t.Fatalf("DB evidence kehilangan metrik atau marker redaksi: %s", field)
		}
	}
}

