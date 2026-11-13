package lab

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/mcpserver"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/wabridge"
)

const statusTestToken = "lab-status-test-bearer-token-0123456789"

// liveSentinel menjalankan Sentinel MCP server asli di atas MemFS dan menghitung permintaan HTTP yang masuk.
func liveSentinel(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "status.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cat, err := policy.LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}

	mfs := kernelfs.NewMemFS()
	mfs.SetFile("/sys/fs/cgroup/cgroup.controllers", "cpu memory io pids\n")
	mfs.SetFile("/proc/meminfo", "MemTotal:        4000000 kB\nMemFree:          800000 kB\nMemAvailable:    1540000 kB\n")
	mfs.SetFile("/proc/pressure/memory", "some avg10=3.14 avg60=1.00 avg300=0.50 total=10\nfull avg10=0.42 avg60=0.10 avg300=0.05 total=2\n")
	mfs.SetFile("/sys/fs/cgroup/franken.slice/secret-billing.service/memory.current", "209715200\n")

	ctx := context.Background()
	base := time.Date(2026, 11, 13, 3, 0, 0, 0, time.UTC)
	for i, st := range []incident.State{incident.StateResolved, incident.StateVerifying, incident.StateEscalated} {
		if err := store.CreateIncident(ctx, &incident.Incident{
			ID: "INC-20261113-030" + string(rune('0'+i)) + "-pi01-lab", Node: "pi01-lab", Cgroup: "/franken.slice/secret-billing.service",
			Severity: "P2", State: st, OpenedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("CreateIncident: %v", err)
		}
	}

	srv, err := mcpserver.New(mcpserver.Config{
		NodeName: "pi01-lab", Version: "9.9.9-secret", Store: store, Catalog: cat, FS: mfs,
		BearerToken: statusTestToken,
	})
	if err != nil {
		t.Fatalf("mcpserver.New: %v", err)
	}
	t.Cleanup(srv.Close)
	handler, err := srv.HTTPHandler()
	if err != nil {
		t.Fatalf("HTTPHandler: %v", err)
	}
	var hits atomic.Int64
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(httpSrv.Close)
	return httpSrv, &hits
}

func TestSentinelStatusSource_ReturnsOnlyWhitelistedLiveFields(t *testing.T) {
	httpSrv, _ := liveSentinel(t)
	client, err := wabridge.NewSentinelClient(httpSrv.URL, statusTestToken)
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	now := time.Date(2026, 11, 13, 4, 0, 0, 0, time.UTC)
	src := newSentinelStatusSource(client, func() time.Time { return now })
	st := src.Status(context.Background())
	if st.Mode != "live" {
		t.Fatalf("expected live mode, got %+v", st)
	}

	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	assertOnlyKeys(t, got, "mode", "node", "uptime_s", "psi", "memory_used_pct", "open_incidents", "latest", "updated_at")
	for _, leak := range []string{"secret-billing", "franken.slice", "9.9.9-secret", "cgroup_v2", "top_cgroups", "capabilities", statusTestToken} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("live status leaked %q: %s", leak, raw)
		}
	}
	if st.Node != "pi01-lab" || st.PSI == nil || st.PSI.SomeAvg10 != 3.14 || st.PSI.FullAvg10 != 0.42 {
		t.Errorf("unexpected node/psi: %+v / %+v", st.Node, st.PSI)
	}
	if st.MemoryUsedPct == nil || *st.MemoryUsedPct != 61.5 {
		t.Errorf("memory_used_pct = %v, want 61.5", st.MemoryUsedPct)
	}
	if st.OpenIncidents == nil || *st.OpenIncidents != 1 {
		t.Errorf("open_incidents = %v, want 1 (only VERIFYING is non-terminal)", st.OpenIncidents)
	}
	if st.Latest == nil || st.Latest.ID != "INC-20261113-0302-pi01-lab" || st.Latest.State != "ESCALATED" {
		t.Errorf("latest = %+v", st.Latest)
	}
	if st.UptimeS == nil || st.UpdatedAt == nil || !st.UpdatedAt.Equal(now) {
		t.Errorf("uptime/updated_at missing: %+v", st)
	}
}

func TestSentinelStatusSource_CachesForFiveSeconds(t *testing.T) {
	httpSrv, hits := liveSentinel(t)
	client, err := wabridge.NewSentinelClient(httpSrv.URL, statusTestToken)
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	var mu sync.Mutex
	now := time.Date(2026, 11, 13, 4, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	src := newSentinelStatusSource(client, clock)
	first := src.Status(context.Background())
	afterFirst := hits.Load()
	if first.Mode != "live" || afterFirst == 0 {
		t.Fatalf("first status must query Sentinel, got %+v hits=%d", first, afterFirst)
	}
	mu.Lock()
	now = now.Add(4 * time.Second)
	mu.Unlock()
	if second := src.Status(context.Background()); second.UpdatedAt == nil || !second.UpdatedAt.Equal(*first.UpdatedAt) || hits.Load() != afterFirst {
		t.Fatalf("status within 5s must be served from cache (hits %d -> %d)", afterFirst, hits.Load())
	}
	mu.Lock()
	now = now.Add(2 * time.Second)
	mu.Unlock()
	if third := src.Status(context.Background()); third.Mode != "live" || hits.Load() == afterFirst {
		t.Fatalf("status after 5s must refresh, got %+v hits=%d", third, hits.Load())
	}
}

func TestSentinelStatusSource_OfflineHidesErrorDetails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadURL := "http://" + ln.Addr().String()
	_ = ln.Close()

	client, err := wabridge.NewSentinelClient(deadURL, statusTestToken)
	if err != nil {
		t.Fatalf("NewSentinelClient: %v", err)
	}
	now := time.Date(2026, 11, 13, 4, 0, 0, 0, time.UTC)
	st := newSentinelStatusSource(client, func() time.Time { return now }).Status(context.Background())
	raw, _ := json.Marshal(st)
	if string(raw) != `{"mode":"offline","updated_at":"2026-11-13T04:00:00Z"}` {
		t.Fatalf("offline status must hide errors, got %s", raw)
	}
}
