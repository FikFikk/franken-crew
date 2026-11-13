package reflex

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

func TestEngine_IDSourceMakesReflexIDsReproducible(t *testing.T) {
	store, err := incident.NewStore(filepath.Join(t.TempDir(), "ids.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	if err := store.CreateIncident(ctx, &incident.Incident{ID: "INC-ID-1", Node: "n", Cgroup: "/franken.slice/a.service", Severity: "P2", State: incident.StateDetected}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	mfs := kernelfs.NewMemFS()
	cg := "/sys/fs/cgroup/franken.slice/a.service"
	mfs.SetFile(cg+"/memory.current", "209715200\n")
	mfs.SetFile(cg+"/memory.reclaim", "")

	eng, err := NewEngine(EngineConfig{
		Store:    store,
		FS:       mfs,
		Clock:    func() time.Time { return time.Date(2026, 11, 13, 3, 19, 0, 0, time.UTC) },
		IDSource: bytes.NewReader(bytes.Repeat([]byte{0x22}, 32)),
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	act, err := eng.ApplyReclaim(ctx, ReclaimRequest{IncidentID: "INC-ID-1", CgroupPath: cg})
	if err != nil {
		t.Fatalf("ApplyReclaim: %v", err)
	}
	if act.ID != "RFX-222222222222" {
		t.Fatalf("reflex ID must come from IDSource, got %q", act.ID)
	}
}
