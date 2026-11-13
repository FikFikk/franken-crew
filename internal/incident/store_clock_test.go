package incident

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStore_SetClockStampsAuditTransitionsAndClaims(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "clock.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	at := time.Date(2026, 11, 13, 3, 17, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return at })

	ctx := context.Background()
	if err := store.CreateIncident(ctx, &Incident{ID: "INC-CLOCK-1", Node: "pi01-sim", Cgroup: "/franken.slice/a.service", Severity: "P2", State: StateDetected}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}
	at = at.Add(6 * time.Second)
	if _, err := store.ClaimIncident(ctx, "INC-CLOCK-1", "franken-sentry"); err != nil {
		t.Fatalf("ClaimIncident: %v", err)
	}
	at = at.Add(30 * time.Second)
	if err := store.TransitionState(ctx, "INC-CLOCK-1", StateEscalated, "sentinel", "test"); err != nil {
		t.Fatalf("TransitionState: %v", err)
	}

	inc, err := store.GetIncident(ctx, "INC-CLOCK-1")
	if err != nil {
		t.Fatalf("GetIncident: %v", err)
	}
	if !inc.OpenedAt.Equal(time.Date(2026, 11, 13, 3, 17, 0, 0, time.UTC)) {
		t.Errorf("opened_at = %s, want the injected clock", inc.OpenedAt)
	}
	if inc.ClosedAt == nil || !inc.ClosedAt.Equal(at) || !inc.UpdatedAt.Equal(at) {
		t.Errorf("closed_at/updated_at must use the injected clock (%s), got closed=%v updated=%s", at, inc.ClosedAt, inc.UpdatedAt)
	}

	audit, err := store.GetAuditTrail(ctx, "INC-CLOCK-1")
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	want := []struct {
		event string
		at    time.Time
	}{
		{"INCIDENT_CREATED", time.Date(2026, 11, 13, 3, 17, 0, 0, time.UTC)},
		{"INCIDENT_CLAIMED", time.Date(2026, 11, 13, 3, 17, 6, 0, time.UTC)},
		{"STATE_TRANSITION", at},
	}
	if len(audit) != len(want) {
		t.Fatalf("audit rows = %d, want %d: %+v", len(audit), len(want), audit)
	}
	for i, w := range want {
		if audit[i].EventType != w.event || !audit[i].CreatedAt.Equal(w.at) {
			t.Errorf("audit[%d] = %s at %s, want %s at %s", i, audit[i].EventType, audit[i].CreatedAt, w.event, w.at)
		}
	}
}

func TestStore_SavePlanWithTriagePersistsBothColumnsAtomically(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "triage.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	if err := store.CreateIncident(ctx, &Incident{ID: "INC-TRIAGE-1", Node: "n", Cgroup: "/x.service", Severity: "P2", State: StateTriaging}); err != nil {
		t.Fatalf("CreateIncident: %v", err)
	}

	if err := store.SavePlanWithTriage(ctx, "INC-TRIAGE-1", `{"plan":1}`, `{"class":"heap_leak"}`); err != nil {
		t.Fatalf("SavePlanWithTriage: %v", err)
	}
	inc, _ := store.GetIncident(ctx, "INC-TRIAGE-1")
	if inc.PlanJSON != `{"plan":1}` || inc.TriageJSON != `{"class":"heap_leak"}` {
		t.Fatalf("plan/triage not persisted: plan=%q triage=%q", inc.PlanJSON, inc.TriageJSON)
	}

	// Pengajuan ulang tanpa triage menyimpan plan baru tanpa menghapus triage sebelumnya
	if err := store.SavePlanWithTriage(ctx, "INC-TRIAGE-1", `{"plan":2}`, ""); err != nil {
		t.Fatalf("SavePlanWithTriage without triage: %v", err)
	}
	inc, _ = store.GetIncident(ctx, "INC-TRIAGE-1")
	if inc.PlanJSON != `{"plan":2}` || inc.TriageJSON != `{"class":"heap_leak"}` {
		t.Fatalf("empty triage must keep the stored triage: plan=%q triage=%q", inc.PlanJSON, inc.TriageJSON)
	}

	if err := store.SavePlanWithTriage(ctx, "INC-MISSING", `{}`, `{}`); err != ErrIncidentNotFound {
		t.Fatalf("missing incident must return ErrIncidentNotFound, got %v", err)
	}
}
