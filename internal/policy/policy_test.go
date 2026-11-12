package policy

import (
	"path/filepath"
	"testing"

	"pgregory.net/rapid"
)

func TestPolicy_LoadCatalogAndProtectedUnits(t *testing.T) {
	catalogPath := filepath.Join("..", "..", "policy", "actions.yaml")
	cat, err := LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("failed to load actions catalog: %v", err)
	}

	// 1. Verifikasi unit yang dilindungi
	protectedUnits := []string{"sshd", "sshd.service", "systemd", "franken-sentinel", "wa-bridge", "tailscaled"}
	for _, u := range protectedUnits {
		if !cat.IsProtectedUnit(u) {
			t.Errorf("expected unit %q to be protected", u)
		}
	}
	if cat.IsProtectedUnit("haunted-api.service") {
		t.Errorf("normal application unit should not be protected")
	}

	// 2. Verifikasi PID yang dilindungi
	if !cat.IsProtectedPID(1) {
		t.Errorf("PID 1 must be strictly protected")
	}
	if cat.IsProtectedPID(9999) {
		t.Errorf("arbitrary user PID should not be protected")
	}

	// 3. Verifikasi tier aksi
	reclaim, ok := cat.GetAction("cgroup_reclaim")
	if !ok || reclaim.Tier != TierL1 {
		t.Errorf("expected cgroup_reclaim to be L1, got: %+v", reclaim)
	}
	pm2Reload, ok := cat.GetAction("pm2_reload")
	if !ok || pm2Reload.Tier != TierL2 {
		t.Errorf("expected pm2_reload to be L2, got: %+v", pm2Reload)
	}
	rawShell, ok := cat.GetAction("raw_shell")
	if !ok || rawShell.Tier != TierL3 {
		t.Errorf("expected raw_shell to be L3, got: %+v", rawShell)
	}
}

func TestPolicy_ValidatePlan_Success(t *testing.T) {
	catalogPath := filepath.Join("..", "..", "policy", "actions.yaml")
	cat, err := LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("failed loading catalog: %v", err)
	}

	validPlan := &Plan{
		IncidentID:         "INC-20261112-0317-pi01",
		SuspectedRootCause: "Memory leak in haunted-api worker 2",
		Options: []PlanOption{
			{
				ID:    "A",
				Label: "Graceful reload of PM2 cluster",
				Steps: []PlanStep{
					{
						ID:             "step-1",
						Action:         "pm2_reload",
						Params:         map[string]any{"app": "haunted-api"},
						EvidenceIDs:    []string{"EVID-001"},
						ExpectedEffect: "Zero-downtime worker instance recycling",
					},
				},
			},
		},
		HumanFollowUp: []string{"Audit memory allocation in database repository layer"},
	}

	res, err := cat.ValidatePlan(validPlan)
	if err != nil {
		t.Fatalf("validation threw error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected plan to be valid, violations: %v", res.Violations)
	}
	if res.PlanHash == "" {
		t.Errorf("expected non-empty plan hash")
	}
}

func TestPolicy_ValidatePlan_RejectsProtectedUnitAndL3(t *testing.T) {
	catalogPath := filepath.Join("..", "..", "policy", "actions.yaml")
	cat, err := LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("failed loading catalog: %v", err)
	}

	// Skenario 1: Mencoba merestart unit yang dilindungi (sshd)
	maliciousPlan1 := &Plan{
		IncidentID: "INC-20261112-0001-pi01",
		Options: []PlanOption{
			{
				ID:    "A",
				Label: "Restart protected unit",
				Steps: []PlanStep{
					{
						ID:          "step-1",
						Action:      "unit_restart",
						Params:      map[string]any{"unit": "sshd.service"},
						EvidenceIDs: []string{"EVID-001"},
					},
				},
			},
		},
	}

	res1, err := cat.ValidatePlan(maliciousPlan1)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if res1.Valid {
		t.Fatalf("expected plan targeting sshd to be REJECTED")
	}

	// Skenario 2: Mencoba memanggil aksi L3 (raw_shell)
	maliciousPlan2 := &Plan{
		IncidentID: "INC-20261112-0002-pi01",
		Options: []PlanOption{
			{
				ID:    "A",
				Label: "Run forbidden shell script",
				Steps: []PlanStep{
					{
						ID:          "step-1",
						Action:      "raw_shell",
						Params:      map[string]any{"cmd": "rm -rf /"},
						EvidenceIDs: []string{"EVID-001"},
					},
				},
			},
		},
	}

	res2, err := cat.ValidatePlan(maliciousPlan2)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if res2.Valid {
		t.Fatalf("expected plan with raw_shell to be REJECTED")
	}

	// Skenario 3: Mencoba aksi tanpa menyertakan evidence_id
	noEvidencePlan := &Plan{
		IncidentID: "INC-20261112-0003-pi01",
		Options: []PlanOption{
			{
				ID:    "A",
				Label: "No evidence provided",
				Steps: []PlanStep{
					{
						ID:          "step-1",
						Action:      "pm2_reload",
						Params:      map[string]any{"app": "haunted-api"},
						EvidenceIDs: []string{}, // Kosong
					},
				},
			},
		},
	}

	res3, err := cat.ValidatePlan(noEvidencePlan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res3.Valid {
		t.Fatalf("expected plan without evidence to be REJECTED")
	}
}

func TestPolicy_CanonicalJSONAndHashDeterminism(t *testing.T) {
	plan1 := &Plan{
		IncidentID:         "INC-01",
		SuspectedRootCause: "Leak",
		Options: []PlanOption{
			{
				ID:    "A",
				Label: "Option A",
				Steps: []PlanStep{
					{ID: "s1", Action: "pm2_reload", Params: map[string]any{"b": 2, "a": 1}, EvidenceIDs: []string{"E1"}},
				},
			},
		},
	}

	plan2 := &Plan{
		IncidentID:         "INC-01",
		SuspectedRootCause: "Leak",
		Options: []PlanOption{
			{
				ID:    "A",
				Label: "Option A",
				Steps: []PlanStep{
					{ID: "s1", Action: "pm2_reload", Params: map[string]any{"a": 1, "b": 2}, EvidenceIDs: []string{"E1"}},
				},
			},
		},
	}

	hash1, err := ComputePlanHash(plan1)
	if err != nil {
		t.Fatalf("hash1 err: %v", err)
	}
	hash2, err := ComputePlanHash(plan2)
	if err != nil {
		t.Fatalf("hash2 err: %v", err)
	}

	// Urutan key dalam map params {"b":2, "a":1} vs {"a":1, "b":2} harus menghasilkan hash identik
	if hash1 != hash2 {
		t.Fatalf("canonical JSON hash mismatch: %s != %s", hash1, hash2)
	}

	// Perubahan kecil satu karakter pada field harus mengubah hash
	plan2.SuspectedRootCause = "Leak."
	hash3, _ := ComputePlanHash(plan2)
	if hash1 == hash3 {
		t.Fatalf("hash should change when plan content changes")
	}
}

// Property-based testing menggunakan rapid: membuktikan invariant P1
// Bahwa tidak ada satupun rencana yang memuat aksi L3 atau unit terlindungi yang dapat lolos validasi
func TestPolicy_Property_P1_NoL3OrProtectedTargetEverValidates(t *testing.T) {
	catalogPath := filepath.Join("..", "..", "policy", "actions.yaml")
	cat, err := LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("failed loading catalog: %v", err)
	}

	rapid.Check(t, func(rt *rapid.T) {
		isL3 := rapid.Bool().Draw(rt, "isL3")
		isProtected := rapid.Bool().Draw(rt, "isProtected")

		if !isL3 && !isProtected {
			return
		}

		actionName := "pm2_reload"
		params := map[string]any{"app": "web"}
		if isL3 {
			actionName = "raw_shell"
		}
		if isProtected {
			actionName = "unit_restart"
			params = map[string]any{"unit": "sshd.service"}
		}

		plan := &Plan{
			IncidentID: "INC-TEST-001",
			Options: []PlanOption{
				{
					ID:    "A",
					Label: "Fuzz test option",
					Steps: []PlanStep{
						{
							ID:          "s1",
							Action:      actionName,
							Params:      params,
							EvidenceIDs: []string{"EVID-001"},
						},
					},
				},
			},
		}

		res, err := cat.ValidatePlan(plan)
		if err != nil {
			rt.Fatalf("unexpected validation error: %v", err)
		}
		if res.Valid {
			rt.Fatalf("invariant violated: plan with isL3=%v isProtected=%v validated as true!", isL3, isProtected)
		}
	})
}
