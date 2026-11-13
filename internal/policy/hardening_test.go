package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func loadRepoCatalog(t *testing.T) *Catalog {
	t.Helper()
	cat, err := LoadCatalog(filepath.Join("..", "..", "policy", "actions.yaml"))
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	return cat
}

// Unit inti dengan nama asli distro (Debian/Ubuntu/Raspberry Pi OS), unit FrankenCrew yang benar-benar
// di-deploy, layanan jaringan, dan gateway Kiro Crew wajib dilindungi agar operator tidak terkunci keluar.
func TestCatalog_ProtectsDistroNetworkAndFrankenUnits(t *testing.T) {
	cat := loadRepoCatalog(t)
	for _, unit := range []string{
		"ssh", "ssh.service", "ssh.socket", "sshd.socket",
		"franken-bridge", "franken-bridge.service",
		"systemd-networkd.service", "NetworkManager.service", "systemd-resolved.service",
		"wpa_supplicant.service", "networking.service", "dhcpcd.service",
		"kirocrew", "kirocrew.service",
	} {
		if !cat.IsProtectedUnit(unit) {
			t.Errorf("expected %q to be a protected unit", unit)
		}
	}
	for _, unit := range []string{"haunted-api.service", "pm2-pi.service", "franken-chaos-workload.service"} {
		if cat.IsProtectedUnit(unit) {
			t.Errorf("application unit %q must stay remediable", unit)
		}
	}
}

func TestValidatePlan_RejectsDuplicateStepIDsAcrossOptions(t *testing.T) {
	cat := loadRepoCatalog(t)
	plan := &Plan{
		IncidentID:         "INC-20261113-1200-node01",
		SuspectedRootCause: "heap leak in worker",
		HumanFollowUp:      []string{},
		Options: []PlanOption{
			{ID: "A", Label: "reload", Steps: []PlanStep{{
				ID: "s1", Action: "pm2_reload", Params: map[string]any{"app": "haunted-api"},
				EvidenceIDs: []string{"ev-1"}, ExpectedEffect: "reload workers",
			}}},
			{ID: "B", Label: "restart", Steps: []PlanStep{{
				ID: "s1", Action: "unit_restart", Params: map[string]any{"unit": "haunted-api.service"},
				EvidenceIDs: []string{"ev-1"}, ExpectedEffect: "restart unit",
			}}},
		},
	}
	res, err := cat.ValidatePlan(plan)
	if err != nil {
		t.Fatalf("ValidatePlan: %v", err)
	}
	if res.Valid {
		t.Fatal("plan reusing step id s1 in two options must be rejected")
	}
	if !containsViolation(res.Violations, "duplicate step id") {
		t.Fatalf("expected a duplicate step id violation, got %v", res.Violations)
	}
}

func containsViolation(violations []string, needle string) bool {
	for _, v := range violations {
		if strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}
