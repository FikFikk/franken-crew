package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/policy"
)

// ErrTargetOutOfScope dikembalikan jika target sebuah langkah berada di luar cgroup insiden yang sedang ditangani.
var ErrTargetOutOfScope = errors.New("target outside incident scope")

// pm2DaemonUnitRegex mengenali unit systemd milik daemon PM2 (`pm2 startup` membuat `pm2-<user>.service`).
var pm2DaemonUnitRegex = regexp.MustCompile(`^pm2-[a-z_][a-z0-9_-]*\.service$`)

// validatePlanAgainstIncident memastikan setiap langkah plan mengutip evidence milik insiden ini dan
// hanya menargetkan unit, aplikasi, proses, atau cgroup yang berada di dalam cgroup insiden.
func (s *Server) validatePlanAgainstIncident(ctx context.Context, inc *incident.Incident, plan *policy.Plan) ([]string, error) {
	evidence, err := s.cfg.Store.GetEvidenceByIncident(ctx, inc.ID)
	if err != nil {
		return nil, fmt.Errorf("load evidence for %s: %w", inc.ID, err)
	}
	known := make(map[string]bool, len(evidence))
	for _, ev := range evidence {
		known[ev.ID] = true
	}

	var violations []string
	for _, opt := range plan.Options {
		for _, step := range opt.Steps {
			for _, evID := range step.EvidenceIDs {
				if !known[strings.TrimSpace(evID)] {
					violations = append(violations, fmt.Sprintf("step %s: evidence_id %q is not recorded for incident %s", step.ID, evID, inc.ID))
				}
			}
			if scopeErr := s.checkStepTargetScope(inc, step.Action, step.Params); scopeErr != nil {
				violations = append(violations, fmt.Sprintf("step %s (%s): %v", step.ID, step.Action, scopeErr))
			}
		}
	}
	return violations, nil
}

// checkStepTargetScope menolak target langkah yang tidak termasuk cgroup insiden. Pemeriksaan ini dijalankan
// saat plan_submit dan diulang tepat sebelum action_execute karena proses bisa pindah cgroup atau PID dipakai ulang.
func (s *Server) checkStepTargetScope(inc *incident.Incident, action string, params map[string]any) error {
	switch action {
	case "unit_restart", "cgroup_throttle", "cgroup_reclaim",
		"pm2_reload", "pm2_restart_instance", "admission_close",
		"process_terminate", "zombie_reap":
	default:
		// Aksi L0/L3 tidak menyentuh target; L3 sudah ditolak oleh katalog kebijakan
		return nil
	}

	incCgroup, incUnit, err := s.incidentScope(inc)
	if err != nil {
		return err
	}

	switch action {
	case "unit_restart":
		return requireIncidentUnit(extractString(params, "unit"), incUnit)

	case "cgroup_throttle":
		if err := requireIncidentUnit(extractString(params, "unit"), incUnit); err != nil {
			return err
		}
		return s.requireCgroupWithinIncident(extractString(params, "cgroup"), incCgroup)

	case "cgroup_reclaim":
		return s.requireCgroupWithinIncident(extractString(params, "cgroup"), incCgroup)

	case "pm2_reload", "pm2_restart_instance", "admission_close":
		return requireAppOfIncidentUnit(extractString(params, "app"), incUnit)

	case "process_terminate":
		pid, ok := extractPositiveInt(params, "pid")
		if !ok {
			return fmt.Errorf("%w: valid pid is required to verify incident cgroup membership", ErrTargetOutOfScope)
		}
		return s.requirePIDWithinIncident(pid, incCgroup)

	case "zombie_reap":
		ppid, ok := extractPositiveInt(params, "parent_pid")
		if !ok {
			return fmt.Errorf("%w: valid parent_pid is required to verify incident cgroup membership", ErrTargetOutOfScope)
		}
		return s.requirePIDWithinIncident(ppid, incCgroup)
	}
	return nil
}

// incidentScope mengembalikan path cgroup relatif insiden beserta nama unit leaf-nya.
func (s *Server) incidentScope(inc *incident.Incident) (string, string, error) {
	_, rel, err := resolveSafeCgroupDir(s.cfg.CgroupRoot, inc.Cgroup)
	if err != nil {
		return "", "", fmt.Errorf("%w: incident cgroup %q is invalid: %v", ErrTargetOutOfScope, inc.Cgroup, err)
	}
	unit := path.Base(rel)
	if rel == "/" || !strings.HasSuffix(unit, ".service") {
		// Insiden tingkat host atau slice tidak boleh mengotorisasi aksi yang menargetkan unit/proses tertentu
		return "", "", fmt.Errorf("%w: incident %s is not bound to a service cgroup (cgroup=%q)", ErrTargetOutOfScope, inc.ID, rel)
	}
	return rel, unit, nil
}

func normalizeUnitName(unit string) string {
	u := strings.TrimSpace(unit)
	if u != "" && !strings.Contains(u, ".") {
		u += ".service"
	}
	return u
}

func requireIncidentUnit(unit, incUnit string) error {
	if normalizeUnitName(unit) != incUnit {
		return fmt.Errorf("%w: unit %q is not the incident unit %q", ErrTargetOutOfScope, unit, incUnit)
	}
	return nil
}

// requireAppOfIncidentUnit mengizinkan aplikasi PM2 hanya bila unit insiden adalah daemon PM2 itu sendiri
// (semua aplikasinya berbagi cgroup tersebut) atau unit per-aplikasi dengan nama yang sama.
func requireAppOfIncidentUnit(app, incUnit string) error {
	cleanApp := strings.TrimSpace(app)
	if pm2DaemonUnitRegex.MatchString(incUnit) {
		return nil
	}
	if cleanApp != "" && cleanApp+".service" == incUnit {
		return nil
	}
	return fmt.Errorf("%w: app %q does not run in incident unit %q", ErrTargetOutOfScope, app, incUnit)
}

func (s *Server) requireCgroupWithinIncident(cg, incCgroup string) error {
	if strings.TrimSpace(cg) == "" {
		// Parameter kosong berarti cgroup insiden itu sendiri
		return nil
	}
	_, rel, err := resolveSafeCgroupDir(s.cfg.CgroupRoot, cg)
	if err != nil {
		return fmt.Errorf("%w: cgroup %q is invalid: %v", ErrTargetOutOfScope, cg, err)
	}
	if !cgroupWithin(rel, incCgroup) {
		return fmt.Errorf("%w: cgroup %s is outside incident cgroup %s", ErrTargetOutOfScope, rel, incCgroup)
	}
	return nil
}

// requirePIDWithinIncident membaca /proc/<pid>/cgroup (entri cgroup v2 `0::/path`) dan menolak secara fail-closed
// bila keanggotaan tidak dapat dibuktikan.
func (s *Server) requirePIDWithinIncident(pid int, incCgroup string) error {
	if s.cfg.FS == nil {
		return fmt.Errorf("%w: cannot verify cgroup of pid %d without procfs access", ErrTargetOutOfScope, pid)
	}
	procRoot := strings.TrimRight(s.cfg.ProcRoot, "/")
	if procRoot == "" {
		procRoot = "/proc"
	}
	raw, err := s.cfg.FS.ReadFile(path.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return fmt.Errorf("%w: cannot verify cgroup of pid %d for incident cgroup %s: %v", ErrTargetOutOfScope, pid, incCgroup, err)
	}
	pidCgroup := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			pidCgroup = path.Clean("/" + strings.TrimSpace(rest))
			break
		}
	}
	if pidCgroup == "" {
		return fmt.Errorf("%w: pid %d has no cgroup v2 entry; cannot match incident cgroup %s", ErrTargetOutOfScope, pid, incCgroup)
	}
	if !cgroupWithin(pidCgroup, incCgroup) {
		return fmt.Errorf("%w: pid %d runs in %s, outside incident cgroup %s", ErrTargetOutOfScope, pid, pidCgroup, incCgroup)
	}
	return nil
}

// cgroupWithin bernilai true bila child sama dengan parent atau berada di bawahnya.
func cgroupWithin(child, parent string) bool {
	c := path.Clean("/" + strings.TrimSpace(child))
	p := path.Clean("/" + strings.TrimSpace(parent))
	if p == "/" {
		return false
	}
	return c == p || strings.HasPrefix(c, p+"/")
}
