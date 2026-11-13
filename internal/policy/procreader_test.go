package policy

import (
	"errors"
	"io/fs"
	"testing"
)

func TestCatalog_SetProcReaderIsUsedForPIDProtection(t *testing.T) {
	cat, err := LoadCatalogFromBytes([]byte("protected_units: [\"sshd\"]\n"))
	if err != nil {
		t.Fatalf("LoadCatalogFromBytes: %v", err)
	}
	fixture := map[string]string{
		"/proc/3120/stat": "3120 (job-runner) S 1 3120 3120 0 -1 4194560 0 0 0 0\n",
		"/proc/3121/stat": "3121 (sshd) S 1 3121 3121 0 -1 4194560 0 0 0 0\n",
		"/proc/3122/stat": "3122 (kworker/u8:3) I 2 0 0 0 -1 69238880 0 0 0 0\n",
	}
	var reads []string
	cat.SetProcReader(func(p string) ([]byte, error) {
		reads = append(reads, p)
		if v, ok := fixture[p]; ok {
			return []byte(v), nil
		}
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	})

	if cat.IsProtectedPID(3120) {
		t.Errorf("job-runner in the fixture must not be protected")
	}
	if !cat.IsProtectedPID(3121) {
		t.Errorf("sshd in the fixture must be protected")
	}
	if !cat.IsProtectedPID(3122) {
		t.Errorf("kernel thread (ppid 2, no cmdline) in the fixture must be protected")
	}
	if len(reads) == 0 {
		t.Fatalf("IsProtectedPID must read through the injected proc reader")
	}

	// Plan validation memakai reader yang sama, bukan /proc host
	res, err := cat.ValidatePlan(&Plan{Options: []PlanOption{{ID: "A", Steps: []PlanStep{{
		ID: "s1", Action: "zombie_reap", Params: map[string]any{"parent_pid": 3121}, EvidenceIDs: []string{"ev-1"},
	}}}}})
	if err != nil {
		t.Fatalf("ValidatePlan: %v", err)
	}
	if res.Valid {
		t.Fatalf("plan targeting the fixture sshd parent must be rejected")
	}

	// Reader eksplisit tetap diutamakan dibanding reader katalog
	if !cat.IsProtectedPIDWithReader(3120, func(string) ([]byte, error) {
		return []byte("3120 (sshd) S 1 3120 3120 0 -1 4194560 0 0 0 0\n"), nil
	}) {
		t.Errorf("explicit reader passed to IsProtectedPIDWithReader must win over the catalog reader")
	}

	cat.SetProcReader(func(string) ([]byte, error) { return nil, errors.New("boom") })
	if cat.IsProtectedPID(3120) {
		t.Errorf("unreadable pid metadata is not protected by name (PID 1/2 rules still apply)")
	}
	if !cat.IsProtectedPID(1) {
		t.Errorf("PID 1 must always be protected")
	}
}
