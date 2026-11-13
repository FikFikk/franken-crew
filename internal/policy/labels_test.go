package policy

import (
	"strings"
	"testing"
)

func TestFormatOptionLabel_MatchesBridgeFormat(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		opt  PlanOption
		want string
	}{
		{
			name: "pm2 app",
			opt:  PlanOption{ID: "A", Steps: []PlanStep{{ID: "s1", Action: "pm2_reload", Params: map[string]any{"app": "haunted-api"}}}},
			want: "A: pm2_reload haunted-api [01234567]",
		},
		{
			name: "unit",
			opt:  PlanOption{ID: "B", Steps: []PlanStep{{ID: "s2", Action: "unit_restart", Params: map[string]any{"unit": "haunted-api.service"}}}},
			want: "B: unit_restart haunted-api.service [01234567]",
		},
		{
			name: "pm2 worker shows pm_id",
			opt:  PlanOption{ID: "A", Steps: []PlanStep{{ID: "s1", Action: "pm2_restart_instance", Params: map[string]any{"app": "haunted-api", "pm_id": 2}}}},
			want: "A: pm2_restart_instance haunted-api pm_id=2 [01234567]",
		},
		{
			name: "pid and two steps",
			opt: PlanOption{ID: "C", Steps: []PlanStep{
				{ID: "s3", Action: "cgroup_throttle", Params: map[string]any{"unit": "worker.service", "memory_high": "240M", "ttl_seconds": 600}},
				{ID: "s4", Action: "zombie_reap", Params: map[string]any{"parent_pid": 3120}},
			}},
			want: "C: cgroup_throttle worker.service + zombie_reap parent_pid=3120 [01234567]",
		},
		{
			name: "no params falls back to action",
			opt:  PlanOption{ID: "D", Steps: []PlanStep{{ID: "s5", Action: "process_terminate", Params: map[string]any{"pid": 4242}}}},
			want: "D: process_terminate pid=4242 [01234567]",
		},
		{
			name: "label used when steps are empty",
			opt:  PlanOption{ID: "A", Label: "Observe only"},
			want: "A: Observe only [01234567]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatOptionLabel(tc.opt, hash); got != tc.want {
				t.Fatalf("FormatOptionLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatOptionLabel_TruncatesLongBodiesAndRedacts(t *testing.T) {
	hash := "fedcba9876543210"
	long := strings.Repeat("x", 200)
	got := FormatOptionLabel(PlanOption{ID: "A", Steps: []PlanStep{{Action: "unit_restart", Params: map[string]any{"unit": long}}}}, hash)
	if len(got) > maxPollOptionLabelLen || !strings.HasSuffix(got, "... [fedcba98]") || !strings.HasPrefix(got, "A: unit_restart ") {
		t.Fatalf("long label must be truncated to %d bytes with the hash kept, got %q (%d bytes)", maxPollOptionLabelLen, got, len(got))
	}

	leaky := FormatOptionLabel(PlanOption{ID: "B", Steps: []PlanStep{{Action: "pm2_reload", Params: map[string]any{"app": "api from 10.1.2.3"}}}}, hash)
	if strings.Contains(leaky, "10.1.2.3") || !strings.Contains(leaky, "[REDACTED_IP]") {
		t.Fatalf("label text must be redacted, got %q", leaky)
	}
}

func TestShortPlanHashAndPollOptionLabels(t *testing.T) {
	if got := ShortPlanHash("  abcdef0123456789 "); got != "abcdef01" {
		t.Fatalf("ShortPlanHash = %q", got)
	}
	if got := ShortPlanHash("abc"); got != "abc" {
		t.Fatalf("ShortPlanHash of a short value must be unchanged, got %q", got)
	}

	plan := &Plan{Options: []PlanOption{
		{ID: "A", Steps: []PlanStep{{Action: "pm2_reload", Params: map[string]any{"app": "haunted-api"}}}},
		{ID: "B", Steps: []PlanStep{{Action: "unit_restart", Params: map[string]any{"unit": "haunted-api.service"}}}},
	}}
	got := PollOptionLabels(plan, "99887766554433221100")
	want := []string{
		"A: pm2_reload haunted-api [99887766]",
		"B: unit_restart haunted-api.service [99887766]",
		PollOptionRollbackReflex,
		PollOptionDismiss,
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("PollOptionLabels = %q, want %q", got, want)
	}
	if PollOptionRollbackReflex != "Rollback Reflex" || PollOptionDismiss != "Dismiss" {
		t.Fatalf("secondary poll labels changed: %q / %q", PollOptionRollbackReflex, PollOptionDismiss)
	}
	if nilLabels := PollOptionLabels(nil, "x"); len(nilLabels) != 2 {
		t.Fatalf("nil plan must still offer the two secondary options, got %q", nilLabels)
	}
}
