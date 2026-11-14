package journal

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMatchPattern_AllCategories(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		wantCat  PatternCategory
		wantPass bool
	}{
		{
			name:     "Kernel Out of memory",
			msg:      "Out of memory: Killed process 1234 (node) total-vm:4194304kB, anon-rss:2097152kB",
			wantCat:  PatternOOM,
			wantPass: true,
		},
		{
			name:     "Kernel page allocation failure ENOMEM",
			msg:      "node: page allocation failure: order:0, mode:0xcc0(GFP_KERNEL), Cannot allocate memory",
			wantCat:  PatternENOMEM,
			wantPass: true,
		},
		{
			name:     "V8 JavaScript heap out of memory",
			msg:      "<--- Last few GCs --->\n[1024:0x55bc] 45000 ms: Mark-sweep: 1400.2 (1420.5) MB; FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory",
			wantCat:  PatternHeapOOM,
			wantPass: true,
		},
		{
			name:     "PM2 crash and restart loop",
			msg:      "PM2 | App [haunted-api:0] exited with code [137] via signal [SIGKILL]\nPM2 | App [haunted-api:0] Restarting process by id 0",
			wantCat:  PatternPM2RestartLoop,
			wantPass: true,
		},
		{
			name:     "Systemd OOM killer unit message",
			msg:      "franken-chaos-workload.service: The kernel OOM killer killed some processes in this unit.",
			wantCat:  PatternOOM,
			wantPass: true,
		},
		{
			name:     "Systemd result oom-kill message",
			msg:      "franken-chaos-workload.service: Failed with result 'oom-kill'.",
			wantCat:  PatternOOM,
			wantPass: true,
		},
		{
			name:     "Normal application log",
			msg:      "HTTP GET /api/v1/health 200 OK duration=1.2ms",
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cat, matched := MatchPattern(tc.msg)
			if matched != tc.wantPass {
				t.Fatalf("expected matched=%v, got %v", tc.wantPass, matched)
			}
			if matched && cat != tc.wantCat {
				t.Errorf("expected category %s, got %s", tc.wantCat, cat)
			}
		})
	}
}

func TestStream_ParsesJSONAndRedactsSecrets(t *testing.T) {
	// Buat stream JSON mirip output journalctl -o json dengan kredensial sensitif
	sampleLogs := `{"MESSAGE":"Normal ping request","__REALTIME_TIMESTAMP":"1700000000000000","_SYSTEMD_UNIT":"app.service"}
{"MESSAGE":"FATAL ERROR: JavaScript heap out of memory while connecting to postgres://admin:superSecretDB123@10.0.0.5:5432/db","_SYSTEMD_UNIT":"haunted-api.service","_COMM":"node","_PID":"4096","__REALTIME_TIMESTAMP":"1700000001000000"}
{"MESSAGE":"PM2 | Restarting process by id 1 after crash","_SYSTEMD_UNIT":"pm2-root.service","_COMM":"pm2","_PID":"1024","__REALTIME_TIMESTAMP":"1700000002000000"}
`

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := make(chan JournalEvent, 5)
	r := strings.NewReader(sampleLogs)

	go func() {
		_ = Stream(ctx, r, out)
		close(out)
	}()

	var events []JournalEvent
	for ev := range out {
		events = append(events, ev)
	}

	// Baris pertama normal diabaikan, hanya 2 baris bermasalah yang harus menghasilkan event
	if len(events) != 2 {
		t.Fatalf("expected 2 journal events, got %d", len(events))
	}

	// Event 1: JavaScript heap out of memory
	ev1 := events[0]
	if ev1.Category != PatternHeapOOM {
		t.Errorf("expected PatternHeapOOM, got %s", ev1.Category)
	}
	if ev1.Unit != "haunted-api.service" || ev1.PID != 4096 {
		t.Errorf("unexpected unit or pid: unit=%s pid=%d", ev1.Unit, ev1.PID)
	}
	// Pastikan password database dan IP disensor otomatis
	if strings.Contains(ev1.Message, "superSecretDB123") {
		t.Errorf("secret password was not redacted in journal event: %s", ev1.Message)
	}
	if !strings.Contains(ev1.Message, "[REDACTED_PASSWORD]") {
		t.Errorf("expected [REDACTED_PASSWORD] marker in message: %s", ev1.Message)
	}

	// Event 2: PM2 restart loop
	ev2 := events[1]
	if ev2.Category != PatternPM2RestartLoop {
		t.Errorf("expected PatternPM2RestartLoop, got %s", ev2.Category)
	}
	if ev2.Unit != "pm2-root.service" {
		t.Errorf("expected pm2-root.service, got %s", ev2.Unit)
	}
}

func TestStream_ParsesSystemdInitScopeOOMWithUNITField(t *testing.T) {
	sample := `{"_SYSTEMD_UNIT":"init.scope","_COMM":"systemd","_PID":"1","UNIT":"franken-chaos-workload.service","MESSAGE":"franken-chaos-workload.service: The kernel OOM killer killed some processes in this unit.","__REALTIME_TIMESTAMP":"1700000003000000"}
{"_SYSTEMD_UNIT":"init.scope","_COMM":"systemd","_PID":"1","UNIT":"franken-chaos-workload.service","MESSAGE":"franken-chaos-workload.service: Failed with result 'oom-kill'.","__REALTIME_TIMESTAMP":"1700000004000000"}
`
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out := make(chan JournalEvent, 4)
	go func() {
		_ = Stream(ctx, strings.NewReader(sample), out)
		close(out)
	}()

	var events []JournalEvent
	for ev := range out {
		events = append(events, ev)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 OOM events, got %d", len(events))
	}
	for i, ev := range events {
		if ev.Category != PatternOOM {
			t.Errorf("event %d: expected PatternOOM, got %s", i, ev.Category)
		}
		if ev.Unit != "franken-chaos-workload.service" {
			t.Errorf("event %d: expected UNIT=franken-chaos-workload.service instead of _SYSTEMD_UNIT init.scope, got %q", i, ev.Unit)
		}
	}
}

func TestBuildJournalctlArgs_IncludesLinesZero(t *testing.T) {
	args := buildJournalctlArgs([]string{"haunted-api.service", "franken-chaos-workload.service"})
	joined := strings.Join(args, " ")
	for _, want := range []string{"--follow", "--lines=0", "--output=json", "--unit=haunted-api.service", "--unit=franken-chaos-workload.service"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q in journalctl args %v", want, args)
		}
	}
}
