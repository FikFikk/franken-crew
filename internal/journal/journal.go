package journal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/FikFikk/franken-crew/internal/redact"
)

// PatternCategory mendefinisikan kategori pola insiden yang dikenali pada stream log.
type PatternCategory string

const (
	PatternOOM            PatternCategory = "OOM"
	PatternENOMEM         PatternCategory = "ENOMEM"
	PatternHeapOOM        PatternCategory = "HEAP_OOM"
	PatternPM2RestartLoop PatternCategory = "PM2_RESTART_LOOP"
)

var (
	// Pola log OOM killer Linux maupun pesan terminasi OOM systemd pada UNIT target
	reOOM = regexp.MustCompile(`(?i)(out of memory|killed process \d+|invoked oom-killer|oom-reaper|kernel oom killer killed|failed with result ['"]?oom-kill['"]?)`)
	// Pola kegagalan alokasi memori sistem
	reENOMEM = regexp.MustCompile(`(?i)(cannot allocate memory|\bENOMEM\b|page allocation failure)`)
	// Pola kehabisan heap pada runtime aplikasi (Node.js, Go runtime, JVM)
	reHeapOOM = regexp.MustCompile(`(?i)(JavaScript heap out of memory|fatal error: runtime: out of memory|java\.lang\.OutOfMemoryError)`)
	// Pola perputaran restart cepat pada process manager PM2
	rePM2Restart = regexp.MustCompile(`(?i)(PM2.*restart|Restarting process by id|Process.*stopped unexpectedly|errored.*restarting)`)
)

// JournalEntry merepresentasikan struktur JSON mentah dari `journalctl -o json`.
type JournalEntry struct {
	Message           string `json:"MESSAGE"`
	SystemdUnit       string `json:"_SYSTEMD_UNIT"`
	Unit              string `json:"UNIT"`
	Comm              string `json:"_COMM"`
	PID               string `json:"_PID"`
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
}

// JournalEvent merepresentasikan kejadian log yang cocok dengan pola anomali memori.
type JournalEvent struct {
	Category  PatternCategory `json:"category"`
	Message   string          `json:"message"`
	Unit      string          `json:"unit"`
	Comm      string          `json:"comm"`
	PID       int             `json:"pid"`
	Timestamp time.Time       `json:"timestamp"`
	RawLine   string          `json:"raw_line,omitempty"`
}

// MatchPattern memeriksa apakah sebuah pesan log cocok dengan salah satu pola anomali memori.
func MatchPattern(message string) (PatternCategory, bool) {
	// Dahulukan pola spesifik runtime (heap OOM) sebelum pola umum kernel out-of-memory
	if reHeapOOM.MatchString(message) {
		return PatternHeapOOM, true
	}
	if rePM2Restart.MatchString(message) {
		return PatternPM2RestartLoop, true
	}
	if reOOM.MatchString(message) {
		return PatternOOM, true
	}
	if reENOMEM.MatchString(message) {
		return PatternENOMEM, true
	}
	return "", false
}

// Stream membaca stream JSON dari io.Reader (misalnya output journalctl), mencocokkan pola, menyensor data, dan mengirim event.
func Stream(ctx context.Context, r io.Reader, out chan<- JournalEvent) error {
	scanner := bufio.NewScanner(r)

	// Alokasikan buffer maksimum 1 MB untuk menangani baris log yang panjang
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var entry JournalEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		category, matched := MatchPattern(entry.Message)
		if !matched {
			continue
		}

		// Sensor pesan log dari token rahasia sebelum dikirimkan ke channel
		redactedMsg := redact.String(entry.Message)

		pid, _ := strconv.Atoi(entry.PID)
		var ts time.Time
		if usec, err := strconv.ParseInt(entry.RealtimeTimestamp, 10, 64); err == nil && usec > 0 {
			ts = time.UnixMicro(usec)
		} else {
			ts = time.Now()
		}

		unitName := entry.SystemdUnit
		// Pesan systemd (PID 1) mencatat OOM milik service dengan _SYSTEMD_UNIT="init.scope" dan UNIT="<unit>.service"
		if entry.Unit != "" && (unitName == "" || unitName == "init.scope") {
			unitName = entry.Unit
		}

		event := JournalEvent{
			Category:  category,
			Message:   redactedMsg,
			Unit:      unitName,
			Comm:      entry.Comm,
			PID:       pid,
			Timestamp: ts,
			RawLine:   redact.String(string(line)),
		}

		select {
		case out <- event:
		case <-ctx.Done():
			return nil
		}
	}

	return scanner.Err()
}

// buildJournalctlArgs menyusun argumen `journalctl` live-tail tanpa mengulang log historis saat restart.
func buildJournalctlArgs(units []string) []string {
	args := []string{"--follow", "--lines=0", "--output=json"}
	for _, u := range units {
		args = append(args, "--unit="+u)
	}
	return args
}

// StartJournalctlStream menjalankan proses `journalctl --follow --lines=0 --output=json` untuk unit tertentu dan mengalirkan event-nya.
func StartJournalctlStream(ctx context.Context, units []string, out chan<- JournalEvent) error {
	args := buildJournalctlArgs(units)

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	// Batasi waktu tunggu proses anak saat ctx dibatalkan agar daemon tidak terkena timeout SIGKILL systemd
	cmd.WaitDelay = 2 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open journalctl pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start journalctl: %w", err)
	}

	streamErr := Stream(ctx, stdout, out)
	// Panggil Wait setelah Stream selesai membaca pipe sesuai kontrak os/exec.StdoutPipe
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if streamErr != nil {
		return streamErr
	}
	return waitErr
}
