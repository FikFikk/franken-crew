package cgroup

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
)

var (
	// ErrEventsFileNotFound dikembalikan jika berkas memory.events tidak ditemukan pada target cgroup.
	ErrEventsFileNotFound = errors.New("cgroup: memory.events file not found")
)

// MemoryEvents menyimpan nilai counter kumulatif dari berkas memory.events cgroup v2.
type MemoryEvents struct {
	Low     uint64 `json:"low"`
	High    uint64 `json:"high"`
	Max     uint64 `json:"max"`
	OOM     uint64 `json:"oom"`
	OOMKill uint64 `json:"oom_kill"`
}

// EventsDelta merepresentasikan selisih kenaikan nilai counter memory.events antar-kejadian.
type EventsDelta struct {
	Cgroup     string       `json:"cgroup"`
	EventsPath string       `json:"events_path"`
	Current    MemoryEvents `json:"current"`
	Delta      MemoryEvents `json:"delta"`
	At         time.Time    `json:"at"`
}

// InotifyPoller mengabstraksikan notifikasi modifikasi berkas berbasis inotify (atau mock untuk test).
type InotifyPoller interface {
	// Watch memantau event modifikasi (IN_MODIFY) pada targetPath dan memanggil onChange setiap kali berkas dimodifikasi.
	Watch(ctx context.Context, targetPath string, onChange func()) error
}

// EventsWatcherConfig menyimpan konfigurasi pemantauan berkas memory.events.
type EventsWatcherConfig struct {
	FS     kernelfs.FS
	Poller InotifyPoller
}

// EventsWatcher membaca delta memory.events dalam < 100 ms saat kernel memodifikasi berkas.
type EventsWatcher struct {
	fs     kernelfs.FS
	poller InotifyPoller
	mu     sync.Mutex
	last   map[string]MemoryEvents
}

// NewEventsWatcher membuat instance watcher baru untuk memory.events.
func NewEventsWatcher(cfg EventsWatcherConfig) *EventsWatcher {
	fsys := cfg.FS
	if fsys == nil {
		fsys = kernelfs.NewOSFS()
	}
	poller := cfg.Poller
	if poller == nil {
		poller = newOSInotifyPoller()
	}
	return &EventsWatcher{
		fs:     fsys,
		poller: poller,
		last:   make(map[string]MemoryEvents),
	}
}

// WatchTarget memantau berkas memory.events pada sebuah cgroup dan mengirimkan EventsDelta ke channel output.
func (w *EventsWatcher) WatchTarget(ctx context.Context, cgroup string, eventsPath string, out chan<- EventsDelta) error {
	// Baca kondisi baseline saat pertama kali mulai memantau
	initial, err := ReadMemoryEvents(w.fs, eventsPath)
	if err != nil {
		return fmt.Errorf("read initial memory.events on %s: %w", eventsPath, err)
	}

	w.mu.Lock()
	w.last[eventsPath] = initial
	w.mu.Unlock()

	return w.poller.Watch(ctx, eventsPath, func() {
		current, readErr := ReadMemoryEvents(w.fs, eventsPath)
		if readErr != nil {
			return
		}

		w.mu.Lock()
		prev := w.last[eventsPath]
		w.last[eventsPath] = current
		w.mu.Unlock()

		delta := computeDelta(prev, current)

		// Kirim event jika ada counter yang bertambah
		if delta.Low > 0 || delta.High > 0 || delta.Max > 0 || delta.OOM > 0 || delta.OOMKill > 0 {
			select {
			case out <- EventsDelta{
				Cgroup:     cgroup,
				EventsPath: eventsPath,
				Current:    current,
				Delta:      delta,
				At:         time.Now(),
			}:
			case <-ctx.Done():
			}
		}
	})
}

// ReadMemoryEvents mem-parsing berkas memory.events menjadi struktur MemoryEvents.
func ReadMemoryEvents(fsys kernelfs.FS, eventsPath string) (MemoryEvents, error) {
	kv, err := kernelfs.ReadKeyValueUint64(fsys, eventsPath)
	if err != nil {
		return MemoryEvents{}, err
	}
	return MemoryEvents{
		Low:     kv["low"],
		High:    kv["high"],
		Max:     kv["max"],
		OOM:     kv["oom"],
		OOMKill: kv["oom_kill"],
	}, nil
}

// computeDelta menghitung selisih pertambahan counter antar dua observasi memory.events.
func computeDelta(prev, current MemoryEvents) MemoryEvents {
	var d MemoryEvents
	if current.Low > prev.Low {
		d.Low = current.Low - prev.Low
	}
	if current.High > prev.High {
		d.High = current.High - prev.High
	}
	if current.Max > prev.Max {
		d.Max = current.Max - prev.Max
	}
	if current.OOM > prev.OOM {
		d.OOM = current.OOM - prev.OOM
	}
	if current.OOMKill > prev.OOMKill {
		d.OOMKill = current.OOMKill - prev.OOMKill
	}
	return d
}

