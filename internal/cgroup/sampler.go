package cgroup

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/psi"
)

const (
	// DefaultSampleInterval adalah interval sampling telemetri berkala (1 detik = 1 Hz).
	DefaultSampleInterval = 1 * time.Second
)

// Sample menyimpan seluruh telemetri memori cgroup hasil pembacaan berkala 1 Hz.
type Sample struct {
	Cgroup        string            `json:"cgroup"`
	MemoryCurrent uint64            `json:"memory_current"`
	MemoryMax     uint64            `json:"memory_max"`
	Stat          map[string]uint64 `json:"stat"`
	Events        MemoryEvents      `json:"events"`
	PSISomeAvg10  float64           `json:"psi_some_avg10"`
	PSIFullAvg10  float64           `json:"psi_full_avg10"`
	At            time.Time         `json:"at"`
}

// Sampler mengelola pembacaan berkala 1 Hz untuk memory.current, memory.stat, dan PSI avg10.
type Sampler struct {
	fs       kernelfs.FS
	interval time.Duration
}

// NewSampler membuat instance Sampler baru dengan fs dan interval tertentu.
func NewSampler(fsys kernelfs.FS, interval time.Duration) *Sampler {
	if fsys == nil {
		fsys = kernelfs.NewOSFS()
	}
	if interval <= 0 {
		interval = DefaultSampleInterval
	}
	return &Sampler{
		fs:       fsys,
		interval: interval,
	}
}

// SampleCgroup membaca seluruh metrik telemetri dari sebuah direktori cgroup secara atomik.
func (s *Sampler) SampleCgroup(cgroupPath string) (Sample, error) {
	now := time.Now()
	cgroupName := path.Base(cgroupPath)

	// 1. Baca memory.current
	currentPath := kernelfs.JoinPath(cgroupPath, "memory.current")
	curBytes, _, err := kernelfs.ReadUint64(s.fs, currentPath)
	if err != nil {
		return Sample{}, fmt.Errorf("read memory.current on %s: %w", cgroupPath, err)
	}

	// 2. Baca memory.max (nilai 0 jika string literal "max")
	maxPath := kernelfs.JoinPath(cgroupPath, "memory.max")
	maxBytes, isMax, err := kernelfs.ReadUint64(s.fs, maxPath)
	if err != nil {
		// Jika berkas tidak ada, anggap tidak dibatasi
		maxBytes = 0
	} else if isMax {
		maxBytes = 0
	}

	// 3. Baca memory.stat (anon, file, slab, sock, shmem, dll.)
	statPath := kernelfs.JoinPath(cgroupPath, "memory.stat")
	statMap, err := kernelfs.ReadKeyValueUint64(s.fs, statPath)
	if err != nil {
		statMap = make(map[string]uint64)
	}

	// 4. Baca memory.events
	eventsPath := kernelfs.JoinPath(cgroupPath, "memory.events")
	events, err := ReadMemoryEvents(s.fs, eventsPath)
	if err != nil {
		events = MemoryEvents{}
	}

	// 5. Baca memory.pressure (PSI) jika ada
	var someAvg10, fullAvg10 float64
	pressurePath := kernelfs.JoinPath(cgroupPath, "memory.pressure")
	if metrics, err := psi.ReadMetrics(s.fs, pressurePath); err == nil {
		someAvg10 = metrics.Some.Avg10
		fullAvg10 = metrics.Full.Avg10
	}

	return Sample{
		Cgroup:        cgroupName,
		MemoryCurrent: curBytes,
		MemoryMax:     maxBytes,
		Stat:          statMap,
		Events:        events,
		PSISomeAvg10:  someAvg10,
		PSIFullAvg10:  fullAvg10,
		At:            now,
	}, nil
}

// Start menjalankan loop sampling 1 Hz untuk daftar cgroup target hingga context dibatalkan.
func (s *Sampler) Start(ctx context.Context, cgroupPaths []string, out chan<- Sample) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, cgPath := range cgroupPaths {
				sample, err := s.SampleCgroup(cgPath)
				if err != nil {
					continue
				}
				select {
				case out <- sample:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}
