package reflex

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/FikFikk/franken-crew/internal/executor"
)

const (
	// DefaultAdmissionDir adalah direktori runtime standar untuk menampung status admission aplikasi.
	DefaultAdmissionDir = "/run/franken"
)

var (
	// validAppNameRegex membatasi nama aplikasi agar aman dari path traversal.
	validAppNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	// validUnitNameRegex membatasi format nama unit systemd agar tidak memuat flag atau karakter berbahaya.
	validUnitNameRegex = regexp.MustCompile(`^[a-zA-Z0-9@._:-]{1,128}$`)
)

// UnitProperties menyimpan properti resource cgroup/systemd yang dapat diatur sementara secara runtime.
type UnitProperties struct {
	MemoryHigh    string `json:"memory_high,omitempty"`
	CPUQuota      string `json:"cpu_quota,omitempty"`
	ResetCPUQuota bool   `json:"reset_cpu_quota,omitempty"`
	IOWeight      string `json:"io_weight,omitempty"`
}

// UnitPropertyDriver mengabstraksikan pembacaan dan modifikasi properti runtime systemd unit.
type UnitPropertyDriver interface {
	// GetProperties membaca properti runtime unit sebelum dimodifikasi agar dapat dikembalikan saat rollback.
	GetProperties(ctx context.Context, unit string) (UnitProperties, error)
	// SetProperties menerapkan properti runtime baru (via systemctl set-property --runtime).
	SetProperties(ctx context.Context, unit string, props UnitProperties) error
}

// AdmissionDriver mengabstraksikan pengendalian berkas gerbang admission aplikasi.
type AdmissionDriver interface {
	// WriteState menulis status admission aplikasi ("closed ..." atau "open").
	WriteState(ctx context.Context, app string, state string) error
	// ReadState membaca status admission saat ini; mengembalikan string kosong jika berkas belum ada.
	ReadState(ctx context.Context, app string) (string, error)
}

// ExecutorPropertyDriver mengimplementasikan UnitPropertyDriver menggunakan safe fixed-argv Executor.
type ExecutorPropertyDriver struct {
	exec    *executor.Executor
	timeout time.Duration
}

// NewExecutorPropertyDriver membuat driver properti systemd berbasis Executor aman.
func NewExecutorPropertyDriver(exec *executor.Executor, timeout time.Duration) *ExecutorPropertyDriver {
	if exec == nil {
		exec = executor.NewExecutor(10 * time.Second)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &ExecutorPropertyDriver{
		exec:    exec,
		timeout: timeout,
	}
}

// GetProperties mengambil nilai MemoryHigh, CPUQuotaPerSecUSec, dan IOWeight unit dari systemd.
func (d *ExecutorPropertyDriver) GetProperties(ctx context.Context, unit string) (UnitProperties, error) {
	if !validUnitNameRegex.MatchString(unit) {
		return UnitProperties{}, fmt.Errorf("invalid systemd unit name %q", unit)
	}

	res, err := d.exec.Execute(ctx, "systemctl", []string{
		"show",
		"--property=MemoryHigh,CPUQuotaPerSecUSec,IOWeight",
		unit,
	}, d.timeout)
	if err != nil {
		return UnitProperties{}, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	if res.ExitCode != 0 {
		return UnitProperties{}, fmt.Errorf("systemctl show %s exited %d: %s", unit, res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	var props UnitProperties
	for _, line := range strings.Split(res.Stdout, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "MemoryHigh":
			props.MemoryHigh = parts[1]
		case "CPUQuotaPerSecUSec":
			props.CPUQuota = normalizeCPUQuotaFromShow(parts[1])
		case "IOWeight":
			props.IOWeight = parts[1]
		}
	}
	return props, nil
}

// normalizeCPUQuotaFromShow mengonversi nilai keluaran systemd CPUQuotaPerSecUSec ke format set-property.
func normalizeCPUQuotaFromShow(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "infinity" || trimmed == "[not set]" {
		return ""
	}
	// Jika format sudah persen, kembalikan langsung
	if strings.HasSuffix(trimmed, "%") {
		return trimmed
	}
	// Jika berupa angka mikrodetik atau detik dari systemctl show, biarkan apa adanya bila valid
	return trimmed
}

// buildSetPropertyArgs menyusun daftar argumen `systemctl set-property --runtime` secara aman dan teruji.
func buildSetPropertyArgs(unit string, props UnitProperties) ([]string, error) {
	if !validUnitNameRegex.MatchString(unit) {
		return nil, fmt.Errorf("invalid systemd unit name %q", unit)
	}

	args := []string{"set-property", "--runtime", unit}
	if props.MemoryHigh != "" {
		args = append(args, "MemoryHigh="+props.MemoryHigh)
	}
	if props.ResetCPUQuota || props.CPUQuota == "infinity" || props.CPUQuota == "[not set]" {
		// Kirim nilai kosong "CPUQuota=" saat mereset kuota karena systemctl menolak "infinity" maupun "[not set]".
		args = append(args, "CPUQuota=")
	} else if props.CPUQuota != "" {
		args = append(args, "CPUQuota="+props.CPUQuota)
	}
	if props.IOWeight != "" {
		if _, err := strconv.Atoi(props.IOWeight); err != nil {
			return nil, fmt.Errorf("invalid IOWeight value %q: %w", props.IOWeight, err)
		}
		args = append(args, "IOWeight="+props.IOWeight)
	}
	return args, nil
}

// SetProperties mengatur properti runtime systemd menggunakan `systemctl set-property --runtime` tanpa shell.
func (d *ExecutorPropertyDriver) SetProperties(ctx context.Context, unit string, props UnitProperties) error {
	args, err := buildSetPropertyArgs(unit, props)
	if err != nil {
		return err
	}

	// Jika tidak ada properti untuk diterapkan, kembalikan nil
	if len(args) == 3 {
		return nil
	}

	res, err := d.exec.Execute(ctx, "systemctl", args, d.timeout)
	if err != nil {
		return fmt.Errorf("systemctl set-property %s: %w", unit, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("systemctl set-property %s exited %d: %s", unit, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// FSAdmissionDriver mengelola berkas status admission di direktori runtime (/run/franken/<app>/admission).
type FSAdmissionDriver struct {
	baseDir string
}

// NewFSAdmissionDriver membuat driver berkas admission pada direktori dasar tertentu.
func NewFSAdmissionDriver(baseDir string) *FSAdmissionDriver {
	if baseDir == "" {
		baseDir = DefaultAdmissionDir
	}
	return &FSAdmissionDriver{baseDir: baseDir}
}

// admissionPath membangun path berkas admission secara aman setelah memvalidasi nama aplikasi.
func (d *FSAdmissionDriver) admissionPath(app string) (string, error) {
	if !validAppNameRegex.MatchString(app) {
		return "", fmt.Errorf("%w: %q", ErrInvalidAppName, app)
	}
	return filepath.Join(d.baseDir, app, "admission"), nil
}

// WriteState menulis status admission secara langsung ke berkas runtime aplikasi.
func (d *FSAdmissionDriver) WriteState(_ context.Context, app string, state string) error {
	targetPath, err := d.admissionPath(app)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("create admission dir for %s: %w", app, err)
	}
	if err := os.WriteFile(targetPath, []byte(state), 0o644); err != nil {
		return fmt.Errorf("write admission file %s: %w", targetPath, err)
	}
	return nil
}

// ReadState membaca isi berkas admission aplikasi saat ini.
func (d *FSAdmissionDriver) ReadState(_ context.Context, app string) (string, error) {
	targetPath, err := d.admissionPath(app)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read admission file %s: %w", targetPath, err)
	}
	return string(data), nil
}
