package kernelfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FS mendefinisikan abstraksi sistem berkas untuk mengakses pseudo-file kernel (/sys/fs/cgroup dan /proc).
type FS interface {
	// ReadFile membaca seluruh isi berkas pada path yang diberikan.
	ReadFile(filePath string) ([]byte, error)
	// WriteFile menulis byte ke berkas kontrol kernel tanpa memicu flag truncate yang tidak perlu.
	WriteFile(filePath string, data []byte) error
	// Stat mengembalikan metadata informasi berkas pada path yang diberikan.
	Stat(filePath string) (fs.FileInfo, error)
	// ReadDir membaca daftar entri direktori pada path yang diberikan.
	ReadDir(dirPath string) ([]fs.DirEntry, error)
}

// OSFS adalah implementasi FS produksi yang langsung mengakses sistem berkas OS Linux.
type OSFS struct{}

// NewOSFS membuat instance OSFS baru untuk penggunaan produksi.
func NewOSFS() *OSFS {
	return &OSFS{}
}

// ReadFile membaca berkas langsung dari sistem berkas host.
func (o *OSFS) ReadFile(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read kernel file %s: %w", filePath, err)
	}
	return data, nil
}

// WriteFile menulis data ke berkas kontrol kernel menggunakan O_WRONLY dalam satu syscall write.
func (o *OSFS) WriteFile(filePath string, data []byte) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open kernel file for write %s: %w", filePath, err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write kernel file %s: %w", filePath, err)
	}
	return nil
}

// Stat memeriksa metadata berkas pada sistem berkas host.
func (o *OSFS) Stat(filePath string) (fs.FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat kernel file %s: %w", filePath, err)
	}
	return info, nil
}

// ReadDir membaca isi direktori pada sistem berkas host.
func (o *OSFS) ReadDir(dirPath string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("readdir kernel path %s: %w", dirPath, err)
	}
	return entries, nil
}

// MemFS adalah implementasi FS berbasis memori untuk pengujian unit menggunakan fixture tanpa akses root.
type MemFS struct {
	mu        sync.RWMutex
	files     map[string][]byte
	dirs      map[string]bool
	writeHook func(filePath string, data []byte) error
}

// NewMemFS membuat instance MemFS kosong yang siap diisi data fixture.
func NewMemFS() *MemFS {
	return &MemFS{
		files: make(map[string][]byte),
		dirs:  map[string]bool{"/": true},
	}
}

// normalizePath menormalkan path menjadi format slash POSIX agar konsisten di semua OS.
func normalizePath(p string) string {
	cleaned := path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

// SetWriteHook memasang callback opsional untuk menyimulasikan respons atau error saat penulisan berkas kernel.
func (m *MemFS) SetWriteHook(hook func(filePath string, data []byte) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeHook = hook
}

// SetFile menyimpan atau memperbarui isi berkas fixture beserta seluruh direktori induknya.
func (m *MemFS) SetFile(filePath string, content string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	norm := normalizePath(filePath)
	m.files[norm] = []byte(content)

	dir := path.Dir(norm)
	for dir != "/" && dir != "." {
		m.dirs[dir] = true
		dir = path.Dir(dir)
	}
	m.dirs["/"] = true
}

// MkdirAll membuat direktori virtual beserta induknya di dalam MemFS.
func (m *MemFS) MkdirAll(dirPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	norm := normalizePath(dirPath)
	for norm != "/" && norm != "." {
		m.dirs[norm] = true
		norm = path.Dir(norm)
	}
	m.dirs["/"] = true
}

// Remove menghapus berkas atau direktori dari MemFS (misal untuk simulasi penghapusan cgroup).
func (m *MemFS) Remove(targetPath string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	norm := normalizePath(targetPath)
	delete(m.files, norm)
	delete(m.dirs, norm)
}

// ReadFile membaca berkas dari penyimpanan memori fixture.
func (m *MemFS) ReadFile(filePath string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	norm := normalizePath(filePath)
	data, ok := m.files[norm]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: norm, Err: fs.ErrNotExist}
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	return copied, nil
}

// WriteFile menulis data ke berkas di memori atau memicu writeHook jika terpasang.
func (m *MemFS) WriteFile(filePath string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	norm := normalizePath(filePath)
	if m.writeHook != nil {
		if err := m.writeHook(norm, data); err != nil {
			return err
		}
	}
	if _, exists := m.files[norm]; !exists {
		return &fs.PathError{Op: "open", Path: norm, Err: fs.ErrNotExist}
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	m.files[norm] = copied
	return nil
}

// Stat mengembalikan fs.FileInfo untuk berkas atau direktori di dalam MemFS.
func (m *MemFS) Stat(filePath string) (fs.FileInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	norm := normalizePath(filePath)
	if data, ok := m.files[norm]; ok {
		return &memFileInfo{
			name:  path.Base(norm),
			size:  int64(len(data)),
			mode:  0o644,
			isDir: false,
		}, nil
	}
	if m.dirs[norm] {
		return &memFileInfo{
			name:  path.Base(norm),
			size:  0,
			mode:  fs.ModeDir | 0o755,
			isDir: true,
		}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: norm, Err: fs.ErrNotExist}
}

// ReadDir mengembalikan daftar entri anak langsung dari sebuah direktori di dalam MemFS.
func (m *MemFS) ReadDir(dirPath string) ([]fs.DirEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	norm := normalizePath(dirPath)
	if !m.dirs[norm] {
		return nil, &fs.PathError{Op: "readdir", Path: norm, Err: fs.ErrNotExist}
	}

	entriesMap := make(map[string]fs.DirEntry)
	prefix := norm
	if prefix != "/" {
		prefix += "/"
	}

	for fPath, data := range m.files {
		if strings.HasPrefix(fPath, prefix) {
			rest := strings.TrimPrefix(fPath, prefix)
			if !strings.Contains(rest, "/") && rest != "" {
				info := &memFileInfo{name: rest, size: int64(len(data)), mode: 0o644, isDir: false}
				entriesMap[rest] = fs.FileInfoToDirEntry(info)
			}
		}
	}

	for dPath := range m.dirs {
		if strings.HasPrefix(dPath, prefix) {
			rest := strings.TrimPrefix(dPath, prefix)
			if !strings.Contains(rest, "/") && rest != "" {
				info := &memFileInfo{name: rest, size: 0, mode: fs.ModeDir | 0o755, isDir: true}
				entriesMap[rest] = fs.FileInfoToDirEntry(info)
			}
		}
	}

	names := make([]string, 0, len(entriesMap))
	for name := range entriesMap {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]fs.DirEntry, 0, len(names))
	for _, name := range names {
		result = append(result, entriesMap[name])
	}
	return result, nil
}

// memFileInfo mengimplementasikan fs.FileInfo untuk entri MemFS.
type memFileInfo struct {
	name  string
	size  int64
	mode  fs.FileMode
	isDir bool
}

func (i *memFileInfo) Name() string       { return i.name }
func (i *memFileInfo) Size() int64        { return i.size }
func (i *memFileInfo) Mode() fs.FileMode  { return i.mode }
func (i *memFileInfo) ModTime() time.Time { return time.Time{} }
func (i *memFileInfo) IsDir() bool        { return i.isDir }
func (i *memFileInfo) Sys() any           { return nil }

// JoinPath menggabungkan segmen path kernel dalam format POSIX standar.
func JoinPath(elem ...string) string {
	cleaned := filepath.ToSlash(path.Join(elem...))
	if !strings.HasPrefix(cleaned, "/") {
		return "/" + cleaned
	}
	return cleaned
}

// ReadUint64 membaca nilai numerik uint64 dari berkas cgroup seperti memory.current atau memory.max.
// Mengembalikan (0, true, nil) apabila berkas berisi string literal "max".
func ReadUint64(fsys FS, filePath string) (uint64, bool, error) {
	raw, err := fsys.ReadFile(filePath)
	if err != nil {
		return 0, false, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "max" {
		return 0, true, nil
	}
	val, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse uint64 from %s (%q): %w", filePath, trimmed, err)
	}
	return val, false, nil
}

// ReadKeyValueUint64 mem-parsing berkas cgroup berformat "key value" per baris seperti memory.events dan memory.stat.
func ReadKeyValueUint64(fsys FS, filePath string) (map[string]uint64, error) {
	raw, err := fsys.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	result := make(map[string]uint64)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid key-value line in %s: %q", filePath, line)
		}
		val, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse value for key %q in %s: %w", fields[0], filePath, err)
		}
		result[fields[0]] = val
	}
	return result, nil
}

// ReadMemTotalBytes membaca total kapasitas RAM host (dalam byte) dari berkas /proc/meminfo.
func ReadMemTotalBytes(fsys FS, procRoot string) (uint64, error) {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	meminfoPath := JoinPath(procRoot, "meminfo")
	raw, err := fsys.ReadFile(meminfoPath)
	if err != nil {
		return 0, err
	}

	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("malformed MemTotal line in %s: %q", meminfoPath, line)
			}
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("parse MemTotal kB in %s: %w", meminfoPath, err)
			}
			return kb * 1024, nil
		}
	}
	return 0, errors.New("MemTotal entry not found in /proc/meminfo")
}
