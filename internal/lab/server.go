package lab

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

const (
	// contentSecurityPolicy hanya mengizinkan aset milik dashboard sendiri; tidak ada skrip atau koneksi pihak ketiga.
	contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

	cacheNoCache = "no-cache"
	cacheAsset   = "public, max-age=300"

	// maxRequestPathLen menolak path yang tidak wajar panjangnya sebelum diproses.
	maxRequestPathLen = 512
)

// contentTypes memetakan ekstensi aset dashboard ke Content-Type eksplisit (nosniff aktif di setiap respons).
var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".svg":         "image/svg+xml",
	".json":        "application/json",
	".map":         "application/json",
	".txt":         "text/plain; charset=utf-8",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".webp":        "image/webp",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".webmanifest": "application/manifest+json",
}

// HandlerConfig mengatur server dashboard Graveyard read-only.
type HandlerConfig struct {
	// Files berisi index.html, dist/, assets/, dan data/ (biasanya ui.Files hasil go:embed).
	Files fs.FS
	// DataDir opsional; /data/* dibaca dari direktori ini lebih dulu, lalu dari Files bila tidak ada.
	DataDir string
	// Status opsional; tanpa sumber /api/status mengembalikan {"mode":"replay"}.
	Status StatusSource
}

type handler struct {
	cfg HandlerConfig
}

// NewHandler membangun handler HTTP GET/HEAD-only untuk dashboard publik beserta header keamanan ketat.
func NewHandler(cfg HandlerConfig) (http.Handler, error) {
	if cfg.Files == nil {
		return nil, errors.New("lab: dashboard files are required")
	}
	if st, err := fs.Stat(cfg.Files, "index.html"); err != nil || st.IsDir() {
		return nil, errors.New("lab: dashboard files must contain index.html")
	}
	return &handler{cfg: cfg}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("Content-Security-Policy", contentSecurityPolicy)
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	hdr.Set("Cross-Origin-Opener-Policy", "same-origin")

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hdr.Set("Allow", "GET, HEAD")
		writePlain(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !isSafeRequestPath(r) {
		writePlain(w, r, http.StatusNotFound, "not found")
		return
	}

	p := r.URL.Path
	switch {
	case p == "/":
		h.serveFS(w, r, h.cfg.Files, "index.html", cacheNoCache, false, true)
	case p == "/healthz":
		hdr.Set("Cache-Control", cacheNoCache)
		writePlain(w, r, http.StatusOK, "ok")
	case p == "/api/status":
		h.serveStatus(w, r)
	case strings.HasPrefix(p, "/dist/"), strings.HasPrefix(p, "/assets/"):
		h.serveFS(w, r, h.cfg.Files, strings.TrimPrefix(p, "/"), cacheAsset, false, true)
	case strings.HasPrefix(p, "/data/"):
		h.serveData(w, r, strings.TrimPrefix(p, "/data/"))
	default:
		writePlain(w, r, http.StatusNotFound, "not found")
	}
}

// isSafeRequestPath menolak traversal (`..`/`.`), slash/backslash ter-encode, segmen kosong, dan path tidak kanonik.
func isSafeRequestPath(r *http.Request) bool {
	p := r.URL.Path
	if p == "" || len(p) > maxRequestPathLen || !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.ContainsAny(p, "\\\x00") {
		return false
	}
	if raw := strings.ToLower(r.URL.RawPath); strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") || strings.Contains(raw, "%00") {
		return false
	}
	if p == "/" {
		return true
	}
	if path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// serveData melayani /data/* dari DataDir (lewat os.Root agar symlink/traversal tidak keluar direktori) lalu fallback ke Files.
func (h *handler) serveData(w http.ResponseWriter, r *http.Request, name string) {
	if !fs.ValidPath(name) {
		writePlain(w, r, http.StatusNotFound, "not found")
		return
	}
	cors := strings.EqualFold(path.Ext(name), ".json")
	if dir := strings.TrimSpace(h.cfg.DataDir); dir != "" {
		if root, err := os.OpenRoot(dir); err == nil {
			served := h.serveFS(w, r, root.FS(), name, cacheNoCache, cors, false)
			_ = root.Close()
			if served {
				return
			}
		}
	}
	h.serveFS(w, r, h.cfg.Files, path.Join("data", name), cacheNoCache, cors, true)
}

// serveFS melayani satu berkas reguler dari fsys. Bila berkas tidak ada, answer404 menentukan apakah 404 langsung
// ditulis (Files bawaan) atau false dikembalikan tanpa menulis respons agar pemanggil bisa mencoba sumber lain.
func (h *handler) serveFS(w http.ResponseWriter, r *http.Request, fsys fs.FS, name, cache string, cors, answer404 bool) bool {
	notFound := func() bool {
		if answer404 {
			writePlain(w, r, http.StatusNotFound, "not found")
		}
		return false
	}
	if !fs.ValidPath(name) {
		return notFound()
	}
	f, err := fsys.Open(name)
	if err != nil {
		return notFound()
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return notFound()
	}

	content, ok := f.(io.ReadSeeker)
	if !ok {
		data, readErr := io.ReadAll(f)
		if readErr != nil {
			return notFound()
		}
		content = bytes.NewReader(data)
	}

	hdr := w.Header()
	hdr.Set("Content-Type", contentTypeFor(name))
	hdr.Set("Cache-Control", cache)
	if cors {
		hdr.Set("Access-Control-Allow-Origin", "*")
	}
	http.ServeContent(w, r, "", st.ModTime(), content)
	return true
}

func (h *handler) serveStatus(w http.ResponseWriter, r *http.Request) {
	st := LiveStatus{Mode: StatusModeReplay}
	if h.cfg.Status != nil {
		st = h.cfg.Status.Status(r.Context())
	}
	body, err := json.Marshal(st)
	if err != nil {
		writePlain(w, r, http.StatusInternalServerError, "status unavailable")
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Cache-Control", cacheNoCache)
	hdr.Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(append(body, '\n'))
	}
}

func writePlain(w http.ResponseWriter, r *http.Request, status int, msg string) {
	hdr := w.Header()
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	if hdr.Get("Cache-Control") == "" {
		hdr.Set("Cache-Control", cacheNoCache)
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, msg)
	}
}

func contentTypeFor(name string) string {
	if ct, ok := contentTypes[strings.ToLower(path.Ext(name))]; ok {
		return ct
	}
	return "application/octet-stream"
}
