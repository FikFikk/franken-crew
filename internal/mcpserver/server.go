package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/FikFikk/franken-crew/internal/approval"
	"github.com/FikFikk/franken-crew/internal/executor"
	"github.com/FikFikk/franken-crew/internal/incident"
	"github.com/FikFikk/franken-crew/internal/kernelfs"
	"github.com/FikFikk/franken-crew/internal/policy"
	"github.com/FikFikk/franken-crew/internal/reflex"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Config menyimpan dependensi dan pengaturan keamanan Sentinel MCP Server.
type Config struct {
	NodeName                  string
	Version                   string
	Store                     *incident.Store
	Catalog                   *policy.Catalog
	Reflex                    *reflex.Engine
	Verifier                  *approval.Verifier
	Runner                    CommandRunner
	FS                        kernelfs.FS
	CgroupRoot                string
	ProcRoot                  string
	JournalReader             JournalReader
	UnitInspector             UnitInspector
	HTTPProber                HTTPProber
	BearerToken               string
	AllowInsecureWildcardBind bool
	HeartbeatInterval         time.Duration
	PostmortemDir             string
	Clock                     func() time.Time
	// Pengaturan eksekusi L2 terisolasi (C4) dan background verification worker (C3)
	PM2Owner              string
	PM2Home               string
	TerminateGracePeriod  time.Duration
	TerminatePollInterval time.Duration
	ProcessAlive          func(ctx context.Context, pid int) bool
	VerifyPollInterval    time.Duration
	// AutoPostmortem menulis postmortem secara deterministik saat verifikasi forward mencapai status final
	AutoPostmortem bool
}

// Server mengimplementasikan MCP Server Sentinel melalui Streamable HTTP/SSE dan JSON-RPC stdio.
type Server struct {
	cfg         Config
	mcpServer   *mcp.Server
	broker      *EventBroker
	psiRing     *PSIRingBuffer
	startedAt   time.Time
	verifyCoord *verifyCoordinator
}

// HealthzResponse merepresentasikan payload JSON endpoint unauthenticated `GET /healthz`.
type HealthzResponse struct {
	Status       string   `json:"status"`
	Version      string   `json:"version"`
	Node         string   `json:"node"`
	UptimeS      int64    `json:"uptime_s"`
	Capabilities []string `json:"capabilities"`
	DegradedNote string   `json:"degraded_note,omitempty"`
}

// New membangun instance Sentinel MCP Server lengkap dengan 9 read/claim tools dan 5 write tools.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("mcpserver: incident store is required")
	}
	if cfg.Catalog == nil {
		return nil, errors.New("mcpserver: policy catalog is required")
	}
	if cfg.NodeName == "" {
		host, err := os.Hostname()
		if err != nil || host == "" {
			host = "sentinel"
		}
		cfg.NodeName = host
	}
	if cfg.Version == "" {
		cfg.Version = "0.1.0"
	}
	if cfg.FS == nil {
		cfg.FS = kernelfs.NewOSFS()
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = kernelfs.DefaultCgroupRoot
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = kernelfs.DefaultProcRoot
	}
	if cfg.Runner == nil {
		cfg.Runner = executor.NewExecutor(15 * time.Second)
	}
	if cfg.JournalReader == nil {
		cfg.JournalReader = &ExecJournalReader{Timeout: 5 * time.Second}
	}
	if cfg.UnitInspector == nil {
		cfg.UnitInspector = &RunnerUnitInspector{Runner: cfg.Runner}
	}
	if cfg.HTTPProber == nil {
		cfg.HTTPProber = &LoopbackHTTPProber{}
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}

	mcpSrv := mcp.NewServer(&mcp.Implementation{
		Name:    "franken-sentinel",
		Version: cfg.Version,
	}, &mcp.ServerOptions{
		Instructions: "FrankenCrew Sentinel MCP server: read-only kernel telemetry (L0) and policy/Ed25519-gated remediation (L1/L2).",
		SchemaCache:  mcp.NewSchemaCache(),
	})

	srv := &Server{
		cfg:         cfg,
		mcpServer:   mcpSrv,
		broker:      NewEventBroker(cfg.NodeName, DefaultEventHistorySize, cfg.HeartbeatInterval),
		psiRing:     NewPSIRingBuffer(DefaultPSIRingCapacity),
		startedAt:   cfg.Clock().UTC(),
		verifyCoord: newVerifyCoordinator(),
	}

	srv.registerReadTools()
	srv.registerWriteTools()
	return srv, nil
}

// Close menghentikan seluruh background verification worker secara bersih.
func (s *Server) Close() {
	if s != nil && s.verifyCoord != nil {
		s.verifyCoord.Close()
	}
}

// MCPServer mengembalikan instance `*mcp.Server` yang telah teregistrasi seluruh tool-nya.
func (s *Server) MCPServer() *mcp.Server {
	return s.mcpServer
}

// Broker mengembalikan broker event SSE `/v1/events` untuk publikasi insiden dan refleks secara real-time.
func (s *Server) Broker() *EventBroker {
	return s.broker
}

// PSIRing mengembalikan ring buffer histori PSI 1 Hz.
func (s *Server) PSIRing() *PSIRingBuffer {
	return s.psiRing
}

// RunStdio menjalankan server MCP di atas transport JSON-RPC stdin/stdout standar.
func (s *Server) RunStdio(ctx context.Context) error {
	return s.mcpServer.Run(ctx, &mcp.StdioTransport{})
}

// RunTransport menjalankan server MCP di atas transport khusus (mis. IOTransport / InMemoryTransport).
func (s *Server) RunTransport(ctx context.Context, transport mcp.Transport) error {
	return s.mcpServer.Run(ctx, transport)
}

// HTTPHandler membangun router HTTP (`/healthz`, `/v1/events`, `/mcp`) yang diamankan dengan Bearer token.
func (s *Server) HTTPHandler() (http.Handler, error) {
	if s.cfg.BearerToken == "" {
		return nil, ErrMissingBearerToken
	}

	streamable := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return s.mcpServer
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    false,
		DisableLocalhostProtection:   false,
		PropagateRequestCancellation: false,
		SessionTimeout:               15 * time.Minute,
	})

	mux := http.NewServeMux()
	// /healthz terbuka untuk watchdog systemd dan pengecekan liveness node tanpa kredensial
	mux.HandleFunc("/healthz", s.handleHealthz)
	// /v1/events dan /mcp wajib dilindungi Bearer authentication
	mux.Handle("/v1/events", BearerAuthMiddleware(s.cfg.BearerToken, s.broker))
	mux.Handle("/mcp", BearerAuthMiddleware(s.cfg.BearerToken, streamable))
	return mux, nil
}

// ListenAndServe memvalidasi alamat bind (hanya Tailscale/loopback/privat) dan menjalankan HTTP server hingga ctx dibatalkan.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	validatedAddr, err := ValidateBindAddr(addr, s.cfg.AllowInsecureWildcardBind)
	if err != nil {
		return err
	}
	handler, err := s.HTTPHandler()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", validatedAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", validatedAddr, err)
	}

	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if serveErr := httpSrv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		s.Close()
		return nil
	case err := <-errCh:
		s.Close()
		return err
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	caps, probeErr := kernelfs.Probe(s.cfg.FS, s.cfg.CgroupRoot, s.cfg.ProcRoot)
	var capList []string
	if caps.CgroupV2 {
		capList = append(capList, "cgroup_v2")
	}
	if caps.PSI {
		capList = append(capList, "psi")
	}
	if caps.MemoryReclaim {
		capList = append(capList, "memory_reclaim")
	}
	if capList == nil {
		capList = []string{}
	}

	uptime := int64(s.cfg.Clock().UTC().Sub(s.startedAt).Seconds())
	if uptime < 0 {
		uptime = 0
	}

	resp := HealthzResponse{
		Status:       "ok",
		Version:      s.cfg.Version,
		Node:         s.cfg.NodeName,
		UptimeS:      uptime,
		Capabilities: capList,
	}

	statusCode := http.StatusOK
	if probeErr != nil || !caps.CgroupV2 || !caps.PSI {
		statusCode = http.StatusServiceUnavailable
		resp.Status = "degraded"
		if probeErr != nil {
			resp.DegradedNote = probeErr.Error()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

