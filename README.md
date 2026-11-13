# FrankenCrew

**FrankenCrew** is a Two-Speed autonomous Linux server self-healing sentinel paired with **Kiro CLI Crew** and human-in-the-loop WhatsApp approvals.

> **Status (Sentinel Core + Headless WhatsApp Bridge + Kiro Crew + Chaos Verification Complete)**
>
> - **Implemented & Tested (Go 1.26+, pure-Go static binary `CGO_ENABLED=0`):** Kernel telemetry (`kernelfs`, `psi`, `cgroup`, `journal`), EWMA Time-To-OOM `detector`, SQLite WAL `incident` store & `redact` pipeline, single-source `policy` & fixed-argv `executor`, L1 TTL `reflex` engine, Ed25519 `approval` protocol, Streamable HTTP/SSE & stdio `mcpserver` (including 120s PSI+RAM stability `verify_health` and `postmortem_generate`), unified `sentinel` daemon, headless `whatsmeow` bridge (`internal/wabridge` + `cmd/wa-bridge`), redacted markdown `postmortem` generator, systemd sandbox units (`deploy/systemd/`), 20-cycle `chaos` suite (`internal/chaos` + `chaos/`), and the `franken` CLI (`keys init`, `sentinel serve`, `mcp serve|stdio|connect`, `wa-login`, `postmortem`, `chaos run`, `guard`).
> - **Implemented Kiro Customization Stack (`.kiro/`):** Spec-driven development specs, multi-mode steering documents, 5 deterministic `v1` hooks (including `.kiro/hooks/preToolUse.json` running `franken guard --audit`), 3 MCP-only specialized agents (`franken-sentry`, `franken-architect`, `franken-remediator`), crons (`incident-sweep`, `morning-digest`), 3 skills (`linux-memory-forensics`, `remediation-runbooks`, `incident-spec-writer`), and `.kiro/settings/mcp.json`.
> - **Planned Next Milestones:** Read-only **Haunted Lab** observability web dashboard and standalone Kiro Crew application packaging (`franken-crew-app`).

## Two-Speed Self-Healing Architecture

1. **Speed 1 — Deterministic Kernel Reflex (`internal/sentinel`, `< 250 ms`):** Watches `/proc/pressure/memory` (`POLLPRI`), `cgroup v2` `memory.pressure`, `memory.events` (`inotify`), and systemd `journalctl` JSON streams while sampling at `1 Hz` into a rolling ring buffer. On P1/P2 memory pressure or `oom_kill`, applies bounded, TTL-reversible L1 reflexes (`cgroup_reclaim` ≤ 25% of `memory.current`, runtime `MemoryHigh` throttling ≥ current usage and ≤ 95% host RAM) backed by persistent SQLite rollback state.
2. **Speed 2 — AI Reasoning + Cryptographic Human Approval (`.kiro/agents/`, MCP, Ed25519):** AI agents (`franken-sentry` → `franken-architect` → `franken-remediator`) connect strictly through Sentinel MCP tools, cite redacted `evidence_id` snapshots, compute canonical SHA-256 `plan_hash` values, require single-use Ed25519 approval tokens for L2 mutations, and verify 120 seconds of healthy PSI (`some_avg10 < 5.0` and `full_avg10 < 1.0`) before resolving incidents.

## Non-Negotiable Safety Guardrails

- **No Raw Shell Execution:** Fixed `exec.Command(binary, args...)` allowlist only; `sh -c` and `bash -c` are forbidden in both Sentinel and `franken guard`.
- **Protected Infrastructure:** PID 1, kernel threads, `sshd`, `systemd-journald`, `systemd-logind`, `dbus`, `tailscaled`, `franken-sentinel`, `wa-bridge`, and `kiro-crew` are hard-blocked across policy, reflex, executor, MCP tools, and Kiro `PreToolUse` hooks.
- **Secret Redaction at Source:** Bearer tokens, API keys (`sk-*`), passwords, JWTs, phone numbers/JIDs, and connection strings are redacted in memory before storage or SSE streaming.
- **Private Control Plane Only:** Sentinel HTTP binds only to Tailscale CGNAT (`100.64.0.0/10` / `fd7a:115c:a1e0::/48`), loopback, or private interfaces with mandatory Bearer auth.

## Repository Layout

```text
cmd/franken/                  # Unified CLI (`keys init`, `sentinel serve`, `mcp serve|stdio|connect`, `wa-login`, `postmortem`, `chaos run`, `guard`)
cmd/wa-bridge/                # Headless WhatsApp bridge daemon & MCP stdio binary (`serve`, `login`, `mcp`)
chaos/                        # Linux chaos workload injector & 20-cycle test harness (`haunted_workload.sh`, `run_chaos_suite.sh`)
deploy/systemd/               # Hardened systemd units (`franken-sentinel.service`, `franken-bridge.service`, `franken.env.example`)
internal/
  kernelfs/                   # Kernel capability probe (cgroup v2, PSI, /proc/meminfo) + MemFS test double
  psi/                        # PSI POLLPRI epoll trigger watcher with 1 Hz fallback polling
  cgroup/                     # inotify memory.events delta watcher, 1 Hz sampler, /proc zombie scanner
  journal/                    # journalctl --follow --output=json parser + secret redaction
  detector/                   # EWMA slope estimator, Time-To-OOM classifier, hysteresis & debounce
  incident/                   # Pure-Go SQLite (modernc.org/sqlite) WAL store & strict state machine
  redact/                     # Secret/PII scrubber applied before persistence and transport
  policy/                     # Single-source actions.yaml loader, plan.schema.json validator, canonical SHA-256 plan_hash
  executor/                   # Fixed-argv allowlisted runner with process-group timeout kills
  reflex/                     # Reversible L1 reflexes + persistent SQLite TTL rollback scheduler
  approval/                   # Ed25519 keygen (`keys init`), token minter, anti-replay nonce verifier
  mcpserver/                  # Official go-sdk MCP server (`/mcp`, `/v1/events` SSE, `/healthz`, `verify_health`, `postmortem_generate`, stdio)
  postmortem/                 # Redacted markdown postmortem generator (`incidents/<id>/postmortem.md`)
  chaos/                      # 20-run end-to-end chaos suite & Sentinel evaluation benchmark
  sentinel/                   # Unified Sentinel daemon orchestrating collectors, reflexes, SQLite & MCP/SSE
  wabridge/                   # Two-way whatsmeow SSE/poll bridge, LID allowlist, Ed25519 signer & 15s heartbeat watcher
policy/                       # `actions.yaml` catalog & `plan.schema.json`
.kiro/
  steering/                   # `rules.md`, `product.md`, `tech.md`, `structure.md`, `linux-kernel.md`, `incident-response.md`
  specs/                      # Requirements, design, and task breakdown (`server-incident-remediation`)
  hooks/                      # Kiro v1 hooks (`policy-sync`, `executor-guard`, `redaction-test`, `preToolUse`, `spec-verify-on-stop`)
  agents/                     # `franken-sentry.json`, `franken-architect.json`, `franken-remediator.json`
  crons/                      # `incident-sweep.json` (`* * * * *`), `morning-digest.json` (`0 7 * * *`)
  skills/                     # `linux-memory-forensics`, `remediation-runbooks`, `incident-spec-writer`
  settings/mcp.json           # MCP client profiles (`franken-sentinel`, `franken-wa`)
```

## Build, Verify, and Run

```bash
# Run static checks and full unit/integration test suite (no root required)
go vet ./...
go test -count=1 ./...

# Install `franken` CLI on PATH (required so `PreToolUse` hook preserves exit code 2 directly)
go install ./cmd/franken

# Build static Linux binaries (pure Go, CGO_ENABLED=0)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/franken-linux-arm64 ./cmd/franken
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/franken-linux-amd64 ./cmd/franken
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/wa-bridge-linux-arm64 ./cmd/wa-bridge
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/wa-bridge-linux-amd64 ./cmd/wa-bridge

# Provision Ed25519 approval keys (0600 private key for wa-bridge, 0644 public key for Sentinel)
go run ./cmd/franken keys init --dir keys

# Pair WhatsApp device via terminal QR code into pure-Go modernc.org/sqlite session store
go run ./cmd/franken wa-login --db wa-bridge-session.db

# Run Sentinel daemon on Linux host with Tailscale + Bearer auth
export FRANKEN_BEARER_TOKEN="replace-with-strong-secret"
go run ./cmd/franken sentinel serve --tailscale --port 8090 --db franken-sentinel.db

# Run headless WhatsApp two-way bridge consuming Sentinel SSE + polls
go run ./cmd/wa-bridge serve --sentinel http://100.64.0.10:8090 --admins +6281234567890 --priv-key keys/bridge-ed25519.key --wa-db wa-bridge-session.db

# Connect Kiro agents over stdio to a remote/local Sentinel Streamable HTTP server
go run ./cmd/franken mcp connect sentinel@localhost --token-env FRANKEN_BEARER_TOKEN

# Run 20 consecutive chaos runs (memory_leak, memory_spike, fork_storm, zombie_storm, log_flood)
go run ./cmd/franken chaos run --runs 20

# Generate redacted markdown postmortem for a closed incident
go run ./cmd/franken postmortem --db franken-sentinel.db --incident INC-20261113-1200-node01 --out incidents
```

## Footprint & Chaos Benchmarks

- **Static `linux/arm64` Binary Sizes (`CGO_ENABLED=0`):** `franken` = `29,932,279 B` (~28.5 MiB), `wa-bridge` = `27,988,246 B` (~26.7 MiB).
- **Sentinel Evaluation Benchmark (`BenchmarkSentinelEvalAndReflexFootprint`):** `35,421 ns/op` (~0.035 ms/cycle), `50,229 B/op`, `40 allocs/op` (measured on Intel Core i7-10750H dev host; live ARM64 board RSS target ≤ 32 MiB to be measured on hardware deploy).
- **Chaos Verification (`franken chaos run --runs 20`):** `20/20 passed`, `0 failed`, `max_reflex_ms = 14.27 ms` (`avg = 3.44 ms`, within 250 ms L1 reflex SLA) across `memory_leak`, `memory_spike`, `fork_storm`, `zombie_storm`, and `log_flood`.
- **systemd Sandboxing ([deploy/systemd/](deploy/systemd/)):** Both `franken-sentinel.service` and `franken-bridge.service` enforce `OOMScoreAdjust=-900`, `MemoryMax=48M`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `ProtectHome=yes`, `PrivateTmp=yes`, and strict `ReadWritePaths`.

## Documentation

- [docs/BLUEPRINT.md](docs/BLUEPRINT.md) — End-to-end architecture, threat model, and demo specification
- [documentation.md](documentation.md) — Entity lifecycles, state transitions, and business constraints (Bahasa Indonesia)
- [documentation-api.md](documentation-api.md) — Sentinel HTTP, SSE, MCP tool, and CLI contracts (Bahasa Indonesia)

## License

This project is licensed under the [MIT License](LICENSE).
