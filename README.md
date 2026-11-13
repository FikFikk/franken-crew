# FrankenCrew

**FrankenCrew** is a Two-Speed autonomous Linux server self-healing sentinel paired with **Kiro CLI Crew** and human-in-the-loop WhatsApp approvals.

> **Status (Sentinel Core + Headless WhatsApp Bridge + Kiro Crew + Chaos Verification Complete)**
>
> - **Implemented & Tested (Go 1.26.11+, pure-Go static binary `CGO_ENABLED=0`, `govulncheck` clean):** Kernel telemetry (`kernelfs`, `psi`, `cgroup`, `journal`), EWMA Time-To-OOM `detector`, SQLite WAL `incident` store & `redact` pipeline, single-source `policy` & fixed-argv `executor`, L1 TTL `reflex` engine, Ed25519 `approval` protocol, Streamable HTTP/SSE & stdio `mcpserver` (including 120s PSI+RAM stability `verify_health` and `postmortem_generate`), unified `sentinel` daemon, headless `whatsmeow` bridge (`internal/wabridge` + `cmd/wa-bridge`), redacted markdown `postmortem` generator, systemd sandbox units (`deploy/systemd/`), 20-cycle `chaos` suite (`internal/chaos` + `chaos/`), and the `franken` CLI (`keys init`, `sentinel serve`, `mcp serve|stdio|connect`, `wa-login`, `postmortem`, `chaos run`, `guard`, `lab simulate|export|serve`).
> - **Implemented Kiro Customization Stack (`.kiro/` + `app.json`):** Spec-driven development specs, multi-mode steering documents, 5 `v1` hooks (including `.kiro/hooks/preToolUse.json` running `franken guard --audit` in the IDE/CLI), a `franken-conductor` orchestrator plus 3 MCP-only specialist agents (`franken-sentry`, `franken-architect`, `franken-remediator`), 3 skills (`linux-memory-forensics`, `remediation-runbooks`, `incident-spec-writer`), `.kiro/settings/mcp.json`, and a Kiro Crew app manifest (`app.json`) with a 15-minute safety-net sweep and a morning digest.
> - **Implemented Graveyard Dashboard (`ui/` + `internal/lab`):** Read-only incident replay landing page and Kiro Crew dashboard page (`app.json` `ui.pages`), served by `franken lab serve` on port 3008 and published at <https://frankencrew.fikfikk.my.id>. See [Incident Replay Dashboard](#incident-replay-dashboard).
> - **Planned Next Milestones:** Measurements on a live ARM64 board (RSS, kernel-to-reflex latency) and recorded replays exported with `franken lab export`.

## Event-Driven Kiro Crew Flow

Events drive the agents; the cron is only a safety net.

1. Sentinel opens a P1/P2/POST_OOM incident and applies L1 reflexes. wa-bridge sends the first WhatsApp alert and posts `phase=TRIAGE` to the Kiro Crew webhook (`POST /api/hooks/agent`, `--crew-webhook-url`).
2. `franken-conductor` (the only agent with `@kirocrew-core`) spawns `franken-sentry` (claim + triage), then `franken-architect` (`plan_submit`), then `franken-remediator` in `MODE=REQUEST_APPROVAL`, which asks wa-bridge for a native poll built from the stored plan.
3. The human votes. wa-bridge mints one single-use Ed25519 token per step and posts `phase=EXECUTE`. The conductor spawns `franken-remediator` in `MODE=EXECUTE`, which runs each step with its own token and starts `verify_health`.
4. Sentinel observes the 120 s recovery window in the background (slope and projected Time-To-OOM), resolves or escalates, and writes the postmortem. wa-bridge sends the final report on `verification.completed`.
5. `incident-sweep` (every 900 s) runs the conductor's `phase=SWEEP` to catch anything a missed webhook left in `DETECTED`/`REFLEX_APPLIED`.

Sentinel rejects any plan or execution whose target is outside the incident cgroup or that cites evidence it never recorded, so a prompt-injected plan cannot reach other services even if a human taps it.

## Two-Speed Self-Healing Architecture

1. **Speed 1 — Deterministic Kernel Reflex (`internal/sentinel`, `< 250 ms`):** Watches `/proc/pressure/memory` (`POLLPRI`), `cgroup v2` `memory.pressure`, `memory.events` (`inotify`), and systemd `journalctl` JSON streams while sampling at `1 Hz` into a rolling ring buffer. On P1/P2 memory pressure or `oom_kill`, applies bounded, TTL-reversible L1 reflexes (`cgroup_reclaim` ≤ 25% of `memory.current`, runtime `MemoryHigh` throttling ≥ current usage and ≤ 95% host RAM) backed by persistent SQLite rollback state.
2. **Speed 2 — AI Reasoning + Cryptographic Human Approval (`.kiro/agents/`, MCP, Ed25519):** AI agents (`franken-sentry` → `franken-architect` → `franken-remediator`) connect strictly through Sentinel MCP tools, cite redacted `evidence_id` snapshots, compute canonical SHA-256 `plan_hash` values, require single-use Ed25519 approval tokens for L2 mutations, and verify 120 seconds of healthy PSI (`some_avg10 < 5.0` and `full_avg10 < 1.0`) before resolving incidents.

## Non-Negotiable Safety Guardrails

- **No Raw Shell Execution:** Fixed `exec.Command(binary, args...)` allowlist only; `sh -c` and `bash -c` are forbidden in both Sentinel and `franken guard`.
- **Protected Infrastructure:** PID 1, kernel threads, `sshd`/`ssh` (Debian/Ubuntu/Raspberry Pi OS unit name), networking units, `systemd-journald`, `systemd-logind`, `dbus`, `tailscaled`, `franken-sentinel`, `wa-bridge`/`franken-bridge`, and `kirocrew` are hard-blocked across policy, reflex, executor, MCP tools, and Kiro `PreToolUse` hooks.
- **Incident Scope:** L1/L2 targets must live inside the incident cgroup, and every cited `evidence_id` must be recorded for that incident. Sentinel checks this at `plan_submit` and again right before `action_execute`.
- **Secret Redaction at Source:** Bearer tokens, API keys (`sk-*`), passwords, JWTs, phone numbers/JIDs, and connection strings are redacted in memory before storage or SSE streaming.
- **Private Control Plane Only:** Sentinel HTTP binds only to Tailscale CGNAT (`100.64.0.0/10` / `fd7a:115c:a1e0::/48`), loopback, or private interfaces with mandatory Bearer auth.

## Repository Layout

```text
cmd/franken/                  # Unified CLI (`keys init`, `sentinel serve`, `mcp serve|stdio|connect`, `wa-login`, `postmortem`, `chaos run`, `guard`, `lab`)
cmd/wa-bridge/                # Headless WhatsApp bridge daemon & MCP stdio binary (`serve`, `login`, `mcp`)
chaos/                        # Linux chaos workload injector & 20-cycle test harness (`haunted_workload.sh`, `run_chaos_suite.sh`)
deploy/systemd/               # Hardened systemd units (`franken-sentinel.service`, `franken-bridge.service`, `franken-lab.service`, `franken.env.example`)
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
  lab/                        # Graveyard replay export, in-process simulation & read-only dashboard server (`franken lab`)
ui/                           # Graveyard landing page, no-build ES modules (`dist/`, Kiro Crew `ui.entry`) & `data/replay.json`
policy/                       # `actions.yaml` catalog & `plan.schema.json`
.kiro/
  steering/                   # `rules.md`, `product.md`, `tech.md`, `structure.md`, `linux-kernel.md`, `incident-response.md`
  specs/                      # Requirements, design, and task breakdown (`server-incident-remediation`)
  hooks/                      # Kiro v1 hooks (`policy-sync`, `executor-guard`, `redaction-test`, `preToolUse`, `spec-verify-on-stop`)
  agents/                     # `franken-conductor.json`, `franken-sentry.json`, `franken-architect.json`, `franken-remediator.json`
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
go run ./cmd/franken sentinel serve --tailscale --port 8090 --db franken-sentinel.db --postmortem-dir incidents --rediscover-interval 10s

# Run headless WhatsApp two-way bridge consuming Sentinel SSE + polls
export KIROCREW_TOKEN="$(kirocrew token)"   # webhook token for event-driven Crew phases
go run ./cmd/wa-bridge serve --sentinel http://100.64.0.10:8090 --admins +6281234567890 --priv-key keys/bridge-ed25519.key --wa-db wa-bridge-session.db --crew-webhook-url http://127.0.0.1:5476/api/hooks/agent

# Connect Kiro agents over stdio to a remote/local Sentinel Streamable HTTP server
go run ./cmd/franken mcp connect sentinel@localhost --token-env FRANKEN_BEARER_TOKEN

# Run 20 consecutive chaos runs (memory_leak, memory_spike, fork_storm, zombie_storm, log_flood)
go run ./cmd/franken chaos run --runs 20

# Generate redacted markdown postmortem for a closed incident
go run ./cmd/franken postmortem --db franken-sentinel.db --incident INC-20261113-1200-node01 --out incidents
```

## Incident Replay Dashboard

The **Graveyard** (`ui/`) replays finished incidents: memory and PSI telemetry, swimlanes for kernel, Sentinel, Crew, human, and verification events, the operator chat with the approval poll, the L1 reflex latency against the 250 ms budget, and the postmortem. It is plain ES modules and SVG with no framework and no build step. The same files serve the public landing page and the Kiro Crew dashboard page that `app.json` registers (`ui.entry: dist/index.mjs`, route `/apps/franken-crew`).

```bash
# Rebuild ui/data/replay.json through the real engine (in-memory cgroup, fake systemd and PM2; labelled "Simulation")
go run ./cmd/franken lab simulate --out ui/data/replay.json

# Export closed incidents from a Sentinel database instead (labelled "Recording")
go run ./cmd/franken lab export --db franken-sentinel.db --out /var/lib/franken/replays/replay.json --source-kind recording

# Serve the dashboard read-only (GET/HEAD only, strict CSP); --sentinel adds the live status badge
go run ./cmd/franken lab serve --listen 127.0.0.1:3008 --data-dir /var/lib/franken/replays \
  --sentinel http://100.64.0.10:8090 --token-env FRANKEN_BEARER_TOKEN
```

`deploy/systemd/franken-lab.service` runs the server with `DynamicUser=yes` and `MemoryMax=32M`. To publish it (for example at <https://frankencrew.fikfikk.my.id>), put a TLS proxy in front of `127.0.0.1:3008`, such as Caddy:

```caddyfile
frankencrew.fikfikk.my.id {
	reverse_proxy 127.0.0.1:3008
}
```

or a Cloudflare Tunnel ingress rule:

```yaml
ingress:
  - hostname: frankencrew.fikfikk.my.id
    service: http://127.0.0.1:3008
  - service: http_status:404
```

Without `--sentinel`, `/api/status` returns `{"mode":"replay"}` and the badge shows replay mode. With it, the badge shows the node, PSI, and open incidents, and the lab process holds the Sentinel bearer token, so run it only on a host you already trust with that token.

## Footprint & Chaos Benchmarks

- **Static `linux/arm64` Binary Sizes (`CGO_ENABLED=0`):** `franken` = `31,045,125 B` (~29.6 MiB, including the embedded Graveyard dashboard), `wa-bridge` = `28,822,917 B` (~27.5 MiB), built with Go 1.26.11.
- **Sentinel Evaluation Benchmark (`BenchmarkSentinelEvalAndReflexFootprint`):** `35,421 ns/op` (~0.035 ms/cycle), `50,229 B/op`, `40 allocs/op` (measured on Intel Core i7-10750H dev host; live ARM64 board RSS target ≤ 32 MiB to be measured on hardware deploy).
- **Chaos Simulation (`franken chaos run --runs 20`):** `20/20 passed`, `0 failed`, `max_reflex_ms = 1.50 ms` (`avg = 1.11 ms`, re-measured 2026-11-13 in an x86-64 Linux sandbox) across `memory_leak`, `memory_spike`, `fork_storm`, `zombie_storm`, and `log_flood`. This suite runs against an in-memory cgroup/procfs fixture with a fake command runner, so the timings measure Go evaluation and SQLite work, not kernel-to-reflex latency on hardware.
- **systemd Sandboxing ([deploy/systemd/](deploy/systemd/)):** Both `franken-sentinel.service` and `franken-bridge.service` enforce `OOMScoreAdjust=-900`, `MemoryMax=48M`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, `ProtectHome=yes`, `PrivateTmp=yes`, and strict `ReadWritePaths`.

## Documentation

- [docs/BLUEPRINT.md](docs/BLUEPRINT.md) — End-to-end architecture, threat model, and demo specification
- [documentation.md](documentation.md) — Entity lifecycles, state transitions, and business constraints (Bahasa Indonesia)
- [documentation-api.md](documentation-api.md) — Sentinel HTTP, SSE, MCP tool, CLI, and Graveyard dashboard contracts (Bahasa Indonesia)
- [docs/DEVPOST_SUBMISSION.md](docs/DEVPOST_SUBMISSION.md) — Kiroween 2026 Devpost answers, including how Kiro was used
- [docs/BLOG_POST.md](docs/BLOG_POST.md) — Draft dev.to article for the Kiroween 2026 blog prize

## License

This project is licensed under the [MIT License](LICENSE).
