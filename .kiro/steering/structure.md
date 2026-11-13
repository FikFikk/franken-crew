---
inclusion: always
---

# Repository Structure & Module Boundaries

## Layout

- `cmd/franken/` — Single binary CLI entrypoint (`keys init`, `mcp serve`, `mcp stdio`, `mcp connect`, `guard`)
- `internal/kernelfs/` — Cgroups v2 & procfs filesystem abstraction (`OSFS` / `MemFS`) and startup probe
- `internal/psi/` — Linux PSI (`memory.pressure`) trigger watcher (`epoll`/`poll(POLLPRI)`) and 1 Hz fallback
- `internal/cgroup/` — `inotify` `memory.events` delta monitor, 1 Hz memory/PSI sampler, `/proc/*/stat` zombie scanner
- `internal/journal/` — `journalctl --follow --output=json` anomaly pattern stream with inline redaction
- `internal/detector/` — EWMA (`alpha=0.3`) Time-To-OOM (TTO) engine, hysteresis, and 5-minute debounce
- `internal/redact/` — Secret/PII redaction pipeline (JWT, Bearer, DSN credentials, PEM keys, IPv4, phone numbers)
- `internal/incident/` — SQLite WAL store, strict incident state machine, evidence snapshots, audit trail, nonces
- `internal/policy/` — `policy/actions.yaml` loader, `schema/plan.schema.json` checks, canonical JSON SHA-256 `plan_hash`
- `internal/executor/` — Static argv-only command runner with timeout and process-group kill
- `internal/reflex/` — Level 1 sub-250ms reflexes (`cgroup_reclaim`, `cgroup_throttle`, `admission_close`) & persistent TTL scheduler
- `internal/approval/` — Ed25519 key provisioning, token minter (PII-hashed), and SQLite anti-replay verifier
- `internal/mcpserver/` — Sentinel MCP server (`/mcp`, `/v1/events` SSE, `/healthz`, stdio) with Tailscale/loopback bind validation
- `policy/` & `schema/` — Authoritative YAML action catalog and JSON Schema for remediation plans
- `docs/BLUEPRINT.md` — Master design blueprint and milestone tracker

