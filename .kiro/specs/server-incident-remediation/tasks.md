# Implementation Plan — Server Incident Remediation

- [x] 1. Kernel access layer
  - [x] 1.1 Implement `internal/kernelfs` with real and fixture backends
  - [x] 1.2 Capability probe: cgroup v2 mounted, PSI available, `memory.reclaim` present; refuse start with hint if PSI missing
  - _Requirements: 1.4, 12.1_

- [x] 2. Signal collectors
  - [x] 2.1 PSI trigger watcher (`some 150000 1000000`) with `poll(POLLPRI)` and POLLERR re-discovery
  - [x] 2.2 inotify watcher for `memory.events` with delta computation
  - [x] 2.3 1 Hz sampler for `memory.current`, `memory.stat`, PSI `avg10`
  - [x] 2.4 Journal stream via `journalctl --follow --output=json`, pattern set (OOM, ENOMEM, heap out of memory, PM2 restart loop)
  - [x] 2.5 Zombie scanner grouping `/proc/*/stat` state `Z` by PPID
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 3. Detector
  - [x] 3.1 EWMA slope + TTO computation
  - [x] 3.2 Severity classification + hysteresis + debounce
  - [x] 3.3 Table tests from recorded fixtures
  - _Requirements: 2.1–2.5_

- [x] 4. Incident store
  - [x] 4.1 SQLite schema (incidents, evidence, reflexes, audit, nonces) with migrations
  - [x] 4.2 State machine with guarded transitions
  - [x] 4.3 Evidence capture + redaction pipeline with tests for every redaction class
  - _Requirements: 4.1–4.4, 10.2_

- [x] 5. Policy engine and executor
  - [x] 5.1 Action catalog + tier table + protected list (single source: `policy/actions.yaml`)
  - [x] 5.2 `plan.schema.json` validation + canonical JSON `plan_hash`
  - [x] 5.3 Fixed-argv executor with timeouts and process-group kill
  - [x] 5.4 Property tests P1, P4
  - _Requirements: 6.2–6.4, 8.1, 8.3, 8.4_

- [x] 6. Reflex engine
  - [x] 6.1 `cgroup_reclaim`, `cgroup_throttle`, `admission_close` with rollback functions
  - [x] 6.2 TTL scheduler surviving Sentinel restart (persisted deadlines)
  - [x] 6.3 Property test P3
  - _Requirements: 3.1–3.4_

- [x] 7. Approval tokens
  - [x] 7.1 Ed25519 key provisioning (`franken keys init`), public key on Sentinel, private key on wa-bridge (0600)
  - [x] 7.2 Mint (bridge) and verify + single-use nonce (Sentinel)
  - [x] 7.3 Property test P2
  - _Requirements: 7.2, 8.2_

- [x] 8. Sentinel MCP server
  - [x] 8.1 Read tools: `node_snapshot`, `incident_list`, `incident_get`, `incident_claim`, `psi_history`, `cgroup_top`, `journal_tail`, `process_tree`, `zombie_report`
  - [x] 8.2 Write tools: `plan_submit`, `action_execute`, `action_rollback`, `incident_transition`, `verify_health`
  - [x] 8.3 Streamable HTTP bound to the Tailscale interface with bearer auth; `/healthz`, `/v1/events` SSE
  - _Requirements: 4, 6.3, 8, 9_

- [x] 9. wa-bridge
  - [x] 9.1 whatsmeow session with modernc SQLite store (`_pragma=foreign_keys(1)`), QR pairing CLI
  - [x] 9.2 Templated first alert from Sentinel SSE (< 2 s)
  - [x] 9.3 Polls: create, decrypt vote, option-hash mapping, allowlist, text-code fallback
  - [x] 9.4 Heartbeat watch (15 s × 3) → `node silent` alert
  - [x] 9.5 MCP stdio tools: `wa_notify`, `wa_request_approval`, `wa_await_decision`, `wa_send_report`
  - _Requirements: 7.1–7.5, 11.2, 11.3_

- [ ] 10. Kiro Crew integration
  - [ ] 10.1 Agents `franken-sentry`, `franken-architect`, `franken-remediator` (no shell tool, MCP-only)
  - [ ] 10.2 `incident-sweep` cron (`* * * * *`) and `morning-digest` cron (`0 7 * * *`)
  - [ ] 10.3 Skills: `linux-memory-forensics`, `remediation-runbooks`, `incident-spec-writer`
  - [ ] 10.4 `preToolUse` audit hook on `action_execute`
  - _Requirements: 5, 6.1, 10.1_

- [ ] 11. Verification and postmortem
  - [ ] 11.1 `verify_health` (120 s window) + reflex rollback on success
  - [ ] 11.2 Postmortem template and Remediator write-up
  - _Requirements: 9.1–9.3, 10.1_

- [ ] 12. Hardening and footprint
  - [ ] 12.1 systemd units (`OOMScoreAdjust=-900`, `MemoryMin=48M`, sandboxing)
  - [ ] 12.2 Footprint benchmark on ARM64 board (RSS, CPU) recorded in README
  - [ ] 12.3 Chaos suite: leak, spike, fork storm, zombie storm, log flood — 20 consecutive green runs
  - _Requirements: 11.1, 12.1, 12.2_

