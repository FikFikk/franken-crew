---
name: linux-memory-forensics
description: Telemetry triangulation playbook for cgroup v2 memory pressure, PSI some/full trends, memory.events deltas, journal signatures, and zombie PPID analysis.
---

# Linux Memory Forensics Skill

Use Level 0 Sentinel MCP tools in order without mutating host state:

1. Call `incident_get` to inspect target cgroup, initial TTO estimate, active L1 reflexes, and attached `evidence_id` snapshots.
2. Call `psi_history` (last 5-10 minutes) alongside `cgroup_top` to triangulate whether pressure is isolated (`some_avg10` high, `full_avg10` low) or host-wide thrashing (`full_avg10 >= 1.0`).
3. Call `journal_tail` (up to 200 redacted lines) on the suspect systemd unit and check for:
   - `heap_leak`: sustained positive `memory.current` slope + `JavaScript heap out of memory` / `Allocation failed`.
   - `traffic_spike`: rapid `some_avg10` burst + ingress saturation without monotonic baseline climb.
   - `fork_storm`: rapid PID/thread explosion + `pids.max` or `cgroup.procs` burst + PM2 restart loop.
   - `zombie_accumulation`: `zombie_report` showing `Z` children clustered under one non-protected `parent_pid`.
   - `log_flood`: high-frequency journal lines (`ENOMEM`, repetitive stack traces, connection errors).
4. Cross-check `process_tree` to verify target PIDs/units exclude protected infrastructure (`PID 1`, `sshd`, `systemd-journald`, `systemd-logind`, `dbus`, `tailscaled`, `franken-sentinel`, `wa-bridge`, `kiro-crew`).
5. Never invent unverified metrics; every claim in the triage summary MUST reference a real `evidence_id`.

