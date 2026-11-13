---
inclusion: manual
---

# Manual Incident Response Playbook

Use `#incident-response` when manually triaging an open incident via Sentinel MCP tools.

## Triage Sequence (Max 12 Tool Calls)

1. Run `incident_claim` (or inspect `incident_list`) to claim an open `DETECTED` or `REFLEX_APPLIED` incident.
2. Inspect `incident_get`, `node_snapshot`, and `psi_history` (window `<= 10` minutes).
3. Inspect `cgroup_top`, `process_tree` for the narrowest suspect cgroup, and `journal_tail` (`<= 200` lines) to capture an `evidence_id`.
4. If zombies exist, call `zombie_report` to identify the unreaping `parent_pid`.

## Allowed Incident Classifications

Pick exactly one root-cause class:
- `heap_leak` — Rising anon RSS slope with positive EWMA TTO and heap OOM logs
- `traffic_spike` — Sudden admission/CPU+memory surge correlated with ingress concurrency
- `fork_storm` — Rapidly multiplying child PIDs under a single unit cgroup
- `zombie_accumulation` — Non-zero `Z` state processes under a parent PID failing `waitpid`
- `log_flood` — Journald/disk buffer pressure coupled with noisy unit output
- `swap_thrash` — High `full avg10` memory pressure stalls relative to usage growth
- `external` — Upstream dependency timeout causing request queueing and heap bloat
- `unknown` — Evidence inconclusive or confidence `< 0.6` (`observe + escalate` only)

