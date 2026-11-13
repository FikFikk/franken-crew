---
name: remediation-runbooks
description: Policy-bounded L1/L2 remediation selection guide mapping verified failure classes to catalog verbs in policy/actions.yaml.
---

# Remediation Runbooks Skill

Only select verbs present in `policy/actions.yaml`. Never construct raw shell strings or L3 actions.

## Mapping by Triage Class

- **`heap_leak`:**
  - Safe L2 Option A: `pm2_reload` (`{app}`) for PM2 clusters or `unit_restart` (`{unit}`) for single systemd workers.
  - Safe L2 Option B: `pm2_restart_instance` (`{app, pm_id}`) when only one worker leaked.
- **`traffic_spike`:**
  - Prefer L1 `admission_close` (`{app, ttl_seconds <= 900}`) before considering L2 restart; do not lower `memory.max`.
- **`fork_storm`:**
  - Target the offending non-protected child worker PID (`process_terminate` `{pid}`) or bounce its runaway unit (`unit_restart` `{unit}`).
- **`zombie_accumulation`:**
  - Zombies are already dead; send `SIGCHLD` via `zombie_reap` (`{parent_pid}`) first. Escalate to parent `unit_restart` only with explicit new human approval if parent ignores reaping.
- **`log_flood`:**
  - Restart the malfunctioning logger/app unit (`unit_restart` `{unit}`), never delete `/var/log` or journal files.
- **Confidence < 0.6 or `unknown`:**
  - Do not propose L2 mutations; transition to `ESCALATED` with operator review recommendations.

## Post-Execution Verification

Always run `verify_health` over the `120` second window (`psi_some_avg10 < 5.0`, `psi_full_avg10 < 1.0`, stable RAM, target unit `active`, zero new `oom_kill`), ensure L1 reflexes roll back, generate `postmortem.md` via `postmortem_generate`, and send `wa_send_report`.

