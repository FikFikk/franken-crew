---
name: incident-spec-writer
description: Structured specification and canonical plan synthesis guide conforming to schema/plan.schema.json, plan_hash immutability, and postmortem output.
---

# Incident Spec & Plan Writer Skill

Follow Requirement 6 and Requirement 10 when producing remediation plans and postmortems:

1. Populate `policy.Plan` strictly conforming to `policy/plan.schema.json`:
   - `incident_id`: exact incident ID (for example `INC-20261113-1015-pi01`).
   - `suspected_root_cause`: specific root cause hypothesis (restart alone is mitigation, not root cause).
   - `options`: 1 to 3 options (`id` = `"A"|"B"|"C"`, `label` <= 60 chars) plus implicit human `"Dismiss"` poll choice handled by `wa-bridge`.
   - `steps`: every step MUST cite >= 1 non-empty `evidence_id`, name a valid catalog action, provide typed `params`, and state `expected_effect`.
   - `human_follow_up`: actionable engineering follow-ups (e.g., fix unbounded cache, adjust PM2 memory limit).
2. Submit via `@franken-sentinel/plan_submit`. If rejected with policy violations, fix violations (up to 2 revisions before Sentinel escalates automatically).
3. Treat `plan_hash` (canonical SHA-256) returned by `plan_submit` as immutable; Ed25519 approval tokens bind strictly to `(incident_id, plan_hash, step_id, action_name, params)`.
4. On terminal states (`RESOLVED`, `ESCALATED`, `DISMISSED`, `EXPIRED`), invoke `@franken-sentinel/postmortem_generate` to render redacted markdown under `incidents/<incident_id>/postmortem.md`.

