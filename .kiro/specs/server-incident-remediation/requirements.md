# Requirements Document — Server Incident Remediation

## Introduction

FrankenCrew protects small Linux hosts (ARM64/AMD64, 1–2 GB RAM) from memory exhaustion, daemon crashes and
process leaks. A deterministic Go daemon (`franken-sentinel`) reacts in milliseconds; a Kiro Crew of three agents
(Sentry, Architect, Remediator) triages, plans and remediates in seconds to minutes; a WhatsApp bridge (`wa-bridge`)
brings the human into the loop with one-tap decisions.

## Glossary

- **PSI** — Pressure Stall Information exposed by cgroup v2 (`memory.pressure`) and `/proc/pressure/memory`.
- **TTO** — Time-To-OOM, predicted seconds until a cgroup or host exhausts memory.
- **Reflex** — an L1 action applied automatically by Sentinel, reversible with a TTL.
- **Approval token** — Ed25519-signed, single-use capability minted by `wa-bridge` after a verified human vote.

## Requirements

### Requirement 1: Memory pressure detection

**User Story:** As a homelab operator, I want stalls detected the moment they begin, so that I can act before the OOM killer does.

#### Acceptance Criteria

1. WHEN Sentinel starts THE SYSTEM SHALL register a PSI trigger `some 150000 1000000` on every monitored cgroup's `memory.pressure` file and on `/proc/pressure/memory`.
2. WHEN a PSI trigger fires THE SYSTEM SHALL produce a pressure event within 100 ms.
3. WHEN `memory.events` changes THE SYSTEM SHALL read the `high`, `max`, `oom` and `oom_kill` deltas within 100 ms using inotify.
4. IF PSI is unavailable on the host THEN THE SYSTEM SHALL refuse to start and print the remediation hint (`psi=1` kernel parameter).

### Requirement 2: OOM prediction and severity

**User Story:** As an operator, I want a severity grade and time-to-OOM, so that responses are proportional.

#### Acceptance Criteria

1. WHILE a cgroup is monitored THE SYSTEM SHALL compute an EWMA slope of `memory.current` at 1 Hz and derive TTO.
2. WHEN TTO < 120 s OR PSI `some avg10` ≥ 25 OR PSI `full avg10` ≥ 5 THE SYSTEM SHALL classify severity P2.
3. WHEN TTO < 30 s OR `memory.events.max` / `oom` increases THE SYSTEM SHALL classify severity P1.
4. WHEN `oom_kill` increases THE SYSTEM SHALL open a POST_OOM incident in forensic mode.
5. THE SYSTEM SHALL apply hysteresis: an incident closes only after half-threshold values hold for 120 s.

### Requirement 3: Reflex mitigation (L1)

**User Story:** As an operator asleep at 3 AM, I want safe automatic first aid, so that the server survives until a decision is made.

#### Acceptance Criteria

1. WHEN severity is P1 or P2 AND the cgroup policy allows reflexes THE SYSTEM SHALL apply at most one L1 action within 250 ms of detection.
2. THE SYSTEM SHALL attach a TTL ≤ 15 min to every L1 action and roll it back automatically on expiry or on incident resolution.
3. IF an incident already has 3 L1 actions THEN THE SYSTEM SHALL reject further L1 actions.
4. THE SYSTEM SHALL never set `MemoryHigh` below the cgroup's current usage.

### Requirement 4: Incident record and evidence

**User Story:** As an agent, I need a complete, redacted evidence bundle, so that I can reason without touching raw secrets.

#### Acceptance Criteria

1. WHEN an incident opens THE SYSTEM SHALL persist it with an ID `INC-<yyyymmdd>-<hhmm>-<node>` and state `DETECTED`.
2. THE SYSTEM SHALL capture PSI history (10 min), top 10 cgroups by memory, unit states, zombie report and the last 200 journal lines of affected units.
3. THE SYSTEM SHALL redact IPv4/IPv6, emails, phone numbers, bearer tokens, JWTs and key-like strings before evidence leaves Sentinel.
4. THE SYSTEM SHALL assign an `evidence_id` to every evidence item.

### Requirement 5: Crew triage

**User Story:** As an operator, I want the incident classified with confidence, so that the plan targets the real problem.

#### Acceptance Criteria

1. WHEN an open incident exists THE Kiro Crew `incident-sweep` cron SHALL claim it within 60 s.
2. THE Sentry agent SHALL output a triage record with exactly one class, a confidence in [0,1] and cited `evidence_id`s.
3. IF confidence < 0.6 THEN THE Architect SHALL produce an `observe + escalate` plan only.

### Requirement 6: Remediation plan as a Kiro spec

**User Story:** As a reviewer, I want every plan to be a readable Kiro spec plus a machine-checkable plan, so that humans and policy can both verify it.

#### Acceptance Criteria

1. THE Architect SHALL write `incidents/<id>/requirements.md`, `design.md`, `tasks.md` and `plan.json`.
2. THE plan SHALL reference only actions from the action catalog in `.kiro/steering/rules.md`.
3. WHEN a plan is submitted THE SYSTEM SHALL validate it against `plan.schema.json` and the policy table, returning a tier per step and a `plan_hash` (SHA-256 of canonical JSON).
4. IF validation fails THEN THE SYSTEM SHALL return machine-readable violations and the Architect SHALL revise at most twice before escalating.

### Requirement 7: Human approval over WhatsApp

**User Story:** As a developer on my phone, I want to approve fixes with one tap, so that I never need a laptop at night.

#### Acceptance Criteria

1. WHEN a plan contains L2 steps THE SYSTEM SHALL send a native WhatsApp poll with ≤ 4 options, the last being `Do nothing — I'll SSH in`.
2. WHEN a vote arrives from an allowlisted JID THE SYSTEM SHALL decrypt it, map the option hash to a plan option and mint an Ed25519 token bound to `incident_id`, `plan_hash`, `step_ids`, `approver` and `exp` (10 min).
3. IF a vote comes from a non-allowlisted JID THEN THE SYSTEM SHALL ignore it and write an audit entry.
4. WHEN the approval expires THE SYSTEM SHALL re-ping once at +5 min and mark the incident `EXPIRED` at +10 min.
5. WHERE polls are unavailable THE SYSTEM SHALL accept a text reply `<nonce> <option-number>`.

### Requirement 8: Safe execution

**User Story:** As an operator, I want guarantees that agents can never run arbitrary commands, so that automation cannot destroy my server.

#### Acceptance Criteria

1. THE SYSTEM SHALL execute only argv templates from the action allowlist; no shell interpreter is ever invoked.
2. WHEN `action_execute` is called for an L2 step THE SYSTEM SHALL verify signature, binding, expiry and single use of the token before execution.
3. IF the target is a protected process or unit THEN THE SYSTEM SHALL reject the action regardless of token.
4. THE SYSTEM SHALL enforce a timeout on every executed command and record exit code, duration and stderr (redacted).

### Requirement 9: Verification and closure

**User Story:** As an operator, I want proof that the server is healthy again, so that I can go back to sleep.

#### Acceptance Criteria

1. WHEN an action completes THE SYSTEM SHALL evaluate health for 120 s (PSI thresholds, unit state, HTTP probe, no new `oom_kill`).
2. WHEN health passes THE SYSTEM SHALL roll back reflexes, set state `RESOLVED` and send a summary message.
3. IF health fails THEN THE SYSTEM SHALL roll back L1 actions, set state `ESCALATED` and notify the human.

### Requirement 10: Postmortem and audit

**User Story:** As a team, we want a written record of every incident, so that we fix root causes.

#### Acceptance Criteria

1. WHEN an incident reaches a terminal state THE Remediator SHALL write `incidents/<id>/postmortem.md`.
2. THE SYSTEM SHALL keep an append-only audit log of every tool call, vote, token and executed action.

### Requirement 11: Degraded modes

**User Story:** As an operator, I want the system to stay useful when parts fail, so that a single failure is never silent.

#### Acceptance Criteria

1. WHILE the Brain host is unreachable THE Sentinel SHALL continue reflexes and queue incidents locally.
2. WHEN `wa-bridge` misses 3 consecutive Sentinel heartbeats (15 s interval) THE SYSTEM SHALL send a `node silent` alert.
3. WHILE WhatsApp is disconnected THE SYSTEM SHALL treat all L2 steps as unapproved.

### Requirement 12: Footprint

**User Story:** As an SBC owner, I want the guardian to be lighter than what it guards.

#### Acceptance Criteria

1. THE Sentinel SHALL stay under 32 MiB RSS and 2% average CPU on a 4-core ARM64 board.
2. THE Sentinel unit SHALL run with `OOMScoreAdjust=-900` and `MemoryMin=48M`.

