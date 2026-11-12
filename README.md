# FrankenCrew: The Resilient Server Sentry 🧟‍♂️⚡

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kiroween 2026](https://img.shields.io/badge/Kiroween_2026-Frankenstein_Category-brightgreen.svg)](https://devpost.com)
[![Kiro Specs](https://img.shields.io/badge/Kiro_Specs-Verified-blue.svg)](.kiro/specs/)

> **"Stitched from spare parts. Never sleeps. So you can."**  
> An autonomous, ultra-lightweight multi-agent server sentry designed for indie hackers, homelabbers, and resource-constrained VPS/SBC servers (1–2 GB RAM).

Built for **Kiroween 2026** (Devpost & AWS Hackathon) under the **Frankenstein Category**, targeting **Best Kiro Crew App** and **Best Demo**.

---

## 🔬 The Frankenstein Stitch

FrankenCrew stitches together three contrast domains into an unexpectedly powerful resilience engine:

```
┌─────────────────────────────────┐
│  Low-Level Linux Kernel (Edge)  │ ➔ cgroups v2, PSI (Pressure Stall Information),
│    franken-sentinel daemon      │   inotify on memory.events, lightweight journald
└────────────────┬────────────────┘
                 │ (Deterministic Reflex < 250ms & Telemetry)
                 ▼
┌─────────────────────────────────┐
│  Kiro Multi-Agent Crew (Brain)  │ ➔ Spec-driven orchestration, steering guardrails,
│   Sentry ➔ Architect ➔ Remediator│   MCP tools, and deterministic approval tokens
└────────────────┬────────────────┘
                 │ (Ed25519 Capability-Bound Approval Protocol)
                 ▼
┌─────────────────────────────────┐
│   Headless WhatsApp Gateway     │ ➔ Two-way interactive native polls & reports
│     wa-bridge (Go/whatsmeow)    │   directly to developer's phone without extra apps
└─────────────────────────────────┘
```

1. **Kernel Telemetry & Deterministic Reflex (Go):** Direct epoll on Linux kernel `memory.pressure` (PSI) triggers. Detects memory stall and computes Time-To-OOM (TTO) in milliseconds before the Linux OOM killer wipes processes. Automatically applies reversible Level 1 (L1) reflexes.
2. **Kiro Crew Autonomous Reasoning:** A 3-agent orchestration (Sentry, Architect, Remediator) using Kiro Specs (`requirements.md`, `design.md`, `tasks.md`) and steering rules. When a restart or destructive action (Level 2) is needed, the Architect drafts a plan validated against strict policy.
3. **Headless Two-Way WhatsApp Messaging:** Sends instant alerts and native polls directly to the developer's smartphone. Human single-tap votes mint single-use Ed25519 approval tokens that authorize the Remediator to execute safe mutations.

---

## 📁 Repository Structure & `.kiro` Directory

This repository strictly complies with the Kiroween hackathon requirements:

```text
franken-crew/
├── .kiro/                               # Mandatory Kiro configuration root
│   ├── steering/                        # Guardrails & boundary rules for agents
│   │   └── rules.md                     # Action tiers (L0-L3), safety constraints
│   ├── specs/                           # Spec-driven development blueprints
│   │   └── server-incident-remediation/ # Formal incident remediation spec
│   │       ├── requirements.md          # EARS-compliant requirements
│   │       ├── design.md                # System design & incident state machine
│   │       └── tasks.md                 # Concrete implementation tasks
│   ├── hooks/                           # Lifecycle hooks & quality gates
│   └── agents/                          # Custom agent definitions
├── docs/
│   └── BLUEPRINT.md                     # Comprehensive technical blueprint (A to Z)
├── documentation.md                     # Business logic, state transitions & lifecycle
├── documentation-api.md                 # MCP tools, HTTP endpoints & scheduled tasks
├── LICENSE                              # MIT License
└── README.md
```

---

## ⚡ Two-Speed Architecture

| Layer | Speed | Executor | Authority & Scope |
|---|---|---|---|
| **Reflex Path** | 1–250 ms | `franken-sentinel` (Go) | Level 1: Reversible (e.g. `cgroup_throttle`, `cgroup_reclaim`), automatic TTL rollback |
| **Reasoning Path** | 30–90 sec | Kiro Multi-Agent Crew | Level 0: Observability, triage, writing incident specs and remediation plans |
| **Decision Path** | Seconds | Human via WhatsApp Poll | Level 2: Irreversible mutations require human vote producing an Ed25519 token |

---

## 🛡️ Non-Negotiable Guardrails

- **Zero Raw Shell:** No arbitrary `sh -c` or `bash -c`. The executor runs only allowlisted, static argv templates.
- **Untouchable Core:** Protected processes (PID 1, sshd, journald, tailscaled, sentinel, wa-bridge) cannot be killed or modified.
- **Safe Cache Dropping:** Global `vm.drop_caches` is prohibited; proactive per-cgroup `memory.reclaim` (Linux 5.19+) is used instead.
- **Ephemeral Mutations:** No persistent edits to `/etc` or unit files; runtime properties (`--runtime`) only.

---

## 📖 Documentation Index

- [Detailed Technical Blueprint (A–Z)](docs/BLUEPRINT.md)
- [Business Logic & Incident Lifecycle](documentation.md)
- [API & MCP Specification](documentation-api.md)
- [Agent Steering Rules](.kiro/steering/rules.md)
- [Incident Remediation Spec Requirements](.kiro/specs/server-incident-remediation/requirements.md)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
