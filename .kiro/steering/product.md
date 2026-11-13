---
inclusion: always
---

# FrankenCrew Product Overview

FrankenCrew is an autonomous, two-speed Linux server incident remediation system designed for resource-constrained VPS and single-board computers (1–2 GB RAM).

## Core Philosophy

1. **Speed without recklessness:** Millisecond L1 containment runs deterministically in Go without waiting on an LLM. Irreversible L2 actions require explicit human approval via WhatsApp poll minting a single-use Ed25519 token.
2. **Evidence before action:** Every hypothesis, plan step, and remediation requires citable redacted telemetry (`evidence_id`).
3. **Minimal footprint:** Sentinel targets <= 32 MiB RSS and zero external heavy runtimes on the monitored host.

## Non-Goals

- Arbitrary remote shell execution (`sh -c`, `bash -c`, `eval`)
- Destructive file edits, persistent `/etc` modifications, or system reboot automation
- Direct WhatsApp-to-shell bridging bypassing policy validation and canonical `plan_hash` binding

