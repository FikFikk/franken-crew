---
title: "FrankenCrew: I stitched a Go kernel watchdog, a Kiro Crew, and a WhatsApp poll into one server monster"
published: false
description: "Splitting a self-healing Linux sentry into reflexes, agents, and a human conscience, built with Kiro for Kiroween 2026."
tags: kiro, go, linux, devops
# cover_image: dev.to needs a PNG or JPG URL; export ui/assets/hero-dark.svg (1200x675) and paste its URL here.
---

<!--
Draft for the Kiroween 2026 Bonus Blog Prize. Before publishing:
1. Replace every [bracketed] note with your own words. Judges read for the builder's voice.
2. Add the demo video and a Graveyard GIF where marked.
3. Keep the hackathon disclosure line below.
-->

*I wrote this post as part of the Kiroween 2026 hackathon, where FrankenCrew is my entry in the Frankenstein
category.*

[Open with your own 3 a.m. story: the server, the service that leaked, what it cost you.]

Small Linux servers die in a predictable way. One process leaks memory, the kernel spends more and more time
reclaiming pages, every request slows down, and finally the OOM killer picks a victim. On a company fleet an
on-call engineer gets paged. On a side project, a student lab, or a Raspberry Pi in a closet, nobody notices
until the morning.

I wanted a sentry for those boxes. I also wanted to use LLM agents for the part they are good at, reading logs
and proposing a fix, without ever letting a model run `systemctl restart` on a hunch. The result is
FrankenCrew: three parts that were never meant to fit together, stitched into one creature.

## Three speeds, three organs

The core idea is to split the work by how fast it has to happen and how much damage a mistake can do.

```text
kernel signals -> Sentinel (Go)      -> L1 reflex: milliseconds, reversible, TTL, no model involved
                     |
                     | webhook
                     v
               Kiro Crew             -> conductor -> sentry -> architect -> remediator: minutes
                     |
                     | WhatsApp poll
                     v
               a human vote          -> one Ed25519 token per step -> L2 action -> 120 s check -> postmortem
```

- **Reflexes** belong to deterministic code. The Sentinel reads PSI and cgroup v2 counters and, for a P1 or P2
  incident, applies at most one reversible action within the 250 ms budget from the spec.
- **Thinking** belongs to agents. A Kiro Crew of four agents triages the incident and writes a plan.
- **Anything irreversible** belongs to a human. Restarts and reloads wait for a vote in a WhatsApp poll.

[GIF: the Graveyard replaying the heap leak incident.]

## Speed 1: reflexes in plain Go

The Sentinel is a small Go daemon. It samples `memory.current`, `memory.pressure` (PSI), and `memory.events`
once per second, and it also wakes early when the kernel signals a PSI trigger or a `memory.events` change.
A detector keeps an exponentially weighted moving average (EWMA) of the memory slope, projects the time to
OOM, and assigns a severity.

Those early wake-ups caused my favourite bug. A PSI trigger can land 10 ms after the last regular sample. With
a fixed EWMA weight, a 10 ms gap counted as much as a full second, and a little jitter in `memory.current`
turned into a steep fake slope. The fix computes the weight from the real gap (from
`internal/detector/detector.go`, comments translated):

```go
// effectiveAlpha returns the EWMA weight for one update across span: 1 - (1-alpha)^(span/ref).
// -Expm1(x*Log1p(-alpha)) is the same value, computed precisely for small alpha or short spans.
func effectiveAlpha(alpha float64, span, ref time.Duration) float64 {
	x := span.Seconds() / ref.Seconds()
	weight := -math.Expm1(x * math.Log1p(-alpha))
	// Keep the weight in (0, 1] even if the math underflows.
	return math.Min(1, math.Max(weight, math.SmallestNonzeroFloat64))
}
```

With α = 0.3 and a one-second reference, a full second still gets a weight of 0.3, a 250 ms span gets about
0.085, and a span shorter than 250 ms does not update the slope at all. The detector also ignores stale samples
and treats a falling `memory.events` counter as a cgroup that systemd recreated. A rapid property test checks that stale samples never change the
result.

When the detector opens a P1 or P2 incident, the reflex engine applies one bounded action, such as a
`memory.reclaim` write capped at 25% of `memory.current` or a runtime `MemoryHigh` throttle. Each reflex gets a
TTL and a rollback row in SQLite, so it is undone on schedule even if the daemon restarts in between.

## Speed 2: a crew that thinks

The thinking happens in a [Kiro Crew](https://kiro.dev/docs/crew/) app. `app.json` ships four agents:

- `franken-conductor` wakes up when wa-bridge calls the Crew webhook, reads the phase (`TRIAGE` when an incident
  opens, `EXECUTE` after a vote), and spawns the right specialist. It is the only agent with the tools that
  spawn other agents, and a test in `deploy/` fails if that changes.
- `franken-sentry` claims the incident and triages it with read-only tools: PSI history, the top cgroups, the
  process tree, and a redacted journal tail.
- `franken-architect` turns the triage into a remediation plan and submits it with `plan_submit`.
- `franken-remediator` requests approval, executes the approved steps, and asks the Sentinel to verify health.

My first version stalled after triage, because nothing told the next agent to start. Moving to webhook-driven
phases fixed that, and an `incident-sweep` cron every 15 minutes catches anything a missed webhook leaves
behind.

The agents never get a shell. They reach the server only through two MCP servers: `franken-sentinel` with 17
tools and `franken-wa` with 4, and each agent's file lists only the tools its role needs. Every write goes
through `plan_submit` and `action_execute`, which means every action an agent attempts passes the policy
engine and the token check.

## The conscience: a WhatsApp poll with teeth

When the plan passes policy, wa-bridge posts a poll to an allowlisted WhatsApp group: option A, option B,
roll back the reflex, or dismiss. A vote is not a yes/no flag that an agent could fake. wa-bridge mints one
Ed25519 token per plan step, and the Sentinel verifies it before it runs anything. These are the claims inside
a token (`internal/approval/token.go`):

```go
type Claims struct {
	IncidentID   string   `json:"incident_id"`
	PlanHash     string   `json:"plan_hash"`
	OptionID     string   `json:"option_id,omitempty"`
	ActionName   string   `json:"action_name"`
	StepIDs      []string `json:"step_ids,omitempty"`
	ApproverHash string   `json:"approver_hash"`
	Nonce        string   `json:"nonce"`
	IssuedAt     int64    `json:"iat"`
	ExpiresAt    int64    `json:"exp"`
}
```

The token is bound to one incident, one plan hash, one action, and one approver. The nonce is consumed on first
use and the token expires. Change one byte of the plan and the hash no longer matches; replay the token and the
nonce check refuses it. Property P2 in the design says "a token for plan X never authorizes plan Y", and a
`pgregory.net/rapid` test checks it: it draws random plans, builds a plan Y that differs only in the action,
the unit, or the incident, and asserts that the token for X is refused for Y.

After the action runs, the Sentinel watches PSI and the memory trend for 120 seconds. If pressure stays low and
the projected time to OOM is safe, the incident is resolved and a redacted postmortem is written. If not, it
escalates to a human, which is what happens in the zombie storm replay.

## Prompt injection, replayed

The second incident in the Graveyard is the one I show people first. A burst of oversized requests fills a
worker's cache, and one logged request body contains instructions addressed to the operator. The journal is
evidence the agents read, so the injected text reaches the model.

It does not matter. The first plan targets `ssh.service` and PID 1. `plan_submit` rejects it: `ssh.service`
and PID 1 are protected, and neither is inside the incident's cgroup. A direct attempt to restart
`ssh.service` is blocked as a protected target. Later, a replayed step token is refused because its nonce was
already used. The incident still resolves, through a plan that restarts only the leaking worker.

The lesson I took from this: treat the model as untrusted input, and put the answer to "what if the agent is
wrong?" in code that the agent cannot talk its way past.

[Screenshot: the event log of the prompt injection incident with the three blocked actions.]

## How Kiro built it

[Say how you split the work between yourself and Kiro, in your own words.]

**A spec before code.** The project began as a Kiro spec in `.kiro/specs/server-incident-remediation/`:
twelve requirements written in EARS form ("WHEN severity is P1 or P2 ... THE SYSTEM SHALL apply at most one
L1 action within 250 ms of detection"), a design, and 52 tasks. The design states four correctness
properties, and each became a property-based test: no plan with an L3 action or a protected target ever
validates, a token for plan X never authorizes plan Y, every reflex is rolled back exactly once, and a reflex
`MemoryHigh` is never below current usage. Example tests show the code works for the cases I thought of. The
properties check it against a hundred generated cases each on every run, which is rapid's default.

**Steering that loads when it matters.** Four steering files load on every turn: product, tech, structure,
and project rules. `linux-kernel.md` loads only when Kiro edits the PSI, cgroup, or kernelfs packages, so
kernel guardrails, such as the rule against writing to `drop_caches`, are present exactly when they apply. The incident
runbook is manual and loads on request.

**Hooks as guard rails.** A `PreToolUse` hook sends every franken-sentinel and franken-wa MCP call through
`franken guard --audit`, which writes a redacted audit row and exits 2 to block a protected target. That is
the same guard the agents meet in production. File-save hooks re-run the executor, approval, reflex, policy,
and redaction tests for the package I touched, and a `Stop` hook runs `go vet` and the whole suite at the end
of every turn.

**Parallel agents for the hardening rounds.** Later rounds ran in Kiro Web. The agent audited the repository
against the hackathon rules, then split independent fixes across sub-agents in separate git worktrees: the
time-aware EWMA, the inotify re-arm for recreated cgroups, and the replay backend. I reviewed each branch and
cherry-picked the results. The Playwright power took the screenshots that checked the dashboard at desktop and
phone widths.

[One moment where Kiro surprised you, and one where you had to correct it.]

## Walking through the Graveyard

Every finished incident becomes a grave you can replay at
[frankencrew.fikfikk.my.id](https://frankencrew.fikfikk.my.id). The page shows the memory and PSI curves,
swimlanes for the kernel, the Sentinel, the Crew, the human, and verification, the chat with the approval poll,
a gauge of the reflex latency against the 250 ms budget, and the postmortem.

The dashboard is plain ES modules and hand-drawn SVG, with no framework and no build step. It renders into a
shadow root, so the same files run as the public landing page and as a page inside the Kiro Crew dashboard
(`ui.pages` in `app.json`). `franken lab serve` embeds it in the Go binary and serves it with a strict Content
Security Policy.

The data is labelled honestly. The current replays come from `franken lab simulate`, which drives the real
detector, reflex engine, policy checks, token verifier, verification worker, and postmortem generator against
an in-memory cgroup and fake systemd. The UI badges them **Simulation**. Steps inside the Crew that the
Sentinel does not log are drawn hollow and marked as inferred. The reflex latency is in-process time, not a
hardware measurement. Real incidents exported with `franken lab export` show up as **Recording**.

## Two more things that broke

- **A watch that went quiet.** When systemd recreates a service's cgroup, an inotify watch on the old
  `memory.events` file stops firing, and current kernels do not send `IN_IGNORED` for kernfs files in that
  case. The poller now re-checks the path once per second and re-arms the watch with backoff.
- **Redaction against numbers.** The regexes that strip phone numbers and IP addresses from evidence also
  mangled long byte counts and dotted values in telemetry. Telemetry series are now stored in an integer
  encoding the redactor leaves alone, and postmortems summarize them instead of dumping raw points.

## Try it

You need Go 1.26.11 or newer. The tests and the dashboard need no root and no real cgroup; the live Sentinel
needs Linux with cgroup v2 and PSI.

```bash
git clone https://github.com/FikFikk/franken-crew.git && cd franken-crew
go test ./...                                    # unit, integration, and property tests
go run ./cmd/franken chaos run --runs 20         # chaos scenarios against an in-memory fixture
mkdir -p /tmp/franken-replays
go run ./cmd/franken lab simulate --out /tmp/franken-replays/replay.json
go run ./cmd/franken lab serve --listen 127.0.0.1:3008 --data-dir /tmp/franken-replays
```

Then open http://127.0.0.1:3008. To run it as a Kiro Crew app, install the folder with
`kirocrew app install "$PWD"`, trust and enable it, and open **Graveyard** in the sidebar.

## What's next

FrankenCrew still has to prove itself on real hardware: resident memory against the 32 MiB target, and the
latency from a kernel signal to an applied reflex. After that, CPU and IO pressure can use the same pipeline.

[Close in your own voice: what you would tell someone who runs a small server, and a thank-you if you want one.]

*Source code: [github.com/FikFikk/franken-crew](https://github.com/FikFikk/franken-crew) (MIT). Built for
Kiroween 2026.*
