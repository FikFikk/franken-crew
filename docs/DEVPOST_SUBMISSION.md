# FrankenCrew: Devpost submission draft (Kiroween 2026)

This file holds draft answers for the Devpost form. Copy each section into the matching field. Text in
`[brackets]` needs your input before you submit: links that do not exist yet, and anything only you can say.
Each technical claim points to a file in this repository so judges can check it.

## Quick facts

| Field | Value |
|---|---|
| Project name | FrankenCrew |
| Tagline | Kernel reflexes in Go, a Kiro Crew of agents, and a WhatsApp poll that keeps a human in charge of small Linux servers. |
| Category | Frankenstein |
| Bonus prizes | [Confirm the exact prize names on the form: Best Kiro Crew App, Best Demo, Blog, Social Blitz] |
| Live demo | https://frankencrew.fikfikk.my.id (incident replays from `franken lab simulate`, labelled as simulation) |
| Repository | https://github.com/FikFikk/franken-crew (MIT) |
| Demo video | [YouTube or Vimeo URL; check the length limit in the rules] |
| Blog post | [dev.to URL once `docs/BLOG_POST.md` is published] |
| Social post | [URL of the post that starts with `#KiroweenHackathon26`] |

## Inspiration

Small Linux boxes die the same way: one service leaks memory, the kernel starts reclaiming, latency climbs,
and the OOM killer picks a victim while everyone is asleep. Big companies have SRE rotations for this. A
student project, a side business, or a Raspberry Pi in a closet has nobody.

LLM agents are good at the part people hate: reading logs, matching symptoms to a cause, and writing a careful
plan. They are a bad fit for the part that has to happen in milliseconds, and nobody should let them run
`systemctl restart` on a guess. So we stitched three parts that were never meant to fit together into one
creature: a deterministic Go daemon for the reflexes, a Kiro Crew of agents for the thinking, and a WhatsApp
poll as the conscience. That is the Frankenstein theme taken literally.

[Add one or two sentences of your own: the server or the night that made you build this.]

## What it does

FrankenCrew runs next to the services it protects and handles a memory incident from first signal to
postmortem:

1. **Detect.** The Sentinel (`internal/sentinel`, `internal/detector`) reads PSI from `memory.pressure`,
   cgroup v2 `memory.current` and `memory.events` (watched with inotify), and journald. A time-aware EWMA of
   the memory slope projects time to OOM and assigns a severity (P1, P2, P3, POST_OOM).
2. **Reflex.** For P1 and P2 it applies at most one reversible L1 reflex, such as a bounded `memory.reclaim`
   or a runtime `MemoryHigh` throttle, inside the 250 ms budget of Requirement 3.1. Every reflex has a TTL
   and a rollback record in SQLite, so it is undone even after a restart (`internal/reflex`).
3. **Think.** `franken-conductor`, a Kiro Crew agent, wakes on wa-bridge webhooks and spawns specialists:
   `franken-sentry` claims and triages, `franken-architect` writes a schema-validated plan, and
   `franken-remediator` asks for approval and later executes (`.kiro/agents/`).
4. **Check.** `plan_submit` validates every plan against `policy/actions.yaml`: allowlisted actions only, no
   L3 actions, protected units and PID 1 refused, and every target inside the incident's own cgroup.
5. **Ask.** wa-bridge posts a WhatsApp poll to allowlisted admins. A vote mints one single-use Ed25519 token
   per plan step, bound to the incident, the plan hash, the action, and the approver (`internal/approval`).
6. **Act and verify.** The Sentinel checks each token, consumes its nonce, runs the step through systemd, and
   then watches PSI and the memory trend for a 120-second forward window. It resolves the incident or
   escalates it to a human.
7. **Remember.** The postmortem generator writes a redacted Markdown report with the timeline, the actions, the
   evidence, and follow-up items (`internal/postmortem`).

The **Graveyard** (`ui/`) replays finished incidents: a memory and PSI chart, swimlanes for kernel, Sentinel,
Crew, human, and verification events, the operator's chat with the approval poll, a reflex latency gauge, and
the postmortem. It runs as the landing page at the live URL and as a page inside the Kiro Crew dashboard.

## How we built it

| Part | Built with | Where |
|---|---|---|
| Sentinel daemon, detector, reflexes | Go 1.26.11, cgroup v2, PSI, inotify, systemd (`systemctl`, `systemd-run`) | `internal/sentinel`, `internal/detector`, `internal/reflex`, `internal/cgroup`, `internal/psi` |
| Incident store and audit trail | Pure-Go SQLite (`modernc.org/sqlite`) | `internal/incident` |
| MCP servers | Official MCP Go SDK (`modelcontextprotocol/go-sdk`), Streamable HTTP with bearer auth | `internal/mcpserver`, `internal/wabridge` |
| Approval channel | `whatsmeow` (WhatsApp multi-device), Ed25519 | `cmd/wa-bridge`, `internal/approval` |
| Agents, skills, schedules | Kiro Crew app manifest | `app.json`, `.kiro/agents`, `.kiro/skills` |
| Graveyard dashboard | Plain ES modules, hand-drawn SVG, no framework and no build step | `ui/`, served by `franken lab serve` |

Everything is pure Go with `CGO_ENABLED=0`, so `franken` and `wa-bridge` cross-compile to static
`linux/arm64` and `linux/amd64` binaries. Both systemd units run with `MemoryMax=48M`, `ProtectSystem=strict`,
and `NoNewPrivileges=yes` (`deploy/systemd/`).

The repository has 111 Go files and 233 Go test functions. The suite passes `go vet`, the race detector, and
`govulncheck` on Go 1.26.11.

## How Kiro was used

### Spec-driven development

The project started as a Kiro spec in `.kiro/specs/server-incident-remediation/`: twelve requirements in EARS
form, a design, and 52 tasks. The requirements fixed the hard numbers before any code existed. Requirement 3.1,
"apply at most one L1 action within 250 ms of detection", is the budget the Graveyard's latency gauge measures
against.

The design lists four correctness properties, and each one became a property-based test with
`pgregory.net/rapid`:

| Property in `design.md` | Test |
|---|---|
| P1: no plan with an L3 action or a protected target ever validates | `TestPolicy_Property_P1_NoL3OrProtectedTargetEverValidates` |
| P2: a token for plan X never authorizes plan Y | `TestApproval_Property_P2_TokenForPlanXNeverAuthorizesPlanY` |
| P3: every applied L1 action is rolled back exactly once | `TestReflex_Property_P3_AppliedActionRolledBackExactlyOnce` |
| P4: a reflex `MemoryHigh` is always at least `memory.current` | `TestReflex_Property_P4_MemoryHighAlwaysGECurrentUsage` |

Two more properties came out of later work: `TestProperty_VoteToTokenExactBinding` (a vote mints a token for
exactly the option voted on) and `TestDetector_Property_StaleSamplesNeverChangeInOrderEvaluations`.

[Your own words: what writing the spec first changed compared with prompting feature by feature.]

### Steering

Six steering files in `.kiro/steering/` load in three different ways:

- `product.md`, `tech.md`, `structure.md`, and `rules.md` load on every turn. They hold the product scope, the
  toolchain and security gate (Go 1.26.11, `govulncheck`), the package map, and project rules such as Go
  comments in Bahasa Indonesia and everything else in English.
- `linux-kernel.md` uses `fileMatch` on `internal/{psi,cgroup,kernelfs}/**`. Its kernel guardrails load only
  while Kiro edits those packages. One example: reclaim must stay per-cgroup, at most 25% of `memory.current`,
  and never touch `drop_caches`.
- `incident-response.md` is manual. It is the runbook, pulled in only when we work on incident flows.

Keeping the kernel rules out of unrelated turns kept the context small, and the rules still applied every
time kernel code was touched.

### Agent hooks

Five hooks in `.kiro/hooks/` act as guard rails on Kiro's own work:

| Hook | Trigger | What it does |
|---|---|---|
| `preToolUse.json` | `PreToolUse` on franken-sentinel and franken-wa MCP tools | Pipes the call through `franken guard --audit`, which records a redacted audit row and exits 2 to block a protected target such as `ssh.service` |
| `executor-guard.json` | Save under `internal/(executor\|approval\|reflex)/` | Re-runs the executor, approval, and reflex tests, the code that can touch the host |
| `policy-sync.json` | Save under `policy/` or `schema/` | Re-runs the policy and MCP server tests whenever the action catalog or the plan schema changes |
| `redaction-test.json` | Save under `internal/(redact\|incident)/` | Re-runs the redaction and incident store tests, so a regex change cannot leak a phone number |
| `spec-verify-on-stop.json` | `Stop` | Runs `go vet ./... && go test -count=1 ./...` at the end of every agent turn |

The `PreToolUse` hook is the same guard the agents meet at runtime, so a development session and a production
incident go through one check.

### MCP

MCP is the trust boundary of the whole design. The agents never get a shell on the server. They get two MCP
servers, and each agent's JSON file lists only the tools its role needs. Only `franken-architect` can call
`plan_submit`, and only `franken-remediator` can call `action_execute`:

- `franken-sentinel` exposes 17 tools over Streamable HTTP with bearer auth, from read-only ones such as
  `node_snapshot`, `psi_history`, `cgroup_top`, and `journal_tail` to gated ones such as `plan_submit`,
  `action_execute`, and `verify_health`. `franken mcp connect` bridges it to stdio for Kiro.
- `franken-wa` exposes 4 tools from wa-bridge: `wa_notify`, `wa_request_approval`, `wa_await_decision`, and
  `wa_send_report`.

Because every write goes through `plan_submit` and `action_execute`, the policy engine and the token verifier
see every action an agent attempts. That is how the second Graveyard incident can show a plan that targets
`ssh.service` rejected by policy and a replayed step token rejected by the nonce check.

### Kiro Crew: a conductor and three specialists

`app.json` packages FrankenCrew as a Kiro Crew app: four agents, three skills, both MCP servers, two cron jobs,
and the Graveyard as a dashboard page (`ui.pages`, route `/apps/franken-crew`).

- **Event-driven phases.** wa-bridge calls the Crew webhook (`POST /api/hooks/agent` with `KIROCREW_TOKEN`)
  when an incident opens and again when an admin votes. `franken-conductor` reads the phase (`TRIAGE` or
  `EXECUTE`) and spawns the specialist for it.
- **One orchestrator.** Only the conductor has the `@kirocrew-core` tools that spawn agents
  (`deploy/crew_orchestration_test.go` enforces this). The specialists cannot start each other.
- **Safety-net crons.** `incident-sweep` runs every 15 minutes in case a webhook was missed, and
  `morning-digest` sends a short daily summary of deferred P3 warnings.
- **Skills on demand.** `linux-memory-forensics`, `remediation-runbooks`, and `incident-spec-writer` load only
  when a specialist needs them.
- **Dashboard page.** The Graveyard entry module (`ui/dist/index.mjs`) default-exports a small React
  component that uses the host's React from the Crew import map and mounts the framework-free replay into a
  shadow root. It also exports `mount()` for other hosts, so the same files serve the landing page.

### Kiro Web, sub-agents, and powers

Later hardening rounds ran in Kiro Web. The agent audited the repository against the rules, opened pull
requests through the GitHub CLI power, and split independent fixes across sub-agents working in separate git
worktrees: the time-aware EWMA fix, the inotify re-arm, and the replay backend were built in parallel and
cherry-picked after review. The Playwright power took the screenshots used to check the Graveyard at desktop
and phone widths and inside a React host page like the Crew dashboard.

[Your own words: the most useful thing Kiro did, and one place where you had to steer it back.]

## Challenges we ran into

- **A watch that went silent.** When systemd recreates a service cgroup, the inotify watch on `memory.events`
  stops firing. Current kernels do not send `IN_IGNORED` for kernfs in that case, so the Linux poller now
  re-checks the path once per second and re-arms the watch with backoff (`internal/cgroup`).
- **A slope from nothing.** Event-driven samples (a PSI trigger, a `memory.events` change) can arrive 10 ms
  after the last 1 Hz sample. With a fixed EWMA weight, that tiny gap produced a steep fake slope. The detector
  now derives the weight from the real gap, `1 − (1 − α)^(Δt / 1 s)`, waits for a 250 ms minimum span, ignores
  stale samples, and treats a falling counter as a recreated cgroup (`internal/detector`).
- **Redaction against numbers.** The phone and IP redaction regexes mangled long byte counts and dotted values
  in stored telemetry. Telemetry series are now stored as integer-encoded evidence that the redactor leaves
  alone, and postmortems summarize them instead of dumping raw points.
- **A crew that stopped after triage.** The first Crew flow stalled once the Sentry finished, because nothing
  told the next agent to start. The fix was the event-driven conductor described above.
- **One approval, several steps.** Multi-step plans exposed a gap in how one approval covered more than one
  step. Tokens are now minted per step and each nonce is consumed on use, so a replayed token is refused.
- **Instructions hidden in logs.** A request body in the journal can contain text addressed to the agents. The
  agents may read it, but the policy engine and the incident scope check decide what runs. The second Graveyard
  incident replays exactly that case.

## Accomplishments that we're proud of

- The reflex path never waits for a model, and no model can take a risky action without a human vote.
- All four design properties are enforced by property-based tests, not only by examples.
- Small footprint: about 35 µs per detector and reflex evaluation cycle in
  `BenchmarkSentinelEvalAndReflexFootprint` on a development laptop, static linux/arm64 binaries of about 29.6 MiB
  (`franken`, which embeds the dashboard) and 27.5 MiB (`wa-bridge`), and 20 of 20 chaos runs passing across
  five failure scenarios with in-process timings.
- The Graveyard is about 100 KB of unminified ES modules with a strict Content Security Policy (no inline
  scripts, no third-party requests), keyboard controls, screen reader labels, and a reduced-motion mode.
- The same `ui/` folder serves the public landing page and the Kiro Crew dashboard page.

## What we learned

- Split the work by speed. Millisecond decisions belong in deterministic code, minute-scale reasoning belongs
  to agents, and anything that cannot be undone needs a human.
- Treat the LLM as untrusted input. The useful question is what the system does when the agent is wrong, and
  the answer has to live in code: policy, scope checks, and signed tokens.
- Specs and properties scale better than prompts. Once P1 to P4 existed as tests, refactors of the approval
  and reflex code had a safety net that example tests alone did not give.
- [One lesson of your own.]

## What's next for FrankenCrew

- Run it on real hardware ([board and kernel version]), measure the resident memory against the 32 MiB target
  and the kernel-to-reflex latency, and publish recorded replays with `franken lab export`.
- Cover CPU and IO pressure with the same reflex and plan pipeline.
- Let the morning digest suggest permanent fixes, such as memory limits and alert thresholds, as pull requests.

## Built with

Go, Linux cgroup v2, PSI, inotify, systemd, SQLite (`modernc.org/sqlite`), Model Context Protocol (official Go
SDK), WhatsApp (`whatsmeow`), Ed25519, `pgregory.net/rapid`, Kiro, Kiro Crew, JavaScript (ES modules), SVG.

## Testing instructions for judges

The tests and the dashboard need Go 1.26.11 or newer (`GOTOOLCHAIN=auto` downloads it), but no root and no
real cgroup. The live Sentinel needs Linux with cgroup v2 and PSI.

```bash
git clone https://github.com/FikFikk/franken-crew.git && cd franken-crew

# 1. Unit, integration, and property-based tests (no root needed)
go vet ./... && go test -count=1 ./...

# 2. Twenty chaos runs against an in-memory cgroup and procfs fixture
go run ./cmd/franken chaos run --runs 20

# 3. Rebuild the replay data through the real engine and open the Graveyard on http://127.0.0.1:3008
mkdir -p /tmp/franken-replays
go run ./cmd/franken lab simulate --out /tmp/franken-replays/replay.json
go run ./cmd/franken lab serve --listen 127.0.0.1:3008 --data-dir /tmp/franken-replays
```

To see the Crew side, install the app into Kiro Crew with `kirocrew app install "$PWD"`, trust and enable it
under Apps, and open **Graveyard** in the sidebar. The page works without a Sentinel. The agents, MCP servers,
and crons need `FRANKEN_BEARER_TOKEN`, a running Sentinel, and a paired wa-bridge (see the README).

## Notes on the data

- The live demo shows incidents from `franken lab simulate`. The simulation drives the real detector, reflex
  engine, policy and scope checks, Ed25519 verifier, verification worker, and postmortem generator against an
  in-memory cgroup and fake systemd and PM2 runners. The UI labels it **Simulation**.
- Lines and dots marked as inferred show Crew-internal steps (spawns, phase changes) reconstructed from the
  conductor protocol. The Sentinel does not log them.
- Reflex latency in the replays is in-process Go and SQLite time from the triggering sample to the applied
  reflex, not kernel-to-reflex latency on hardware.
- [Once you record real incidents, export them with `franken lab export --db franken-sentinel.db --out
  replay.json --source-kind recording` and the UI labels them **Recording**.]

## Social Blitz drafts

Each post must start with `#KiroweenHackathon26`. Attach a Graveyard screen recording or the hero image.

1. `#KiroweenHackathon26` I stitched a Go kernel watchdog, a Kiro Crew of AI agents, and a WhatsApp poll into
   one monster. The Sentinel applies a reversible reflex first, the agents plan the fix, and nothing risky runs
   until I vote. Replays: https://frankencrew.fikfikk.my.id
2. `#KiroweenHackathon26` My favourite FrankenCrew replay: hidden instructions in a log ask the agents to
   restart ssh.service. The policy engine rejects the plan and the Sentinel refuses a replayed approval token.
   [link]
3. `#KiroweenHackathon26` Built with @kirodotdev: an EARS spec, four correctness properties turned into rapid
   property tests, steering that loads kernel rules only for kernel code, and hooks that guard the agents' MCP
   calls. [repo link]

[Check the official Kiro handle for each platform before posting.]
