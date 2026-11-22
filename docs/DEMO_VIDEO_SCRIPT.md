# FrankenCrew demo video: script and shot list

Target length: **2:50**. The rules say judges do not have to watch past 3:00, so the last frame with the URL
must land before that.

To build this video in code with Remotion, follow [REMOTION_VIDEO.md](REMOTION_VIDEO.md). It uses the shot
list and narration below as its script.

## What the rules require

From the [Kiroween 2026 official rules](https://kiroween.devpost.com/rules):

- Shorter than three minutes.
- Uploaded to **YouTube** and set to **Public**. The rules name YouTube only, not Vimeo. Unlisted may not count
  as publicly visible, so use Public.
- Footage of the project running on the platform it was built for (Linux, the browser, Kiro Crew).
- No third-party trademarks, copyrighted music, or other material you do not have permission to use. Record
  without music, or use a track from the YouTube Audio Library that allows reuse.
- In English, or with an English translation. Upload English captions; the narration below can be pasted in as
  a transcript.

The Presentation score asks four things: does the video show the project working end to end, does it say what
problem is solved and for whom, is it easy to follow, and is it memorable. The script answers them in that
order.

## Footage

### Already recorded

`docs/media/graveyard-replay-broll.webm` (1280x720, 89 seconds, no audio) was recorded with the Playwright
power from the live site and contains, in order (times are approximate):

| From | To | What is on screen |
|---|---|---|
| 0:00 | 0:05 | Landing page hero. The first second shows the replay data loading, so start the cut at 0:02 |
| 0:05 | 0:14 | Scroll down to the Graveyard; the heap leak incident header and its six numbers |
| 0:14 | 0:41 | Heap leak replay at 4x: T0 detected, L1 reflex 0.78 ms, Crew triage, poll sent, approved, L2 executed, verify window, RESOLVED |
| 0:41 | 0:47 | Operator phone (vote, approval, final report) and flight recorder for the heap leak |
| 0:47 | 1:17 | Prompt injection incident header, then its replay at 4x |
| 1:17 | 1:22 | Phone and flight recorder: replayed step token rejected, incident resolved |
| 1:22 | 1:29 | Event log filtered to the Sentinel lane: plan rejected by policy, `ssh.service` restart blocked |

YouTube accepts `.webm` directly, and any editor (CapCut, DaVinci Resolve, Clipchamp, Shotcut) can cut it.

### Still to record (about 10 minutes of work)

1. **Terminal, large font (18 pt or more), dark theme**, in the repository root:

   ```bash
   go test -count=1 -run Property -v ./internal/policy ./internal/approval ./internal/reflex | grep -E -- "--- PASS|^ok"
   go run ./cmd/franken chaos run --runs 20 | tail -6
   ```

   Both were run on this branch: the four P1 to P4 property tests pass, and the chaos suite ends with a line
   like `Summary: passed=20/20 failed=0 max_reflex_ms=1.61 avg_reflex_ms=1.11`. The timings change a little
   on every run.

2. **GitHub in the browser:** the repository root with `.kiro/` visible, then
   `.kiro/specs/server-incident-remediation/requirements.md` (scroll to Requirement 3.1), then
   `.kiro/hooks/preToolUse.json`.

3. **Kiro Crew dashboard:** the Graveyard page under Apps, to show that the same UI runs inside Crew.

4. **Optional, strongest shot:** your phone screen with a real FrankenCrew poll from a paired wa-bridge. If
   you have it, it replaces the simulated phone panel in shot 4 and shows the project on real hardware. If you
   record it, blur the phone numbers.

## Shot list and narration

About 380 words, which fits 2:50 at 120 to 150 words per minute. Read it aloud once with a timer and cut a sentence if you run
long. Change any wording that does not sound like you.

| Time | Screen | Narration |
|---|---|---|
| 0:00 to 0:14 | B-roll 0:02 to 0:05, the hero (hold the last frame) | It's 3 a.m. A service on a small Linux server is leaking memory. In about two minutes the OOM killer will pick a victim, and nobody is on call. |
| 0:14 to 0:32 | Landing page, "One monster, four isolated organs" section | FrankenCrew stitches together three parts that were never meant to fit. A Go daemon, the Sentinel, handles reflexes in milliseconds. A Kiro Crew of four AI agents does the thinking. And a WhatsApp poll keeps a human in charge of anything that can't be undone. |
| 0:32 to 1:18 | B-roll 0:05 to 0:47, heap leak (slow the replay part slightly to fill the slot) | This replay comes from the real engine, driven against a simulated cgroup. Pressure crosses ten percent, and the Sentinel opens an incident with two minutes left before OOM. Less than a millisecond later it applies one reversible reflex: a bounded memory reclaim with a timer to undo it. No model is involved. Then the Crew wakes up. The Sentry triages, the Architect writes a plan, and the Sentinel checks it against the policy. The plan arrives as a WhatsApp poll. The admin votes, the bridge signs a single-use token for that one step, and only then does the reload run. The Sentinel watches for 120 seconds and writes the postmortem. |
| 1:18 to 1:46 | B-roll 0:47 to 1:29, prompt injection and the blocked rows (cut the middle of the replay or play it at 1.5x) | What if an agent is wrong, or tricked? Here a log line tells the operator to restart ssh.service. The agents read it, and it doesn't matter. The policy rejects the plan, because ssh is protected and outside the incident's cgroup. A direct restart is blocked. And a replayed approval token is refused, because its nonce was already used. |
| 1:46 to 2:22 | GitHub `.kiro/`, `requirements.md`, `preToolUse.json`, then the property test output | I built FrankenCrew with Kiro, spec first. Twelve requirements in EARS form, a design with four properties that must never break, and 52 tasks. Each property became a property-based test, like "a token for plan X never authorizes plan Y". Steering loads the kernel rules only when Kiro edits kernel code. A PreToolUse hook sends every call to the FrankenCrew MCP tools through the same guard the agents meet in production. The audit and hardening rounds ran in Kiro Web, and each one came back as a pull request. |
| 2:22 to 2:38 | Kiro Crew dashboard with the Graveyard page, then the chaos summary in the terminal | The whole thing installs as a Kiro Crew app: four agents, two crons, two MCP servers, and this Graveyard as a dashboard page. Twenty chaos runs across five failure types: twenty passes. |
| 2:38 to 2:50 | Landing page hero with the URL in large text | FrankenCrew. Reflexes in Go, thinking in Kiro, and a human with the last word. Replays at frankencrew dot fikfikk dot my dot id. |

## Upload checklist

- Title: `FrankenCrew: kernel reflexes, a Kiro Crew, and a WhatsApp vote (Kiroween 2026)`
- Visibility: **Public**. Audience: not made for kids.
- Description:

  ```text
  FrankenCrew keeps small Linux servers alive. A Go Sentinel applies one reversible reflex within 250 ms of a
  memory incident, a Kiro Crew of four agents triages it and writes a plan, and nothing irreversible runs until
  an admin votes in a WhatsApp poll that mints a single-use Ed25519 token.

  Built with Kiro for the Kiroween 2026 hackathon (Frankenstein category).

  Live replays: https://frankencrew.fikfikk.my.id
  Code (MIT): https://github.com/FikFikk/franken-crew

  The replays shown are simulations through the real engine and are labelled as such in the UI.
  ```

- Captions: upload the narration column as an English transcript, or check YouTube's automatic captions.
- After upload, open the link in a private window to confirm it plays without signing in, then paste it into
  the Devpost form and into `docs/DEVPOST_SUBMISSION.md`.
