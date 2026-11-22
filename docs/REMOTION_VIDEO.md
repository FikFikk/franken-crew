# FrankenCrew demo video in Remotion: design

The Kiroween demo video is a [Remotion](https://www.remotion.dev/) 4 project in
[`apps/video/`](../apps/video/). This file records how it is built and the rules it follows. The narration
comes from [DEMO_VIDEO_SCRIPT.md](DEMO_VIDEO_SCRIPT.md), and the commands are in
[apps/video/README.md](../apps/video/README.md).

It follows section E of [BLUEPRINT.md](BLUEPRINT.md) (Remotion 4, `apps/video/`, voiceover-driven timing,
burned-in captions) and updates it to what the project has today: Graveyard footage instead of asciinema
casts, the Graveyard color palette, and data generated from the repository.

`.kiro/steering/remotion.md` loads automatically for any file under `apps/video/` and pulls this file in.

## 1. Output and hard limits

| Item | Value |
|---|---|
| Composition id | `FrankenCrewDemo` |
| Size and rate | 1920x1080, 30 fps |
| Budget length | 5100 frames (2:50) without a voiceover |
| Hard maximum | 5250 frames (2:55). `calculateMetadata` throws above this. Judges stop at 3:00. |
| Output | `apps/video/out/frankencrew-demo.mp4`, H.264, CRF 18, AAC |
| Language | English narration and on-screen text, captions burned in, `.srt` for YouTube |

From the [official rules](https://kiroween.devpost.com/rules): the video must show the project working, and it
must not include third-party trademarks or copyrighted music without permission. So:

- No WhatsApp or Meta logo, icon, or WhatsApp's brand green (`#25D366`). The narration says "WhatsApp"; the
  phone on screen is a generic chat built from wa-bridge's message formats.
- No music unless it is royalty-free with a license that allows this use. The project has none.
- The Graveyard footage and screenshot come from `franken lab simulate`. A "SIMULATION REPLAY" chip is on
  screen whenever they are.

Remotion is free for individuals and companies of up to three people
([license](https://www.remotion.dev/docs/license/pricing)). The project uses Remotion 4.0.545 and mediabunny
1.66.0 (pinned to the version `@remotion/media` depends on, so only one copy is bundled).

## 2. Where the data comes from

Nothing on screen is typed by hand. `npm run data` (`apps/video/scripts/collect-data.mjs`) builds
`src/data/` from the repository:

| Output | Source |
|---|---|
| `replay.json`, `app.json`, `preToolUse.json` | Copied from `ui/data/`, the repo root, and `.kiro/hooks/` |
| `repo.narration` | The narration column of the shot list in `docs/DEMO_VIDEO_SCRIPT.md` (7 rows) |
| `repo.chaosRuns`, `repo.chaosSummary` | A fresh `franken chaos run --runs 20` |
| `repo.propertyTests` | A fresh `go test -run 'Property_P[1-4]'` in policy, approval, and reflex |
| `repo.guard` | The `PreToolUse` hook's command run on a payload that targets `ssh.service` (must exit 2) |
| `repo.spec` | Requirement and task counts, criterion 3.1, and P1 to P4 from the spec files |
| `repo.steering` | Every `.kiro/steering/*.md` with its `inclusion` and `fileMatchPattern` |
| `repo.mcpTools` | `mcp.AddTool(` calls in `internal/mcpserver` (15) and `internal/wabridge/mcp_tools.go` (4) |
| `repo.mergedPRs` | Merge commits in `git log` (the PR title is the merge commit body) |
| `repo.injectedLog` | The prompt-injection journal line in `internal/lab/simulate.go` |

The script fails loudly if anything is missing: fewer than 20 chaos runs, a failing property test, a guard
that does not block, or a shot list without 7 narration rows. `src/data/` is committed, so the video builds
without Go.

Assets in `public/`: `footage/graveyard-replay-broll.webm` (1280x720, 25 fps, 89.2 s, recorded from the live
site with the Playwright power), `img/prompt-injection-blocked.png` (the event log screenshot), and the two
logos from `ui/assets/`.

## 3. Timing: voiceover first, cue words second

`src/script.ts` lists the seven scenes with a frame budget, a tail, a voiceover file, a caption file, and a
map of **cue words**. `src/timeline.ts` resolves them in `calculateMetadata`:

- **Scene length** = `max(budget, 6 + voiceover frames + tail)`. Without a voiceover file the scene keeps its
  budget and plays silently.
- **Cue frame** = the start of the first caption token that begins with the cue word, plus the 6-frame lead-in.
  Without captions, or when Whisper spelled the word differently, the frame is estimated from the word's
  character offset in the narration, spread over the spoken part of the scene.
- Studio and `npm run stills` print every cue; a `~` marks an estimate.

Every animation that matches a spoken phrase starts on its cue, so recording the voice re-times the whole
video. Scenes use `Series`, and each one fades in and out over 10 frames on the same background, so the
voiceover can live inside its scene without the overlap problem of `TransitionSeries` (BLUEPRINT.md E.5).

### Time-warped footage

The Graveyard replay in the footage runs at its own pace. `WarpedVideo` (`src/components/Footage.tsx`) plays
the file in segments with different playback rates, so that a given moment in the source lands on a given
cue frame. The anchors are source seconds read from the replay clock in the recording:

| Moment in the footage | Source time | S3 cue |
|---|---|---|
| Scroll from the hero to the Graveyard starts | 5.0 s | scene start |
| `T-0:14`, PSI just crossed 10% | 15.0 s | "Pressure" |
| `T+0:00`, T0 detected | 17.0 s | "incident" |
| L1 reflex label visible | 17.6 s | "reflex" |
| `T+0:05`, Sentry claimed the incident | 18.3 s | "Crew" |
| `T+0:33`, poll sent | 22.3 s | "poll" |
| `T+1:10`, operator approved | 26.4 s | "votes" |
| `T+1:17`, L2 executed | 28.0 s | "reload" |
| Inside the 120 s verify window | 30.5 s | "watches" |
| `T+3:17`, RESOLVED | 41.0 s | scene end |

S4 uses the prompt-injection part of the same file: 47.6 s (incident header with "3 unsafe actions blocked")
at the start, 50.0 s at "log", and 77.0 s just after "rejects", when the event log screenshot takes over.

## 4. Look and feel

Colors come from the Graveyard (`ui/dist/styles.mjs`, copied into `src/theme.ts`). Fonts load through
`@remotion/google-fonts`: Inter for text, JetBrains Mono for code, numbers, and terminals, and Creepster only
for "IT'S ALIVE". The latin subsets have no arrow or check glyphs, so `src/components/Glyphs.tsx` draws them as
SVG. Text is at least 26 px (labels) and mostly 30 px or more, with 64 px margins. Entrances use a damped
spring; nothing shakes. A neon stitch line, the Frankenstein motif, crosses the screen at the end of S1, S2,
and S4.

## 5. Scenes

Budgets add up to 5100 frames. Lengths grow with the recorded voiceover.

| Scene | Budget | Content | Cues |
|---|---|---|---|
| S1 Hook | 420 | A clock runs from 03:17:01 to 03:19:00 UTC while memory and PSI for the heap leak draw from `replay.json`. "PSI some avg10 crossed 10%" appears where PSI crosses, "projected time to OOM: 119 s" at "two", and "Nobody is on call." at "nobody". | service, two, nobody |
| S2 Three organs | 540 (+60 tail) | Logo, then three cards: Sentinel (reflexes), Kiro Crew (thinking, agent count from `app.json`), Human (conscience). Arrows labelled webhook, poll, and "one Ed25519 token per step", then "IT'S ALIVE". | Go, Kiro, WhatsApp |
| S3 Heap leak | 1380 | Time-warped footage in a browser frame, a six-step rail that lights up per cue (values from the incident), and a phone overlay from poll to reload with the alert, the poll options, the vote, and the minted token, all from `replay.json`. A real phone recording replaces the mock if `footage/phone-poll.mp4` exists. | Pressure, incident, reflex, Crew, poll, votes, reload, watches |
| S4 Prompt injection | 840 (+36 tail) | Incident header, then the real injected journal line typed over dimmed footage. At "rejects" the event log screenshot takes over, and three stamps (PLAN REJECTED, BLOCKED, REFUSED, with their replay times) land as the matching rows light up. Closes on "RESOLVED at T+3:03 by restarting only worker pm_id=2". | log, rejects, blocked, refused |
| S5 Built with Kiro | 1080 | One panel, five beats titled with real paths: criterion 3.1 typed with EARS keywords highlighted and counters (12 requirements, 4 properties, 52 of 52 tasks); P1 to P4 with their test names and PASS times; the steering files with their inclusion modes; the hook JSON and the guard run (`exit 2 · blocked` with the real message); the merged pull requests. | Twelve, four, tasks, Each, Steering, pre(ToolUse), guard, audit |
| S6 Crew app and chaos | 480 (+30 tail) | `app.json` (agents, crons, MCP servers with tool counts, dashboard page) beside a terminal printing the 20 chaos runs and the summary. A Crew dashboard recording replaces the top of the card if `footage/crew-dashboard.mp4` exists. | four, crons, MCP, Graveyard, Twenty, passes |
| S7 Outro | 360 (+90 tail) | Logo, the three-part tagline on its spoken words, then the URL, the repository, and "Kiroween 2026 · Frankenstein category · MIT license" held still. `npm run thumbnail` takes the thumbnail from here. | Reflexes, thinking, human, Replays |

## 6. Voiceover and captions

Record one take per scene, mono WAV, to `public/vo/01-hook.wav` … `07-outro.wav`, normalized to about
-16 LUFS. Your own voice is recommended: judges score whether the pitch is clear and memorable.

`npm run captions` installs Whisper.cpp 1.5.5 into `.whisper/` (compiled from source on macOS and Linux, a
prebuilt binary on Windows), downloads `medium.en` (about 1.5 GB; set `WHISPER_MODEL=small.en` for less),
converts each file to 16 kHz with Remotion's bundled ffmpeg, and writes `public/captions/*.json` in Remotion's
`Caption` format. A small fix list corrects common spellings (PSI, cgroup, Ed25519, OOM, Kiro, FrankenCrew).
Check the JSON and fix misheard words by hand; keep the times.

`src/components/Captions.tsx` shows the captions as pages of about 1.4 s, centered 64 px above the bottom,
with the current word highlighted. `npm run srt` bundles the project, reads the resolved scenes through
`selectComposition`, shifts each scene's captions to its start, and writes `out/frankencrew-demo.srt`.

## 7. Checks before uploading

- [ ] `npm run lint` passes, and Studio shows a length under 2:55.
- [ ] `npm run stills -- --cues` shows each cue landing on the right visual. No cue should still be an estimate
      (`~`) once captions exist, unless Whisper misheard that word; then fix the caption text.
- [ ] `npm run data` ran after the last engine change, so the numbers match the code.
- [ ] The "SIMULATION REPLAY" chip is visible whenever Graveyard footage or the screenshot is on screen.
- [ ] No third-party logos and no unlicensed music.
- [ ] Captions are readable on a phone, and nothing important sits within 64 px of an edge.
- [ ] `out/frankencrew-demo.srt` and `out/thumbnail.png` exist for the upload.

Then follow the upload checklist in [DEMO_VIDEO_SCRIPT.md](DEMO_VIDEO_SCRIPT.md).

## 8. How it was verified

In a Kiro Web session the project was built, then rendered end to end with a robot test voice (meSpeak, not
committed) to exercise the full path: the voiceover stretched S2, S5, and S7, Whisper `base.en` produced
captions for all seven files, most cues resolved from the captions, and the complete video rendered at half
size in about 100 seconds. The test voice and captions were deleted afterwards, so the committed project
renders silently until the real voiceover is recorded.

## 9. Kiro features this exercises

- `.kiro/steering/remotion.md` is a `fileMatch` steering file for `apps/video/**`. It pulls in this file with
  `#[[file:docs/REMOTION_VIDEO.md]]`, so the video rules load only while Kiro edits the video.
- The Playwright power recorded the Graveyard footage and the screenshot, and checked rendered stills.
- The blueprint's `scene-still` hook (BLUEPRINT.md B.2) can be added as a file-save hook on
  `apps/video/src/scenes/**` that runs `npm run stills` for review.
- Remotion's agent skills (`npx remotion skills add`, installed to `apps/video/.agents/skills`) can be copied
  into `.kiro/skills/` if you want Kiro to load Remotion's own best practices too.
