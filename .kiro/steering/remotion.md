---
inclusion: fileMatch
fileMatchPattern: "apps/video/**"
---

# Remotion demo video rules

The design of the demo video is `docs/REMOTION_VIDEO.md`; the commands are in `apps/video/README.md`. Keep
the design doc in sync when you change scenes, cues, or data sources.

#[[file:docs/REMOTION_VIDEO.md]]

## Determinism

- Drive every animation from `useCurrentFrame()` with the helpers in `src/anim.ts` (`enter`, `fadeIn`,
  `typed`) or with clamped `interpolate()` and `spring()`.
- Never use `Math.random()`, `Date.now()`, timers, or CSS transitions and animations. Use `random('<seed>')`
  from `remotion` when variation is needed.
- Load fonts with `@remotion/google-fonts` only (`src/fonts.ts`). Draw arrows, checks, and other symbols
  outside the latin subset with `src/components/Glyphs.tsx`.

## Timing

- Scene lengths and cue frames come from `src/timeline.ts`. Start an animation on a cue (`cue(scene, name)`),
  not on a hard-coded frame, whenever it matches a spoken phrase. Add new cue words in `src/script.ts`; the
  word must occur in that scene's narration, or `calculateMetadata` throws.
- Footage moments are anchored with `WarpedVideo` source times measured from the replay clock in the
  recording. Re-measure them if the footage is re-recorded.

## Media

- Use `<Video>` and `<Audio>` from `@remotion/media` (with the `objectFit` prop), and `<Img>` from `remotion`.
- Reference local assets with `staticFile()`. No remote URLs at render time.
- Install Remotion packages with `npx remotion add <package>`. Keep `mediabunny` pinned to the version
  `@remotion/media` depends on, so only one copy is bundled.

## Truthfulness

- Every number, log line, test name, and file name on screen comes from `src/data/`, produced by
  `npm run data` from the repository. Never type a number by hand.
- Show the "SIMULATION REPLAY" chip whenever Graveyard footage or screenshots are on screen.
- Narration text comes from `docs/DEMO_VIDEO_SCRIPT.md`. Change it there, then run `npm run data`, `npm run vo`
  (or re-record), and `npm run captions`, so voice, captions, and cues stay in step.
- Fix a mispronunciation in the `LEXICON` of `scripts/make-vo.mjs`, never in the narration text.

## Rules from the Kiroween official rules

- Total length at most 5250 frames at 30 fps (2:55). `calculateMetadata` throws if a change goes over.
- No WhatsApp, Meta, or other third-party logos or brand assets. Say "WhatsApp" in the narration and use a
  generic chat look on screen.
- No copyrighted music. Music is optional and must be royalty-free with a license that allows this use.
- All text in English.

## Readability

- 1920x1080. Main text at least 30 px, small labels at least 26 px, and 64 px away from every edge.
- Keep the bottom 128 px free in every scene; captions appear there.
- Text in `theme.text` on `theme.bg` or `theme.panel`. Do not put text directly over moving footage without a
  panel behind it.

## Checks after each change

- `npm run lint` passes (ESLint and `tsc`).
- `npm run stills` (or `npm run stills -- <frame>`) renders, and the images look right.
- Code comments in Bahasa Indonesia (team convention from `rules.md`). Identifiers, on-screen text, and
  commit messages in English.
