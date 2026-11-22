---
inclusion: fileMatch
fileMatchPattern: "apps/video/**"
---

# Remotion demo video rules

The build spec for the demo video is `docs/REMOTION_VIDEO.md`. Read it before changing anything under
`apps/video/`, and keep the video in sync with it.

#[[file:docs/REMOTION_VIDEO.md]]

## Determinism

- Drive every animation from `useCurrentFrame()` with `interpolate()` (always clamped) or `spring()`.
- Never use `Math.random()`, `Date.now()`, `new Date()`, timers, or CSS transitions and animations. Use
  `random('<seed>')` from `remotion` when variation is needed.
- Load fonts with `@remotion/google-fonts` only. No system fonts, so renders look the same on every machine.

## Media

- Use `<Video>` and `<Audio>` from `@remotion/media`, and `<Img>` from `remotion`.
- Reference local assets with `staticFile()`. No remote URLs at render time.
- Install Remotion packages with `npx remotion add <package>` so every package stays on the same version.

## Truthfulness

- Every number, log line, test name, and file name on screen comes from a file in `apps/video/src/data/`,
  produced by `apps/video/scripts/collect-data.sh` from the real repository. Never type a number by hand.
- Footage from `franken lab simulate` must carry the "Simulation replay" label while it is on screen.
- Narration text comes from `docs/DEMO_VIDEO_SCRIPT.md`. Change it there first, then in `src/script.ts`.

## Rules from the Kiroween official rules

- Total length at most 5250 frames at 30 fps (2:55). `calculateMetadata` must throw if a change goes over.
- No WhatsApp, Meta, or other third-party logos or brand assets. Say "WhatsApp" in the narration and use a
  generic chat look on screen.
- No copyrighted music. Music is optional and must be royalty-free with a license that allows this use.
- All text in English.

## Readability

- 1920x1080. Keep text at least 36 px tall and 64 px away from every edge.
- Body text in `theme.text` on `theme.bg` or `theme.panel`. Do not put text directly over moving footage
  without a panel behind it.

## Checks after each change

- `npx tsc --noEmit` passes.
- `npx remotion still FrankenCrewDemo out/check.png --frame=<a frame inside the scene you changed>` renders,
  and the image looks right.
- Code comments in Bahasa Indonesia (team convention from `rules.md`). Identifiers, on-screen text, and
  commit messages in English.
