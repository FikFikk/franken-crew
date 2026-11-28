#!/usr/bin/env node
// Menulis out/frankencrew-demo.srt untuk YouTube dari caption tiap scene.
// Durasi dan posisi scene diambil dari calculateMetadata lewat selectComposition, jadi sama persis dengan video.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {bundle} from '@remotion/bundler';
import {selectComposition} from '@remotion/renderer';
import {serializeSrt} from '@remotion/captions';

const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.resolve(here, '..');
const VO_LEAD_IN = 6; // sama dengan src/script.ts
const MAX_CHARS = 42;
const MAX_GAP_MS = 600;

const serveUrl = await bundle({entryPoint: path.join(project, 'src/index.ts')});
const composition = await selectComposition({serveUrl, id: 'FrankenCrewDemo', inputProps: {}});
const {fps} = composition;

const lines = [];
for (const scene of composition.props.scenes) {
  if (!scene.captionTokens) {
    console.warn(`${scene.id}: no captions (${scene.captions}); skipped`);
    continue;
  }
  const offsetMs = ((scene.startFrame + VO_LEAD_IN) / fps) * 1000;
  let cue = [];
  let length = 0;
  const flush = () => {
    if (cue.length) lines.push(cue.map((t, i) => (i === 0 ? {...t, text: t.text.trimStart()} : t)));
    cue = [];
    length = 0;
  };
  for (const token of scene.captionTokens) {
    const shifted = {...token, startMs: token.startMs + offsetMs, endMs: token.endMs + offsetMs};
    const prev = cue.at(-1);
    if (prev && (length + token.text.length > MAX_CHARS || shifted.startMs - prev.endMs > MAX_GAP_MS)) flush();
    cue.push(shifted);
    length += token.text.length;
    if (/[.?!]$/.test(token.text.trim())) {
      // Ekor kalimat 1-2 kata digabung ke cue sebelumnya bila masih satu kalimat dan muat
      const prev = lines.at(-1);
      const prevText = prev ? prev.map((t) => t.text).join('') : '';
      if (prev && cue.length <= 2 && !/[.?!]$/.test(prevText.trim()) && prevText.length + length <= MAX_CHARS + 16 && prev[0].startMs >= offsetMs) {
        prev.push(...cue);
        cue = [];
        length = 0;
      } else {
        flush();
      }
    }
  }
  flush();
}

if (lines.length === 0) {
  console.error('No captions found. Run `npm run captions` after recording the voiceover.');
  process.exit(1);
}
const out = path.join(project, 'out/frankencrew-demo.srt');
fs.mkdirSync(path.dirname(out), {recursive: true});
fs.writeFileSync(out, `${serializeSrt({lines})}\n`);
console.log(`wrote ${path.relative(process.cwd(), out)} (${lines.length} cues, video ${(composition.durationInFrames / fps).toFixed(1)} s)`);
