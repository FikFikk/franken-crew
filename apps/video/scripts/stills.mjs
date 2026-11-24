#!/usr/bin/env node
// Render still per scene (bundle sekali) untuk review visual cepat: `npm run stills`.
// Argumen opsional: frame absolut, misalnya `npm run stills -- 1200 2400`.
// Default: frame di 35% dan 85% tiap scene; `--cues` menambah satu still setelah setiap cue;
// `--thumbnail` menulis out/thumbnail.png dari frame diam terakhir S7 untuk YouTube.
import path from 'node:path';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {bundle} from '@remotion/bundler';
import {renderStill, selectComposition} from '@remotion/renderer';

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(here, process.argv.includes('--thumbnail') ? '../out' : '../out/stills');
fs.mkdirSync(outDir, {recursive: true});

const serveUrl = await bundle({entryPoint: path.resolve(here, '../src/index.ts')});
const composition = await selectComposition({serveUrl, id: 'FrankenCrewDemo', inputProps: {}});
const scenes = composition.props.scenes;

const withCues = process.argv.includes('--cues');
const thumbnail = process.argv.includes('--thumbnail');
const requested = process.argv.slice(2).map(Number).filter((n) => Number.isFinite(n));
const frames = thumbnail
  ? [{frame: composition.durationInFrames - 30, name: 'thumbnail'}]
  : requested.length
  ? requested.map((f) => ({frame: f, name: `frame-${f}`}))
  : scenes.flatMap((s) => [
      {frame: s.startFrame + Math.round(s.durationInFrames * 0.35), name: `${s.id}-35`},
      {frame: s.startFrame + Math.round(s.durationInFrames * 0.85), name: `${s.id}-85`},
      ...(withCues ? Object.entries(s.cueFrames).map(([cue, f]) => ({frame: s.startFrame + f + 12, name: `${s.id}-cue-${cue}`})) : []),
    ]);

console.log(`${composition.durationInFrames} frames (${(composition.durationInFrames / composition.fps).toFixed(1)} s)`);
for (const s of scenes) {
  const cues = Object.entries(s.cueFrames)
    .map(([k, f]) => `${k}@${f}${s.cueSource[k] === 'captions' ? '' : '~'}`)
    .join(' ');
  console.log(`  ${s.id} ${s.title.padEnd(20)} start ${String(s.startFrame).padStart(4)} len ${String(s.durationInFrames).padStart(4)} vo=${s.hasVo ? 'yes' : 'no'}  ${cues}`);
}
for (const f of frames) {
  const output = path.join(outDir, `${f.name}.png`);
  await renderStill({serveUrl, composition, frame: f.frame, output, imageFormat: 'png'});
  console.log(`  wrote ${path.relative(process.cwd(), output)} (frame ${f.frame})`);
}
