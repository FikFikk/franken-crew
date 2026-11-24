#!/usr/bin/env node
// Membuat public/captions/<scene>.json dari rekaman VO di public/vo/ dengan Whisper.cpp lokal.
// Jalankan: `npm run captions` (semua scene) atau `npm run captions -- 03-heap-leak` (satu scene).
// Unduhan pertama: whisper.cpp dikompilasi (butuh make dan compiler C++) dan model medium.en sekitar 1.5 GB.
// Ganti model lewat env, misalnya WHISPER_MODEL=small.en.
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {downloadWhisperModel, installWhisperCpp, toCaptions, transcribe} from '@remotion/install-whisper-cpp';

const here = path.dirname(fileURLToPath(import.meta.url));
const project = path.resolve(here, '..');
const voDir = path.join(project, 'public/vo');
const outDir = path.join(project, 'public/captions');
const whisperPath = path.join(project, '.whisper');
// 1.5.5 adalah versi di contoh dokumentasi Remotion dan tersedia sebagai biner Windows; versi >= 1.7.3 butuh cmake
const WHISPER_VERSION = process.env.WHISPER_CPP_VERSION ?? '1.5.5';
const model = process.env.WHISPER_MODEL ?? 'medium.en';

// Ejaan istilah teknis yang sering salah didengar Whisper; waktu token tidak diubah
const FIXES = [
  [/\bP\.?S\.?I\b/gi, 'PSI'],
  [/\bC group\b/gi, 'cgroup'],
  [/\bE\.?D\.? ?25519\b/gi, 'Ed25519'],
  [/\bO\.?O\.?M\b/g, 'OOM'],
  [/\bKero\b|\bKeiro\b/g, 'Kiro'],
  [/\bFranken ?crew\b/gi, 'FrankenCrew'],
];

const only = process.argv[2];
const files = fs
  .readdirSync(voDir)
  .filter((f) => f.endsWith('.wav') && (!only || f.startsWith(only)))
  .sort();
if (files.length === 0) {
  console.error(`No WAV files in ${path.relative(process.cwd(), voDir)}. Record the voiceover first (docs/REMOTION_VIDEO.md section 7).`);
  process.exit(1);
}

await installWhisperCpp({to: whisperPath, version: WHISPER_VERSION});
await downloadWhisperModel({model, folder: whisperPath});
fs.mkdirSync(outDir, {recursive: true});

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
for (const file of files) {
  // Whisper butuh WAV mono 16 kHz; ffmpeg bawaan Remotion dipakai agar tidak perlu ffmpeg sistem
  const tmp = path.join(os.tmpdir(), `vo-16k-${file}`);
  execFileSync(npx, ['remotion', 'ffmpeg', '-y', '-v', 'error', '-i', path.join(voDir, file), '-ar', '16000', '-ac', '1', tmp], {
    cwd: project,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  const whisperCppOutput = await transcribe({
    inputPath: tmp,
    whisperPath,
    whisperCppVersion: WHISPER_VERSION,
    model,
    tokenLevelTimestamps: true,
  });
  const {captions} = toCaptions({whisperCppOutput});
  const fixed = captions.map((c) => ({...c, text: FIXES.reduce((t, [re, to]) => t.replace(re, to), c.text)}));
  const out = path.join(outDir, file.replace(/\.wav$/, '.json'));
  fs.writeFileSync(out, `${JSON.stringify(fixed, null, 2)}\n`);
  console.log(`wrote ${path.relative(process.cwd(), out)} (${fixed.length} tokens)`);
}
console.log('Check the JSON for misheard words and fix the text by hand; keep the times.');
