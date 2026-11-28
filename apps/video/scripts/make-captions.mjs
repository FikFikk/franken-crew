#!/usr/bin/env node
// Membuat public/captions/<scene>.json dari rekaman VO di public/vo/ dengan Whisper.cpp lokal.
// Jalankan: `npm run captions` (semua scene) atau `npm run captions -- 03-heap-leak` (satu scene).
// Unduhan pertama: whisper.cpp dikompilasi (butuh make dan compiler C++) dan model medium.en sekitar 1.5 GB.
// Ganti model lewat env, misalnya WHISPER_MODEL=small.en.
// Teks caption disejajarkan ke narasi di DEMO_VIDEO_SCRIPT.md: Whisper memberi waktu, naskah memberi ejaan.
// Pakai `--no-snap` untuk menyimpan teks Whisper apa adanya (misalnya saat membaca di luar naskah).
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {downloadWhisperModel, installWhisperCpp, toCaptions, transcribe} from '@remotion/install-whisper-cpp';
import {narrationByName, project} from './narration.mjs';

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

const args = process.argv.slice(2);
const snap = !args.includes('--no-snap');
const only = args.find((a) => !a.startsWith('--'));
const narration = narrationByName();

const key = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

// Gabungkan token Whisper menjadi kata: token tanpa spasi depan adalah lanjutan kata sebelumnya (subkata, tanda baca)
const toWords = (tokens) => {
  const words = [];
  for (const t of tokens) {
    const prev = words.at(-1);
    if (prev && !/^\s/.test(t.text)) {
      prev.text += t.text;
      prev.endMs = t.endMs;
    } else {
      words.push({text: t.text.trim(), startMs: t.startMs, endMs: t.endMs, confidence: t.confidence});
    }
  }
  return words.filter((w) => key(w.text));
};

// Sejajarkan kata naskah dengan kata Whisper (LCS pada bentuk ternormalisasi). Kata yang cocok memakai waktu
// Whisper; rentang yang tidak cocok dibagi rata menurut panjang karakter di dalam waktu yang tersedia.
const snapToScript = (scriptText, heard) => {
  const script = scriptText.split(/\s+/).filter(Boolean);
  const a = script.map(key);
  const b = heard.map((w) => key(w.text));
  const dp = Array.from({length: a.length + 1}, () => new Int32Array(b.length + 1));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const pairs = [];
  for (let i = 0, j = 0; i < a.length && j < b.length; ) {
    if (a[i] === b[j]) pairs.push([i++, j++]);
    else if (dp[i + 1][j] >= dp[i][j + 1]) i++;
    else j++;
  }
  const out = [];
  const misheard = [];
  const fill = (i0, i1, j0, j1, fromMs, toMs) => {
    if (i1 <= i0) return;
    const start = j1 > j0 ? heard[j0].startMs : fromMs;
    const end = j1 > j0 ? heard[j1 - 1].endMs : Math.max(toMs, fromMs);
    const lengths = script.slice(i0, i1).map((w) => w.length);
    const total = lengths.reduce((x, y) => x + y, 0);
    let at = start;
    for (let i = i0; i < i1; i++) {
      const dur = ((end - start) * lengths[i - i0]) / total;
      out.push({text: ` ${script[i]}`, startMs: Math.round(at), endMs: Math.round(at + dur), timestampMs: Math.round(at + dur / 2), confidence: null});
      at += dur;
    }
    misheard.push(`"${script.slice(i0, i1).join(' ')}" heard as "${heard.slice(j0, j1).map((w) => w.text).join(' ')}"`);
  };
  let pi = 0;
  let pj = 0;
  let lastEnd = heard[0]?.startMs ?? 0;
  for (const [i, j] of [...pairs, [a.length, b.length]]) {
    const nextStart = j < b.length ? heard[j].startMs : (heard.at(-1)?.endMs ?? lastEnd);
    fill(pi, i, pj, j, lastEnd, nextStart);
    if (i < a.length) {
      const w = heard[j];
      out.push({text: ` ${script[i]}`, startMs: w.startMs, endMs: w.endMs, timestampMs: Math.round((w.startMs + w.endMs) / 2), confidence: w.confidence});
      lastEnd = w.endMs;
    }
    pi = i + 1;
    pj = j + 1;
  }
  return {captions: out, matched: pairs.length, total: script.length, misheard};
};


const files = fs
  .readdirSync(voDir)
  .filter((f) => f.endsWith('.wav') && (!only || f.startsWith(only)))
  .sort();
if (files.length === 0) {
  console.error(`No WAV files in ${path.relative(process.cwd(), voDir)}. Record the voiceover or run npm run vo first (docs/REMOTION_VIDEO.md section 6).`);
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
  const name = file.replace(/\.wav$/, '');
  const out = path.join(outDir, `${name}.json`);
  let result;
  if (snap && narration[name]) {
    const snapped = snapToScript(narration[name], toWords(captions));
    result = snapped.captions;
    const pct = ((100 * snapped.matched) / snapped.total).toFixed(0);
    console.log(`wrote ${path.relative(process.cwd(), out)}: ${snapped.matched}/${snapped.total} script words heard as written (${pct}%)`);
    for (const m of snapped.misheard) console.log(`    ${m}`);
  } else {
    result = captions.map((c) => ({...c, text: FIXES.reduce((t, [re, to]) => t.replace(re, to), c.text)}));
    console.log(`wrote ${path.relative(process.cwd(), out)} (${result.length} tokens, Whisper text)`);
  }
  fs.writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
}
console.log(snap ? 'Caption text follows the script; Whisper supplied the timing.' : 'Check the JSON for misheard words and fix the text by hand; keep the times.');
