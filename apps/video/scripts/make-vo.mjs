#!/usr/bin/env node
// Menyintesis voiceover per scene ke public/vo/<scene>.wav dengan Kokoro-82M (Apache-2.0), lokal di CPU.
// Jalankan: `npm run vo` (semua scene) atau `npm run vo -- 03-heap-leak` (satu scene).
// kokoro-js tidak ada di package.json (sekitar 350 MB, dan onnxruntime-node gagal dipasang di Linux tanpa
// melewati CUDA). Pasang hanya saat perlu: ONNXRUNTIME_NODE_INSTALL_CUDA=skip npm install --no-save kokoro-js@1.2.1
// Unduhan pertama: model ONNX sekitar 310 MB dari Hugging Face, disimpan di cache transformers.js.
// Env: KOKORO_VOICE (bawaan af_heart), KOKORO_SPEED (bawaan 0.95), KOKORO_GAP_MS jeda antar kalimat (bawaan 350).
import fs from 'node:fs';
import path from 'node:path';
import {narrationByName, project} from './narration.mjs';

const {KokoroTTS} = await import('kokoro-js').catch(() => {
  console.error('kokoro-js is not installed. Run once, from apps/video:');
  console.error('  ONNXRUNTIME_NODE_INSTALL_CUDA=skip npm install --no-save kokoro-js@1.2.1');
  process.exit(1);
});

const MODEL = 'onnx-community/Kokoro-82M-v1.0-ONNX';
const voice = process.env.KOKORO_VOICE ?? 'af_heart';
const speed = Number(process.env.KOKORO_SPEED ?? 0.95);
const gapMs = Number(process.env.KOKORO_GAP_MS ?? 350);
const outDir = path.join(project, 'public/vo');

// Ejaan untuk pengucapan saja; teks narasi dan caption tetap memakai ejaan asli.
// Diperiksa dengan fonemizer espeak bawaan kokoro-js: "Kiro" terbaca "KY-roh", "nonce" terbaca "non-see".
const LEXICON = [
  [/\bKiro\b/g, 'Keyro'],
  [/\bnonce\b/g, 'nonss'],
  [/\bOOM\b/g, 'O O M'],
];

const spoken = (text) => LEXICON.reduce((t, [re, to]) => t.replace(re, to), text);
const sentences = (text) => text.split(/(?<=[.?!]["”]?)\s+(?=["“A-Z0-9])/).filter((s) => s.trim());

// Buang hening di awal/akhir potongan, sisakan 40 ms agar konsonan tidak terpotong
const trim = (samples, rate) => {
  const threshold = 0.008;
  let a = 0;
  let b = samples.length - 1;
  while (a < b && Math.abs(samples[a]) < threshold) a++;
  while (b > a && Math.abs(samples[b]) < threshold) b--;
  const pad = Math.round(rate * 0.04);
  return samples.subarray(Math.max(0, a - pad), Math.min(samples.length, b + pad));
};

const level = (samples) => {
  let peak = 0;
  let sum = 0;
  for (const s of samples) {
    peak = Math.max(peak, Math.abs(s));
    sum += s * s;
  }
  return {rms: Math.sqrt(sum / samples.length), peak};
};
const db = (x) => 20 * Math.log10(x);

// Semua scene ke RMS yang sama, lalu limiter lookahead 5 ms, supaya kerasnya suara sama antar scene.
// Remotion menggandakan VO mono ke stereo dan encoder AAC menambah overshoot: -19 dBFS RMS dengan plafon
// -4.5 dBFS menghasilkan sekitar -16 LUFS dan true peak di bawah -1 dBTP di MP4 akhir.
const RMS_DB = -19;
const CEILING_DB = -4.5;
const normalize = (samples, rate) => {
  const gain = 10 ** (RMS_DB / 20) / level(samples).rms;
  for (let i = 0; i < samples.length; i++) samples[i] *= gain;
  const ceiling = 10 ** (CEILING_DB / 20);
  const look = Math.round(rate * 0.005);
  const release = 1 - Math.exp(-1 / (rate * 0.08));
  const need = new Float32Array(samples.length);
  for (let i = 0; i < samples.length; i++) need[i] = Math.min(1, ceiling / Math.max(Math.abs(samples[i]), 1e-9));
  let g = 1;
  for (let i = 0; i < samples.length; i++) {
    let target = 1;
    for (let j = i, end = Math.min(samples.length, i + look); j < end; j++) target = Math.min(target, need[j]);
    g = target < g ? target : g + (target - g) * release;
    samples[i] *= g;
  }
  const out = level(samples);
  return {rmsDb: db(out.rms), peakDb: db(out.peak)};
};

// WAV PCM 16-bit mono
const writeWav = (file, samples, rate) => {
  const data = Buffer.alloc(samples.length * 2);
  for (let i = 0; i < samples.length; i++) {
    data.writeInt16LE(Math.round(Math.max(-1, Math.min(1, samples[i])) * 32767), i * 2);
  }
  const header = Buffer.alloc(44);
  header.write('RIFF', 0);
  header.writeUInt32LE(36 + data.length, 4);
  header.write('WAVEfmt ', 8);
  header.writeUInt32LE(16, 16);
  header.writeUInt16LE(1, 20);
  header.writeUInt16LE(1, 22);
  header.writeUInt32LE(rate, 24);
  header.writeUInt32LE(rate * 2, 28);
  header.writeUInt16LE(2, 32);
  header.writeUInt16LE(16, 34);
  header.write('data', 36);
  header.writeUInt32LE(data.length, 40);
  fs.writeFileSync(file, Buffer.concat([header, data]));
};

const scenes = narrationByName();
const only = process.argv[2];
const names = Object.keys(scenes).filter((n) => !only || n.startsWith(only));
if (names.length === 0) {
  console.error(`No scene matches "${only}". Scenes: ${Object.keys(scenes).join(', ')}`);
  process.exit(1);
}

const tts = await KokoroTTS.from_pretrained(MODEL, {dtype: 'fp32', device: 'cpu'});
if (!(voice in tts.voices)) {
  console.error(`Unknown voice ${voice}. English voices: ${Object.keys(tts.voices).filter((v) => /^[ab][fm]_/.test(v)).join(' ')}`);
  process.exit(1);
}
fs.mkdirSync(outDir, {recursive: true});

let total = 0;
for (const name of names) {
  const chunks = [];
  let rate = 24000;
  // Satu kalimat per panggilan: Kokoro memotong input di atas 510 token fonem
  for (const sentence of sentences(spoken(scenes[name]))) {
    const audio = await tts.generate(sentence, {voice, speed});
    rate = audio.sampling_rate;
    chunks.push(trim(audio.audio, rate));
  }
  const gap = Math.round((rate * gapMs) / 1000);
  const length = chunks.reduce((n, c) => n + c.length, 0) + gap * (chunks.length - 1);
  const samples = new Float32Array(length);
  let at = 0;
  for (const c of chunks) {
    samples.set(c, at);
    at += c.length + gap;
  }
  const lv = normalize(samples, rate);
  const file = path.join(outDir, `${name}.wav`);
  writeWav(file, samples, rate);
  const secs = samples.length / rate;
  total += secs;
  const words = scenes[name].split(/\s+/).length;
  console.log(
    `wrote ${path.relative(process.cwd(), file)}: ${secs.toFixed(1)} s, ${chunks.length} sentences, ` +
      `${Math.round((words / secs) * 60)} wpm, RMS ${lv.rmsDb.toFixed(1)} dBFS, peak ${lv.peakDb.toFixed(1)} dBFS`,
  );
}
console.log(`${total.toFixed(1)} s of speech with voice ${voice} at speed ${speed}. Next: npm run captions`);
