// Helper bersama untuk skrip VO dan caption: teks narasi per scene dan nama file VO.
// Narasi dibaca dari src/data/repo.ts (hasil `npm run data` dari docs/DEMO_VIDEO_SCRIPT.md),
// nama file dari src/script.ts, supaya tidak ada daftar kedua yang bisa berbeda.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const project = path.resolve(here, '..');

export const readNarration = () => {
  const src = fs.readFileSync(path.join(project, 'src/data/repo.ts'), 'utf8');
  // repo.ts berisi `export const repo = <JSON> as const;`
  const repo = JSON.parse(src.slice(src.indexOf('{'), src.lastIndexOf('}') + 1));
  return repo.narration;
};

// ['01-hook', '02-organs', ...] dalam urutan scene
export const voNames = () => {
  const src = fs.readFileSync(path.join(project, 'src/script.ts'), 'utf8');
  return [...src.matchAll(/vo: 'vo\/([\w-]+)\.wav'/g)].map((m) => m[1]);
};

export const narrationByName = () => {
  const narration = readNarration();
  const names = voNames();
  if (names.length !== narration.length) {
    throw new Error(`src/script.ts lists ${names.length} voiceover files but the narration has ${narration.length} rows`);
  }
  return Object.fromEntries(names.map((n, i) => [n, narration[i]]));
};
