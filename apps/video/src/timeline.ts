// Menghitung durasi scene dari panjang VO dan frame tiap cue dari caption (atau estimasi dari teks narasi).
// Dipakai oleh calculateMetadata di Root.tsx; scripts/make-srt.mjs membaca hasilnya lewat selectComposition.
import type {Caption} from '@remotion/captions';
import {FPS, VO_LEAD_IN, type SceneDef} from './script';

export type ResolvedScene = SceneDef & {
  startFrame: number; // posisi absolut scene di video
  durationInFrames: number;
  hasVo: boolean;
  speechStart: number; // frame lokal
  speechEnd: number; // frame lokal
  captionTokens: Caption[] | null;
  cueFrames: Record<string, number>;
  cueSource: Record<string, 'captions' | 'estimate'>;
};

export type Extras = {phonePoll: boolean; crewDashboard: boolean};

export type DemoProps = {scenes: ResolvedScene[]; extras: Extras};

const norm = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');

// Estimasi posisi kata berdasarkan offset karakter di narasi; cukup akurat untuk pembacaan dengan tempo rata
const estimateCue = (narration: string, word: string, speechStart: number, speechEnd: number): number | null => {
  const target = norm(word);
  const re = /\S+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(narration)) !== null) {
    if (norm(m[0]).startsWith(target)) {
      return speechStart + Math.round((m.index / narration.length) * (speechEnd - speechStart));
    }
  }
  return null;
};

export const resolveScene = (
  def: SceneDef,
  voFrames: number,
  captionTokens: Caption[] | null,
): Omit<ResolvedScene, 'startFrame'> => {
  const durationInFrames = Math.max(def.budgetFrames, VO_LEAD_IN + voFrames + def.tailFrames);
  const speechStart = VO_LEAD_IN;
  const speechEnd = voFrames > 0 ? VO_LEAD_IN + voFrames : durationInFrames - def.tailFrames;
  const cueFrames: Record<string, number> = {};
  const cueSource: Record<string, 'captions' | 'estimate'> = {};

  for (const [name, word] of Object.entries(def.cues)) {
    const token = captionTokens?.find((t) => norm(t.text).startsWith(norm(word)));
    let frame: number | null;
    if (token) {
      frame = VO_LEAD_IN + Math.round((token.startMs / 1000) * FPS);
      cueSource[name] = 'captions';
    } else {
      frame = estimateCue(def.narration, word, speechStart, speechEnd);
      cueSource[name] = 'estimate';
    }
    if (frame === null) {
      throw new Error(`Cue "${name}" (word "${word}") does not occur in the narration of ${def.id}. Fix src/script.ts.`);
    }
    cueFrames[name] = Math.min(Math.max(frame, 0), durationInFrames - 1);
  }

  return {...def, durationInFrames, hasVo: voFrames > 0, speechStart, speechEnd, captionTokens, cueFrames, cueSource};
};

// Ambil frame cue; gagal keras bila nama cue salah ketik
export const cue = (scene: ResolvedScene, name: string): number => {
  const f = scene.cueFrames[name];
  if (f === undefined) throw new Error(`Unknown cue "${name}" in ${scene.id}`);
  return f;
};
