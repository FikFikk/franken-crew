// Satu sumber kebenaran untuk urutan scene, anggaran frame, file VO, dan kata pemicu animasi.
// Teks narasi berasal dari docs/DEMO_VIDEO_SCRIPT.md lewat src/data/repo.ts (npm run data).
import {repo} from './data/repo';

export type SceneId = 'S1' | 'S2' | 'S3' | 'S4' | 'S5' | 'S6' | 'S7';

export type SceneDef = {
  id: SceneId;
  title: string;
  budgetFrames: number; // durasi minimum dari DEMO_VIDEO_SCRIPT.md
  tailFrames: number; // jeda setelah VO selesai sebelum scene berganti
  vo: string; // relatif ke public/
  captions: string; // relatif ke public/
  narration: string;
  // nama cue -> kata (awalan) di narasi yang memicu animasi
  cues: Record<string, string>;
};

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;
export const TARGET_FRAMES = 5100; // 2:50
export const MAX_FRAMES = 5250; // 2:55; juri tidak wajib menonton lewat 3:00
export const VO_LEAD_IN = 6; // VO mulai 6 frame setelah scene dimulai

const n = repo.narration;

export const SCENES: SceneDef[] = [
  {
    id: 'S1', title: 'Hook', budgetFrames: 420, tailFrames: 24,
    vo: 'vo/01-hook.wav', captions: 'captions/01-hook.json', narration: n[0],
    cues: {service: 'service', twoMinutes: 'two', nobody: 'nobody'},
  },
  {
    id: 'S2', title: 'Three organs', budgetFrames: 540, tailFrames: 60,
    vo: 'vo/02-organs.wav', captions: 'captions/02-organs.json', narration: n[1],
    cues: {sentinel: 'Go', crew: 'Kiro', human: 'WhatsApp'},
  },
  {
    id: 'S3', title: 'Heap leak', budgetFrames: 1380, tailFrames: 18,
    vo: 'vo/03-heap-leak.wav', captions: 'captions/03-heap-leak.json', narration: n[2],
    cues: {
      psi: 'Pressure', opened: 'incident', reflex: 'reflex', crew: 'Crew',
      poll: 'poll', votes: 'votes', reload: 'reload', watches: 'watches',
    },
  },
  {
    id: 'S4', title: 'Prompt injection', budgetFrames: 840, tailFrames: 36,
    vo: 'vo/04-injection.wav', captions: 'captions/04-injection.json', narration: n[3],
    cues: {log: 'log', rejects: 'rejects', blocked: 'blocked', refused: 'refused'},
  },
  {
    id: 'S5', title: 'Built with Kiro', budgetFrames: 1080, tailFrames: 18,
    vo: 'vo/05-kiro.wav', captions: 'captions/05-kiro.json', narration: n[4],
    cues: {
      twelve: 'Twelve', four: 'four', tasks: 'tasks', properties: 'Each',
      steering: 'Steering', hook: 'pre', guard: 'guard', web: 'audit',
    },
  },
  {
    id: 'S6', title: 'Crew app and chaos', budgetFrames: 480, tailFrames: 30,
    vo: 'vo/06-crew.wav', captions: 'captions/06-crew.json', narration: n[5],
    cues: {agents: 'four', crons: 'crons', servers: 'MCP', page: 'Graveyard', chaos: 'Twenty', passes: 'passes'},
  },
  {
    id: 'S7', title: 'Outro', budgetFrames: 360, tailFrames: 90,
    vo: 'vo/07-outro.wav', captions: 'captions/07-outro.json', narration: n[6],
    cues: {go: 'Reflexes', kiro: 'thinking', human: 'human', url: 'Replays'},
  },
];
