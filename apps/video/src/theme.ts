// Warna diambil dari ui/dist/styles.mjs agar video serasi dengan footage Graveyard
export const theme = {
  bg: '#07080c',
  panel: '#0f121a',
  panel2: '#141927',
  line: 'rgba(255,255,255,.14)',
  lineSoft: 'rgba(255,255,255,.075)',
  text: '#e7e9f0',
  muted: '#8b93a7',
  faint: '#5d6478',
  kernel: '#ffb347',
  sentinel: '#5cffa1',
  crew: '#9b8cff',
  human: '#ff6ad5',
  verify: '#4fd8ff',
  error: '#ff5a6a',
  radius: 18,
  margin: 64,
} as const;

export type Lane = 'kernel' | 'sentinel' | 'crew' | 'human' | 'verify' | 'error';

export const laneColor = (lane: Lane): string => theme[lane];

// Tata letak bersama untuk scene yang memakai footage (S3, S4)
export const footageLayout = {
  x: 64,
  y: 72,
  chromeH: 72,
  videoW: 1376,
  videoH: 774,
  railX: 1480,
  railW: 376,
} as const;
