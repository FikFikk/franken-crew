// Helper animasi; semua berbasis frame agar render deterministik
import {interpolate, spring} from 'remotion';

export const clamp = {extrapolateLeft: 'clamp', extrapolateRight: 'clamp'} as const;

// Pegas 0..1 yang mulai di frame `at`; bernilai 0 sebelum `at`
export const enter = (frame: number, at: number, fps: number, durationInFrames = 24): number =>
  frame < at ? 0 : spring({frame: frame - at, fps, config: {damping: 200}, durationInFrames});

// Fade linear 0..1 dari `at` selama `dur` frame
export const fadeIn = (frame: number, at: number, dur = 12): number => interpolate(frame, [at, at + dur], [0, 1], clamp);

// Fade linear 1..0 yang selesai tepat di `end`
export const fadeOut = (frame: number, end: number, dur = 12): number =>
  interpolate(frame, [end - dur, end], [1, 0], clamp);

// Jumlah karakter yang sudah "diketik" pada frame ini
export const typed = (frame: number, at: number, dur: number, length: number): number =>
  Math.floor(interpolate(frame, [at, at + dur], [0, length], clamp));

export const mib = (bytes: number): number => bytes / (1024 * 1024);
