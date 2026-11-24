import {interpolate, useCurrentFrame, useVideoConfig} from 'remotion';
import {clamp, enter} from '../anim';
import {sans} from '../fonts';
import {footageLayout as L, laneColor, theme, type Lane} from '../theme';
import {Check} from './Glyphs';

export type Step = {lane: Lane; title: React.ReactNode; sub: React.ReactNode; at: number};

// Daftar langkah di kanan footage: redup sebelum cue, menyala saat cue, diberi centang setelah langkah berikutnya
export const StepRail: React.FC<{steps: Step[]; enterAt?: number}> = ({steps, enterAt = 0}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  return (
    <div
      style={{
        position: 'absolute',
        left: L.railX,
        top: L.y,
        width: L.railW,
        height: L.chromeH + L.videoH,
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
        fontFamily: sans,
      }}
    >
      {steps.map((s, i) => {
        const next = steps[i + 1];
        const active = frame >= s.at;
        const done = active && next !== undefined && frame >= next.at;
        const color = laneColor(s.lane);
        const lit = enter(frame, s.at, fps, 18);
        const slide = enter(frame, enterAt + i * 6, fps);
        const glow = interpolate(lit, [0, 1], [0, 1], clamp) * (done ? 0.25 : 1);
        return (
          <div
            key={i}
            style={{
              flex: 1,
              display: 'flex',
              gap: 18,
              alignItems: 'center',
              padding: '0 20px',
              borderRadius: 16,
              background: theme.panel,
              border: `1.5px solid ${active ? color : theme.lineSoft}`,
              boxShadow: active ? `0 0 ${28 * glow}px ${color}55` : undefined,
              opacity: (active ? 1 : 0.38) * slide,
              transform: `translateX(${(1 - slide) * 40}px)`,
            }}
          >
            <div
              style={{
                width: 48,
                height: 48,
                flex: 'none',
                borderRadius: 48,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: active ? color : 'transparent',
                border: `2px solid ${active ? color : theme.faint}`,
                color: theme.bg,
                fontSize: 26,
                fontWeight: 800,
              }}
            >
              {done ? <Check size={28} color={theme.bg} /> : <span style={{color: active ? theme.bg : theme.faint}}>{i + 1}</span>}
            </div>
            <div style={{display: 'flex', flexDirection: 'column', gap: 4}}>
              <div style={{fontSize: 32, fontWeight: 700, lineHeight: 1.15, color: active ? theme.text : theme.muted}}>{s.title}</div>
              <div style={{fontSize: 28, lineHeight: 1.2, color: active ? color : theme.faint}}>{s.sub}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
