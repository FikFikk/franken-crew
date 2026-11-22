import {interpolate, useCurrentFrame, useVideoConfig} from 'remotion';
import {clamp, enter} from '../anim';
import {mono, sans} from '../fonts';
import {theme} from '../theme';

// Cap merah "ditolak" yang mendarat dengan pegas pada frame `at`
export const Stamp: React.FC<{at: number; title: string; detail: React.ReactNode; time: string; tilt?: number}> = ({
  at,
  title,
  detail,
  time,
  tilt = -3,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, at, fps, 16);
  if (frame < at) return <div style={{flex: 1}} />;
  const scale = interpolate(p, [0, 1], [1.35, 1], clamp);
  return (
    <div style={{flex: 1, display: 'flex', alignItems: 'center'}}>
      <div
        style={{
          width: '100%',
          boxSizing: 'border-box',
          padding: '18px 22px',
          border: `4px solid ${theme.error}`,
          borderRadius: 14,
          background: 'rgba(255,90,106,.08)',
          transform: `rotate(${tilt}deg) scale(${scale})`,
          opacity: p,
          fontFamily: sans,
        }}
      >
        <div style={{fontSize: 40, fontWeight: 800, color: theme.error, letterSpacing: '0.03em', whiteSpace: 'nowrap'}}>{title}</div>
        <div style={{fontSize: 30, lineHeight: 1.25, color: theme.text, marginTop: 6}}>
          <span style={{fontFamily: mono, color: theme.muted}}>{time}</span> · {detail}
        </div>
      </div>
    </div>
  );
};
