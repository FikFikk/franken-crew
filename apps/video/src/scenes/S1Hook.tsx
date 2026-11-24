import {AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig} from 'remotion';
import {clamp, enter, fadeIn} from '../anim';
import {Chip} from '../components/Panel';
import {MemoryChart, chartX, chartYPsi, type Point} from '../components/MemoryChart';
import {Stitch} from '../components/Stitch';
import {mono, sans} from '../fonts';
import {heapLeak, node} from '../replay';
import {theme} from '../theme';
import {cue, type Extras, type ResolvedScene} from '../timeline';

const T0 = -119;
const T1 = 0;
const CHART = {x: 64, y: 250, w: 1792, h: 560};

// Jam berjalan dari opened_at + t, tanpa Date agar jelas deterministik
const clock = (openedAt: string, t: number): string => {
  const [hh, mm, ss] = openedAt.slice(11, 19).split(':').map(Number);
  const total = hh * 3600 + mm * 60 + ss + Math.floor(t);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(Math.floor(total / 3600) % 24)}:${p(Math.floor(total / 60) % 60)}:${p(total % 60)}`;
};

const Swatch: React.FC<{color: string}> = ({color}) => (
  <span style={{display: 'inline-block', width: 30, height: 6, borderRadius: 3, background: color, verticalAlign: 'middle', marginRight: 8}} />
);

export const S1Hook: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const twoMin = cue(scene, 'twoMinutes');
  const nobody = cue(scene, 'nobody');
  const service = cue(scene, 'service');
  const revealT = interpolate(frame, [18, twoMin], [T0, T1], clamp);
  const points = heapLeak.series.points as unknown as Point[];
  const psiEvent = heapLeak.events.find((e) => e.kind === 'psi.rising');
  const psiT = psiEvent?.t ?? -15;
  const psiAt = revealT >= psiT;
  const tto = Math.round(heapLeak.tto_seconds);

  return (
    <AbsoluteFill style={{fontFamily: sans, color: theme.text}}>
      <div style={{position: 'absolute', left: 64, top: 56, opacity: fadeIn(frame, 0, 20)}}>
        <div style={{fontFamily: mono, fontSize: 96, fontWeight: 700, letterSpacing: '-0.02em'}}>
          {clock(heapLeak.opened_at, revealT)} <span style={{fontSize: 48, color: theme.muted}}>UTC</span>
        </div>
        <div style={{fontSize: 34, color: theme.muted, marginTop: 6, opacity: fadeIn(frame, service - 6, 14)}}>
          node <span style={{fontFamily: mono, color: theme.text}}>{node}</span> ·{' '}
          <span style={{fontFamily: mono, color: theme.text}}>{heapLeak.unit}</span> is leaking memory
        </div>
      </div>
      <div style={{position: 'absolute', right: 64, top: 72, opacity: fadeIn(frame, 10, 20)}}>
        <Chip color={theme.kernel}>SIMULATION REPLAY DATA</Chip>
      </div>

      <div style={{position: 'absolute', left: CHART.x, top: CHART.y}}>
        <MemoryChart points={points} limitBytes={heapLeak.series.limit_bytes} t0={T0} t1={T1} revealT={revealT} width={CHART.w} height={CHART.h} />
        <div style={{position: 'absolute', right: 110, top: -44, display: 'flex', gap: 28, fontSize: 30, color: theme.muted}}>
          <span><Swatch color={theme.sentinel} /> memory.current</span>
          <span><Swatch color={theme.kernel} /> PSI some avg10</span>
        </div>
        {psiAt ? (
          <div
            style={{
              position: 'absolute',
              left: chartX(psiT, T0, T1, CHART.w) - 420,
              top: chartYPsi(10, CHART.h) - 92,
              opacity: enter(frame, Math.round(interpolate(psiT, [T0, T1], [18, twoMin])), fps, 14),
            }}
          >
            <Chip color={theme.kernel}>{psiEvent?.title ?? 'PSI some avg10 crossed 10%'}</Chip>
          </div>
        ) : null}
        {frame >= twoMin ? (
          <div
            style={{
              position: 'absolute',
              right: 110,
              top: 70,
              transform: `scale(${interpolate(enter(frame, twoMin, fps, 16), [0, 1], [1.2, 1])})`,
              transformOrigin: 'right center',
              opacity: enter(frame, twoMin, fps, 16),
            }}
          >
            <Chip color={theme.error} style={{fontSize: 40, padding: '10px 24px'}}>
              projected time to OOM: {tto} s
            </Chip>
          </div>
        ) : null}
      </div>

      {frame >= nobody ? (
        <div
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            top: 836,
            textAlign: 'center',
            fontSize: 84,
            fontWeight: 800,
            letterSpacing: '-0.02em',
            opacity: enter(frame, nobody, fps, 18),
            transform: `translateY(${(1 - enter(frame, nobody, fps, 18)) * 20}px)`,
          }}
        >
          Nobody is on call.
        </div>
      ) : null}
      <Stitch at={scene.durationInFrames - 24} />
    </AbsoluteFill>
  );
};
