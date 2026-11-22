import {AbsoluteFill, Sequence, staticFile, useVideoConfig} from 'remotion';
import {Video} from '@remotion/media';
import {mono} from '../fonts';
import {footageLayout as L, theme} from '../theme';

export const FOOTAGE = 'footage/graveyard-replay-broll.webm';

export type Anchor = {frame: number; src: number}; // frame lokal scene -> detik di file sumber

// Jaga anchor tetap naik agar tidak ada segmen dengan durasi atau laju nol/negatif
const monotonic = (anchors: Anchor[]): Anchor[] => {
  const out: Anchor[] = [];
  for (const a of anchors) {
    const prev = out.at(-1);
    if (!prev) {
      out.push(a);
      continue;
    }
    out.push({frame: Math.max(a.frame, prev.frame + 6), src: Math.max(a.src, prev.src + 0.05)});
  }
  return out;
};

// Footage diputar per segmen dengan laju berbeda, sehingga momen tertentu di sumber jatuh tepat di frame cue
export const WarpedVideo: React.FC<{src?: string; anchors: Anchor[]}> = ({src = FOOTAGE, anchors}) => {
  const {fps} = useVideoConfig();
  const a = monotonic(anchors);
  return (
    <>
      {a.slice(0, -1).map((start, i) => {
        const end = a[i + 1];
        const duration = end.frame - start.frame;
        const rate = ((end.src - start.src) * fps) / duration;
        return (
          <Sequence key={start.frame} from={start.frame} durationInFrames={duration} premountFor={30} name={`footage ${start.src}s`}>
            <Video
              src={staticFile(src)}
              trimBefore={Math.round(start.src * fps)}
              playbackRate={rate}
              muted
              objectFit="cover"
              style={{width: '100%', height: '100%'}}
            />
          </Sequence>
        );
      })}
    </>
  );
};

// Bingkai browser untuk footage Graveyard, dengan label simulasi yang selalu tampil
export const FootageFrame: React.FC<{children: React.ReactNode; label?: string}> = ({
  children,
  label = 'real engine',
}) => (
  <div
    style={{
      position: 'absolute',
      left: L.x,
      top: L.y,
      width: L.videoW,
      height: L.chromeH + L.videoH,
      borderRadius: theme.radius,
      overflow: 'hidden',
      border: `1px solid ${theme.line}`,
      background: theme.panel,
      boxShadow: '0 30px 80px rgba(0,0,0,.55)',
    }}
  >
    <div
      style={{
        height: L.chromeH,
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        padding: '0 24px',
        background: theme.panel2,
        borderBottom: `1px solid ${theme.lineSoft}`,
        fontFamily: mono,
        fontSize: 30,
        color: theme.muted,
      }}
    >
      {[theme.error, theme.kernel, theme.sentinel].map((c) => (
        <span key={c} style={{width: 16, height: 16, borderRadius: 16, background: c, opacity: 0.7}} />
      ))}
      <span style={{marginLeft: 16, color: theme.text}}>frankencrew.fikfikk.my.id</span>
      <span style={{flex: 1}} />
      <span
        style={{
          padding: '4px 14px',
          borderRadius: 999,
          border: `1.5px solid ${theme.kernel}`,
          color: theme.kernel,
          fontWeight: 700,
          letterSpacing: '0.06em',
        }}
      >
        SIMULATION REPLAY
      </span>
      <span>{label}</span>
    </div>
    <div style={{position: 'relative', width: L.videoW, height: L.videoH, overflow: 'hidden'}}>
      <AbsoluteFill>{children}</AbsoluteFill>
    </div>
  </div>
);
