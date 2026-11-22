import {AbsoluteFill, interpolate, useCurrentFrame} from 'remotion';
import {clamp} from '../anim';
import {theme} from '../theme';

// Motif Frankenstein: jahitan neon yang tergambar dari kiri ke kanan mulai frame `at`
export const Stitch: React.FC<{at: number; y?: number; duration?: number}> = ({at, y = 540, duration = 14}) => {
  const frame = useCurrentFrame();
  const progress = interpolate(frame, [at, at + duration], [0, 1], clamp);
  if (progress <= 0) return null;
  const width = 1920;
  const stitches = [];
  for (let x = 24; x < width; x += 48) {
    stitches.push(<path key={x} d={`M${x - 10} ${y - 14} L${x + 10} ${y + 14}`} />);
  }
  return (
    <AbsoluteFill style={{pointerEvents: 'none'}}>
      <svg width={width} height={1080} style={{position: 'absolute', inset: 0}}>
        <defs>
          <clipPath id={`stitch-${at}`}>
            <rect x={0} y={0} width={width * progress} height={1080} />
          </clipPath>
          <filter id={`glow-${at}`} x="-10%" y="-200%" width="120%" height="500%">
            <feGaussianBlur stdDeviation="5" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <g clipPath={`url(#stitch-${at})`} filter={`url(#glow-${at})`} stroke={theme.sentinel} strokeLinecap="round">
          <path d={`M0 ${y} L${width} ${y}`} strokeWidth={3} strokeDasharray="30 18" />
          <g strokeWidth={4}>{stitches}</g>
        </g>
      </svg>
    </AbsoluteFill>
  );
};
