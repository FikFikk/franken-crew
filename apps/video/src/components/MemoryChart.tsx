import {mono} from '../fonts';
import {mib} from '../anim';
import {tLabel} from '../replay';
import {theme} from '../theme';

export type Point = readonly [number, number, number, number]; // [t detik, byte memori, PSI some, PSI full]

const PAD = {left: 170, right: 110, top: 30, bottom: 64};

// Grafik memory.current dan PSI some dari replay.json, terungkap sampai waktu `revealT`
export const MemoryChart: React.FC<{
  points: readonly Point[];
  limitBytes: number;
  t0: number;
  t1: number;
  revealT: number;
  width: number;
  height: number;
  psiMax?: number;
}> = ({points, limitBytes, t0, t1, revealT, width, height, psiMax = 20}) => {
  const w = width - PAD.left - PAD.right;
  const h = height - PAD.top - PAD.bottom;
  const x = (t: number) => PAD.left + ((t - t0) / (t1 - t0)) * w;
  const yMem = (b: number) => PAD.top + h - (b / limitBytes) * h;
  const yPsi = (p: number) => PAD.top + h - (p / psiMax) * h;

  const shown = points.filter((p) => p[0] >= t0 && p[0] <= revealT);
  const memLine = shown.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p[0]).toFixed(1)} ${yMem(p[1]).toFixed(1)}`).join(' ');
  const psiLine = shown.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p[0]).toFixed(1)} ${yPsi(p[2]).toFixed(1)}`).join(' ');
  const last = shown.at(-1);
  const area = last ? `${memLine} L${x(last[0]).toFixed(1)} ${PAD.top + h} L${x(shown[0][0]).toFixed(1)} ${PAD.top + h} Z` : '';
  const ticks = [0, 128, 256, 384, 512].filter((m) => m * 1024 * 1024 <= limitBytes);

  return (
    <svg width={width} height={height} style={{overflow: 'visible', fontFamily: mono}}>
      <defs>
        <linearGradient id="mem-fill" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stopColor={theme.sentinel} stopOpacity={0.28} />
          <stop offset="1" stopColor={theme.sentinel} stopOpacity={0.02} />
        </linearGradient>
      </defs>
      {ticks.map((m) => (
        <g key={m}>
          <line x1={PAD.left} x2={PAD.left + w} y1={yMem(m * 1048576)} y2={yMem(m * 1048576)} stroke={theme.lineSoft} />
          <text x={PAD.left - 18} y={yMem(m * 1048576) + 10} textAnchor="end" fontSize={30} fill={theme.muted}>
            {m} MiB
          </text>
        </g>
      ))}
      {[10, 20].map((p) => (
        <text key={p} x={PAD.left + w + 18} y={yPsi(p) + 10} fontSize={30} fill={theme.kernel} opacity={0.8}>
          {p}%
        </text>
      ))}
      <line
        x1={PAD.left}
        x2={PAD.left + w}
        y1={yPsi(10)}
        y2={yPsi(10)}
        stroke={theme.kernel}
        strokeOpacity={0.35}
        strokeDasharray="4 10"
        strokeWidth={2}
      />
      <line
        x1={PAD.left}
        x2={PAD.left + w}
        y1={yMem(limitBytes)}
        y2={yMem(limitBytes)}
        stroke={theme.error}
        strokeDasharray="14 10"
        strokeWidth={3}
      />
      <text x={PAD.left + 12} y={yMem(limitBytes) - 16} fontSize={30} fill={theme.error}>
        memory.max {Math.round(mib(limitBytes))} MiB
      </text>
      {[t0, (t0 + t1) / 2, t1].map((t) => (
        <text key={t} x={x(t)} y={PAD.top + h + 48} textAnchor="middle" fontSize={30} fill={theme.faint}>
          {tLabel(Math.round(t))}
        </text>
      ))}
      {area ? <path d={area} fill="url(#mem-fill)" /> : null}
      {psiLine ? <path d={psiLine} fill="none" stroke={theme.kernel} strokeWidth={4} strokeLinejoin="round" /> : null}
      {memLine ? <path d={memLine} fill="none" stroke={theme.sentinel} strokeWidth={6} strokeLinejoin="round" /> : null}
      {last ? (
        <>
          <circle cx={x(last[0])} cy={yMem(last[1])} r={11} fill={theme.sentinel} />
          <circle cx={x(last[0])} cy={yPsi(last[2])} r={8} fill={theme.kernel} />
        </>
      ) : null}
    </svg>
  );
};

export const chartX = (t: number, t0: number, t1: number, width: number): number =>
  PAD.left + ((t - t0) / (t1 - t0)) * (width - PAD.left - PAD.right);

export const chartYPsi = (p: number, height: number, psiMax = 20): number =>
  PAD.top + (height - PAD.top - PAD.bottom) * (1 - p / psiMax);
