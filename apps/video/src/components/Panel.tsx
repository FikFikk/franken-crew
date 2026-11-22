import {mono, sans} from '../fonts';
import {theme} from '../theme';

// Panel standar: latar panel, garis 1 px, radius 18, judul opsional berupa path file (mono)
export const Panel: React.FC<{
  x: number;
  y: number;
  w: number;
  h: number;
  title?: string;
  right?: React.ReactNode;
  accent?: string;
  style?: React.CSSProperties;
  bodyStyle?: React.CSSProperties;
  children?: React.ReactNode;
}> = ({x, y, w, h, title, right, accent, style, bodyStyle, children}) => (
  <div
    style={{
      position: 'absolute',
      left: x,
      top: y,
      width: w,
      height: h,
      boxSizing: 'border-box',
      background: theme.panel,
      border: `1px solid ${accent ?? theme.line}`,
      borderRadius: theme.radius,
      overflow: 'hidden',
      display: 'flex',
      flexDirection: 'column',
      fontFamily: sans,
      color: theme.text,
      ...style,
    }}
  >
    {title ? (
      <div
        style={{
          height: 72,
          flex: 'none',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 28px',
          borderBottom: `1px solid ${theme.lineSoft}`,
          background: theme.panel2,
          fontFamily: mono,
          fontSize: 30,
          color: theme.muted,
          gap: 24,
        }}
      >
        <span style={{whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}}>{title}</span>
        {right}
      </div>
    ) : null}
    <div style={{position: 'relative', flex: 1, ...bodyStyle}}>{children}</div>
  </div>
);

export const Chip: React.FC<{color: string; children: React.ReactNode; style?: React.CSSProperties}> = ({
  color,
  children,
  style,
}) => (
  <span
    style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 10,
      padding: '6px 16px',
      borderRadius: 999,
      border: `1.5px solid ${color}`,
      color,
      background: 'rgba(7,8,12,.72)',
      fontFamily: mono,
      fontSize: 30,
      fontWeight: 600,
      whiteSpace: 'nowrap',
      ...style,
    }}
  >
    {children}
  </span>
);
