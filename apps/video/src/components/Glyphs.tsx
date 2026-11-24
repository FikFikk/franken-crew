// Panah dan centang digambar sebagai SVG karena subset latin Google Fonts tidak memuat glyph-nya
export const Arrow: React.FC<{size?: number; color?: string}> = ({size = 28, color = 'currentColor'}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" style={{display: 'inline-block', verticalAlign: '-0.12em', margin: '0 0.2em'}}>
    <path d="M3 12h16M13 6l6 6-6 6" stroke={color} strokeWidth={2.4} fill="none" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Check: React.FC<{size?: number; color?: string}> = ({size = 28, color = 'currentColor'}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" style={{display: 'inline-block'}}>
    <path d="M4 12.5l5 5L20 6.5" stroke={color} strokeWidth={3} fill="none" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Dot: React.FC<{size?: number; color: string; glow?: number}> = ({size = 18, color, glow = 0}) => (
  <span
    style={{
      display: 'inline-block',
      width: size,
      height: size,
      borderRadius: size,
      background: color,
      boxShadow: glow > 0 ? `0 0 ${glow}px ${color}` : undefined,
      flex: 'none',
    }}
  />
);

const GreaterEqual: React.FC<{size?: number}> = ({size = 26}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" style={{display: 'inline-block', verticalAlign: '-0.12em', margin: '0 0.15em'}}>
    <path d="M6 5l12 6-12 6M6 21h12" stroke="currentColor" strokeWidth={2.4} fill="none" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

// Teks dengan → dan ≥ dirender sebagai SVG, karena glyph itu tidak ada di subset font yang dimuat
export const Glyphed: React.FC<{text: string; size?: number}> = ({text, size = 28}) => (
  <>
    {text.split(/([\u2192\u2265])/).map((part, i) =>
      part === '\u2192' ? <Arrow key={i} size={size} /> : part === '\u2265' ? <GreaterEqual key={i} size={size} /> : <span key={i}>{part}</span>,
    )}
  </>
);
