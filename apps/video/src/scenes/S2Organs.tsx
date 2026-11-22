import {AbsoluteFill, Img, interpolate, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';
import {clamp, enter} from '../anim';
import {Stitch} from '../components/Stitch';
import {mono, sans, spooky} from '../fonts';
import {crewApp} from '../replay';
import {theme} from '../theme';
import {cue, type Extras, type ResolvedScene} from '../timeline';

const CARD = {y: 250, w: 520, h: 390, gap: 116};
const cardX = (i: number) => 64 + i * (CARD.w + CARD.gap);

type Organ = {name: string; color: string; title: string; line1: string; line2: string; at: number};

const OrganCard: React.FC<{organ: Organ; index: number}> = ({organ, index}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, organ.at, fps, 22);
  return (
    <div
      style={{
        position: 'absolute',
        left: cardX(index),
        top: CARD.y,
        width: CARD.w,
        height: CARD.h,
        boxSizing: 'border-box',
        padding: '34px 36px',
        borderRadius: theme.radius,
        background: theme.panel,
        border: `1px solid ${theme.line}`,
        borderTop: `6px solid ${organ.color}`,
        boxShadow: `0 0 60px ${organ.color}22`,
        opacity: p,
        transform: `translateY(${(1 - p) * 60}px)`,
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
      }}
    >
      <div style={{fontFamily: mono, fontSize: 30, color: organ.color, letterSpacing: '0.08em'}}>{organ.name.toUpperCase()}</div>
      <div style={{fontSize: 64, fontWeight: 800, letterSpacing: '-0.02em'}}>{organ.title}</div>
      <div style={{fontSize: 36, fontWeight: 600, lineHeight: 1.2}}>{organ.line1}</div>
      <div style={{fontSize: 32, color: theme.muted, lineHeight: 1.3}}>{organ.line2}</div>
    </div>
  );
};

export const S2Organs: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const sentinelAt = cue(scene, 'sentinel');
  const crewAt = cue(scene, 'crew');
  const humanAt = cue(scene, 'human');
  const linksAt = humanAt + 36;
  const aliveAt = Math.max(scene.speechEnd - 6, linksAt + 20);

  // Logo masuk di tengah lalu naik ke atas sebelum kartu pertama muncul
  const logoIn = enter(frame, 0, fps, 24);
  const move = interpolate(frame, [sentinelAt - 40, sentinelAt - 8], [0, 1], clamp);
  const logoW = interpolate(move, [0, 1], [960, 480]);
  const logoTop = interpolate(move, [0, 1], [540 - (960 * 241) / 720 / 2, 48]);

  const organs: Organ[] = [
    {name: 'Sentinel', color: theme.sentinel, title: 'Reflexes', line1: 'Go daemon, milliseconds', line2: 'One reversible action. No model.', at: sentinelAt},
    {name: 'Kiro Crew', color: theme.crew, title: 'Thinking', line1: `${crewApp.agents.length} agents, minutes`, line2: 'Triage and a plan, through MCP only', at: crewAt},
    {name: 'Human', color: theme.human, title: 'Conscience', line1: 'WhatsApp vote', line2: 'Nothing irreversible without it', at: humanAt},
  ];

  const draw = (at: number) => interpolate(frame, [at, at + 24], [0, 1], clamp);
  const midY = CARD.y + CARD.h / 2;
  const arcY = CARD.y + CARD.h + 90;
  const returnPath = `M${cardX(2) + CARD.w / 2} ${CARD.y + CARD.h} C ${cardX(2) + CARD.w / 2} ${arcY}, ${cardX(0) + CARD.w / 2} ${arcY}, ${cardX(0) + CARD.w / 2} ${CARD.y + CARD.h}`;
  const alive = enter(frame, aliveAt, fps, 20);

  return (
    <AbsoluteFill style={{fontFamily: sans, color: theme.text}}>
      <Img
        src={staticFile('img/logo-lockup.webp')}
        style={{position: 'absolute', left: (1920 - logoW) / 2, top: logoTop, width: logoW, opacity: logoIn}}
      />
      {organs.map((o, i) => (
        <OrganCard key={o.name} organ={o} index={i} />
      ))}
      <svg width={1920} height={1080} style={{position: 'absolute', inset: 0}}>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" fill={theme.text} />
          </marker>
        </defs>
        {[0, 1].map((i) => {
          const x1 = cardX(i) + CARD.w + 8;
          const x2 = cardX(i + 1) - 8;
          return (
            <line
              key={i}
              x1={x1}
              x2={x1 + (x2 - x1) * draw(linksAt + i * 12)}
              y1={midY}
              y2={midY}
              stroke={theme.text}
              strokeWidth={3}
              markerEnd={draw(linksAt + i * 12) > 0.95 ? 'url(#arrow)' : undefined}
            />
          );
        })}
        <path
          d={returnPath}
          fill="none"
          stroke={theme.verify}
          strokeWidth={3}
          pathLength={1}
          strokeDasharray={`${draw(linksAt + 24)} 1`}
          markerEnd={draw(linksAt + 24) > 0.95 ? 'url(#arrow)' : undefined}
        />
      </svg>
      {[
        {text: 'webhook', x: (cardX(0) + CARD.w + cardX(1)) / 2, y: midY - 70, at: linksAt},
        {text: 'poll', x: (cardX(1) + CARD.w + cardX(2)) / 2, y: midY - 70, at: linksAt + 12},
        {text: 'one Ed25519 token per step', x: 960, y: arcY - 4, at: linksAt + 30},
      ].map((l) => (
        <div
          key={l.text}
          style={{
            position: 'absolute',
            left: l.x,
            top: l.y,
            transform: 'translateX(-50%)',
            fontFamily: mono,
            fontSize: 26,
            color: l.text === 'poll' || l.text === 'webhook' ? theme.text : theme.verify,
            whiteSpace: 'nowrap',
            opacity: draw(l.at),
          }}
        >
          {l.text}
        </div>
      ))}
      {frame >= aliveAt ? (
        <div
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            top: 790,
            textAlign: 'center',
            fontFamily: spooky,
            fontSize: 128,
            color: theme.sentinel,
            textShadow: `0 0 36px ${theme.sentinel}88`,
            opacity: alive,
            transform: `scale(${interpolate(alive, [0, 1], [1.3, 1])})`,
          }}
        >
          IT&apos;S ALIVE
        </div>
      ) : null}
      <Stitch at={scene.durationInFrames - 24} y={CARD.y - 40} />
    </AbsoluteFill>
  );
};
