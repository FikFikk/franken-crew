import {interpolate, useCurrentFrame, useVideoConfig} from 'remotion';
import {clamp, enter} from '../anim';
import {mono, sans} from '../fonts';
import {theme} from '../theme';

// Bentuk pesan dan poll mengikuti ui/data/replay.json (format pesan wa-bridge)
export type ChatMessage = {t: number; from: string; kind: string; text: string};
export type Poll = {title: string; options: readonly string[]; chosen: number; approver: string};

// Hilangkan markup WhatsApp (*tebal* dan `kode`) dan hash plan di akhir opsi poll
const plain = (s: string) => s.replace(/[*`]/g, '');
const withoutHash = (s: string) => s.replace(/\s*\[[0-9a-f]{8}\]$/, '');

const Bubble: React.FC<{at: number; mine?: boolean; label: string; labelColor: string; children: React.ReactNode}> = ({
  at,
  mine,
  label,
  labelColor,
  children,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, at, fps, 18);
  if (frame < at) return null;
  return (
    <div
      style={{
        alignSelf: mine ? 'flex-end' : 'flex-start',
        flex: 'none',
        maxWidth: '88%',
        padding: '12px 18px',
        borderRadius: 18,
        background: mine ? 'linear-gradient(135deg, #3a1d3a, #2a1838)' : theme.panel2,
        border: `1px solid ${mine ? 'rgba(255,106,213,.35)' : theme.lineSoft}`,
        opacity: p,
        transform: `translateY(${(1 - p) * 24}px)`,
      }}
    >
      <div style={{fontSize: 26, fontWeight: 700, color: labelColor, marginBottom: 4}}>{label}</div>
      <div style={{fontSize: 30, lineHeight: 1.3, color: theme.text}}>{children}</div>
    </div>
  );
};

export const PhoneChat: React.FC<{
  x: number;
  y: number;
  w: number;
  h: number;
  messages: readonly ChatMessage[];
  poll: Poll;
  planHash: string;
  enterAt: number;
  exitAt: number;
  alertAt: number;
  pollAt: number;
  voteAt: number;
  tokenAt: number;
}> = ({x, y, w, h, messages, poll, planHash, enterAt, exitAt, alertAt, pollAt, voteAt, tokenAt}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const inP = enter(frame, enterAt, fps, 22);
  const outP = interpolate(frame, [exitAt, exitAt + 14], [1, 0], clamp);
  if (frame < enterAt || frame > exitAt + 14) return null;

  const alert = messages.find((m) => m.kind === 'alert');
  const vote = messages.find((m) => m.kind === 'vote');
  const approval = messages.find((m) => m.from === 'bot' && /step token/.test(m.text));
  const tokens = approval?.text.match(/(\d+) single-use Ed25519 step token/)?.[1] ?? '1';
  const voted = frame >= voteAt;
  const barP = interpolate(frame, [voteAt, voteAt + 20], [0, 1], clamp);

  return (
    <div
      style={{
        position: 'absolute',
        left: x,
        top: y,
        width: w,
        height: h,
        boxSizing: 'border-box',
        borderRadius: 44,
        border: `3px solid ${theme.line}`,
        background: theme.bg,
        boxShadow: '0 30px 90px rgba(0,0,0,.7)',
        overflow: 'hidden',
        fontFamily: sans,
        opacity: inP * outP,
        transform: `translateY(${(1 - inP) * 60}px)`,
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <div style={{display: 'flex', alignItems: 'center', gap: 16, padding: '22px 24px', background: theme.panel, borderBottom: `1px solid ${theme.lineSoft}`}}>
        <div
          style={{
            width: 56,
            height: 56,
            borderRadius: 56,
            background: `linear-gradient(135deg, ${theme.sentinel}, ${theme.verify})`,
            color: theme.bg,
            fontWeight: 800,
            fontSize: 24,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          FC
        </div>
        <div>
          <div style={{fontSize: 32, fontWeight: 700}}>FrankenCrew Ops</div>
          <div style={{fontSize: 26, color: theme.muted}}>allowlisted admins only</div>
        </div>
      </div>
      <div style={{flex: 1, minHeight: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', gap: 14, padding: 18, justifyContent: 'flex-end'}}>
        {alert ? (
          <Bubble at={alertAt} label="FrankenCrew bot" labelColor={theme.sentinel}>
            {plain(alert.text.split('\n')[0])}
          </Bubble>
        ) : null}
        <Bubble at={pollAt} label={`POLL · plan ${planHash.slice(0, 8)}`} labelColor={theme.human}>
          <div style={{display: 'flex', flexDirection: 'column', gap: 10, marginTop: 4}}>
            {poll.options.map((o, i) => {
              const chosen = voted && i === poll.chosen;
              return (
                <div key={o} style={{flex: 'none'}}>
                  <div style={{display: 'flex', justifyContent: 'space-between', gap: 12, fontSize: 30, color: chosen ? theme.text : theme.muted}}>
                    <span>{withoutHash(o)}</span>
                    <span style={{fontFamily: mono, color: chosen ? theme.human : theme.faint}}>{chosen ? 1 : 0}</span>
                  </div>
                  <div style={{height: 6, borderRadius: 6, background: theme.lineSoft, marginTop: 6}}>
                    <div style={{height: 6, borderRadius: 6, width: `${(chosen ? barP : 0) * 100}%`, background: theme.human}} />
                  </div>
                </div>
              );
            })}
          </div>
        </Bubble>
        {vote ? (
          <Bubble at={voteAt} mine label="Operator · admin" labelColor={theme.human}>
            Voted {withoutHash(vote.text)}
          </Bubble>
        ) : null}
        {frame >= tokenAt ? (
          <div
            style={{
              alignSelf: 'center',
              flex: 'none',
              padding: '8px 18px',
              borderRadius: 999,
              border: `1.5px solid ${theme.verify}`,
              color: theme.verify,
              fontFamily: mono,
              fontSize: 26,
              opacity: enter(frame, tokenAt, fps, 16),
            }}
          >
            {tokens} single-use Ed25519 token minted
          </div>
        ) : null}
      </div>
    </div>
  );
};
