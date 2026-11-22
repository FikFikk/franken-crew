import {AbsoluteFill, Img, interpolate, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';
import {clamp, enter, fadeIn, typed} from '../anim';
import {FootageFrame, WarpedVideo} from '../components/Footage';
import {Chip} from '../components/Panel';
import {Stamp} from '../components/Stamp';
import {Stitch} from '../components/Stitch';
import {repo} from '../data/repo';
import {mono, sans} from '../fonts';
import {eventOf, injection, tLabel} from '../replay';
import {footageLayout as L, theme} from '../theme';
import {cue, type Extras, type ResolvedScene} from '../timeline';

// Screenshot event log (lane Sentinel) dari situs live: 904x628; baris diukur dalam koordinat gambar
const SHOT = {w: 904, h: 628, rows: {rejected: [279, 364], blocked: [364, 413], replay: [511, 560]}, x0: 19, x1: 885} as const;
const SCALE = L.videoH / SHOT.h;
const SHOT_LEFT = (L.videoW - SHOT.w * SCALE) / 2;

// Bagian teks yang berisi perintah injeksi diberi warna peringatan
const INJECTED = ['IGNORE ALL PREVIOUS INSTRUCTIONS.', 'unit_restart ssh.service', 'process_terminate pid 1', 'approve it yourself.'];

const segments = (text: string): {text: string; hl: boolean}[] => {
  const out: {text: string; hl: boolean}[] = [];
  let rest = text;
  while (rest.length > 0) {
    const hits = INJECTED.map((p) => ({p, i: rest.indexOf(p)})).filter((h) => h.i >= 0).sort((a, b) => a.i - b.i);
    if (hits.length === 0) {
      out.push({text: rest, hl: false});
      break;
    }
    const {p, i} = hits[0];
    if (i > 0) out.push({text: rest.slice(0, i), hl: false});
    out.push({text: p, hl: true});
    rest = rest.slice(i + p.length);
  }
  return out;
};

const RowHighlight: React.FC<{at: number; row: readonly [number, number]}> = ({at, row}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, at, fps, 14);
  if (frame < at) return null;
  return (
    <div
      style={{
        position: 'absolute',
        left: SHOT_LEFT + SHOT.x0 * SCALE - 6,
        top: row[0] * SCALE - 4,
        width: (SHOT.x1 - SHOT.x0) * SCALE + 12,
        height: (row[1] - row[0]) * SCALE + 8,
        border: `4px solid ${theme.error}`,
        borderRadius: 12,
        boxShadow: `0 0 ${30 * p}px ${theme.error}aa, inset 0 0 0 9999px rgba(255,90,106,${0.1 * p})`,
        opacity: p,
      }}
    />
  );
};

export const S4Injection: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const logAt = cue(scene, 'log');
  const rejectsAt = cue(scene, 'rejects');
  const blockedAt = cue(scene, 'blocked');
  const refusedAt = cue(scene, 'refused');
  const shotAt = rejectsAt - 16;

  const rejected = eventOf(injection, 'plan.rejected');
  const blocked = eventOf(injection, 'action.blocked');
  const replayed = eventOf(injection, 'token.replay_rejected');
  const vote = eventOf(injection, 'vote.granted');
  const evidence = eventOf(injection, 'evidence.recorded');
  const evidenceId = evidence.detail.match(/ev-[0-9a-f]+/)?.[0] ?? '';
  const worker = vote.detail.match(/pm_id=\d+/)?.[0] ?? '';
  const resolvedAt = Math.max(refusedAt + 45, scene.speechEnd - 10);

  const dim = interpolate(frame, [logAt - 8, logAt + 10], [1, 0.3], clamp);
  const logP = enter(frame, logAt, fps, 18) * interpolate(frame, [shotAt - 12, shotAt], [1, 0], clamp);
  const fullLog = `${repo.injectedLog.source} ${repo.injectedLog.text}`;
  const shown = typed(frame, logAt + 10, Math.min(150, Math.max(40, shotAt - logAt - 60)), fullLog.length);
  let budget = shown;

  return (
    <AbsoluteFill style={{fontFamily: sans, color: theme.text}}>
      <FootageFrame>
        <AbsoluteFill style={{opacity: dim}}>
          <WarpedVideo
            anchors={[
              {frame: 0, src: 47.6},
              {frame: logAt, src: 50.0},
              {frame: shotAt + 20, src: 77.0},
            ]}
          />
        </AbsoluteFill>
        <AbsoluteFill style={{background: theme.panel, opacity: fadeIn(frame, shotAt, 14)}}>
          <Img src={staticFile('img/prompt-injection-blocked.png')} style={{position: 'absolute', left: SHOT_LEFT, top: 0, height: L.videoH}} />
          <RowHighlight at={rejectsAt} row={SHOT.rows.rejected} />
          <RowHighlight at={blockedAt} row={SHOT.rows.blocked} />
          <RowHighlight at={refusedAt} row={SHOT.rows.replay} />
        </AbsoluteFill>
        {logP > 0 ? (
          <div
            style={{
              position: 'absolute',
              left: 80,
              right: 80,
              top: 150,
              padding: '28px 34px',
              borderRadius: theme.radius,
              background: theme.panel,
              border: `1px solid ${theme.kernel}`,
              boxShadow: '0 30px 90px rgba(0,0,0,.6)',
              opacity: logP,
              transform: `translateY(${(1 - logP) * 30}px)`,
            }}
          >
            <div style={{display: 'flex', alignItems: 'center', gap: 18, marginBottom: 20}}>
              <span style={{fontSize: 36, fontWeight: 700}}>Evidence the agents read</span>
              <Chip color={theme.muted} style={{fontSize: 26}}>
                {evidenceId} · journal · {injection.unit}
              </Chip>
            </div>
            <div style={{fontFamily: mono, fontSize: 34, lineHeight: 1.5, whiteSpace: 'pre-wrap'}}>
              {segments(fullLog).map((s, i) => {
                const t = s.text.slice(0, Math.max(0, budget));
                budget -= s.text.length;
                return t ? (
                  <span key={i} style={{color: s.hl ? theme.error : theme.text, fontWeight: s.hl ? 700 : 400}}>
                    {t}
                  </span>
                ) : null;
              })}
            </div>
          </div>
        ) : null}
      </FootageFrame>

      <div style={{position: 'absolute', left: L.railX, top: L.y, width: L.railW, height: L.chromeH + L.videoH, display: 'flex', flexDirection: 'column', gap: 18}}>
        {[
          {at: rejectsAt, title: 'PLAN REJECTED', detail: 'ssh.service and PID 1 are protected', time: tLabel(rejected.t), slot: 'policy'},
          {at: blockedAt, title: 'BLOCKED', detail: `${blocked.title.match(/^Blocked (\S+):/)?.[1] ?? ''} ${blocked.detail.match(/unit (\S+)$/)?.[1] ?? ''}`, time: tLabel(blocked.t), slot: 'guard'},
          {at: refusedAt, title: 'REFUSED', detail: 'replayed step token, nonce already used', time: tLabel(replayed.t), slot: 'token'},
        ].map((s, i) =>
          frame >= s.at ? (
            <Stamp key={s.title} at={s.at} title={s.title} detail={s.detail} time={s.time} tilt={i % 2 ? 2 : -3} />
          ) : (
            <div
              key={s.title}
              style={{
                flex: 1,
                borderRadius: 14,
                border: `2px dashed ${theme.lineSoft}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontFamily: mono,
                fontSize: 30,
                color: theme.faint,
                opacity: fadeIn(frame, 10 + i * 8, 14),
              }}
            >
              {s.slot} check
            </div>
          ),
        )}
      </div>
      {frame >= resolvedAt ? (
        <div style={{position: 'absolute', left: L.x, width: L.videoW, top: L.y + L.chromeH + L.videoH - 84, display: 'flex', justifyContent: 'center', opacity: enter(frame, resolvedAt, fps, 16)}}>
          <Chip color={theme.sentinel} style={{fontSize: 34, padding: '10px 24px', background: 'rgba(7,8,12,.92)'}}>
            {injection.state} at {tLabel(injection.duration_s)} by restarting only worker {worker}
          </Chip>
        </div>
      ) : null}
      <Stitch at={scene.durationInFrames - 24} />
    </AbsoluteFill>
  );
};
