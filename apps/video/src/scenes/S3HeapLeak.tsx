import {AbsoluteFill, Sequence, staticFile} from 'remotion';
import {Video} from '@remotion/media';
import {FootageFrame, WarpedVideo, type Anchor} from '../components/Footage';
import {PhoneChat} from '../components/PhoneChat';
import {StepRail, type Step} from '../components/StepRail';
import {mono, sans} from '../fonts';
import {eventOf, heapLeak} from '../replay';
import {footageLayout as L, theme} from '../theme';
import {cue, type Extras, type ResolvedScene} from '../timeline';

// Detik di footage sumber saat langkah terlihat; diukur dari jam replay di rekaman (docs/REMOTION_VIDEO.md bagian 3)
const SRC = {start: 5.0, psi: 15.0, opened: 17.0, reflex: 17.6, crew: 18.3, poll: 22.3, votes: 26.4, reload: 28.0, watches: 30.5, end: 41.0};

export const S3HeapLeak: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene, extras}) => {
  const c = (name: keyof typeof SRC) => cue(scene, name);
  const anchors: Anchor[] = [
    {frame: 0, src: SRC.start},
    ...(['psi', 'opened', 'reflex', 'crew', 'poll', 'votes', 'reload', 'watches'] as const).map((k) => ({frame: c(k), src: SRC[k]})),
    {frame: scene.durationInFrames, src: SRC.end},
  ];

  const plan = eventOf(heapLeak, 'plan.accepted');
  const executed = eventOf(heapLeak, 'action.executed');
  const steps: Step[] = [
    {lane: 'kernel', title: 'Pressure rises', sub: 'PSI some over 10%', at: c('psi')},
    {lane: 'sentinel', title: 'Incident opened', sub: `${heapLeak.severity} · ${Math.round(heapLeak.tto_seconds)} s to OOM`, at: c('opened')},
    {lane: 'sentinel', title: 'L1 reflex, no model', sub: `reclaim, ${heapLeak.reflex_latency_ms} ms`, at: c('reflex')},
    {lane: 'crew', title: 'Crew triages', sub: plan.title.replace(/^Plan accepted by Sentinel$/, 'plan passes policy'), at: c('crew')},
    {lane: 'human', title: 'Human votes', sub: 'one Ed25519 token', at: c('poll')},
    {lane: 'verify', title: executed.title.replace(/^Executed (\S+).*$/, '$1'), sub: `${heapLeak.stats.verify_window_s} s verify, ${heapLeak.state}`, at: c('reload')},
  ];

  const phone = {x: L.x + 20, y: L.y + L.chromeH + 20, w: 560, h: L.videoH - 40};
  const phoneIn = c('poll') - 16;
  const phoneOut = c('reload') + 24;

  return (
    <AbsoluteFill style={{fontFamily: sans, color: theme.text}}>
      <FootageFrame>
        <WarpedVideo anchors={anchors} />
      </FootageFrame>
      <StepRail steps={steps} enterAt={8} />
      {extras.phonePoll ? (
        <RealPhone {...phone} from={phoneIn} until={phoneOut} />
      ) : (
        <PhoneChat
          {...phone}
          messages={heapLeak.messages}
          poll={heapLeak.poll}
          planHash={heapLeak.plan_hash}
          enterAt={phoneIn}
          exitAt={phoneOut}
          alertAt={phoneIn}
          pollAt={c('poll')}
          voteAt={c('votes')}
          tokenAt={c('votes') + Math.round((c('reload') - c('votes')) * 0.45)}
        />
      )}
    </AbsoluteFill>
  );
};

// Rekaman layar HP asli (opsional): public/footage/phone-poll.mp4, nomor telepon sudah diburamkan
const RealPhone: React.FC<{x: number; y: number; w: number; h: number; from: number; until: number}> = ({x, y, w, h, from, until}) => (
  <Sequence from={from} durationInFrames={until - from} layout="none" name="real phone">
    <div style={{position: 'absolute', left: x, top: y, width: w, height: h, borderRadius: 44, overflow: 'hidden', border: `3px solid ${theme.line}`}}>
      <Video src={staticFile('footage/phone-poll.mp4')} muted objectFit="cover" style={{width: '100%', height: '100%'}} />
      <div style={{position: 'absolute', left: 16, bottom: 16, fontFamily: mono, fontSize: 26, color: theme.text, background: 'rgba(7,8,12,.8)', padding: '6px 12px', borderRadius: 10}}>
        Real phone · numbers blurred
      </div>
    </div>
  </Sequence>
);
