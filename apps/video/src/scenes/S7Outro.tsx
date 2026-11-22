import {AbsoluteFill, Img, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';
import {enter} from '../anim';
import {mono, sans} from '../fonts';
import {theme} from '../theme';
import {cue, type Extras, type ResolvedScene} from '../timeline';

export const S7Outro: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const urlAt = cue(scene, 'url');
  const lines = [
    {text: 'Reflexes in Go.', color: theme.sentinel, at: cue(scene, 'go')},
    {text: 'Thinking in Kiro.', color: theme.crew, at: cue(scene, 'kiro')},
    {text: 'A human with the last word.', color: theme.human, at: cue(scene, 'human')},
  ];
  const url = enter(frame, urlAt, fps, 20);
  return (
    <AbsoluteFill style={{fontFamily: sans, color: theme.text, alignItems: 'center'}}>
      <Img src={staticFile('img/logo-lockup.webp')} style={{position: 'absolute', top: 150, width: 600, opacity: enter(frame, 0, fps, 24)}} />
      <div style={{position: 'absolute', top: 420, display: 'flex', gap: 40, fontSize: 52, fontWeight: 700}}>
        {lines.map((l) => {
          const e = enter(frame, l.at, fps, 18);
          return (
            <span key={l.text} style={{color: l.color, opacity: e, transform: `translateY(${(1 - e) * 20}px)`}}>
              {l.text}
            </span>
          );
        })}
      </div>
      <div style={{position: 'absolute', top: 580, textAlign: 'center', opacity: url, transform: `scale(${0.96 + 0.04 * url})`}}>
        <div style={{fontFamily: mono, fontSize: 96, fontWeight: 700, color: theme.sentinel, textShadow: `0 0 40px ${theme.sentinel}55`}}>
          frankencrew.fikfikk.my.id
        </div>
        <div style={{fontFamily: mono, fontSize: 44, color: theme.text, marginTop: 26}}>github.com/FikFikk/franken-crew</div>
        <div style={{fontSize: 34, color: theme.muted, marginTop: 22}}>Kiroween 2026 · Frankenstein category · MIT license</div>
      </div>
    </AbsoluteFill>
  );
};
