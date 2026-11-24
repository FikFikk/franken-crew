import {AbsoluteFill, Sequence, Series, interpolate, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';
import {Audio} from '@remotion/media';
import {clamp} from './anim';
import {Captions} from './components/Captions';
import {SCENE_COMPONENTS} from './scenes';
import {VO_LEAD_IN} from './script';
import {theme} from './theme';
import type {DemoProps, Extras, ResolvedScene} from './timeline';

// Fade masuk/keluar di dalam scene, jadi Series tidak overlap dan VO aman di dalam scene
const SceneShell: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene, extras}) => {
  const frame = useCurrentFrame();
  const {durationInFrames} = useVideoConfig();
  const opacity = interpolate(frame, [0, 10, durationInFrames - 10, durationInFrames], [0, 1, 1, 0], clamp);
  const Scene = SCENE_COMPONENTS[scene.id];
  return (
    <AbsoluteFill style={{backgroundColor: theme.bg}}>
      <AbsoluteFill style={{opacity}}>
        <Scene scene={scene} extras={extras} />
        {scene.captionTokens ? <Captions tokens={scene.captionTokens} offsetFrames={VO_LEAD_IN} /> : null}
      </AbsoluteFill>
      {scene.hasVo ? (
        <Sequence from={VO_LEAD_IN} layout="none">
          <Audio src={staticFile(scene.vo)} />
        </Sequence>
      ) : null}
    </AbsoluteFill>
  );
};

export const FrankenCrewDemo: React.FC<DemoProps> = ({scenes, extras}) => (
  <AbsoluteFill style={{backgroundColor: theme.bg}}>
    <Series>
      {scenes.map((scene) => (
        <Series.Sequence key={scene.id} durationInFrames={scene.durationInFrames} name={`${scene.id} ${scene.title}`}>
          <SceneShell scene={scene} extras={extras} />
        </Series.Sequence>
      ))}
    </Series>
  </AbsoluteFill>
);
