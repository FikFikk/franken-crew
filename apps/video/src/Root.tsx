import {Composition, getStaticFiles, staticFile, type CalculateMetadataFunction} from 'remotion';
import type {Caption} from '@remotion/captions';
import {ALL_FORMATS, Input, UrlSource} from 'mediabunny';
import {FrankenCrewDemo} from './FrankenCrewDemo';
import {FPS, HEIGHT, MAX_FRAMES, SCENES, TARGET_FRAMES, WIDTH} from './script';
import {resolveScene, type DemoProps, type ResolvedScene} from './timeline';

const exists = (file: string): boolean => getStaticFiles().some((f) => f.name === file);

// Durasi VO dalam frame; 0 jika file belum direkam, supaya preview tetap jalan tanpa suara
const voFrames = async (file: string): Promise<number> => {
  if (!exists(file)) return 0;
  const input = new Input({formats: ALL_FORMATS, source: new UrlSource(staticFile(file))});
  return Math.ceil((await input.computeDuration()) * FPS);
};

const loadCaptions = async (file: string): Promise<Caption[] | null> => {
  if (!exists(file)) return null;
  const res = await fetch(staticFile(file));
  return (await res.json()) as Caption[];
};

const calculateMetadata: CalculateMetadataFunction<DemoProps> = async () => {
  const resolved = await Promise.all(
    SCENES.map(async (def) => resolveScene(def, await voFrames(def.vo), await loadCaptions(def.captions))),
  );
  let start = 0;
  const scenes: ResolvedScene[] = resolved.map((s) => {
    const scene = {...s, startFrame: start};
    start += s.durationInFrames;
    return scene;
  });
  if (start > MAX_FRAMES) {
    throw new Error(
      `Video is ${start} frames (${(start / FPS).toFixed(1)} s); the limit is ${MAX_FRAMES}. Shorten the voiceover.`,
    );
  }
  return {
    durationInFrames: start,
    props: {
      scenes,
      extras: {phonePoll: exists('footage/phone-poll.mp4'), crewDashboard: exists('footage/crew-dashboard.mp4')},
    },
  };
};

export const Root: React.FC = () => (
  <Composition
    id="FrankenCrewDemo"
    component={FrankenCrewDemo}
    width={WIDTH}
    height={HEIGHT}
    fps={FPS}
    durationInFrames={TARGET_FRAMES}
    defaultProps={{scenes: [], extras: {phonePoll: false, crewDashboard: false}}}
    calculateMetadata={calculateMetadata}
  />
);
