import type React from 'react';
import type {SceneId} from '../script';
import type {Extras, ResolvedScene} from '../timeline';
import {S1Hook} from './S1Hook';
import {S2Organs} from './S2Organs';
import {S3HeapLeak} from './S3HeapLeak';
import {S4Injection} from './S4Injection';
import {S5Kiro} from './S5Kiro';
import {S6Crew} from './S6Crew';
import {S7Outro} from './S7Outro';

export const SCENE_COMPONENTS: Record<SceneId, React.FC<{scene: ResolvedScene; extras: Extras}>> = {
  S1: S1Hook,
  S2: S2Organs,
  S3: S3HeapLeak,
  S4: S4Injection,
  S5: S5Kiro,
  S6: S6Crew,
  S7: S7Outro,
};
