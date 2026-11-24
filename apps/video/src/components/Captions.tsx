import {useMemo} from 'react';
import {AbsoluteFill, Sequence, useCurrentFrame, useVideoConfig} from 'remotion';
import {createTikTokStyleCaptions, type Caption, type TikTokPage} from '@remotion/captions';
import {sans} from '../fonts';
import {theme} from '../theme';

const SWITCH_EVERY_MS = 1400;

// Satu halaman caption; kata yang sedang diucapkan diberi warna aksen
const Page: React.FC<{page: TikTokPage}> = ({page}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const nowMs = page.startMs + (frame / fps) * 1000;
  return (
    <AbsoluteFill style={{justifyContent: 'flex-end', alignItems: 'center', paddingBottom: 64}}>
      <div
        style={{
          maxWidth: 1500,
          padding: '10px 28px',
          borderRadius: 999,
          background: 'rgba(15,18,26,.85)',
          border: `1px solid ${theme.line}`,
          fontFamily: sans,
          fontSize: 40,
          fontWeight: 600,
          lineHeight: 1.3,
          color: theme.text,
          textAlign: 'center',
          whiteSpace: 'pre',
        }}
      >
        {page.tokens.map((t) => (
          <span key={t.fromMs} style={{color: nowMs >= t.fromMs && nowMs < t.toMs ? theme.sentinel : theme.text}}>
            {t.text}
          </span>
        ))}
      </div>
    </AbsoluteFill>
  );
};

export const Captions: React.FC<{tokens: Caption[]; offsetFrames: number}> = ({tokens, offsetFrames}) => {
  const {fps} = useVideoConfig();
  const {pages} = useMemo(
    () => createTikTokStyleCaptions({captions: tokens, combineTokensWithinMilliseconds: SWITCH_EVERY_MS}),
    [tokens],
  );
  return (
    <>
      {pages.map((page, i) => {
        const next = pages[i + 1] ?? null;
        const from = offsetFrames + Math.round((page.startMs / 1000) * fps);
        const endMs = Math.min(next ? next.startMs : Infinity, page.startMs + page.durationMs + 300);
        const duration = Math.round(((endMs - page.startMs) / 1000) * fps);
        if (duration <= 0) return null;
        return (
          <Sequence key={page.startMs} from={from} durationInFrames={duration} name="caption">
            <Page page={page} />
          </Sequence>
        );
      })}
    </>
  );
};
