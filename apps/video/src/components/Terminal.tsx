import {useCurrentFrame} from 'remotion';
import {typed} from '../anim';
import {mono} from '../fonts';
import {theme} from '../theme';

export type TermLine = {text: string; color?: string; at: number};

// Baris muncul pada frame `at` masing-masing dan diketik selama `typeFrames`; hanya `maxLines` terakhir yang tampil
export const Terminal: React.FC<{
  lines: TermLine[];
  typeFrames?: number;
  maxLines?: number;
  fontSize?: number;
  prompt?: string;
  promptAt?: number;
}> = ({lines, typeFrames = 0, maxLines = 99, fontSize = 30, prompt, promptAt = 0}) => {
  const frame = useCurrentFrame();
  const visible = lines.filter((l) => frame >= l.at).slice(-maxLines);
  return (
    <div style={{fontFamily: mono, fontSize, lineHeight: 1.45, color: theme.text, whiteSpace: 'pre'}}>
      {prompt && frame >= promptAt ? (
        <div>
          <span style={{color: theme.sentinel}}>$ </span>
          {prompt.slice(0, typed(frame, promptAt, 20, prompt.length))}
        </div>
      ) : null}
      {visible.map((l) => {
        const chars = typeFrames > 0 ? typed(frame, l.at, typeFrames, l.text.length) : l.text.length;
        return (
          <div key={`${l.at}-${l.text}`} style={{color: l.color ?? theme.text}}>
            {l.text.slice(0, chars)}
          </div>
        );
      })}
    </div>
  );
};
