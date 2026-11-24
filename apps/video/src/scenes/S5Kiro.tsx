import {AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig} from 'remotion';
import {clamp, enter, fadeIn, typed} from '../anim';
import {Arrow, Check, Glyphed} from '../components/Glyphs';
import {Chip, Panel} from '../components/Panel';
import {repo} from '../data/repo';
import {mono, sans} from '../fonts';
import {theme} from '../theme';
import {cue, type Extras, type ResolvedScene} from '../timeline';

const PANEL = {x: 64, y: 64, w: 1792, h: 856};

// Beat 1: kriteria EARS diketik, lalu tiga angka dari spec
const SpecBeat: React.FC<{start: number; twelve: number; four: number; tasks: number}> = ({start, twelve, four, tasks}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const text = repo.spec.criterion31;
  const shown = typed(frame, start + 12, 110, text.length);
  const words = text.slice(0, shown).split(/(\s+)/);
  const keywords = new Set(['WHEN', 'AND', 'THE', 'SYSTEM', 'SHALL', 'IF', 'THEN']);
  const stats = [
    {value: repo.spec.requirementCount, label: 'requirements in EARS form', at: twelve, color: theme.sentinel},
    {value: repo.spec.properties.length, label: 'correctness properties', at: four, color: theme.crew},
    {value: repo.spec.taskDone, label: `of ${repo.spec.taskCount} tasks done`, at: tasks, color: theme.verify},
  ];
  return (
    <div style={{position: 'absolute', inset: 0, padding: '48px 56px', display: 'flex', flexDirection: 'column', gap: 40}}>
      <Chip color={theme.sentinel} style={{alignSelf: 'flex-start'}}>Requirement 3.1</Chip>
      <div style={{fontSize: 52, lineHeight: 1.35, fontWeight: 500, minHeight: 280}}>
        {words.map((w, i) => (
          <span key={i} style={{color: keywords.has(w) ? theme.sentinel : theme.text, fontWeight: keywords.has(w) ? 800 : 500}}>
            {w}
          </span>
        ))}
      </div>
      <div style={{display: 'flex', gap: 32, marginTop: 'auto'}}>
        {stats.map((s) => {
          const p = enter(frame, s.at, fps, 20);
          const n = Math.round(interpolate(frame, [s.at, s.at + 20], [0, s.value], clamp));
          return (
            <div key={s.label} style={{flex: 1, padding: '28px 32px', borderRadius: 16, background: theme.panel2, border: `1px solid ${theme.lineSoft}`, opacity: Math.max(0.25, p)}}>
              <div style={{fontFamily: mono, fontSize: 96, fontWeight: 700, color: s.color}}>{frame >= s.at ? n : 0}</div>
              <div style={{fontSize: 34, color: theme.muted}}>{s.label}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Beat 2: P1..P4 dari design.md dan hasil go test yang asli
const PropertyBeat: React.FC<{start: number}> = ({start}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  return (
    <div style={{position: 'absolute', inset: 0, padding: '32px 56px', display: 'flex', flexDirection: 'column', gap: 16}}>
      {repo.spec.properties.map((p, i) => {
        const test = repo.propertyTests.find((t) => t.property === p.id);
        const at = start + 10 + i * 18;
        const e = enter(frame, at, fps, 18);
        const quoted = p.id === 'P2';
        return (
          <div
            key={p.id}
            style={{
              display: 'flex',
              gap: 28,
              alignItems: 'center',
              padding: '14px 28px',
              borderRadius: 16,
              background: theme.panel2,
              border: `1.5px solid ${quoted && frame >= start + 90 ? theme.crew : theme.lineSoft}`,
              opacity: e,
              transform: `translateX(${(1 - e) * 40}px)`,
            }}
          >
            <div style={{fontFamily: mono, fontSize: 40, fontWeight: 700, color: theme.crew, width: 70}}>{p.id}</div>
            <div style={{flex: 1}}>
              <div style={{fontSize: 36, fontWeight: 600, lineHeight: 1.22}}>
                <Glyphed text={p.text.replace(/`/g, '')} size={30} />
              </div>
              <div style={{fontFamily: mono, fontSize: 28, color: theme.muted, marginTop: 4}}>{test?.name}</div>
            </div>
            <Chip color={theme.sentinel}>
              <Check size={26} color={theme.sentinel} /> PASS {test?.seconds}s
            </Chip>
          </div>
        );
      })}
      <div style={{fontFamily: mono, fontSize: 30, color: theme.faint, marginTop: 'auto'}}>
        pgregory.net/rapid · {repo.propertyPackagesOk} packages ok
      </div>
    </div>
  );
};

// Beat 3: steering dengan mode inclusion dari frontmatter
const SteeringBeat: React.FC<{start: number}> = ({start}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const pulse = 0.5 + 0.5 * Math.sin((frame - start) / 6);
  return (
    <div style={{position: 'absolute', inset: 0, padding: '40px 56px', display: 'flex', gap: 56}}>
      <div style={{flex: 1, display: 'flex', flexDirection: 'column', gap: 14}}>
        {repo.steering.map((s, i) => {
          const kernel = s.file === 'linux-kernel.md';
          const e = enter(frame, start + 8 + i * 6, fps, 16);
          const color = s.inclusion === 'always' ? theme.muted : s.inclusion === 'fileMatch' ? theme.kernel : theme.crew;
          return (
            <div
              key={s.file}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 20,
                padding: '14px 24px',
                borderRadius: 14,
                background: theme.panel2,
                border: `2px solid ${kernel ? `rgba(255,179,71,${0.4 + 0.6 * pulse})` : theme.lineSoft}`,
                boxShadow: kernel ? `0 0 ${24 * pulse}px rgba(255,179,71,.35)` : undefined,
                opacity: e,
              }}
            >
              <span style={{fontFamily: mono, fontSize: 32, width: 420, whiteSpace: 'nowrap'}}>{s.file}</span>
              <Chip color={color} style={{fontSize: 28}}>{s.inclusion}</Chip>
              {s.pattern ? <span style={{fontFamily: mono, fontSize: 28, color: theme.muted}}>{s.pattern}</span> : null}
            </div>
          );
        })}
      </div>
      <div style={{width: 500, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 28, fontSize: 36, lineHeight: 1.35, opacity: fadeIn(frame, start + 40, 16)}}>
        <div>
          <span style={{color: theme.kernel, fontWeight: 700}}>fileMatch</span> rules load only while Kiro edits matching files.
        </div>
        <div style={{color: theme.muted}}>Kernel guardrails for kernel code, video rules for the video.</div>
      </div>
    </div>
  );
};

// Beat 4: hook PreToolUse dan hasil franken guard yang dijalankan saat collect-data
const HookBeat: React.FC<{start: number; guardAt: number}> = ({start, guardAt}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const g = repo.guard;
  const payloadAt = start + 24;
  const boxAt = start + 44;
  const resultAt = Math.max(guardAt, boxAt + 20);
  const key = (k: string) => <span style={{color: theme.verify}}>&quot;{k}&quot;</span>;
  const val = (v: string, hl = false) => <span style={{color: hl ? theme.sentinel : theme.kernel, fontWeight: hl ? 700 : 400}}>&quot;{v}&quot;</span>;
  const box = (at: number, border: string, children: React.ReactNode) => {
    const e = enter(frame, at, fps, 18);
    return (
      <div style={{padding: '20px 26px', borderRadius: 16, border: `2px solid ${border}`, background: theme.panel2, opacity: e, transform: `translateY(${(1 - e) * 24}px)`}}>
        {children}
      </div>
    );
  };
  const arrowDown = (at: number) => (
    <div style={{textAlign: 'center', opacity: fadeIn(frame, at, 10), transform: 'rotate(90deg)'}}>
      <Arrow size={44} color={theme.muted} />
    </div>
  );
  return (
    <div style={{position: 'absolute', inset: 0, padding: '40px 56px', display: 'flex', gap: 48}}>
      <div style={{width: 860, fontFamily: mono, fontSize: 30, lineHeight: 1.55, whiteSpace: 'pre-wrap', wordBreak: 'break-all', opacity: fadeIn(frame, start + 6, 14)}}>
        {'{\n  '}
        {key('trigger')}: {val(g.trigger, true)},{'\n  '}
        {key('matcher')}: {val(g.matcher)},{'\n  '}
        {key('action')}: {'{\n    '}
        {key('type')}: {val('command')},{'\n    '}
        {key('command')}: {val(g.command, true)}
        {'\n  }\n}'}
      </div>
      <div style={{flex: 1, display: 'flex', flexDirection: 'column', gap: 10, justifyContent: 'center', fontFamily: mono, fontSize: 30}}>
        {box(
          payloadAt,
          theme.crew,
          <>
            <div style={{color: theme.crew}}>{g.payload.tool_name}</div>
            <div>
              {g.payload.tool_input.action} <span style={{color: theme.error}}>unit: {g.payload.tool_input.params.unit}</span>
            </div>
          </>,
        )}
        {arrowDown(payloadAt + 10)}
        {box(boxAt, theme.text, <div style={{fontWeight: 700}}>{g.command}</div>)}
        {arrowDown(boxAt + 10)}
        {box(
          resultAt,
          theme.error,
          <>
            <div style={{color: theme.error, fontWeight: 700, fontSize: 40}}>exit {g.exitCode} · blocked</div>
            <div style={{color: theme.muted, marginTop: 6, lineHeight: 1.35}}>{g.blockedLine}</div>
          </>,
        )}
      </div>
    </div>
  );
};

// Beat 5: pull request yang di-merge, dari merge commit git
const WebBeat: React.FC<{start: number}> = ({start}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  return (
    <div style={{position: 'absolute', inset: 0, padding: '40px 56px', display: 'flex', flexDirection: 'column', gap: 20}}>
      {repo.mergedPRs.map((pr, i) => {
        const e = enter(frame, start + 10 + i * 14, fps, 18);
        return (
          <div
            key={pr.number}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 28,
              padding: '24px 30px',
              borderRadius: 16,
              background: theme.panel2,
              border: `1px solid ${theme.lineSoft}`,
              opacity: e,
              transform: `translateY(${(1 - e) * 30}px)`,
            }}
          >
            <span style={{fontFamily: mono, fontSize: 44, fontWeight: 700, color: theme.muted, width: 90}}>#{pr.number}</span>
            <span style={{flex: 1, fontSize: 38, fontWeight: 600, lineHeight: 1.25}}>{pr.title}</span>
            <Chip color={theme.crew}>merged</Chip>
          </div>
        );
      })}
      <div style={{fontSize: 34, color: theme.muted, marginTop: 'auto', opacity: fadeIn(frame, start + 60, 16)}}>
        Opened by Kiro Web from its sandbox, one pull request per round.
      </div>
    </div>
  );
};

export const S5Kiro: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene}) => {
  const frame = useCurrentFrame();
  const starts = [0, cue(scene, 'properties'), cue(scene, 'steering'), cue(scene, 'hook'), cue(scene, 'web')];
  const titles = [
    '.kiro/specs/server-incident-remediation/requirements.md',
    "go test -run 'Property_P[1-4]' ./internal/...",
    '.kiro/steering/',
    '.kiro/hooks/preToolUse.json',
    'github.com/FikFikk/franken-crew · merged pull requests',
  ];
  const labels = ['Spec', 'Properties', 'Steering', 'Hook', 'Kiro Web'];
  const beat = starts.reduce((acc, s, i) => (frame >= s ? i : acc), 0);
  const ends = [...starts.slice(1), scene.durationInFrames];
  const visibility = (i: number) => fadeIn(frame, starts[i], 10) * interpolate(frame, [ends[i] - 8, ends[i]], [1, 0], clamp);

  return (
    <AbsoluteFill style={{fontFamily: sans, color: theme.text}}>
      <Panel
        {...PANEL}
        title={titles[beat]}
        right={
          <span style={{display: 'flex', gap: 10}}>
            {labels.map((l, i) => (
              <span
                key={l}
                style={{
                  fontFamily: sans,
                  fontSize: 26,
                  padding: '4px 12px',
                  borderRadius: 999,
                  color: i === beat ? theme.bg : theme.faint,
                  background: i === beat ? theme.sentinel : 'transparent',
                  fontWeight: 700,
                }}
              >
                {l}
              </span>
            ))}
          </span>
        }
      >
        {[
          <SpecBeat key="spec" start={starts[0]} twelve={cue(scene, 'twelve')} four={cue(scene, 'four')} tasks={cue(scene, 'tasks')} />,
          <PropertyBeat key="props" start={starts[1]} />,
          <SteeringBeat key="steer" start={starts[2]} />,
          <HookBeat key="hook" start={starts[3]} guardAt={cue(scene, 'guard')} />,
          <WebBeat key="web" start={starts[4]} />,
        ].map((node, i) =>
          visibility(i) > 0 ? (
            <div key={i} style={{position: 'absolute', inset: 0, opacity: visibility(i)}}>
              {node}
            </div>
          ) : null,
        )}
      </Panel>
    </AbsoluteFill>
  );
};
