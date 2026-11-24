import {AbsoluteFill, staticFile, useCurrentFrame, useVideoConfig} from 'remotion';
import {Video} from '@remotion/media';
import {enter, fadeIn} from '../anim';
import {Chip, Panel} from '../components/Panel';
import {Terminal, type TermLine} from '../components/Terminal';
import {repo} from '../data/repo';
import {mono, sans} from '../fonts';
import {crewApp} from '../replay';
import {theme} from '../theme';
import {cue, type Extras, type ResolvedScene} from '../timeline';

const Section: React.FC<{at: number; title: string; color: string; children: React.ReactNode}> = ({at, title, color, children}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const e = enter(frame, at, fps, 18);
  return (
    <div style={{opacity: Math.max(0.2, e), transform: `translateX(${(1 - e) * 24}px)`}}>
      <div style={{fontSize: 38, fontWeight: 800, color, marginBottom: 8}}>{title}</div>
      <div style={{fontFamily: mono, fontSize: 30, lineHeight: 1.45, color: theme.text}}>{children}</div>
    </div>
  );
};

export const S6Crew: React.FC<{scene: ResolvedScene; extras: Extras}> = ({scene, extras}) => {
  const frame = useCurrentFrame();
  const chaosAt = cue(scene, 'chaos');
  const passesAt = cue(scene, 'passes');
  const tools: Record<string, number> = {'franken-sentinel': repo.mcpTools.sentinel, 'franken-wa': repo.mcpTools.wa};

  // Baris chaos dicetak merata dari awal scene sampai kata "Twenty"
  const first = 24;
  const step = Math.max(2, Math.floor((chaosAt - first) / repo.chaosRuns.length));
  const lines: TermLine[] = repo.chaosRuns.map((r, i) => ({
    text: `[${String(r.run).padStart(2, '0')}/${r.of}] ${r.scenario.padEnd(12)} ${r.status}  ${r.reflexMs.padStart(4)} ms  ${r.l2}`,
    color: r.status === 'PASS' ? theme.text : theme.error,
    at: first + i * step,
  }));
  const summary = repo.chaosSummary.replace(/^Summary: /, '');

  return (
    <AbsoluteFill style={{fontFamily: sans, color: theme.text}}>
      <Panel x={64} y={64} w={760} h={856} title="app.json · Kiro Crew app" bodyStyle={{padding: '30px 36px', display: 'flex', flexDirection: 'column', gap: 30}}>
        {extras.crewDashboard ? (
          <div style={{borderRadius: 14, overflow: 'hidden', border: `1px solid ${theme.line}`, height: 386}}>
            <Video src={staticFile('footage/crew-dashboard.mp4')} muted objectFit="cover" style={{width: '100%', height: '100%'}} />
          </div>
        ) : null}
        <Section at={cue(scene, 'agents')} title={`${crewApp.agents.length} agents`} color={theme.crew}>
          {extras.crewDashboard ? crewApp.agents.join(', ') : crewApp.agents.map((a) => <div key={a}>{a}</div>)}
        </Section>
        <Section at={cue(scene, 'crons')} title={`${crewApp.crons.length} crons`} color={theme.verify}>
          {crewApp.crons.map((c) => (
            <div key={c.name}>
              {c.name} <span style={{color: theme.muted}}>· {c.schedule}</span>
            </div>
          ))}
        </Section>
        <Section at={cue(scene, 'servers')} title={`${crewApp.mcpServers.length} MCP servers`} color={theme.sentinel}>
          {crewApp.mcpServers.map((m) => (
            <div key={m}>
              {m} <span style={{color: theme.muted}}>· {tools[m] ?? '?'} tools</span>
            </div>
          ))}
        </Section>
        <Section at={cue(scene, 'page')} title="Dashboard page" color={theme.human}>
          {crewApp.pages.map((p) => (
            <div key={p.route}>
              {p.route} <span style={{color: theme.muted}}>· {p.label}</span>
            </div>
          ))}
        </Section>
      </Panel>

      <Panel x={864} y={64} w={992} h={856} title="franken chaos run --runs 20" bodyStyle={{padding: '26px 32px'}}>
        <Terminal lines={lines} maxLines={11} prompt="franken chaos run --runs 20" promptAt={4} />
        <div
          style={{
            position: 'absolute',
            left: 32,
            right: 32,
            bottom: 30,
            opacity: fadeIn(frame, passesAt - 4, 12),
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
          }}
        >
          <Chip color={theme.sentinel} style={{fontSize: 40, alignSelf: 'flex-start', padding: '10px 24px'}}>
            {summary.split(' ')[0].replace('passed=', '')} passed · {summary.split(' ')[1]}
          </Chip>
          <div style={{fontFamily: mono, fontSize: 30, color: theme.muted}}>{summary.split(' ').slice(2).join('  ')}</div>
        </div>
      </Panel>
    </AbsoluteFill>
  );
};
