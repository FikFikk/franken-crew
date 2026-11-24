// Akses bertipe ke replay.json (output `franken lab simulate`) dan app.json
import app from './data/app.json';
import replay from './data/replay.json';

type Incident = (typeof replay.incidents)[number];
export type ReplayEvent = Incident['events'][number];

const byScenario = (scenario: string): Incident => {
  const inc = replay.incidents.find((i) => i.scenario === scenario);
  if (!inc) throw new Error(`replay.json has no ${scenario} incident; run npm run data`);
  return inc;
};

export const node = replay.node;
export const heapLeak = byScenario('heap_leak');
export const injection = byScenario('prompt_injection');

export const eventOf = (inc: Incident, kind: string): ReplayEvent => {
  const e = inc.events.find((ev) => ev.kind === kind);
  if (!e) throw new Error(`${inc.id} has no ${kind} event`);
  return e;
};

// Format waktu relatif seperti di Graveyard: T+1:04, T-0:15
export const tLabel = (t: number): string => {
  const s = Math.round(Math.abs(t));
  return `T${t < 0 ? '-' : '+'}${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};

export const crewApp = {
  agents: app.agents.map((p) => p.replace(/^.*\//, '').replace(/\.json$/, '')),
  crons: app.crons.map((c) => ({
    name: c.name,
    schedule: 'every' in c ? `every ${c.every} s` : 'cron_expr' in c ? String(c.cron_expr) : '',
  })),
  mcpServers: Object.keys(app.mcpServers),
  pages: app.ui.pages.map((p) => ({route: p.route, label: p.label})),
};
