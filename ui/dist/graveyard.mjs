// FrankenCrew Graveyard: interactive incident replay (frankencrew.replay/v1).
// Framework-free; renders into an open shadow root so host styles cannot interfere.

import { h, s, put, clamp, countUpTo, niceCeil, fmtClock, fmtDuration, fmtMs, fmtRel, copyText, downloadText, waText, MiB } from './dom.mjs';
import { css } from './styles.mjs';
import { renderMarkdown } from './markdown.mjs';
import { LANES, createStage, sparkline } from './chart.mjs';

export const SCHEMA = 'frankencrew.replay/v1';
export const DEFAULT_DATA_URL = new URL('../data/replay.json', import.meta.url).href;

const REPO = 'https://github.com/FikFikk/franken-crew';
const BUDGET_MS = 250; // requirements.md: at most one L1 action within 250 ms of detection.
const SPEEDS = [1, 2, 4, 8];
const LAPSE_GAP = 5; // Time-lapse stops this many incident seconds before the next event.
const LAPSE_SPEED = 12;
const PIPELINE = ['DETECTED', 'REFLEX_APPLIED', 'TRIAGING', 'PLANNED', 'WAITING_APPROVAL', 'REMEDIATING', 'VERIFYING'];
const STATE_BY_KIND = {
  'incident.opened': 'DETECTED',
  'reflex.applied': 'REFLEX_APPLIED',
  'incident.claimed': 'TRIAGING',
  'plan.accepted': 'PLANNED',
  'poll.sent': 'WAITING_APPROVAL',
  'action.executed': 'REMEDIATING',
  'verify.started': 'VERIFYING',
  'incident.resolved': 'RESOLVED',
  'incident.escalated': 'ESCALATED',
};

const byTime = (a, b) => a.t - b.t;

/** Validates a replay document and returns a copy with events and messages sorted by time. */
export function normalizeReplay(data) {
  if (!data || data.schema !== SCHEMA || !Array.isArray(data.incidents)) {
    throw new Error(`unsupported replay data (expected schema ${SCHEMA})`);
  }
  return {
    ...data,
    incidents: data.incidents.map((inc) => ({
      ...inc,
      events: (inc.events || []).filter((e) => Number.isFinite(e.t)).slice().sort(byTime),
      messages: (inc.messages || []).filter((m) => Number.isFinite(m.t)).slice().sort(byTime),
      series: inc.series || { limit_bytes: 0, points: [] },
    })),
  };
}

export async function loadReplay(url = DEFAULT_DATA_URL, { signal } = {}) {
  const res = await fetch(url, { signal, cache: 'no-cache', headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`could not load ${url} (HTTP ${res.status})`);
  return normalizeReplay(await res.json());
}

/** Headline numbers for a replay, used by the landing page hero. */
export function summarize(replay) {
  const incs = normalizeReplay(replay).incidents;
  const lat = incs.map((i) => i.reflex_latency_ms).filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  const mid = lat.length >> 1;
  const median = lat.length ? (lat.length % 2 ? lat[mid] : (lat[mid - 1] + lat[mid]) / 2) : NaN;
  const executed = incs.filter((i) => i.events.some((e) => e.kind === 'action.executed'));
  const approved = executed.filter((i) => {
    const firstExec = i.events.find((e) => e.kind === 'action.executed');
    return i.events.some((e) => e.kind === 'vote.granted' && e.t <= firstExec.t);
  });
  return {
    node: replay.node || '',
    sourceKind: replay.source?.kind || 'simulation',
    sourceLabel: replay.source?.label || '',
    incidents: incs.length,
    resolved: incs.filter((i) => i.state === 'RESOLVED').length,
    escalated: incs.filter((i) => i.state === 'ESCALATED').length,
    blocked: incs.reduce((n, i) => n + (i.stats?.blocked || 0), 0),
    reflexMedianMs: median,
    reflexMaxMs: lat.length ? lat[lat.length - 1] : NaN,
    l2Runs: executed.length,
    l2Approved: approved.length,
  };
}

function stateTimeline(events) {
  const out = [];
  for (const e of events) {
    let st = null;
    if (e.kind === 'state' || e.kind === 'incident.claimed') {
      const m = /([A-Z_]{4,})\s*→\s*([A-Z_]{4,})/.exec(`${e.title || ''} ${e.detail || ''}`);
      st = m ? m[2] : null;
    }
    st = st || STATE_BY_KIND[e.kind] || null;
    if (st && (!out.length || out[out.length - 1].state !== st)) out.push({ t: e.t, state: st });
  }
  return out;
}

function stateAt(states, t) {
  let st = null;
  for (const x of states) {
    if (x.t <= t + 1e-6) st = x.state;
    else break;
  }
  return st;
}

/** Derives the time window, scales, and milestones for one incident. */
function prepare(inc) {
  const events = inc.events;
  const all = (inc.series?.points || []).filter((p) => Array.isArray(p) && p.length >= 4 && p.every(Number.isFinite)).sort((a, b) => a[0] - b[0]);
  const firstT = events.length ? events[0].t : 0;
  const tEnd = Math.max(events.length ? events[events.length - 1].t : Number(inc.duration_s) || 0, 0);
  const seriesStart = all.length ? all[0][0] : firstT - 45;
  const tMin = Math.max(seriesStart, Math.min(firstT, 0) - 45);
  const tMax = tEnd + Math.max(4, (tEnd - tMin) * 0.025);
  const points = all.filter((p) => p[0] >= tMin - 1 && p[0] <= tMax + 1);
  const limit = Number(inc.series?.limit_bytes) || 0;
  const peak = points.reduce((m, p) => Math.max(m, p[1]), 0);
  const memMax = limit > 0 ? Math.max(limit * 1.16, peak * 1.05) : niceCeil((peak * 1.2) / MiB) * MiB;
  const psiPeak = points.reduce((m, p) => Math.max(m, p[2], p[3]), 0);
  const find = (kind) => events.find((e) => e.kind === kind) || null;
  const poll = inc.poll && Number.isFinite(inc.poll.t) ? inc.poll : null;
  const vote = find('vote.granted') || (poll && Number.isFinite(poll.voted_t) ? { t: poll.voted_t } : null);
  return {
    inc,
    events,
    points,
    tMin,
    tMax,
    tEnd,
    tStart: Math.max(tMin, Math.min(firstT, 0) - 6),
    limit,
    memMax,
    psiMax: Math.max(5, niceCeil(psiPeak * 1.15)),
    states: stateTimeline(events),
    reflexLabel: fmtMs(inc.reflex_latency_ms),
    marks: {
      opened: find('incident.opened'),
      reflex: find('reflex.applied'),
      poll: poll ? { t: poll.t } : find('poll.sent'),
      vote,
      exec: find('action.executed'),
      verifyStart: find('verify.started'),
      verifyEnd: find('verify.passed') || find('verify.failed'),
    },
  };
}

const ICONS = {
  play: 'M8 5.5v13l11-6.5z',
  pause: 'M7 5h3.5v14H7zM13.5 5H17v14h-3.5z',
  prev: 'M6 6h2.2v12H6zM9.6 12 18 18V6z',
  next: 'M15.8 6H18v12h-2.2zM14.4 12 6 6v12z',
  restart: 'M12 5a7 7 0 1 1-6.6 4.7l1.9.7A5 5 0 1 0 12 7v3L7.5 6 12 2z',
};

const GLYPHS = {
  bolt: ['0 0 24 24', 'M13 2 4 14h7l-1 8 9-12h-7z', 'currentColor', 'none'],
  left: ['0 0 24 24', 'M15 5 8 12l7 7', 'none', 'currentColor'],
  right: ['0 0 24 24', 'M9 5l7 7-7 7', 'none', 'currentColor'],
  read: ['0 0 28 20', 'M2 11l4.5 4.5L15 6M12 15.5 13.5 17 24 6', 'none', 'currentColor'],
};

/** Small inline icons, so the UI never depends on emoji or symbol font coverage. */
function glyph(name) {
  const [box, d, fill, stroke] = GLYPHS[name];
  return s('svg', { class: 'ic', viewBox: box, fill, stroke, 'stroke-width': '2.6', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
    s('path', { d }));
}

function icon(name) {
  return s('svg', { viewBox: '0 0 24 24', fill: 'currentColor', 'aria-hidden': 'true' }, s('path', { d: ICONS[name] }));
}

function logo() {
  return s('svg', { width: '22', height: '22', viewBox: '0 0 24 24', fill: 'none', stroke: '#5cffa1', 'stroke-width': '1.7',
    'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
  s('path', { d: 'M12 2.6c-4.6 0-7.9 3.1-7.9 7.5 0 2.6 1.2 4.4 3 5.5V19c0 .8.7 1.5 1.5 1.5h6.8c.8 0 1.5-.7 1.5-1.5v-3.4c1.8-1.1 3-2.9 3-5.5 0-4.4-3.3-7.5-7.9-7.5z' }),
  s('circle', { cx: '8.9', cy: '10.6', r: '1.7', fill: '#5cffa1', stroke: 'none' }),
  s('circle', { cx: '15.1', cy: '10.6', r: '1.7', fill: '#5cffa1', stroke: 'none' }),
  s('path', { d: 'M12.7 13.2 11 15.6h2l-1.4 2.3' }));
}

function epitaph(inc) {
  if (inc.state === 'RESOLVED') return `Laid to rest after ${fmtDuration(inc.duration_s)}`;
  if (inc.state === 'ESCALATED') return `Woke a human after ${fmtDuration(inc.duration_s)}`;
  return String(inc.state || '').toLowerCase();
}

class Graveyard {
  constructor(root, opts) {
    this.root = root;
    this.opts = opts;
    this.reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.speed = SPEEDS.includes(opts.speed) ? opts.speed : 2;
    this.lapse = opts.timeLapse !== false;
    this.t = 0;
    this.sel = -1;
    this.wantPlay = false;
    this.playing = false;
    this.userControl = false;
    this.visible = typeof IntersectionObserver !== 'function';
    this.timers = new Map();
    this.abort = typeof AbortController === 'function' ? new AbortController() : null;
    this.app = h('div', { class: 'app', role: 'region', tabindex: '-1', 'aria-label': 'FrankenCrew Graveyard: incident replays' });
    this.app.addEventListener('keydown', (e) => this.onKey(e));
    root.append(this.app);
  }

  async start() {
    put(this.app, this.renderTop(null),
      h('div', { class: 'loading', role: 'status' }, h('div', { class: 'bars', 'aria-hidden': 'true' }, h('i'), h('i'), h('i')), 'Exhuming incident replays…'));
    let data;
    try {
      data = this.opts.replay ? normalizeReplay(this.opts.replay) : await loadReplay(this.opts.dataUrl || DEFAULT_DATA_URL, { signal: this.abort?.signal });
      if (!data.incidents.length) throw new Error('the replay file contains no incidents');
    } catch (err) {
      if (this.destroyed || err?.name === 'AbortError') return;
      put(this.app, this.renderTop(null), h('div', { class: 'failed', role: 'alert' },
        h('b', null, 'The Graveyard is empty'),
        h('p', null, String(err?.message || err)),
        h('p', null, 'Generate a replay with ', h('code', null, 'franken lab simulate --out ui/data/replay.json'),
          ' or export real incidents with ', h('code', null, 'franken lab export --db franken-sentinel.db --out replay.json'), '.')));
      return;
    }
    if (this.destroyed) return;
    this.data = data;
    this.build();
    this.observe();
    this.select(clamp(Number(this.opts.incident) || 0, 0, data.incidents.length - 1), { autoplay: true });
  }

  renderTop(data) {
    const kind = data ? (data.source?.kind === 'recording' ? 'recording' : 'simulation') : null;
    return h('header', { class: 'top' },
      h('div', { class: 'brand' },
        h('div', { class: 'logo' }, logo()),
        h('div', null,
          h('h2', null, 'The Graveyard'),
          h('p', null, 'Incidents FrankenCrew has put to rest, replayed from the Sentinel audit trail.'))),
      kind && h('div', { class: 'source' },
        h('span', { class: `badge ${kind}` }, kind === 'recording' ? 'Recording' : 'Simulation'),
        h('span', null, data.source?.label || ''),
        data.node && h('span', null, '· node ', h('code', null, data.node))),
      data?.source?.detail && h('details', { class: 'about' }, h('summary', null, 'About this data'), h('p', null, data.source.detail)));
  }

  build() {
    const d = this.data;
    const list = h('nav', { class: 'list', 'aria-label': 'Replayed incidents' }, h('div', { class: 'list-title' }, `${d.incidents.length} graves`));
    this.tombs = d.incidents.map((inc, i) => {
      const bad = inc.state !== 'RESOLVED';
      const tomb = h('button', {
        type: 'button', class: ['tomb', bad && 'bad'], 'aria-current': 'false',
        'aria-label': `${inc.title}, ${inc.state}, ${fmtDuration(inc.duration_s)}`,
        onClick: () => {
          this.takeControl();
          this.select(i, { autoplay: true });
        },
      },
      h('div', { class: 'tomb-row' }, h('span', { class: `pill ${bad ? 'bad' : 'ok'}` }, inc.state), h('span', { class: 'sev' }, inc.severity)),
      h('div', { class: 'tomb-title' }, inc.title),
      h('div', { class: 'tomb-id' }, inc.id),
      sparkline(inc.series?.points),
      h('div', { class: 'epitaph' }, epitaph(inc)),
      h('div', { class: 'tomb-meta' },
        h('span', null, glyph('bolt'), ` ${fmtMs(inc.reflex_latency_ms)}`),
        h('span', null, `${inc.events.length} events`),
        inc.stats?.blocked ? h('span', null, `${inc.stats.blocked} blocked`) : null));
      list.append(tomb);
      return tomb;
    });

    this.headEl = h('div', { class: 'inc-head' });
    this.statsEl = h('div', { class: 'stats' });
    this.pipeEl = h('ol', { class: 'pipeline', 'aria-label': 'Incident state' });
    this.stage = createStage({
      onSeek: (t) => {
        this.takeControl();
        this.pause();
        this.seek(t);
      },
      onSelect: (i) => {
        this.takeControl();
        this.pause();
        this.selectEvent(i);
      },
    });
    this.liveEl = h('div', { class: 'sr', 'aria-live': 'polite' });
    const main = h('div', { class: 'main' },
      this.headEl, this.statsEl, this.pipeEl, this.buildPlayer(), this.stage.el,
      h('div', { class: 'panels' }, this.buildPhone(), this.buildTerminal(), this.buildNow()),
      this.buildTabs());
    const foot = h('footer', { class: 'foot' },
      h('span', null, `${d.schema} · generated ${d.generated_at || 'n/a'}`),
      h('span', null, 'Hollow dots and ~ lines are reconstructed from the Crew protocol, not logged events. ',
        h('a', { href: `${REPO}#incident-replay-dashboard`, target: '_blank', rel: 'noopener noreferrer' }, 'How replays are made')));
    put(this.app, this.renderTop(d), h('div', { class: 'layout' }, list, main), foot, this.liveEl);
  }

  buildPlayer() {
    const ctl = (name, label, fn) => h('button', { type: 'button', class: 'btn', 'aria-label': label, title: label, onClick: () => {
      this.takeControl();
      fn();
    } }, icon(name));
    this.playBtn = h('button', { type: 'button', class: 'btn primary', 'aria-label': 'Play', title: 'Play (Space)', onClick: () => {
      this.takeControl();
      if (this.wantPlay) this.pause();
      else this.play();
    } }, icon('play'));
    this.speedBtns = SPEEDS.map((sp) => h('button', { type: 'button', 'aria-pressed': String(sp === this.speed), 'aria-label': `${sp} times speed`,
      onClick: () => this.setSpeed(sp) }, `${sp}×`));
    this.scrub = h('input', { class: 'scrub', type: 'range', min: '0', max: '1', step: '0.1', value: '0', 'aria-label': 'Replay position',
      onInput: (e) => {
        this.takeControl();
        this.pause();
        this.seek(Number(e.target.value));
      } });
    this.clockRel = h('span', null, 'T+0:00');
    this.clockAbs = h('span', { class: 'abs' });
    this.lapseEl = h('span', { class: 'lapse', 'aria-hidden': 'true' }, `time-lapse ${LAPSE_SPEED}×`);
    const quiet = h('input', { type: 'checkbox', checked: this.lapse, onChange: (e) => {
      this.lapse = e.target.checked;
    } });
    return h('div', { class: 'player', role: 'group', 'aria-label': 'Replay controls' },
      ctl('restart', 'Restart replay (R)', () => this.restart()),
      ctl('prev', 'Previous event (Left arrow)', () => this.step(-1)),
      this.playBtn,
      ctl('next', 'Next event (Right arrow)', () => this.step(1)),
      h('div', { class: 'speeds', role: 'group', 'aria-label': 'Playback speed' }, this.speedBtns),
      this.scrub,
      h('div', { class: 'clock', 'aria-hidden': 'true' }, this.clockRel, this.clockAbs),
      this.lapseEl,
      h('label', { class: 'quiet' }, quiet, 'Skip quiet time'),
      h('span', { class: 'keys', 'aria-hidden': 'true' }, h('kbd', null, 'Space'), ' play  ', h('kbd', null, glyph('left')), h('kbd', null, glyph('right')), ' events  ',
        h('kbd', null, 'R'), ' restart'));
  }

  buildPhone() {
    this.msgsEl = h('div', { class: 'msgs', role: 'log', 'aria-label': 'Operator chat messages' });
    return h('section', { class: 'card phone', 'aria-label': 'Operator phone' },
      h('div', { class: 'card-head' }, h('h4', null, 'Operator phone'), h('span', null, 'WhatsApp group via wa-bridge')),
      h('div', { class: 'screen' },
        h('div', { class: 'chat-head' }, h('div', { class: 'avatar', 'aria-hidden': 'true' }, 'FC'),
          h('div', null, h('b', null, 'FrankenCrew Ops'), h('small', null, 'bot · allowlisted admins only'))),
        this.msgsEl));
  }

  buildTerminal() {
    this.termEl = h('div', { class: 'term-screen', role: 'log', tabindex: '0', 'aria-label': 'Flight recorder: every event in order' });
    return h('section', { class: 'card term', 'aria-label': 'Flight recorder' },
      h('div', { class: 'card-head' }, h('h4', null, 'Flight recorder'), h('span', null, 'kernel · sentinel · crew · human · verify')),
      this.termEl);
  }

  buildNow() {
    this.evEl = h('div', { class: 'ev' });
    this.gaugeEl = h('div', { class: 'gauge' });
    return h('section', { class: 'card evcard', 'aria-label': 'Selected event and reflex latency' },
      h('div', null, h('div', { class: 'card-head' }, h('h4', null, 'Event'), h('span', null, 'click a dot or a log line')), this.evEl),
      this.gaugeEl);
  }

  buildTabs() {
    const defs = [['postmortem', 'Postmortem'], ['log', 'Event log'], ['raw', 'Raw JSON']];
    const list = h('div', { class: 'tablist', role: 'tablist', 'aria-label': 'Incident details' });
    this.tabBtns = {};
    this.tabPanels = {};
    const panels = defs.map(([id, label], i) => {
      this.tabBtns[id] = h('button', {
        type: 'button', class: 'tab', role: 'tab', id: `tab-${id}`, 'aria-controls': `panel-${id}`,
        'aria-selected': String(i === 0), tabindex: i === 0 ? '0' : '-1', onClick: () => this.showTab(id),
      }, label);
      list.append(this.tabBtns[id]);
      this.tabPanels[id] = h('div', { class: 'tabpanel', role: 'tabpanel', id: `panel-${id}`, 'aria-labelledby': `tab-${id}`, hidden: i !== 0 });
      return this.tabPanels[id];
    });
    list.addEventListener('keydown', (e) => {
      const ids = defs.map(([id]) => id);
      const cur = ids.findIndex((id) => this.tabBtns[id].getAttribute('aria-selected') === 'true');
      let next = -1;
      if (e.key === 'ArrowRight') next = (cur + 1) % ids.length;
      else if (e.key === 'ArrowLeft') next = (cur - 1 + ids.length) % ids.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = ids.length - 1;
      if (next < 0) return;
      e.preventDefault();
      e.stopPropagation();
      this.showTab(ids[next]);
      this.tabBtns[ids[next]].focus();
    });
    return h('section', { class: 'tabs', 'aria-label': 'Postmortem and raw data' }, list, panels);
  }

  showTab(id) {
    for (const [key, btn] of Object.entries(this.tabBtns)) {
      const on = key === id;
      btn.setAttribute('aria-selected', String(on));
      btn.setAttribute('tabindex', on ? '0' : '-1');
      this.tabPanels[key].hidden = !on;
    }
  }

  observe() {
    if (typeof IntersectionObserver !== 'function') return;
    this.io = new IntersectionObserver((entries) => {
      const vis = entries.some((e) => e.isIntersecting);
      this.visible = vis;
      if (!vis) this.suspend();
      else if (this.wantPlay && !this.playing) this.resume();
    }, { threshold: 0.2 });
    this.io.observe(this.app);
  }

  select(i, { autoplay = false } = {}) {
    this.pause();
    this.clearLater('advance');
    this.index = i;
    this.model = prepare(this.data.incidents[i]);
    this.tombs.forEach((b, k) => b.setAttribute('aria-current', String(k === i)));
    this.shown = { events: -1, msgs: -1, state: undefined, voted: undefined, sel: -2 };
    this.termCount = 0;
    this.chatCount = 0;
    this.pollOpts = null;
    this.renderHead();
    this.renderStats();
    this.renderGauge();
    this.renderPostmortem();
    this.renderLog();
    this.renderRaw();
    this.stage.setModel(this.model);
    this.scrub.min = String(this.model.tMin);
    this.scrub.max = String(this.model.tEnd);
    // Reduced motion: show the whole incident at once and never start playback on our own.
    this.seek(this.reduced ? this.model.tEnd : this.model.tStart);
    if (autoplay && !this.reduced && this.opts.autoplay !== false) this.play();
  }

  seek(t) {
    const m = this.model;
    this.t = clamp(t, m.tMin, m.tEnd);
    this.renderTime();
  }

  renderTime() {
    const m = this.model;
    const t = this.t;
    const n = countUpTo(m.events, t);
    if (n !== this.shown.events) {
      this.sel = n - 1;
      this.renderTerminal(n, n > this.shown.events && this.shown.events >= 0);
      this.shown.events = n;
    }
    const k = countUpTo(m.inc.messages, t);
    if (k !== this.shown.msgs) {
      this.renderChat(k, k > this.shown.msgs && this.shown.msgs >= 0);
      this.shown.msgs = k;
    }
    const poll = m.inc.poll;
    const voted = Boolean(poll && Number.isFinite(poll.voted_t) && t >= poll.voted_t - 1e-6);
    if (voted !== this.shown.voted) {
      this.shown.voted = voted;
      this.updatePoll(voted);
    }
    const st = stateAt(m.states, t);
    if (st !== this.shown.state) {
      this.shown.state = st;
      this.renderPipeline(st);
      if (this.playing && st) this.announce(`${st.replace(/_/g, ' ').toLowerCase()} at ${fmtRel(t)}`);
    }
    if (this.sel !== this.shown.sel) {
      this.renderSelection();
      this.shown.sel = this.sel;
    }
    this.stage.update(t, this.sel);
    const span = m.tEnd - m.tMin || 1;
    this.scrub.value = String(t);
    this.scrub.style.setProperty('--p', `${((t - m.tMin) / span) * 100}%`);
    this.scrub.setAttribute('aria-valuetext', `${fmtRel(t)}, ${fmtClock(m.inc.opened_at, t)} UTC`);
    this.clockRel.textContent = fmtRel(t);
    this.clockAbs.textContent = `${fmtClock(m.inc.opened_at, t)} UTC`;
  }

  play() {
    if (!this.model) return;
    this.clearLater('advance');
    if (this.t >= this.model.tEnd - 1e-6) this.seek(this.model.tStart);
    this.wantPlay = true;
    this.updatePlayButton();
    if (this.visible) this.resume();
  }

  pause() {
    this.wantPlay = false;
    this.suspend();
    this.updatePlayButton();
  }

  resume() {
    if (this.playing || this.destroyed) return;
    this.playing = true;
    this.lastFrame = 0;
    this.frame = requestAnimationFrame(this.loop);
  }

  suspend() {
    this.playing = false;
    cancelAnimationFrame(this.frame);
    this.lapseEl?.classList.remove('on');
  }

  loop = (now) => {
    if (!this.playing) return;
    const dt = this.lastFrame ? Math.min(0.1, (now - this.lastFrame) / 1000) : 0;
    this.lastFrame = now;
    const m = this.model;
    const next = m.events[countUpTo(m.events, this.t)];
    const lapsing = this.lapse && next !== undefined && next.t - this.t > LAPSE_GAP;
    let nt = this.t + dt * (lapsing ? Math.max(this.speed, LAPSE_SPEED) : this.speed);
    if (lapsing) nt = Math.min(nt, next.t - LAPSE_GAP);
    this.lapseEl.classList.toggle('on', lapsing);
    if (nt >= m.tEnd - 1e-6) {
      this.seek(m.tEnd);
      this.finish();
      return;
    }
    this.seek(nt);
    this.frame = requestAnimationFrame(this.loop);
  };

  finish() {
    this.pause();
    const inc = this.model.inc;
    this.announce(`${inc.id} ${String(inc.state).toLowerCase()} after ${fmtDuration(inc.duration_s)}`);
    // Guided tour: until someone touches the controls, move on to the next grave.
    if (!this.userControl && this.opts.tour !== false && this.data.incidents.length > 1) {
      this.later('advance', () => this.select((this.index + 1) % this.data.incidents.length, { autoplay: true }), 5000);
    }
  }

  updatePlayButton() {
    if (!this.playBtn) return;
    const label = this.wantPlay ? 'Pause' : 'Play';
    this.playBtn.setAttribute('aria-label', label);
    this.playBtn.setAttribute('title', `${label} (Space)`);
    put(this.playBtn, icon(this.wantPlay ? 'pause' : 'play'));
  }

  restart() {
    this.seek(this.model.tStart);
    this.play();
  }

  setSpeed(sp) {
    this.speed = sp;
    this.speedBtns.forEach((b, i) => b.setAttribute('aria-pressed', String(SPEEDS[i] === sp)));
  }

  step(dir) {
    const target = this.sel + dir;
    if (target < 0) {
      this.pause();
      this.seek(this.model.tStart);
      return;
    }
    if (target >= this.model.events.length) return;
    this.pause();
    this.selectEvent(target);
  }

  selectEvent(i) {
    const e = this.model.events[i];
    if (!e) return;
    this.seek(e.t);
    this.sel = i;
    this.renderSelection();
    this.shown.sel = i;
    this.stage.update(this.t, i);
  }

  takeControl() {
    this.userControl = true;
    this.clearLater('advance');
  }

  later(key, fn, ms) {
    this.clearLater(key);
    this.timers.set(key, setTimeout(() => {
      this.timers.delete(key);
      if (!this.destroyed) fn();
    }, ms));
  }

  clearLater(key) {
    clearTimeout(this.timers.get(key));
    this.timers.delete(key);
  }

  announce(text) {
    if (this.liveEl) this.liveEl.textContent = text;
  }

  onKey(e) {
    if (!this.model || e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey) return;
    const target = e.composedPath()[0];
    const el = target instanceof Element ? target : null;
    const typing = el?.closest('input, textarea, select');
    const control = el?.closest('button, a, summary, [role="tab"]');
    if (e.key === ' ' || e.key === 'k') {
      if (typing || (control && e.key === ' ')) return;
      this.takeControl();
      if (this.wantPlay) this.pause();
      else this.play();
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      if (typing || el?.closest('[role="tablist"]')) return;
      this.takeControl();
      const dir = e.key === 'ArrowLeft' ? -1 : 1;
      if (e.shiftKey) {
        this.pause();
        this.seek(this.t + dir * 10);
      } else {
        this.step(dir);
      }
    } else if (e.key === 'r' || e.key === 'R') {
      if (typing) return;
      this.takeControl();
      this.restart();
    } else {
      return;
    }
    e.preventDefault();
  }

  destroy() {
    this.destroyed = true;
    this.abort?.abort();
    this.suspend();
    for (const id of this.timers.values()) clearTimeout(id);
    this.timers.clear();
    this.io?.disconnect();
    this.stage?.destroy();
    this.app.remove();
  }

  renderHead() {
    const inc = this.model.inc;
    const chip = (k, v) => h('span', { class: 'chip' }, h('span', { class: 'k' }, k), v);
    const conf = Number.isFinite(inc.confidence) ? ` · ${Math.round(inc.confidence * 100)}%` : '';
    put(this.headEl,
      h('div', { class: 'eyebrow' }, `${inc.id} · opened ${String(inc.opened_at || '').replace('T', ' ').replace('Z', ' UTC')}`),
      h('h3', null, inc.title),
      h('div', { class: 'chips' },
        chip('severity', inc.severity),
        chip('class', `${inc.class || 'unknown'}${conf}`),
        inc.unit && chip('unit', h('code', null, inc.unit)),
        inc.cgroup && chip('cgroup', h('code', null, inc.cgroup)),
        inc.plan_hash && chip('plan', h('code', null, String(inc.plan_hash).slice(0, 8)))),
      inc.triage_summary && h('p', { class: 'triage' }, inc.triage_summary));
  }

  renderStats() {
    const inc = this.model.inc;
    const p = inc.poll;
    const human = p && Number.isFinite(p.voted_t) && Number.isFinite(p.t) ? p.voted_t - p.t : NaN;
    const resolved = inc.state === 'RESOLVED';
    const stat = (v, l, cls, title) => h('div', { class: ['stat', cls], title }, h('div', { class: 'v' }, v), h('div', { class: 'l' }, l));
    put(this.statsEl,
      stat(fmtMs(inc.reflex_latency_ms), 'L1 reflex latency', 'good', 'Triggering sample to applied reflex, measured in the Sentinel process'),
      stat(Number.isFinite(inc.tto_seconds) ? `${Math.round(inc.tto_seconds)} s` : '–', 'projected time to OOM', 'warn', 'Detector estimate when the incident opened'),
      stat(Number.isFinite(human) ? fmtDuration(human) : '–', 'human decision', null, 'Approval poll sent to vote received'),
      stat(fmtDuration(inc.duration_s), resolved ? 'detect to resolved' : 'detect to escalated', resolved ? 'good' : 'bad'),
      stat(String(inc.stats?.blocked ?? 0), 'unsafe actions blocked', inc.stats?.blocked ? 'warn' : null,
        'Policy rejections, protected-target blocks, and replayed step tokens'),
      stat(`${inc.stats?.reflexes ?? 0} / ${inc.stats?.l2_steps ?? 0}`, 'L1 reflexes / L2 steps', null));
  }

  renderPipeline(st) {
    const m = this.model;
    const seen = new Set(m.states.map((x) => x.state));
    const chips = ['WATCHING', ...PIPELINE.filter((p) => seen.has(p))];
    if (m.inc.state && !chips.includes(m.inc.state)) chips.push(m.inc.state);
    const cur = st ? chips.indexOf(st) : 0;
    put(this.pipeEl, ...chips.map((name, i) => {
      const now = i === cur;
      const bad = now && (name === 'ESCALATED' || name === 'FAILED');
      return h('li', { class: [i < cur && 'done', now && 'now', bad && 'bad', name === 'WATCHING' && !now && 'pre'], 'aria-current': now ? 'step' : undefined },
        name.replace(/_/g, ' '));
    }));
  }

  renderSelection() {
    const m = this.model;
    const e = m.events[this.sel];
    for (const n of this.termEl.querySelectorAll('.ln.sel')) n.classList.remove('sel');
    if (!e) {
      this.evEl.className = 'ev';
      put(this.evEl,
        h('div', { class: 'k' }, h('span', null, 'pre-incident')),
        h('div', { class: 'ttl' }, 'Sentinel watching'),
        h('div', { class: 'd' }, 'Sampling memory.current, PSI, and memory.events once per second. Nothing has crossed a threshold yet.'));
      return;
    }
    this.termEl.querySelector(`.ln[data-i="${this.sel}"]`)?.classList.add('sel');
    this.evEl.className = `ev lane-${e.lane}`;
    put(this.evEl,
      h('div', { class: 'k' },
        h('b', null, e.lane),
        h('span', null, `${fmtRel(e.t)} · ${fmtClock(m.inc.opened_at, e.t)} UTC`),
        h('code', null, e.kind),
        e.inferred && h('span', { class: 'inf' }, 'INFERRED')),
      h('div', { class: 'ttl' }, e.title),
      h('div', { class: 'd' }, h('code', null, e.actor), ' ', e.detail || ''),
      e.inferred && h('div', { class: 'd' }, 'Reconstructed from the conductor and remediator protocol. The Sentinel does not log Crew-internal steps, so this line is shown for context only.'),
      h('div', { class: 'ev-nav' },
        h('button', { type: 'button', class: 'btn small', disabled: this.sel <= 0, onClick: () => {
          this.takeControl();
          this.step(-1);
        } }, 'Previous'),
        h('button', { type: 'button', class: 'btn small', disabled: this.sel >= m.events.length - 1, onClick: () => {
          this.takeControl();
          this.step(1);
        } }, 'Next'),
        h('span', { class: 'keys' }, `${this.sel + 1} / ${m.events.length}`)));
  }

  renderTerminal(n, append) {
    const ev = this.model.events;
    if (!append) {
      this.termEl.replaceChildren();
      this.termCount = 0;
    }
    this.cursor?.remove();
    this.termEl.querySelector('.idle')?.remove();
    for (let i = this.termCount; i < n; i++) this.termEl.append(this.renderLine(ev[i], i));
    this.termCount = n;
    if (n === 0) {
      this.termEl.append(h('div', { class: 'ln lane-sentinel idle' }, h('span', { class: 'ts' }, '--:--:--'), h('span', { class: 'who' }, 'franken-sentinel'),
        h('span', { class: 'what' }, 'watching memory.pressure, memory.events, and PSI…')));
    }
    this.cursor = this.cursor || h('span', { class: 'cursor', 'aria-hidden': 'true' });
    this.termEl.append(this.cursor);
    this.termEl.scrollTop = this.termEl.scrollHeight;
  }

  renderLine(e, i) {
    const line = h('div', {
      class: ['ln', `lane-${e.lane}`, e.inferred && 'inferred', `lvl-${e.level}`], dataset: { i },
      title: e.inferred ? 'Inferred: reconstructed from the Crew protocol, not a logged event' : undefined,
    },
    h('span', { class: 'ts' }, fmtClock(this.model.inc.opened_at, e.t)),
    h('span', { class: 'who' }, e.actor),
    h('span', { class: 'what' }, e.title),
    e.detail && h('span', { class: 'why' }, e.detail));
    line.addEventListener('click', () => {
      this.takeControl();
      this.pause();
      this.selectEvent(i);
    });
    return line;
  }

  renderChat(k, append) {
    const msgs = this.model.inc.messages;
    if (!append) {
      this.msgsEl.replaceChildren();
      this.chatCount = 0;
      this.pollOpts = null;
    }
    this.msgsEl.querySelector('.empty')?.remove();
    for (let i = this.chatCount; i < k; i++) this.msgsEl.append(this.renderMessage(msgs[i]));
    this.chatCount = k;
    if (k === 0) this.msgsEl.append(h('div', { class: 'empty' }, 'Quiet. wa-bridge posts here when the Sentinel opens an incident.'));
    this.msgsEl.scrollTop = this.msgsEl.scrollHeight;
  }

  renderMessage(m) {
    const inc = this.model.inc;
    const me = m.from === 'operator';
    const meta = h('span', { class: 'meta' }, fmtClock(inc.opened_at, m.t), me && glyph('read'));
    if (m.kind === 'poll' && inc.poll && Array.isArray(inc.poll.options)) {
      const p = inc.poll;
      this.pollOpts = p.options.map((o) => h('div', { class: 'opt' },
        h('span', { class: 'radio', 'aria-hidden': 'true' }), h('span', null, o), h('span', { class: 'votes' }, '0'), h('span', { class: 'bar' }, h('i'))));
      this.voterEl = h('div', { class: 'voter' });
      const el = h('div', { class: 'msg poll' },
        h('span', { class: 'from' }, 'FrankenCrew bot'),
        h('span', { class: 'poll-tag' }, 'POLL · choose one'),
        h('div', { class: 'poll-q' }, waText(p.title || m.text)),
        this.pollOpts, this.voterEl, meta);
      this.updatePoll(Boolean(this.shown.voted));
      return el;
    }
    const who = me ? 'Operator · allowlisted admin' : 'FrankenCrew bot';
    const body = me && m.kind === 'vote' ? [h('strong', null, 'Voted: '), m.text] : waText(m.text);
    return h('div', { class: ['msg', me && 'me'] }, h('span', { class: 'from' }, who), body, meta);
  }

  updatePoll(voted) {
    if (!this.pollOpts) return;
    const p = this.model.inc.poll;
    this.pollOpts.forEach((o, i) => {
      const chosen = voted && i === p.chosen;
      o.classList.toggle('chosen', chosen);
      o.querySelector('.votes').textContent = chosen ? '1 vote' : '0';
    });
    this.voterEl.textContent = voted
      ? `Voted by ${p.approver || 'an allowlisted admin'} at ${fmtClock(this.model.inc.opened_at, p.voted_t)} · one Ed25519 token minted per step`
      : 'Waiting for an allowlisted admin to vote…';
  }

  renderGauge() {
    const inc = this.model.inc;
    const ms = Number(inc.reflex_latency_ms);
    const lo = Math.log10(0.01);
    const hi = Math.log10(1000);
    const pos = (v) => `${(clamp((Math.log10(v) - lo) / (hi - lo), 0, 1) * 100).toFixed(2)}%`;
    const ok = Number.isFinite(ms) && ms > 0;
    const ratio = ok ? BUDGET_MS / ms : NaN;
    const recorded = this.data.source?.kind === 'recording';
    put(this.gaugeEl,
      h('div', { class: 'g-head' }, h('h4', null, 'L1 reflex latency'), h('span', { class: 'g-val' }, fmtMs(ms))),
      h('div', { class: 'g-track', role: 'img', 'aria-label': `${fmtMs(ms)} measured against a ${BUDGET_MS} millisecond budget, log scale` },
        h('span', { class: 'g-budget', style: { left: pos(BUDGET_MS) } }, h('span', null, `budget ${BUDGET_MS} ms`)),
        ok && h('span', { class: 'g-mark', style: { left: pos(ms) } })),
      h('div', { class: 'g-scale', 'aria-hidden': 'true' }, [0.01, 0.1, 1, 10, 100, 1000].map((v) => h('span', { style: { left: pos(v) } }, v === 1000 ? '1000 ms' : String(v)))),
      h('p', { class: 'g-note' },
        ok ? `${ratio >= 10 ? Math.round(ratio).toLocaleString('en-US') : ratio.toFixed(1)}× inside the ${BUDGET_MS} ms budget of Requirement 3.1 (log scale). ` : '',
        recorded
          ? 'Recorded by the Sentinel (REFLEX_LATENCY audit row): triggering sample to applied reflex.'
          : 'Simulation: in-process Go and SQLite time from the triggering sample to the applied reflex, not kernel-to-reflex latency on hardware.'));
  }

  renderPostmortem() {
    const inc = this.model.inc;
    const md = inc.postmortem_markdown || '';
    const panel = this.tabPanels.postmortem;
    if (!md) {
      put(panel, h('p', { class: 'note' }, 'No postmortem stored for this incident.'));
      return;
    }
    const { root, toc } = renderMarkdown(md, { idPrefix: `pm${this.index}` });
    const body = h('div', { class: 'pm-body', tabindex: '0', 'aria-label': 'Postmortem document' }, root);
    const copyBtn = h('button', { type: 'button', class: 'btn small', onClick: async () => {
      const ok = await copyText(md, this.root);
      copyBtn.textContent = ok ? 'Copied' : 'Copy failed';
      this.later('copy-pm', () => {
        copyBtn.textContent = 'Copy markdown';
      }, 1600);
    } }, 'Copy markdown');
    const dlBtn = h('button', { type: 'button', class: 'btn small', onClick: () => downloadText(`${inc.id}-postmortem.md`, md) }, 'Download .md');
    const tocEl = h('nav', { class: 'toc', 'aria-label': 'Postmortem sections' }, toc.map((item) => h('button', {
      type: 'button', class: item.level === 3 ? 'l3' : undefined, title: item.text,
      onClick: () => {
        const target = root.querySelector(`#${CSS.escape(item.id)}`);
        if (target) body.scrollTo({ top: target.offsetTop - 8, behavior: this.reduced ? 'auto' : 'smooth' });
      },
    }, item.text)));
    put(panel,
      h('div', { class: 'toolbar' }, h('span', { class: 'note grow' }, 'Written by internal/postmortem from the redacted audit trail when the incident closed.'), copyBtn, dlBtn),
      h('div', { class: 'pm' }, tocEl, body));
  }

  renderLog() {
    const m = this.model;
    const active = new Set(LANES.map((l) => l.id));
    const tbody = h('tbody');
    const fill = () => {
      put(tbody, ...m.events.flatMap((e, i) => (active.has(e.lane) ? [h('tr', { class: e.inferred ? 'inferred' : undefined },
        h('td', null, h('button', { type: 'button', title: 'Jump the replay to this event', onClick: () => {
          this.takeControl();
          this.pause();
          this.selectEvent(i);
        } }, fmtRel(e.t))),
        h('td', null, h('span', { class: `lane lane-${e.lane}` }, h('i'), e.lane)),
        h('td', null, h('code', null, e.actor)),
        h('td', null, e.title, e.inferred ? ' (inferred)' : ''),
        h('td', { class: 'd' }, e.detail || ''))] : [])));
    };
    const chips = LANES.map((l) => h('button', { type: 'button', class: `fchip lane-${l.id}`, 'aria-pressed': 'true', onClick: (ev) => {
      if (active.has(l.id)) active.delete(l.id);
      else active.add(l.id);
      ev.currentTarget.setAttribute('aria-pressed', String(active.has(l.id)));
      fill();
    } }, h('i'), l.label));
    fill();
    const inferred = m.events.filter((e) => e.inferred).length;
    put(this.tabPanels.log,
      h('div', { class: 'toolbar' },
        h('div', { class: 'filters', role: 'group', 'aria-label': 'Filter events by lane' }, chips),
        h('span', { class: 'grow' }),
        h('span', { class: 'note' }, `${m.events.length} events · ${inferred} inferred`)),
      h('div', { class: 'log-wrap', tabindex: '0', role: 'region', 'aria-label': 'Event log table' },
        h('table', { class: 'log' },
          h('thead', null, h('tr', null, ['Time', 'Lane', 'Actor', 'Event', 'Detail'].map((c) => h('th', { scope: 'col' }, c)))),
          tbody)));
  }

  renderRaw() {
    const inc = this.model.inc;
    const view = {
      ...inc,
      series: { limit_bytes: inc.series?.limit_bytes, points: `[${inc.series?.points?.length || 0} samples of t_s, memory_bytes, psi_some, psi_full]` },
      postmortem_markdown: `[${(inc.postmortem_markdown || '').length} characters, see the Postmortem tab]`,
    };
    const json = JSON.stringify(view, null, 2);
    const copyBtn = h('button', { type: 'button', class: 'btn small', onClick: async () => {
      const ok = await copyText(json, this.root);
      copyBtn.textContent = ok ? 'Copied' : 'Copy failed';
      this.later('copy-raw', () => {
        copyBtn.textContent = 'Copy JSON';
      }, 1600);
    } }, 'Copy JSON');
    put(this.tabPanels.raw,
      h('div', { class: 'toolbar' },
        h('span', { class: 'note grow' }, `Schema ${this.data.schema}. The series and postmortem are abbreviated here.`),
        copyBtn,
        h('a', { class: 'btn small', href: this.opts.dataUrl || DEFAULT_DATA_URL, download: 'replay.json' }, 'Download replay.json')),
      h('pre', { class: 'raw', tabindex: '0', 'aria-label': 'Incident JSON' }, json));
  }
}

let sheet = null;

function adoptStyles(root) {
  try {
    if ('adoptedStyleSheets' in root && typeof CSSStyleSheet === 'function' && 'replaceSync' in CSSStyleSheet.prototype) {
      if (!sheet) {
        sheet = new CSSStyleSheet();
        sheet.replaceSync(css);
      }
      root.adoptedStyleSheets = [sheet];
      return;
    }
  } catch {
    // Older engines: fall back to a <style> element inside the shadow root.
  }
  root.append(h('style', null, css));
}

/**
 * Mounts the Graveyard into `target` (an element that can host a shadow root) and returns a cleanup function.
 * options: { replay, dataUrl, incident, autoplay = true, tour = true, speed = 2, timeLapse = true }
 */
export function mount(target, options = {}) {
  if (!target || typeof target.attachShadow !== 'function') throw new TypeError('FrankenCrew Graveyard: mount() needs a DOM element');
  const root = target.shadowRoot || target.attachShadow({ mode: 'open' });
  root.replaceChildren();
  adoptStyles(root);
  const app = new Graveyard(root, options || {});
  app.start();
  return () => app.destroy();
}

export default mount;
