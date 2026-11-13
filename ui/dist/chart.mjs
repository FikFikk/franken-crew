// FrankenCrew Graveyard: telemetry chart (memory, PSI) and event swimlanes drawn in
// one SVG on a shared time axis, re-rendered at the container's pixel width.

import { h, s, put, clamp, niceCeil, fmtBytes, fmtRel, fmtPct, fmtClock, countUpTo, MiB } from './dom.mjs';

export const LANES = [
  { id: 'kernel', label: 'Kernel' },
  { id: 'sentinel', label: 'Sentinel' },
  { id: 'crew', label: 'Crew' },
  { id: 'human', label: 'Human' },
  { id: 'verify', label: 'Verify' },
];

const PAD_L = 70;
const PAD_R = 46;
const PLOT_TOP = 34;
const PLOT_H = 176;
const LANE_TOP = PLOT_TOP + PLOT_H + 16;
const LANE_H = 24;
const LANES_BOTTOM = LANE_TOP + LANES.length * LANE_H;
const HEIGHT = LANES_BOTTOM + 24;

/** Index of the last point with p[0] <= t (points sorted by time), or -1. */
function pointIndex(points, t) {
  let lo = 0;
  let hi = points.length - 1;
  let ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (points[mid][0] <= t) {
      ans = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return ans;
}

function nearestPoint(points, t) {
  const i = pointIndex(points, t);
  if (i < 0) return points[0];
  if (i >= points.length - 1) return points[points.length - 1];
  return t - points[i][0] <= points[i + 1][0] - t ? points[i] : points[i + 1];
}

function pathOf(points, x, y) {
  let d = '';
  for (let i = 0; i < points.length; i++) d += `${i ? 'L' : 'M'}${x(points[i][0]).toFixed(1)},${y(points[i]).toFixed(1)}`;
  return d;
}

/** Tiny memory sparkline for the incident list. */
export function sparkline(points, width = 200, height = 30) {
  const svg = s('svg', { class: 'spark', viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  if (!points || points.length < 2) return svg;
  const t0 = points[0][0];
  const span = points[points.length - 1][0] - t0 || 1;
  let lo = Infinity;
  let hi = -Infinity;
  for (const p of points) {
    lo = Math.min(lo, p[1]);
    hi = Math.max(hi, p[1]);
  }
  const range = hi - lo || 1;
  const step = Math.max(1, Math.floor(points.length / 90));
  const sampled = points.filter((_, i) => i % step === 0);
  const line = pathOf(sampled, (t) => ((t - t0) / span) * width, (p) => height - 2 - ((p[1] - lo) / range) * (height - 5));
  svg.append(s('path', { class: 'spark-area', d: `${line}L${width},${height}L0,${height}Z` }), s('path', { d: line }));
  return svg;
}

/**
 * Builds the stage. model comes from graveyard.mjs prepare(): { inc, events, tMin, tMax, tEnd,
 * memMax, psiMax, limit, marks }. Returns { el, setModel(model), update(t, sel), destroy() }.
 */
export function createStage({ onSeek, onSelect }) {
  const show = { memory: true, psiSome: true, psiFull: true };
  const groups = {};
  const applyVisibility = () => {
    for (const [key, g] of Object.entries(groups)) g.style.display = show[key] ? '' : 'none';
  };
  const legend = (key, label, color, dash) =>
    h('button', {
      type: 'button', class: ['lg', dash && 'dash'], 'aria-pressed': 'true', style: { '--c': color },
      onClick: (e) => {
        show[key] = !show[key];
        e.currentTarget.setAttribute('aria-pressed', String(show[key]));
        applyVisibility();
      },
    }, h('i'), label);

  const svg = s('svg', { class: 'chart', role: 'img', 'aria-label': 'Telemetry chart' });
  const tip = h('div', { class: 'tip', hidden: true });
  const stamp = h('div', { class: 'stamp', 'aria-hidden': 'true' });
  const wrap = h('div', { class: 'chart-wrap' }, svg, tip, stamp);
  const el = h('section', { class: 'stage', 'aria-label': 'Telemetry and event timeline' },
    h('div', { class: 'stage-head' },
      h('h4', null, 'Memory · PSI · events'),
      h('div', { class: 'legend' },
        legend('memory', 'memory.current', 'var(--sentinel)'),
        legend('psiSome', 'PSI some avg10', 'var(--kernel)'),
        legend('psiFull', 'PSI full avg10', 'var(--error)', true),
        h('span', { class: 'legend-note' }, h('b'), 'hollow = inferred from protocol'))),
    wrap);

  let model = null;
  let width = 0;
  let last = { t: 0, sel: -1 };
  let dyn = null;
  let dragging = false;

  const ro = typeof ResizeObserver === 'function'
    ? new ResizeObserver(() => {
      const w = Math.round(wrap.clientWidth);
      if (model && w > 0 && Math.abs(w - width) >= 2) {
        render();
        update(last.t, last.sel);
      }
    })
    : null;
  ro?.observe(wrap);

  function render() {
    const W = Math.max(320, Math.round(wrap.clientWidth || 860));
    width = W;
    svg.setAttribute('viewBox', `0 0 ${W} ${HEIGHT}`);
    svg.setAttribute('width', String(W));
    svg.setAttribute('height', String(HEIGHT));
    svg.replaceChildren();
    const { inc, tMin, tMax, memMax, psiMax, limit, marks } = model;
    const plotW = W - PAD_L - PAD_R;
    const x = (t) => PAD_L + ((t - tMin) / (tMax - tMin || 1)) * plotW;
    const tAt = (px) => clamp(tMin + ((px - PAD_L) / plotW) * (tMax - tMin), tMin, tMax);
    const yMem = (b) => PLOT_TOP + PLOT_H - (b / memMax) * PLOT_H;
    const yPsi = (v) => PLOT_TOP + PLOT_H - (v / psiMax) * PLOT_H;
    const pts = model.points;

    svg.append(s('defs', null,
      s('linearGradient', { id: 'fcg-mem', x1: '0', y1: '0', x2: '0', y2: '1' },
        s('stop', { offset: '0%', 'stop-color': '#5cffa1', 'stop-opacity': '0.3' }),
        s('stop', { offset: '100%', 'stop-color': '#5cffa1', 'stop-opacity': '0.01' }))));

    // Grid and axes: memory on the left, PSI on the right, incident-relative time below.
    const grid = s('g', { class: 'grid' });
    const axis = s('g', { class: 'axis' });
    const memStep = limit > 0 ? limit / 4 : niceCeil(memMax / 4 / MiB) * MiB;
    for (let b = 0; b <= memMax + 1; b += memStep) {
      grid.append(s('line', { x1: PAD_L, x2: W - PAD_R, y1: yMem(b), y2: yMem(b) }));
      axis.append(s('text', { x: PAD_L - 8, y: yMem(b) + 3.5, 'text-anchor': 'end' }, `${Math.round(b / MiB)} MiB`));
    }
    for (const v of [psiMax / 2, psiMax]) {
      axis.append(s('text', { x: W - PAD_R + 8, y: yPsi(v) + 3.5 }, `${+v.toFixed(1)}%`));
    }
    const pxPerS = plotW / (tMax - tMin || 1);
    const step = [10, 15, 30, 60, 120, 300, 600].find((st) => st * pxPerS >= 64) || 600;
    for (let t = Math.ceil(tMin / step) * step; t <= tMax; t += step) {
      grid.append(s('line', { class: t === 0 ? 't0' : undefined, x1: x(t), x2: x(t), y1: PLOT_TOP, y2: LANES_BOTTOM }));
      axis.append(s('text', { x: x(t), y: LANES_BOTTOM + 16, 'text-anchor': 'middle' }, fmtRel(t)));
    }
    svg.append(grid);

    // Phase bands: waiting for the human vote, then the forward verification window.
    const band = (t0, t1, cls, label) => {
      if (!Number.isFinite(t0) || !Number.isFinite(t1) || t1 <= t0) return;
      const bx = x(t0);
      const bw = x(t1) - bx;
      svg.append(s('rect', { class: cls, x: bx, y: PLOT_TOP, width: bw, height: LANES_BOTTOM - PLOT_TOP }));
      if (bw > 84) svg.append(s('text', { class: 'band-label', x: bx + 6, y: PLOT_TOP + 12 }, label));
    };
    band(marks.poll?.t, marks.vote?.t, 'band-wait', 'awaiting human vote');
    band(marks.verifyStart?.t, marks.verifyEnd?.t, 'band-verify', `verify window ${inc.stats?.verify_window_s ?? ''}s`.trim());
    svg.append(axis);

    // Series: memory area and line, PSI some and full, and the cgroup memory.max limit.
    if (limit > 0) {
      svg.append(s('line', { class: 'limit', x1: PAD_L, x2: W - PAD_R, y1: yMem(limit), y2: yMem(limit) }),
        s('text', { class: 'limit-label', x: PAD_L + 6, y: yMem(limit) - 5 }, `memory.max ${fmtBytes(limit)}`));
    }
    if (pts.length > 1) {
      const memLine = pathOf(pts, x, (p) => yMem(p[1]));
      groups.memory = s('g', null,
        s('path', { class: 'mem-area', d: `${memLine}L${x(pts[pts.length - 1][0]).toFixed(1)},${yMem(0)}L${x(pts[0][0]).toFixed(1)},${yMem(0)}Z` }),
        s('path', { class: 'mem-line', d: memLine }));
      groups.psiSome = s('g', null, s('path', { class: 'psi-some', d: pathOf(pts, x, (p) => yPsi(p[2])) }));
      groups.psiFull = s('g', null, s('path', { class: 'psi-full', d: pathOf(pts, x, (p) => yPsi(p[3])) }));
      svg.append(groups.memory, groups.psiSome, groups.psiFull);
      applyVisibility();
    }

    // Milestone flags in two rows above the plot, placed in priority order. A flag that fits in neither row is
    // dropped rather than drawn over another; its event still shows in the swimlanes. Narrow charts use short labels.
    const rows = [[], []];
    const compact = plotW < 520;
    const flag = (t, lane, full, short) => {
      const label = compact ? short : full;
      if (!Number.isFinite(t)) return;
      const fx = x(t);
      // Measure the rendered label; fall back to an estimate while the chart is not laid out.
      const text = s('text', null, label);
      const g = s('g', { class: `mark lane-${lane}` }, text);
      svg.append(g);
      const measured = text.getComputedTextLength?.() || 0;
      const fw = Math.ceil(measured > 0 ? measured : label.length * 6.6) + 12;
      const left = clamp(fx - 2, PAD_L - 30, W - fw - 2);
      const right = left + fw;
      const row = rows.findIndex((taken) => taken.every(([a, b]) => right + 4 <= a || left >= b + 4));
      if (row < 0) {
        g.remove();
        return;
      }
      rows[row].push([left, right]);
      const fy = 2 + row * 16;
      text.setAttribute('x', (left + 6).toFixed(1));
      text.setAttribute('y', String(fy + 10.5));
      g.prepend(s('line', { x1: fx, x2: fx, y1: fy + 14, y2: PLOT_TOP + PLOT_H }), s('rect', { x: left, y: fy, width: fw, height: 14, rx: 4 }));
    };
    const failed = marks.verifyEnd?.kind === 'verify.failed';
    flag(marks.opened?.t, 'sentinel', 'T0 detected', 'T0');
    flag(marks.reflex?.t, 'sentinel', `L1 reflex ${model.reflexLabel}`, 'L1');
    flag(marks.vote?.t, 'human', 'approved', 'vote');
    flag(marks.verifyEnd?.t, 'verify', failed ? 'verify failed' : 'verified', failed ? 'fail' : 'ok');
    flag(marks.poll?.t, 'human', 'poll sent', 'poll');
    flag(marks.exec?.t, 'crew', 'L2 executed', 'L2');

    // Swimlanes: one row per lane, events as dots; same-lane dots never overlap (shifted right, in order).
    LANES.forEach((lane, i) => {
      const y = LANE_TOP + i * LANE_H;
      svg.append(s('g', { class: `lane-${lane.id}` },
        s('rect', { class: 'lane-row', x: PAD_L, y: y + 1, width: plotW, height: LANE_H - 2, rx: 4 }),
        s('text', { class: 'lane-label', x: PAD_L - 8, y: y + LANE_H / 2 + 3.5, 'text-anchor': 'end' }, lane.label)));
    });
    const laneIndex = new Map(LANES.map((l, i) => [l.id, i]));
    const lastX = new Map();
    const dots = model.events.map((ev, idx) => {
      const li = laneIndex.has(ev.lane) ? laneIndex.get(ev.lane) : 1;
      const cx = Math.max(x(ev.t), (lastX.get(li) ?? -Infinity) + 8);
      lastX.set(li, cx);
      const dot = s('circle', {
        class: ['dot', `lane-${ev.lane}`, ev.inferred && 'inferred', `lvl-${ev.level}`],
        cx: cx.toFixed(1), cy: LANE_TOP + li * LANE_H + LANE_H / 2, r: 5,
      }, s('title', null, `${fmtRel(ev.t)} · ${ev.actor} · ${ev.title}${ev.inferred ? ' (inferred)' : ''}`));
      dot.addEventListener('click', (e) => {
        e.stopPropagation();
        onSelect(idx);
      });
      return dot;
    });

    // Dynamic overlay: future dimming, playhead, hover guide, and the pointer hit area.
    const future = s('rect', { class: 'future', x: PAD_L, y: 0, width: 0, height: LANES_BOTTOM + 2 });
    const hoverLine = s('line', { class: 'hover-line', y1: PLOT_TOP, y2: LANES_BOTTOM, visibility: 'hidden' });
    const hit = s('rect', { class: 'hit', x: PAD_L, y: PLOT_TOP, width: plotW, height: LANES_BOTTOM - PLOT_TOP });
    const playhead = s('line', { class: 'playhead', y1: PLOT_TOP - 4, y2: LANES_BOTTOM });
    const phDot = s('circle', { class: 'ph-dot', r: 3.5, cx: -10, cy: -10 });
    const phBg = s('rect', { x: 0, y: LANES_BOTTOM + 4, width: 50, height: 16, rx: 4, fill: '#07080c' });
    const phLabel = s('text', { class: 'ph-label', y: LANES_BOTTOM + 16, 'text-anchor': 'middle' });
    svg.append(hit, future, ...dots, hoverLine, playhead, phDot, phBg, phLabel);
    dyn = { x, tAt, yMem, dots, future, playhead, phDot, phBg, phLabel, hoverLine, hit, lit: -1, sel: -2 };

    const peak = pts.reduce((m, p) => Math.max(m, p[1]), 0);
    const psiPeak = pts.reduce((m, p) => Math.max(m, p[2]), 0);
    svg.setAttribute('aria-label', `Memory and PSI for ${inc.id}: peak ${fmtBytes(peak)}${limit ? ` of ${fmtBytes(limit)} memory.max` : ''}, ` +
      `peak PSI some ${fmtPct(psiPeak)}; ${model.events.length} events across ${LANES.length} lanes.`);
    bindPointer();
  }

  function localX(e) {
    const rect = svg.getBoundingClientRect();
    const scale = rect.width / width || 1;
    return { px: (e.clientX - rect.left) / scale, scale };
  }

  function hideTip() {
    tip.hidden = true;
    dyn?.hoverLine.setAttribute('visibility', 'hidden');
  }

  function showTip(e) {
    const { px, scale } = localX(e);
    const p = nearestPoint(model.points, dyn.tAt(px));
    if (!p) return;
    const gx = dyn.x(p[0]);
    dyn.hoverLine.setAttribute('x1', gx.toFixed(1));
    dyn.hoverLine.setAttribute('x2', gx.toFixed(1));
    dyn.hoverLine.setAttribute('visibility', 'visible');
    const pct = model.limit ? ` (${Math.round((p[1] / model.limit) * 100)}% of max)` : '';
    put(tip,
      h('div', null, h('b', null, fmtRel(p[0])), h('span', { class: 'tt' }, `  ${fmtClock(model.inc.opened_at, p[0])} UTC`)),
      h('div', null, `mem ${fmtBytes(p[1])}${pct}`),
      h('div', null, `PSI some ${fmtPct(p[2])} · full ${fmtPct(p[3])}`));
    tip.hidden = false;
    tip.style.left = `${clamp(gx * scale, 96, Math.max(96, wrap.clientWidth - 96))}px`;
    tip.style.top = `${Math.max(64, dyn.yMem(p[1]) * scale)}px`;
  }

  function bindPointer() {
    const hit = dyn.hit;
    hit.addEventListener('pointermove', (e) => {
      showTip(e);
      if (dragging) onSeek(dyn.tAt(localX(e).px));
    });
    hit.addEventListener('pointerleave', () => {
      if (!dragging) hideTip();
    });
    hit.addEventListener('pointerdown', (e) => {
      dragging = true;
      hit.setPointerCapture?.(e.pointerId);
      onSeek(dyn.tAt(localX(e).px));
    });
    const end = (e) => {
      dragging = false;
      if (hit.hasPointerCapture?.(e.pointerId)) hit.releasePointerCapture(e.pointerId);
    };
    hit.addEventListener('pointerup', end);
    hit.addEventListener('pointercancel', (e) => {
      end(e);
      hideTip();
    });
  }

  function update(t, sel = -1) {
    last = { t, sel };
    if (!dyn) return;
    const px = clamp(dyn.x(t), PAD_L, width - PAD_R);
    const pxs = px.toFixed(1);
    dyn.future.setAttribute('x', pxs);
    dyn.future.setAttribute('width', Math.max(0, width - PAD_R - px).toFixed(1));
    dyn.playhead.setAttribute('x1', pxs);
    dyn.playhead.setAttribute('x2', pxs);
    dyn.phLabel.setAttribute('x', pxs);
    dyn.phLabel.textContent = fmtRel(t);
    dyn.phBg.setAttribute('x', (px - 25).toFixed(1));
    const i = pointIndex(model.points, t);
    if (i >= 0 && show.memory) {
      dyn.phDot.setAttribute('cx', pxs);
      dyn.phDot.setAttribute('cy', dyn.yMem(model.points[i][1]).toFixed(1));
    } else {
      dyn.phDot.setAttribute('cx', '-10');
    }
    const n = countUpTo(model.events, t);
    if (n !== dyn.lit || sel !== dyn.sel) {
      dyn.dots.forEach((d, k) => {
        d.classList.toggle('on', k < n);
        d.classList.toggle('sel', k === sel);
      });
      dyn.lit = n;
      dyn.sel = sel;
    }
    stamp.classList.toggle('on', t >= model.tEnd - 1e-6);
  }

  function setModel(m) {
    model = m;
    stamp.textContent = m.inc.state;
    stamp.className = `stamp ${m.inc.state === 'RESOLVED' ? 'ok' : 'bad'}`;
    hideTip();
    render();
  }

  return { el, setModel, update, destroy: () => ro?.disconnect() };
}
