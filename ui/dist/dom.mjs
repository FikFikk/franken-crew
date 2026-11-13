// FrankenCrew Graveyard: DOM helpers and formatters.
// Every string reaches the page through textContent or setAttribute, never innerHTML,
// so replay data cannot inject markup.

const SVG_NS = 'http://www.w3.org/2000/svg';

export const MiB = 1024 * 1024;

function apply(el, attrs) {
  if (!attrs) return el;
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') {
      el.setAttribute('class', Array.isArray(value) ? value.filter(Boolean).join(' ') : String(value));
    } else if (key === 'text') {
      el.textContent = String(value);
    } else if (key === 'dataset') {
      for (const [k, v] of Object.entries(value)) el.dataset[k] = String(v);
    } else if (key === 'style') {
      for (const [prop, v] of Object.entries(value)) el.style.setProperty(prop, String(v));
    } else if (key.startsWith('on') && typeof value === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else {
      el.setAttribute(key, value === true ? '' : String(value));
    }
  }
  return el;
}

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

/** Creates an HTML element: h('div', { class: 'x' }, 'text', childNode). */
export function h(tag, attrs, ...children) {
  return append(apply(document.createElement(tag), attrs), children);
}

/** Creates an SVG element with the same calling convention as h(). */
export function s(tag, attrs, ...children) {
  return append(apply(document.createElementNS(SVG_NS, tag), attrs), children);
}

/** Replaces el's children; unlike native replaceChildren, falsy children are skipped instead of stringified. */
export function put(el, ...children) {
  el.replaceChildren();
  return append(el, children);
}

export function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, v));
}

/** Smallest "nice" number (1, 2, 2.5, 5 x 10^k) that is >= v. */
export function niceCeil(v) {
  if (!(v > 0)) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) {
    if (m * exp >= v - 1e-9) return m * exp;
  }
  return 10 * exp;
}

export function fmtBytes(b) {
  if (!Number.isFinite(b)) return '–';
  if (b >= 1024 * MiB) return `${(b / (1024 * MiB)).toFixed(2)} GiB`;
  return `${(b / MiB).toFixed(b >= 100 * MiB ? 0 : 1)} MiB`;
}

/** Incident-relative time: T−0:15, T+1:05. */
export function fmtRel(t) {
  const a = Math.abs(Math.round(t));
  const sign = Math.round(t) < 0 ? '−' : '+';
  return `T${sign}${Math.floor(a / 60)}:${String(a % 60).padStart(2, '0')}`;
}

export function fmtDuration(sec) {
  const total = Math.max(0, Math.round(sec));
  const m = Math.floor(total / 60);
  const r = total % 60;
  return m ? `${m}m ${String(r).padStart(2, '0')}s` : `${r}s`;
}

export function fmtMs(ms) {
  if (!Number.isFinite(ms)) return '–';
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 10) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

export function fmtPct(v, digits = 1) {
  return Number.isFinite(v) ? `${v.toFixed(digits)}%` : '–';
}

/** Wall-clock time (UTC) of an incident-relative offset. */
export function fmtClock(openedAt, offsetS) {
  const base = Date.parse(openedAt);
  if (!Number.isFinite(base)) return '';
  return new Date(base + Math.round(offsetS) * 1000).toISOString().slice(11, 19);
}

/** Number of items whose .t is <= t (items sorted by t). */
export function countUpTo(items, t) {
  let lo = 0;
  let hi = items.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (items[mid].t <= t + 1e-6) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Renders WhatsApp markup (*bold*, `code`, newlines) as DOM nodes. */
export function waText(text) {
  const out = [];
  String(text ?? '').split('\n').forEach((line, i) => {
    if (i) out.push(h('br'));
    const re = /(\*[^*\n]+\*|`[^`\n]+`)/g;
    let last = 0;
    let m;
    while ((m = re.exec(line))) {
      if (m.index > last) out.push(line.slice(last, m.index));
      const tok = m[0];
      out.push(tok[0] === '*' ? h('strong', null, tok.slice(1, -1)) : h('code', null, tok.slice(1, -1)));
      last = m.index + tok.length;
    }
    if (last < line.length) out.push(line.slice(last));
  });
  return out;
}

/** Copies text to the clipboard; falls back to a hidden textarea when the async API is blocked. */
export async function copyText(text, scope = document.body) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall through to the legacy path.
  }
  const ta = h('textarea', { readonly: true, 'aria-hidden': 'true', style: { position: 'fixed', top: '-1000px', opacity: '0' } });
  ta.value = text;
  scope.append(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

/** Offers text as a file download without touching the network. */
export function downloadText(filename, text, type = 'text/markdown') {
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = h('a', { href: url, download: filename, style: { display: 'none' } });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
