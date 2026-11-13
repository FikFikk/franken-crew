// FrankenCrew Graveyard: safe renderer for the postmortem Markdown subset that
// internal/postmortem emits (headings, bullet and task lists, tables, fenced code,
// paragraphs, **bold**, `code`, http(s) links). Output is DOM nodes only.

import { h } from './dom.mjs';

const INLINE_SRC = '(`[^`]+`|\\*\\*[^*]+\\*\\*|\\[[^\\]]+\\]\\([^)\\s]+\\))';

function safeHref(raw) {
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

/** Inline markup to DOM nodes. A fresh RegExp per call keeps recursion safe. */
export function inline(text) {
  const re = new RegExp(INLINE_SRC, 'g');
  const out = [];
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok[0] === '`') {
      out.push(h('code', null, tok.slice(1, -1)));
    } else if (tok.startsWith('**')) {
      out.push(h('strong', null, inline(tok.slice(2, -2))));
    } else {
      const link = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(tok);
      const href = link && safeHref(link[2]);
      out.push(href ? h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, link[1]) : link ? link[1] : tok);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function plain(text) {
  return String(text).replace(/\*\*|`/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1');
}

function splitRow(row) {
  let r = row.trim();
  if (r.startsWith('|')) r = r.slice(1);
  if (r.endsWith('|') && !r.endsWith('\\|')) r = r.slice(0, -1);
  return r.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
}

const isFence = (l) => /^```/.test(l);
const isHeading = (l) => /^#{1,6}\s+/.test(l);
const isList = (l) => /^\s*[-*]\s+/.test(l);
const isTableStart = (l, next) => /^\s*\|/.test(l) && next !== undefined && /^\s*\|?\s*:?-{3,}/.test(next);

/**
 * Renders Markdown into a container. Returns { root, toc } where toc lists the
 * level-2 and level-3 headings ({ id, level, text }) for an outline.
 * Heading levels shift down by two (# -> h3) because the host page owns h1/h2.
 */
export function renderMarkdown(md, { idPrefix = 'pm' } = {}) {
  const root = h('div', { class: 'md' });
  const toc = [];
  const used = new Map();
  const lines = String(md || '').replace(/\r\n?/g, '\n').split('\n');
  const slug = (text) => {
    const base = `${idPrefix}-${plain(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'section'}`;
    const n = used.get(base) || 0;
    used.set(base, n + 1);
    return n ? `${base}-${n}` : base;
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    if (isFence(line)) {
      const lang = line.slice(3).trim() || 'text';
      const buf = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) buf.push(lines[i++]);
      i++;
      root.append(h('pre', { class: 'md-code', dataset: { lang } }, h('code', null, buf.join('\n'))));
      continue;
    }
    if (isHeading(line)) {
      const level = /^#+/.exec(line)[0].length;
      const text = line.replace(/^#+\s+/, '').trim();
      const id = slug(text);
      root.append(h(`h${Math.min(6, level + 2)}`, { id, class: `md-h${level}` }, inline(text)));
      if (level === 2 || level === 3) toc.push({ id, level, text: plain(text) });
      i++;
      continue;
    }
    if (isTableStart(line, lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) rows.push(splitRow(lines[i++]));
      const table = h('table', null,
        h('thead', null, h('tr', null, head.map((c) => h('th', { scope: 'col' }, inline(c))))),
        h('tbody', null, rows.map((r) => h('tr', null, head.map((_, ci) => h('td', null, inline(r[ci] ?? '')))))));
      root.append(h('div', { class: 'md-table', tabindex: '0', role: 'region', 'aria-label': 'Table' }, table));
      continue;
    }
    if (isList(line)) {
      const ul = h('ul', { class: 'md-list' });
      while (i < lines.length && isList(lines[i])) {
        const item = lines[i++].replace(/^\s*[-*]\s+/, '');
        const task = /^\[( |x|X)\]\s+(.*)$/.exec(item);
        if (task) {
          const done = task[1] !== ' ';
          ul.append(h('li', { class: 'md-task' },
            h('input', { type: 'checkbox', disabled: true, checked: done, 'aria-label': done ? 'Done' : 'Open' }),
            h('span', null, inline(task[2]))));
        } else {
          ul.append(h('li', null, inline(item)));
        }
      }
      root.append(ul);
      continue;
    }
    const para = [];
    while (i < lines.length && lines[i].trim() && !isFence(lines[i]) && !isHeading(lines[i]) && !isList(lines[i]) &&
      !isTableStart(lines[i], lines[i + 1])) {
      para.push(lines[i++].trim());
    }
    if (para.length) root.append(h('p', null, inline(para.join(' '))));
    else i++;
  }
  return { root, toc };
}
