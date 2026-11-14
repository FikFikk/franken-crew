// Halaman landing FrankenCrew: navigasi mobile, tab instalasi, badge Sentinel live, metrik hero, dan mount Graveyard.
// Dimuat sebagai modul ES dari index.html (CSP melarang inline script). Semua komentar wajib Bahasa Indonesia.

import { mount, loadReplay, summarize } from '../dist/index.mjs';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const base = document.baseURI;
const STATUS_URL = new URL('api/status', base).href;
const DATA_URL = new URL('data/replay.json', base).href;
const STATUS_EVERY_MS = 15000;

// Format durasi milidetik secara konsisten untuk panel statistik
function fmtMs(ms) {
  if (!Number.isFinite(ms)) return '--';
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 10) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

// Menutup menu drawer mobile saat tautan diklik, Escape ditekan, atau layar diperlebar
function initMobileNav() {
  const drawer = $('#nav-drawer');
  if (!drawer) return;
  const summary = $('summary', drawer);

  const closeDrawer = (restoreFocus) => {
    if (!drawer.open) return;
    drawer.open = false;
    if (restoreFocus && summary) summary.focus();
  };

  for (const link of $$('.drawer-panel a', drawer)) {
    link.addEventListener('click', () => closeDrawer(false));
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDrawer(true);
  });

  document.addEventListener('click', (e) => {
    if (drawer.open && !drawer.contains(e.target)) closeDrawer(false);
  });

  const mq = window.matchMedia('(min-width: 1024px)');
  if (typeof mq.addEventListener === 'function') {
    mq.addEventListener('change', (e) => {
      if (e.matches) closeDrawer(false);
    });
  }
}

// Mengatur interaksi tab instalasi CLI dengan dukungan keyboard penuh
function initTabs() {
  for (const group of $$('[data-tabs]')) {
    const tabs = $$('[role="tab"]', group);
    const select = (tab, focus) => {
      for (const t of tabs) {
        const on = t === tab;
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
        const panel = document.getElementById(t.getAttribute('aria-controls'));
        if (panel) panel.hidden = !on;
      }
      if (focus) tab.focus();
    };
    tabs.forEach((tab, i) => {
      tab.addEventListener('click', () => select(tab, false));
      tab.addEventListener('keydown', (e) => {
        const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
        if (next === undefined) return;
        e.preventDefault();
        select(tabs[(next + tabs.length) % tabs.length], true);
      });
    });
  }
}

// Menyalin perintah dari tab aktif ke clipboard dengan fallback execCommand
async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text, readOnly: true });
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
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
}

// Menangani tombol Copy pada dok instalasi CLI
function initCopy() {
  for (const btn of $$('[data-copy]')) {
    let timer = 0;
    btn.addEventListener('click', async () => {
      const code = $('[role="tabpanel"]:not([hidden]) code', btn.closest('[data-tabs]') || document);
      if (!code) return;
      const ok = await writeClipboard(code.textContent.trim());
      btn.textContent = ok ? 'Copied' : 'Ctrl+C';
      btn.classList.toggle('done', ok);
      if (!ok) getSelection()?.selectAllChildren(code);
      clearTimeout(timer);
      timer = setTimeout(() => {
        btn.textContent = 'Copy';
        btn.classList.remove('done');
      }, 1800);
    });
  }
}

// Memantau status konektivitas Sentinel setiap 15 detik saat tab aktif
function initStatus() {
  const el = $('#status');
  if (!el) return;
  const text = $('.status-text', el);
  let timer = 0;
  const set = (state, label, title) => {
    el.dataset.state = state;
    text.textContent = label;
    el.title = title;
  };
  const tick = async () => {
    clearTimeout(timer);
    if (!document.hidden) {
      const ctrl = new AbortController();
      const abort = setTimeout(() => ctrl.abort(), 5000);
      try {
        const res = await fetch(STATUS_URL, { cache: 'no-store', signal: ctrl.signal, headers: { Accept: 'application/json' } });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const st = await res.json();
        if (st.mode === 'live') {
          const psi = Number(st.psi?.some_avg10);
          const open = Number(st.open_incidents) || 0;
          set('live', `Live · ${st.node || 'sentinel'} · PSI ${Number.isFinite(psi) ? psi.toFixed(1) : '--'}% · ${open} open`,
            `Sentinel reachable. Updated ${st.updated_at || 'just now'}.`);
        } else if (st.mode === 'offline') {
          set('offline', 'Sentinel offline', 'This dashboard is wired to a Sentinel but cannot reach it right now.');
        } else {
          set('replay', 'Replay mode', 'No live Sentinel is connected to this dashboard. The Graveyard shows recorded or simulated incidents.');
        }
      } catch {
        set('static', 'Static replay', 'Served without the franken lab API, so there is no live Sentinel status. The Graveyard shows bundled replay data.');
      } finally {
        clearTimeout(abort);
      }
    }
    timer = setTimeout(tick, STATUS_EVERY_MS);
  };
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) tick();
  });
  tick();
}

// Memformat stempel waktu relatif T-mm:ss / T+mm:ss dengan tanda hubung ASCII
function rel(t) {
  const a = Math.abs(Math.round(t));
  return `T${Math.round(t) < 0 ? '-' : '+'}${Math.floor(a / 60)}:${String(a % 60).padStart(2, '0')}`;
}

// Mengisi panel KPI 2x2 dari ringkasan dataset replay
function fillStats(sum) {
  const put = (key, value) => {
    const el = $(`[data-stat="${key}"]`);
    if (el) el.textContent = value;
  };
  put('reflex', fmtMs(sum.reflexMedianMs));
  put('approved', `${sum.l2Approved}/${sum.l2Runs}`);
  put('blocked', String(sum.blocked));
  put('incidents', String(sum.incidents));
  put('incidents-detail', `incidents replayed (${sum.resolved} resolved, ${sum.escalated} escalated)`);
  put('source', sum.sourceKind === 'recording'
    ? `Figures come from incidents recorded on ${sum.node || 'a live node'}, replayed in the Graveyard below.`
    : 'Figures come from the simulation dataset in the Graveyard below (franken lab simulate). Latency is in-process Go and SQLite time, not a hardware measurement.');
}

const TEASER_KINDS = ['psi.rising', 'incident.opened', 'reflex.applied', 'plan.accepted', 'vote.granted', 'action.executed', 'incident.resolved', 'incident.escalated'];

// Helper aman untuk memperbarui teks elemen teaser
function setTeaserField(box, key, value) {
  const el = $(`[data-teaser="${key}"]`, box);
  if (el) el.textContent = value;
}

// Menampilkan kondisi kosong atau galat pada panel pratinjau konsol
function fillTeaserFallback(kind, message) {
  const box = $('#teaser');
  if (!box) return;
  box.dataset.uiState = kind;
  const badge = $('[data-teaser="state"]', box);
  if (badge) {
    badge.classList.toggle('bad', kind === 'error');
    badge.textContent = kind === 'error' ? 'UNAVAILABLE' : 'EMPTY';
  }
  setTeaserField(box, 'id', 'data/replay.json');
  setTeaserField(box, 'title', kind === 'error' ? 'Replay dataset unavailable' : 'No incidents in dataset');
  const log = $('[data-teaser="log"]', box);
  if (log) {
    const li = document.createElement('li');
    const time = Object.assign(document.createElement('time'), { textContent: '00:00' });
    const line = document.createElement('span');
    const who = Object.assign(document.createElement('b'), { textContent: 'franken' });
    line.append(who, ` ${message}`);
    li.append(time, line);
    log.replaceChildren(li);
  }
  setTeaserField(box, 'foot', 'Inspect options inside the Graveyard below');
}

// Mengisi pratinjau konsol insiden terbaru dari dataset replay
function fillTeaser(replay) {
  const box = $('#teaser');
  const inc = replay.incidents?.[0];
  if (!box || !inc) {
    fillTeaserFallback('empty', 'Run franken lab simulate --out ui/data/replay.json to populate traces.');
    return;
  }
  box.dataset.uiState = 'ready';
  setTeaserField(box, 'state', inc.state);
  const badge = $('[data-teaser="state"]', box);
  if (badge) badge.classList.toggle('bad', inc.state !== 'RESOLVED');
  setTeaserField(box, 'id', inc.id);
  setTeaserField(box, 'title', inc.title);
  const log = $('[data-teaser="log"]', box);
  if (log) {
    const picked = inc.events.filter((e) => !e.inferred && TEASER_KINDS.includes(e.kind)).slice(0, 7);
    log.replaceChildren(...picked.map((e) => {
      const li = document.createElement('li');
      li.className = e.lane;
      const time = Object.assign(document.createElement('time'), { textContent: rel(e.t) });
      const line = document.createElement('span');
      const who = Object.assign(document.createElement('b'), { textContent: e.actor });
      line.append(who, ` ${e.title}`);
      li.append(time, line);
      return li;
    }));
  }
  const kind = replay.source?.kind === 'recording' ? 'Recorded' : 'Simulated';
  setTeaserField(box, 'foot', `${kind} on ${replay.node || 'unknown node'} · ${inc.events.length} events · full replay below`);
}

// Memuat replay dari server dan me-mount simulator Graveyard
async function initGraveyard() {
  const target = $('#graveyard-app');
  if (!target) return;
  let replay = null;
  let failed = false;
  try {
    replay = await loadReplay(DATA_URL);
  } catch (err) {
    failed = true;
    console.warn('[FrankenCrew] replay data unavailable:', err);
  }
  if (replay) {
    fillStats(summarize(replay));
    fillTeaser(replay);
  } else if (failed) {
    fillTeaserFallback('error', 'Failed to load data/replay.json; check the Graveyard simulator below.');
    const srcNote = $('[data-stat="source"]');
    if (srcNote) srcNote.textContent = 'Replay dataset could not be fetched from data/replay.json.';
  }
  // Tanpa data eksternal, komponen merender empty state dan cara membuat dataset replay.
  mount(target, replay ? { replay, dataUrl: DATA_URL } : { dataUrl: DATA_URL });
}

initMobileNav();
initTabs();
initCopy();
initStatus();
initGraveyard();
