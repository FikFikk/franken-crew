// FrankenCrew Graveyard: stylesheet adopted into the component's shadow root, so it
// neither leaks into the host page (Kiro Crew dashboard, landing page) nor inherits from it.
const base = String.raw`
:host { all: initial; display: block; color-scheme: dark; }
.app {
  --bg: #07080c; --panel: #0f121a; --panel-2: #141927; --line: rgba(255,255,255,.075); --line-2: rgba(255,255,255,.14);
  --text: #e7e9f0; --muted: #8b93a7; --faint: #5d6478;
  --kernel: #ffb347; --sentinel: #5cffa1; --crew: #9b8cff; --human: #ff6ad5; --verify: #4fd8ff; --error: #ff5a6a;
  --accent: #5cffa1;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  container: graveyard / inline-size;
  position: relative; box-sizing: border-box; color: var(--text); font: 14px/1.5 var(--sans);
  -webkit-font-smoothing: antialiased; text-align: left;
  background:
    radial-gradient(900px 360px at 0% 0%, rgba(92,255,161,.06), transparent 60%),
    radial-gradient(800px 380px at 100% 0%, rgba(155,140,255,.08), transparent 60%),
    var(--bg);
  border: 1px solid var(--line); border-radius: 18px; overflow: hidden; overflow: clip;
}
.app *, .app *::before, .app *::after { box-sizing: border-box; }
:where(.app) button { font: inherit; color: inherit; cursor: pointer; }
.app a.btn { text-decoration: none; color: var(--text); }
.ic { display: inline-block; width: 12px; height: 12px; vertical-align: -1px; flex: none; }
.app :focus-visible { outline: 2px solid var(--verify); outline-offset: 2px; border-radius: 6px; }
.app h2, .app h3, .app h4, .app p { margin: 0; }
.app code { font-family: var(--mono); }
.app ::selection { background: rgba(92,255,161,.25); }
.app * { scrollbar-width: thin; scrollbar-color: #2a3142 transparent; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.lane-kernel { --lane: var(--kernel); } .lane-sentinel { --lane: var(--sentinel); } .lane-crew { --lane: var(--crew); }
.lane-human { --lane: var(--human); } .lane-verify { --lane: var(--verify); }

.top { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px 20px;
  padding: 16px 20px; border-bottom: 1px solid var(--line); }
.brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
.logo { width: 36px; height: 36px; flex: none; border-radius: 10px; display: grid; place-items: center;
  background: linear-gradient(145deg, rgba(92,255,161,.18), rgba(155,140,255,.14)); border: 1px solid rgba(92,255,161,.3);
  box-shadow: 0 0 24px rgba(92,255,161,.18); }
.brand h2 { font-size: 16px; font-weight: 650; letter-spacing: -.01em; }
.brand p { color: var(--muted); font-size: 12.5px; }
.source { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); }
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 999px; font: 600 10.5px/1.4 var(--mono);
  letter-spacing: .08em; text-transform: uppercase; border: 1px solid currentColor; }
.badge::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.badge.simulation { color: var(--kernel); background: rgba(255,179,71,.08); }
.badge.recording { color: var(--sentinel); background: rgba(92,255,161,.08); }
.about { flex-basis: 100%; font-size: 12.5px; color: var(--muted); }
.about summary { cursor: pointer; width: max-content; color: var(--text); opacity: .85; }
.about summary:hover { opacity: 1; }
.about p { margin-top: 8px; max-width: 110ch; line-height: 1.6; }
`;

const layout = String.raw`
.layout { display: grid; grid-template-columns: minmax(0, 1fr); }
.list { display: flex; gap: 10px; padding: 14px 16px; overflow-x: auto; scroll-snap-type: x proximity;
  border-bottom: 1px solid var(--line); }
@container graveyard (min-width: 980px) {
  .layout { grid-template-columns: 268px minmax(0, 1fr); }
  .list { flex-direction: column; overflow: visible; border-bottom: 0; border-right: 1px solid var(--line); padding: 16px;
    position: sticky; top: var(--sticky-top, 0px); align-self: start; }
}
.list-title { display: none; font: 600 10.5px/1 var(--mono); letter-spacing: .1em; text-transform: uppercase; color: var(--faint);
  margin: 2px 2px 4px; }
@container graveyard (min-width: 980px) { .list-title { display: block; } }
.tomb { flex: 0 0 232px; scroll-snap-align: start; display: grid; gap: 6px; text-align: left; padding: 14px 14px 12px;
  border: 1px solid var(--line); border-radius: 26px 26px 10px 10px; color: var(--text);
  background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.012));
  transition: border-color .2s, box-shadow .2s, transform .2s, background .2s; }
.tomb:hover { border-color: var(--line-2); transform: translateY(-1px); }
.tomb[aria-current="true"] { border-color: rgba(92,255,161,.5);
  background: linear-gradient(180deg, rgba(92,255,161,.07), rgba(255,255,255,.012));
  box-shadow: 0 0 0 1px rgba(92,255,161,.15), 0 10px 30px -12px rgba(92,255,161,.35); }
.tomb.bad[aria-current="true"] { border-color: rgba(255,90,106,.55); box-shadow: 0 0 0 1px rgba(255,90,106,.15), 0 10px 30px -12px rgba(255,90,106,.35);
  background: linear-gradient(180deg, rgba(255,90,106,.07), rgba(255,255,255,.012)); }
.tomb-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.pill { font: 600 10px/1 var(--mono); letter-spacing: .08em; padding: 4px 7px; border-radius: 999px; }
.pill.ok { color: var(--sentinel); background: rgba(92,255,161,.1); }
.pill.bad { color: var(--error); background: rgba(255,90,106,.12); }
.sev { font: 600 10.5px/1 var(--mono); color: var(--kernel); }
.tomb-title { font-size: 13.5px; font-weight: 600; line-height: 1.35; }
.tomb-id { font: 11px/1.3 var(--mono); color: var(--faint); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.spark { display: block; width: 100%; height: 30px; }
.spark path { fill: none; stroke: var(--sentinel); stroke-width: 1.4; vector-effect: non-scaling-stroke; }
.tomb.bad .spark path { stroke: var(--error); }
.spark .spark-area { fill: rgba(92,255,161,.08); stroke: none; }
.tomb.bad .spark .spark-area { fill: rgba(255,90,106,.08); }
.epitaph { font-size: 11.5px; color: var(--muted); font-style: italic; }
.tomb-meta { display: flex; gap: 10px; font: 11px/1.3 var(--mono); color: var(--muted); }

.main { min-width: 0; display: grid; gap: 14px; padding: 18px 20px 22px; align-content: start; }
.inc-head { display: grid; gap: 8px; }
.eyebrow { font: 11.5px/1.3 var(--mono); color: var(--muted); }
.inc-head h3 { font-size: 21px; line-height: 1.25; font-weight: 650; letter-spacing: -.015em; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { font-size: 11.5px; padding: 2px 8px; border-radius: 6px; background: rgba(255,255,255,.04); border: 1px solid var(--line); }
.chip .k { color: var(--muted); margin-right: 4px; }
.chip code { font-size: 11px; }
.triage { color: var(--muted); font-size: 13px; max-width: 92ch; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(128px, 1fr)); gap: 8px; }
.stat { padding: 10px 12px; border-radius: 12px; background: var(--panel); border: 1px solid var(--line); }
.stat .v { font-size: 18px; font-weight: 650; font-variant-numeric: tabular-nums; letter-spacing: -.01em; }
.stat .l { font-size: 11.5px; color: var(--muted); }
.stat.good .v { color: var(--sentinel); } .stat.bad .v { color: var(--error); } .stat.warn .v { color: var(--kernel); }
`;

const player = String.raw`
.player { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 12px; padding: 10px 12px; border-radius: 14px;
  background: var(--panel); border: 1px solid var(--line); }
.btn { display: inline-grid; place-items: center; min-width: 34px; height: 34px; padding: 0 10px; border-radius: 9px;
  border: 1px solid var(--line-2); background: rgba(255,255,255,.03); font-size: 12.5px; transition: background .15s, border-color .15s; }
.btn:hover { background: rgba(255,255,255,.08); }
.btn.primary { background: var(--accent); border-color: var(--accent); color: #04140b; font-weight: 650;
  box-shadow: 0 0 22px rgba(92,255,161,.3); }
.btn.primary:hover { background: #7dffb6; }
.btn svg { width: 15px; height: 15px; display: block; }
.btn.small { height: 28px; min-width: 28px; padding: 0 9px; font-size: 12px; border-radius: 8px; }
.speeds { display: inline-flex; border: 1px solid var(--line-2); border-radius: 9px; overflow: hidden; }
.speeds button { border: 0; background: transparent; padding: 0 9px; height: 32px; font: 12px var(--mono); color: var(--muted); }
.speeds button + button { border-left: 1px solid var(--line); }
.speeds button[aria-pressed="true"] { background: rgba(92,255,161,.14); color: var(--accent); }
.scrub { flex: 1 1 200px; min-width: 160px; height: 22px; margin: 0; background: transparent; -webkit-appearance: none; appearance: none; --p: 0%; }
.scrub::-webkit-slider-runnable-track { height: 4px; border-radius: 4px;
  background: linear-gradient(90deg, var(--accent) var(--p), rgba(255,255,255,.12) var(--p)); }
.scrub::-moz-range-track { height: 4px; border-radius: 4px; background: rgba(255,255,255,.12); }
.scrub::-moz-range-progress { height: 4px; border-radius: 4px; background: var(--accent); }
.scrub::-webkit-slider-thumb { -webkit-appearance: none; width: 14px; height: 14px; margin-top: -5px; border-radius: 50%;
  background: #fff; border: 0; box-shadow: 0 0 0 4px rgba(92,255,161,.25); }
.scrub::-moz-range-thumb { width: 14px; height: 14px; border-radius: 50%; background: #fff; border: 0; box-shadow: 0 0 0 4px rgba(92,255,161,.25); }
.clock { display: grid; font: 12.5px/1.25 var(--mono); min-width: 92px; }
.clock .abs { color: var(--faint); font-size: 11px; }
.lapse { font: 600 10.5px/1 var(--mono); color: var(--kernel); letter-spacing: .06em; padding: 4px 7px; border-radius: 6px;
  background: rgba(255,179,71,.1); visibility: hidden; }
.lapse.on { visibility: visible; }
.quiet { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--muted); cursor: pointer; user-select: none; }
.quiet input { accent-color: var(--accent); margin: 0; }
.keys { font-size: 11px; color: var(--faint); }
.keys kbd .ic { width: 10px; height: 10px; vertical-align: -1px; }
.keys kbd { font: 10.5px var(--mono); padding: 1px 5px; border: 1px solid var(--line-2); border-bottom-width: 2px; border-radius: 4px; color: var(--muted); }
@container graveyard (max-width: 720px) { .keys { display: none; } }

.pipeline { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px; }
.pipeline li { font: 600 10.5px/1 var(--mono); letter-spacing: .04em; padding: 6px 8px; border-radius: 7px;
  color: var(--faint); border: 1px solid var(--line); transition: background .25s, color .25s, box-shadow .25s; }
.pipeline li.done { color: #b7f3cf; border-color: rgba(92,255,161,.22); background: rgba(92,255,161,.045); }
.pipeline li.now { color: #04140b; background: var(--accent); border-color: var(--accent); box-shadow: 0 0 18px rgba(92,255,161,.35); }
.pipeline li.now.bad { background: var(--error); border-color: var(--error); color: #1a0306; box-shadow: 0 0 18px rgba(255,90,106,.4); }
.pipeline li.pre { color: var(--muted); border-style: dashed; }
`;

const stage = String.raw`
.stage { position: relative; padding: 12px 12px 6px; border-radius: 14px; background: var(--panel); border: 1px solid var(--line); }
.stage-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px; }
.stage-head h4 { font: 600 11px/1 var(--mono); letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.legend { display: flex; flex-wrap: wrap; gap: 6px; }
.lg { display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px; border-radius: 6px; border: 1px solid var(--line);
  background: transparent; font-size: 11.5px; color: var(--text); }
.lg[aria-pressed="false"] { opacity: .45; }
.lg i { width: 12px; height: 3px; border-radius: 2px; background: var(--c); }
.lg.dash i { background: repeating-linear-gradient(90deg, var(--c) 0 3px, transparent 3px 6px); }
.legend-note { font-size: 11px; color: var(--faint); display: inline-flex; align-items: center; gap: 6px; }
.legend-note b { display: inline-block; width: 9px; height: 9px; border-radius: 50%; border: 1.5px dashed var(--crew); }
.chart-wrap { position: relative; }
.chart { display: block; width: 100%; height: auto; overflow: visible; user-select: none; touch-action: pan-y; }
.chart text { font: 10.5px var(--mono); fill: var(--muted); }
.chart .axis text { fill: var(--faint); }
.chart .grid line { stroke: rgba(255,255,255,.05); }
.chart .grid line.t0 { stroke: rgba(255,255,255,.16); }
.chart .mem-area { fill: url(#fcg-mem); }
.chart .mem-line { fill: none; stroke: var(--sentinel); stroke-width: 1.6; }
.chart .psi-some { fill: none; stroke: var(--kernel); stroke-width: 1.5; }
.chart .psi-full { fill: none; stroke: var(--error); stroke-width: 1.2; stroke-dasharray: 3 3; }
.chart .limit { stroke: var(--error); stroke-dasharray: 6 5; opacity: .65; }
.chart .limit-label { fill: var(--error); opacity: .85; }
.chart .band-verify { fill: rgba(79,216,255,.075); }
.chart .band-wait { fill: rgba(255,106,213,.06); }
.chart .band-label { fill: var(--faint); }
.chart .mark line { stroke: var(--lane); stroke-width: 1.2; opacity: .75; }
.chart .mark rect { fill: rgba(7,8,12,.92); stroke: var(--lane); stroke-width: 1; }
.chart .mark text { fill: var(--lane); font-weight: 600; }
.chart .lane-row { fill: rgba(255,255,255,.018); }
.chart .lane-label { fill: var(--lane); font-weight: 600; }
.chart .dot { fill: var(--lane); stroke: var(--lane); stroke-width: 1.5; opacity: .3; cursor: pointer; transition: opacity .2s; }
.chart .dot.on { opacity: 1; filter: drop-shadow(0 0 4px var(--lane)); }
.chart .dot.inferred { fill: var(--bg); stroke-dasharray: 2 1.6; }
.chart .dot.sel { stroke: #fff; stroke-width: 2; }
.chart .dot.lvl-error { fill: var(--error); stroke: var(--error); }
.chart .future { fill: var(--bg); opacity: .6; pointer-events: none; }
.chart .playhead { stroke: #fff; stroke-width: 1.3; opacity: .9; pointer-events: none; }
.chart .ph-dot { fill: #fff; stroke: var(--sentinel); stroke-width: 2; pointer-events: none; }
.chart .ph-label { fill: #fff; font-weight: 600; pointer-events: none; }
.chart .hover-line { stroke: rgba(255,255,255,.35); stroke-dasharray: 2 3; pointer-events: none; }
.chart .hit { fill: transparent; cursor: crosshair; }
.tip { position: absolute; z-index: 2; pointer-events: none; transform: translate(-50%, calc(-100% - 10px)); white-space: nowrap;
  padding: 6px 8px; border-radius: 8px; font: 11.5px/1.45 var(--mono); background: rgba(10,12,18,.95); border: 1px solid var(--line-2);
  box-shadow: 0 8px 24px rgba(0,0,0,.4); }
.tip[hidden] { display: none; }
.tip .tt { color: var(--muted); }
.stamp { position: absolute; top: 46px; right: 26px; z-index: 1; padding: 4px 14px; border: 2px solid currentColor; border-radius: 10px;
  font: 800 18px/1.3 var(--mono); letter-spacing: .2em; opacity: 0; transform: rotate(-9deg) scale(.6);
  transition: opacity .35s, transform .45s cubic-bezier(.2,1.6,.4,1); pointer-events: none; background: rgba(7,8,12,.6); }
.stamp.on { opacity: .95; transform: rotate(-9deg) scale(1); }
.stamp.ok { color: var(--sentinel); text-shadow: 0 0 16px rgba(92,255,161,.5); }
.stamp.bad { color: var(--error); text-shadow: 0 0 16px rgba(255,90,106,.5); }
`;

const panels = String.raw`
.panels { display: grid; gap: 12px; grid-template-columns: minmax(0, 1fr); }
@container graveyard (min-width: 760px) {
  .panels { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .panels .evcard { grid-column: 1 / -1; display: grid; grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr); gap: 18px; }
}
@container graveyard (min-width: 1360px) {
  .panels { grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr) minmax(0, .95fr); }
  .panels .evcard { grid-column: auto; display: block; }
}
.card { min-width: 0; padding: 12px 14px 14px; border-radius: 14px; background: var(--panel); border: 1px solid var(--line); }
.card-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 10px; }
.card-head h4 { font: 600 11px/1 var(--mono); letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.card-head span { font-size: 11px; color: var(--faint); }

.screen { border-radius: 12px; border: 1px solid var(--line); background: #0a0c11; overflow: hidden; }
.chat-head { display: flex; align-items: center; gap: 10px; padding: 9px 12px; border-bottom: 1px solid var(--line);
  background: rgba(255,255,255,.025); }
.avatar { width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; font: 700 11px var(--mono); color: #04140b;
  background: linear-gradient(140deg, var(--sentinel), var(--crew)); flex: none; }
.chat-head b { display: block; font-size: 13px; font-weight: 600; }
.chat-head small { display: block; font-size: 11px; color: var(--muted); }
.msgs { height: 312px; overflow-y: auto; padding: 12px 10px; display: flex; flex-direction: column; gap: 8px;
  background: radial-gradient(circle at 20% 10%, rgba(255,255,255,.025) 0 1px, transparent 1px) 0 0 / 18px 18px; }
.msg { max-width: 90%; align-self: flex-start; padding: 7px 10px 5px; border-radius: 4px 12px 12px 12px; background: #1a1f2b;
  font-size: 12.5px; line-height: 1.45; overflow-wrap: anywhere; animation: fc-in .35s ease both; }
.msg.me { align-self: flex-end; border-radius: 12px 4px 12px 12px; background: linear-gradient(135deg, rgba(255,106,213,.24), rgba(155,140,255,.22)); }
.msg code { font-size: 11.5px; padding: 0 4px; border-radius: 4px; background: rgba(255,255,255,.08); }
.msg .meta { display: flex; justify-content: flex-end; align-items: center; gap: 3px; font-size: 10px; color: var(--faint); margin-top: 3px; }
.msg .meta .ic { width: 14px; height: 10px; color: var(--verify); }
.msg .from { display: block; font-size: 11px; font-weight: 600; color: var(--sentinel); margin-bottom: 2px; }
.msg.me .from { color: var(--human); }
.poll-tag { font: 600 10px/1 var(--mono); letter-spacing: .08em; color: var(--human); margin-bottom: 5px; display: block; }
.poll-q { font-weight: 600; margin-bottom: 4px; }
.opt { display: grid; grid-template-columns: 16px minmax(0, 1fr) auto; gap: 4px 8px; align-items: center; padding: 6px 0 4px;
  border-top: 1px solid var(--line); font-size: 12px; }
.radio { width: 14px; height: 14px; border-radius: 50%; border: 1.5px solid var(--muted); display: grid; place-items: center;
  font-size: 9px; color: #1a0316; }
.opt.chosen .radio { background: var(--human); border-color: var(--human); }
.opt.chosen .radio::after { content: ''; width: 3px; height: 6px; margin-top: -2px; border: solid #1a0316; border-width: 0 2px 2px 0; transform: rotate(45deg); }
.opt .votes { font: 10.5px var(--mono); color: var(--faint); }
.opt.chosen .votes { color: var(--human); }
.bar { grid-column: 2 / 4; height: 3px; border-radius: 2px; background: rgba(255,255,255,.07); overflow: hidden; }
.bar i { display: block; height: 100%; width: 0; background: var(--human); transition: width .6s ease; }
.opt.chosen .bar i { width: 100%; }
.voter { font-size: 10.5px; color: var(--muted); margin-top: 4px; }
.empty { margin: auto; font-size: 12px; color: var(--faint); text-align: center; padding: 20px; }
`;

const term = String.raw`
.term-screen { height: 360px; overflow-y: auto; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--line);
  background: #05060a; font: 11.5px/1.55 var(--mono); }
.ln { display: grid; grid-template-columns: 58px 124px minmax(0, 1fr); gap: 0 10px; padding: 2px 0; animation: fc-in .3s ease both; }
.ln .ts { color: var(--faint); }
.ln .who { color: var(--lane); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ln .what { color: var(--text); }
.ln .why { grid-column: 3; color: var(--faint); font-size: 11px; overflow-wrap: anywhere; display: -webkit-box; -webkit-box-orient: vertical;
  -webkit-line-clamp: 2; line-clamp: 2; overflow: hidden; }
.ln.sel .why { -webkit-line-clamp: unset; line-clamp: none; }
.ln.inferred { opacity: .8; }
.ln.inferred .what { font-style: italic; color: var(--muted); }
.ln.inferred .what::before { content: '~ '; color: var(--crew); font-style: normal; }
.ln.lvl-warn .what { color: var(--kernel); } .ln.lvl-error .what { color: var(--error); } .ln.lvl-ok .what { color: var(--sentinel); }
.ln.sel { background: rgba(79,216,255,.07); border-radius: 4px; }
.cursor { display: inline-block; width: 7px; height: 13px; margin-top: 4px; background: var(--accent); animation: fc-blink 1s steps(2) infinite; }
@container graveyard (max-width: 560px) {
  .ln { grid-template-columns: 54px minmax(0, 1fr); }
  .ln .who { grid-column: 2; }
  .ln .what, .ln .why { grid-column: 2; }
}

.ev { border-left: 3px solid var(--lane, var(--line-2)); padding: 2px 0 2px 12px; display: grid; gap: 4px; min-height: 120px; align-content: start; }
.ev .k { font: 11px/1.4 var(--mono); color: var(--muted); display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.ev .k b { color: var(--lane); font-weight: 600; }
.ev .ttl { font-size: 15px; font-weight: 600; line-height: 1.35; }
.ev .d { font-size: 12.5px; color: var(--muted); overflow-wrap: anywhere; }
.inf { font: 600 10px/1 var(--mono); letter-spacing: .06em; padding: 3px 6px; border-radius: 5px; color: var(--crew);
  border: 1px dashed var(--crew); }
.ev-nav { display: flex; gap: 6px; margin-top: 8px; }
.gauge { margin-top: 16px; display: grid; gap: 8px; }
.g-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
.g-head h4 { font: 600 11px/1 var(--mono); letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.g-val { font-size: 22px; font-weight: 700; color: var(--accent); font-variant-numeric: tabular-nums; text-shadow: 0 0 18px rgba(92,255,161,.35); }
.g-track { position: relative; height: 10px; border-radius: 6px; margin: 8px 0 2px;
  background: linear-gradient(90deg, rgba(92,255,161,.4), rgba(92,255,161,.18) 55%, rgba(255,179,71,.3) 80%, rgba(255,90,106,.55)); }
.g-mark { position: absolute; top: -5px; width: 3px; height: 20px; margin-left: -1.5px; border-radius: 2px; background: #fff;
  box-shadow: 0 0 10px rgba(92,255,161,.9); }
.g-budget { position: absolute; top: -6px; height: 22px; border-left: 2px dashed var(--error); }
.g-budget span { position: absolute; top: -16px; left: -2px; transform: translateX(-100%); font: 10px var(--mono); color: var(--error); white-space: nowrap; padding-right: 4px; }
.g-scale { position: relative; height: 14px; font: 10px var(--mono); color: var(--faint); }
.g-scale span { position: absolute; top: 0; transform: translateX(-50%); white-space: nowrap; }
.g-scale span:first-child { transform: none; } .g-scale span:last-child { transform: translateX(-100%); }
.g-note { font-size: 11.5px; color: var(--muted); }
`;

const tabs = String.raw`
.tabs { border-radius: 14px; background: var(--panel); border: 1px solid var(--line); overflow: hidden; }
.tablist { display: flex; gap: 2px; padding: 0 10px; border-bottom: 1px solid var(--line); overflow-x: auto; }
.tab { border: 0; background: none; padding: 11px 12px 9px; font-size: 13px; color: var(--muted); border-bottom: 2px solid transparent; white-space: nowrap; }
.tab:hover { color: var(--text); }
.tab[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
.tabpanel { padding: 14px; }
.tabpanel[hidden] { display: none; }
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 12px; }
.toolbar .grow { flex: 1; }
.toolbar .note { font-size: 11.5px; color: var(--faint); }
.pm { display: grid; gap: 14px; }
@container graveyard (min-width: 900px) { .pm { grid-template-columns: 210px minmax(0, 1fr); } }
.toc { display: none; align-content: start; gap: 2px; font-size: 12.5px; }
@container graveyard (min-width: 900px) { .toc { display: grid; } }
.toc button { text-align: left; border: 0; background: none; padding: 4px 8px; border-radius: 6px; color: var(--muted);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; }
.toc button:hover { background: rgba(255,255,255,.05); color: var(--text); }
.toc button.l3 { padding-left: 20px; font-size: 12px; }
.pm-body { position: relative; max-height: 600px; overflow: auto; padding-right: 6px; }
.md { font-size: 13px; line-height: 1.6; color: #d5d9e3; }
.md h3, .md h4, .md h5, .md h6 { color: var(--text); line-height: 1.3; margin: 18px 0 8px; letter-spacing: -.01em; }
.md h3 { font-size: 18px; margin-top: 0; } .md h4 { font-size: 15px; } .md h5 { font-size: 13.5px; color: var(--muted); }
.md p { margin: 0 0 10px; }
.md ul { margin: 0 0 12px; padding-left: 20px; }
.md li { margin: 2px 0; }
.md li.md-task { list-style: none; margin-left: -20px; display: flex; gap: 8px; align-items: baseline; }
.md li.md-task input { accent-color: var(--accent); margin: 0; transform: translateY(2px); }
.md code { font-size: 12px; padding: 1px 5px; border-radius: 5px; background: rgba(255,255,255,.06); color: #f2f4f8; }
.md strong { color: var(--text); }
.md a { color: var(--verify); }
.md-table { overflow-x: auto; margin: 0 0 14px; border: 1px solid var(--line); border-radius: 10px; }
.md table { border-collapse: collapse; width: 100%; font-size: 12px; }
.md th, .md td { padding: 6px 9px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
.md th { color: var(--muted); font-weight: 600; background: rgba(255,255,255,.025); white-space: nowrap; }
.md td { max-width: 460px; overflow-wrap: anywhere; }
.md tr:last-child td { border-bottom: 0; }
.md-code { margin: 0 0 14px; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--line); background: #05060a;
  overflow: auto; font: 11.5px/1.55 var(--mono); white-space: pre; }
.md-code code { padding: 0; background: none; font-size: inherit; }
.filters { display: flex; flex-wrap: wrap; gap: 6px; }
.fchip { display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 999px; border: 1px solid var(--line-2);
  background: transparent; font-size: 11.5px; }
.fchip i { width: 8px; height: 8px; border-radius: 50%; background: var(--lane); }
.fchip[aria-pressed="false"] { opacity: .45; }
.log-wrap { max-height: 520px; overflow: auto; border: 1px solid var(--line); border-radius: 10px; }
.log { border-collapse: collapse; width: 100%; font-size: 12px; }
.log th { position: sticky; top: 0; background: #121623; color: var(--muted); font-weight: 600; text-align: left; padding: 7px 9px; z-index: 1; }
.log td { padding: 6px 9px; border-top: 1px solid var(--line); vertical-align: top; }
.log td.d { color: var(--muted); overflow-wrap: anywhere; }
.log button { border: 0; background: none; padding: 0; font: 11.5px var(--mono); color: var(--verify); text-decoration: underline dotted; }
.log .lane { display: inline-flex; align-items: center; gap: 6px; color: var(--lane); font: 11px var(--mono); }
.log .lane i { width: 7px; height: 7px; border-radius: 50%; background: var(--lane); }
.log tr.inferred td { font-style: italic; }
.raw { margin: 0; max-height: 520px; overflow: auto; padding: 12px; border-radius: 10px; border: 1px solid var(--line); background: #05060a;
  font: 11.5px/1.55 var(--mono); color: #c8cede; white-space: pre; }
`;

const states = String.raw`
.loading, .failed { padding: 48px 24px; display: grid; gap: 10px; justify-items: center; text-align: center; color: var(--muted); }
.loading .bars { display: grid; gap: 8px; width: min(520px, 100%); }
.loading .bars i { display: block; height: 12px; border-radius: 6px;
  background: linear-gradient(90deg, rgba(255,255,255,.04) 0, rgba(255,255,255,.1) 50%, rgba(255,255,255,.04) 100%) 0 0 / 400px 100%;
  animation: fc-shimmer 1.4s linear infinite; }
.loading .bars i:nth-child(2) { width: 82%; } .loading .bars i:nth-child(3) { width: 64%; }
.failed b { color: var(--error); font-size: 15px; }
.failed code { font-size: 12px; padding: 2px 6px; border-radius: 5px; background: rgba(255,255,255,.06); color: var(--text); }
.foot { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px; padding: 10px 20px; border-top: 1px solid var(--line);
  font-size: 11.5px; color: var(--faint); }
.foot a { color: var(--muted); }

@container graveyard (max-width: 560px) {
  .top { padding: 14px; }
  .main { padding: 14px 12px 18px; }
  .stage { padding: 10px 6px 4px; }
  .card { padding: 12px 10px; }
  .stamp { top: 40px; right: 12px; padding: 2px 9px; font-size: 13px; border-width: 1.5px; }
}

@keyframes fc-in { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
@keyframes fc-blink { 50% { opacity: 0; } }
@keyframes fc-shimmer { from { background-position: -400px 0; } to { background-position: 400px 0; } }
@media (prefers-reduced-motion: reduce) {
  .app *, .app *::before, .app *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
`;

export const css = [base, layout, player, stage, panels, term, tabs, states].join('\n');
