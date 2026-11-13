// FrankenCrew: Kiro Crew dashboard entry (app.json ui.entry = "dist/index.mjs").
//
// The Crew dashboard imports /apps/franken-crew/ui/dist/index.mjs and renders the default export as a
// React component, with React provided by the host through window.__kirocrew_modules (no bundler, no
// bare imports). The component only owns a <div>; the Graveyard itself is framework-free and mounts
// into that div's shadow root. Other hosts (the landing page, `franken lab serve`) call mount() directly.

import { mount, loadReplay, summarize, normalizeReplay, SCHEMA, DEFAULT_DATA_URL } from './graveyard.mjs';

export { mount, loadReplay, summarize, normalizeReplay, SCHEMA, DEFAULT_DATA_URL };

const hostStyle = { padding: '16px 24px 32px', overflowY: 'auto', flex: '1 1 auto', minHeight: 0 };

export default function FrankenCrewGraveyard() {
  const React = globalThis.__kirocrew_modules?.react;
  if (!React) throw new Error('FrankenCrew Graveyard: React was not provided by the Kiro Crew host; call mount(element) instead.');
  const ref = React.useRef(null);
  React.useEffect(() => mount(ref.current), []);
  return React.createElement('div', { ref, 'data-app': 'franken-crew', style: hostStyle });
}
