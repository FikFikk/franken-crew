#!/usr/bin/env node
// Mengumpulkan data asli dari repo agar semua angka, log, dan nama file di video bisa ditelusuri ke sumbernya.
// Jalankan dari apps/video: `npm run data`. Butuh Go (GOTOOLCHAIN=auto mengunduh versi yang benar) dan git.
import {execFileSync, spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const outDir = path.resolve(here, '../src/data');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, {cwd: root, encoding: 'utf8', maxBuffer: 64 << 20, ...opts});

const fail = (msg) => {
  throw new Error(`collect-data: ${msg}`);
};

fs.mkdirSync(outDir, {recursive: true});

// 1. Salin data JSON apa adanya
for (const [from, to] of [
  ['ui/data/replay.json', 'replay.json'],
  ['app.json', 'app.json'],
  ['.kiro/hooks/preToolUse.json', 'preToolUse.json'],
]) {
  fs.copyFileSync(path.join(root, from), path.join(outDir, to));
}

// 2. Build biner franken sekali; `go run` mengubah exit code 2 menjadi 1, jadi pakai biner langsung
const bin = path.join(os.tmpdir(), `franken-video-data${process.platform === 'win32' ? '.exe' : ''}`);
run('go', ['build', '-o', bin, './cmd/franken'], {stdio: ['ignore', 'pipe', 'inherit']});

// 3. Chaos suite 20 run
const chaosOut = run(bin, ['chaos', 'run', '--runs', '20'], {stdio: ['ignore', 'pipe', 'ignore']});
const chaosRuns = [];
let chaosSummary = '';
for (const line of chaosOut.split('\n')) {
  const m = line.match(/^\[(\d+)\/(\d+)\]\s+(\S+)\s+status=(\S+).*?reflex=\d+ \(([\d.]+)ms\)\s+l2=(\S+)\s+state=(\S+)/);
  if (m) {
    chaosRuns.push({run: Number(m[1]), of: Number(m[2]), scenario: m[3], status: m[4], reflexMs: m[5], l2: m[6], state: m[7]});
  } else if (line.startsWith('Summary:')) {
    chaosSummary = line.trim();
  }
}
if (chaosRuns.length !== 20 || !chaosSummary) fail(`unexpected chaos output:\n${chaosOut}`);

// 4. Property test P1..P4
const pt = spawnSync(
  'go',
  ['test', '-count=1', '-run', 'Property_P[1-4]', '-v', './internal/policy', './internal/approval', './internal/reflex'],
  {cwd: root, encoding: 'utf8', maxBuffer: 64 << 20},
);
if (pt.status !== 0) fail(`property tests failed:\n${pt.stdout}\n${pt.stderr}`);
const propertyTests = [];
for (const line of pt.stdout.split('\n')) {
  const m = line.match(/^--- PASS: (\S+_Property_(P[1-4])_\S+) \(([\d.]+)s\)/);
  if (m) propertyTests.push({name: m[1], property: m[2], seconds: m[3]});
}
const packagesOk = pt.stdout.split('\n').filter((l) => l.startsWith('ok')).length;
if (propertyTests.length !== 4) fail(`expected 4 property tests, got ${propertyTests.length}`);

// 5. Hook PreToolUse sungguhan: payload yang menargetkan ssh.service harus diblokir dengan exit 2
const hook = JSON.parse(read('.kiro/hooks/preToolUse.json')).hooks[0];
const guardPayload = {
  hook_event_name: 'PreToolUse',
  tool_name: '@franken-sentinel/action_execute',
  tool_input: {incident_id: 'INC-20261113-0344-pi01-sim-02', action: 'unit_restart', params: {unit: 'ssh.service'}},
};
const [guardCmd, ...guardArgs] = hook.action.command.split(' ');
if (guardCmd !== 'franken') fail(`unexpected hook command ${hook.action.command}`);
const guard = spawnSync(bin, guardArgs, {cwd: root, input: JSON.stringify(guardPayload), encoding: 'utf8'});
const blockedLine = (guard.stderr.split('\n').find((l) => l.startsWith('BLOCKED')) ?? '').trim();
if (guard.status !== 2 || !blockedLine) fail(`guard did not block: status ${guard.status}\n${guard.stderr}`);

// 6. Spec: jumlah requirement, task, dan kriteria 3.1
const requirements = read('.kiro/specs/server-incident-remediation/requirements.md');
const requirementCount = (requirements.match(/^### Requirement \d+/gm) ?? []).length;
const req3 = requirements.split(/^### /m).find((s) => s.startsWith('Requirement 3:'));
const criterion31 = req3?.match(/^1\. (.+)$/m)?.[1]?.trim();
if (!criterion31) fail('Requirement 3.1 not found');
const tasks = read('.kiro/specs/server-incident-remediation/tasks.md');
const taskCount = (tasks.match(/^\s*- \[[ x]\]/gm) ?? []).length;
const taskDone = (tasks.match(/^\s*- \[x\]/gm) ?? []).length;
const design = read('.kiro/specs/server-incident-remediation/design.md');
const properties = [...design.matchAll(/^\s*- (P[1-4]): (.+)$/gm)].map((m) => ({id: m[1], text: m[2].trim()}));
if (properties.length !== 4) fail('design.md properties P1..P4 not found');

// 7. Steering: nama file dan mode inclusion dari frontmatter
const steeringDir = path.join(root, '.kiro/steering');
const steering = fs
  .readdirSync(steeringDir)
  .filter((f) => f.endsWith('.md'))
  .sort()
  .map((f) => {
    const head = fs.readFileSync(path.join(steeringDir, f), 'utf8').split(/^---$/m)[1] ?? '';
    const inclusion = head.match(/inclusion:\s*(\S+)/)?.[1] ?? 'always';
    const pattern = head.match(/fileMatchPattern:\s*"?([^"\n]+)"?/)?.[1] ?? null;
    return {file: f, inclusion, pattern};
  });

// 8. Jumlah tool MCP yang benar-benar didaftarkan
const countAddTool = (dir, filter) =>
  fs
    .readdirSync(path.join(root, dir))
    .filter((f) => f.endsWith('.go') && !f.endsWith('_test.go') && filter(f))
    .reduce((n, f) => n + (read(`${dir}/${f}`).match(/mcp\.AddTool\(/g) ?? []).length, 0);
const mcpTools = {
  sentinel: countAddTool('internal/mcpserver', () => true),
  wa: countAddTool('internal/wabridge', (f) => f === 'mcp_tools.go'),
};

// 9. Pull request yang sudah di-merge, dari merge commit (judul PR ada di body)
const merges = run('git', ['log', '--merges', '--format=%s%x1f%b%x1e']);
const mergedPRs = merges
  .split('\x1e')
  .map((rec) => rec.trim())
  .filter(Boolean)
  .map((rec) => {
    const [subject, body] = rec.split('\x1f');
    const n = subject.match(/^Merge pull request #(\d+)/)?.[1];
    return n ? {number: Number(n), title: (body ?? '').trim().split('\n')[0]} : null;
  })
  .filter(Boolean)
  .sort((a, b) => a.number - b.number);

// 10. Baris log berisi prompt injection dari simulasi
const sim = read('internal/lab/simulate.go');
const inj = sim.match(/journalLine\([^,]+,\s*"([^"]+)",\s*`([^`]*IGNORE[^`]*)`\)/);
if (!inj) fail('injected journal line not found in internal/lab/simulate.go');

// 11. Narasi per scene dari docs/DEMO_VIDEO_SCRIPT.md (kolom terakhir tabel shot list)
const scriptDoc = read('docs/DEMO_VIDEO_SCRIPT.md');
const narration = scriptDoc
  .split('\n')
  .filter((l) => /^\| \d:\d\d to \d:\d\d \|/.test(l))
  .map((l) => l.split('|').map((c) => c.trim()).filter(Boolean).at(-1));
if (narration.length !== 7) fail(`expected 7 narration rows, got ${narration.length}`);

const repo = {
  collectedAtCommit: run('git', ['rev-parse', '--short', 'HEAD']).trim(),
  narration,
  spec: {requirementCount, criterion31, taskCount, taskDone, properties},
  propertyTests,
  propertyPackagesOk: packagesOk,
  chaosRuns,
  chaosSummary,
  guard: {
    command: hook.action.command,
    trigger: hook.trigger,
    matcher: hook.matcher,
    payload: guardPayload,
    exitCode: guard.status,
    blockedLine,
  },
  steering,
  mcpTools,
  mergedPRs,
  injectedLog: {source: inj[1], text: inj[2]},
};

const banner = '// Dihasilkan oleh scripts/collect-data.mjs dari repo. Jangan diedit manual; jalankan `npm run data`.\n';
fs.writeFileSync(path.join(outDir, 'repo.ts'), `${banner}export const repo = ${JSON.stringify(repo, null, 2)} as const;\n`);
console.log(`data collected in ${path.relative(root, outDir)} (commit ${repo.collectedAtCommit})`);
console.log(`  ${chaosSummary}`);
console.log(`  property tests: ${propertyTests.length} PASS, guard exit ${guard.status}, MCP tools ${mcpTools.sentinel}+${mcpTools.wa}`);
