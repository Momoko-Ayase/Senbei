import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { LANGUAGES, loadLanguage, show, t, technical } from '../i18n.js';
import { find, makeEntries, makeGroup, makeItem, state, targets } from '../state.js';
import * as view from '../view.js';
import { lineText } from '../detail.js';
import { rowState, shownPath, typeTag } from '../ui.js';
import { reportText } from '../text.js';

const web = new URL('..', import.meta.url);
const catalogs = Object.fromEntries(
  await Promise.all(
    LANGUAGES.map(async ([tag]) => [tag, (await import(new URL(`i18n/${tag}.js`, web))).default]),
  ),
);

/** Load the English catalog, as the page does before it draws anything. */
async function english() {
  globalThis.document ??= { documentElement: {} };
  await loadLanguage('en');
}

function reset() {
  Object.assign(state, {
    groups: [],
    selected: null,
    multi: [],
    filter: 'all',
    search: '',
    tab: 'overview',
    logLevel: 'all',
    showNonTargets: false,
    run: null,
    saving: false,
    scans: [],
    out: { mode: 'downloads', dir: null },
    notice: null,
  });
  state.collapsed.clear();
}

const candidate = (path) => ({ path, open: null });

/** The result of a job, as `run.js` records it. */
function resultOf(info, outputs = []) {
  return {
    info: { warnings: [], errors: [], findings: [], routes: [], log: [], error: null, note: null, profile: null, metadata: null, elf: null, ...info },
    lang: 'en',
    durationMs: 6,
    retried: false,
    companionUsed: false,
    companionSize: null,
    companionSha256: null,
    inputSha256: null,
    outputs: outputs.map((output) => ({ blob: null, size: 1, sha256: null, embedded: false, saved: null, saveFailed: null, refused: false, ...output })),
  };
}

const profile = (extra = {}) => ({
  observed: { platform: 'windows_pe', format: 'pe32_plus', kind: 'native_dll' },
  evidence: ['signature'],
  recognition: 'recognized',
  static_validation: 'clean',
  selected: 'dll',
  ...extra,
});

test('the generated catalogs match the desktop wording they are taken from', () => {
  execFileSync(process.execPath, [fileURLToPath(new URL('tools/gen-i18n.mjs', web)), '--check'], {
    stdio: 'pipe',
  });
});

test('every language has the same keys and placeholders', () => {
  const placeholders = (text) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
  const english = catalogs.en;
  for (const [tag, catalog] of Object.entries(catalogs)) {
    assert.deepEqual(Object.keys(catalog), Object.keys(english), tag);
    for (const [key, text] of Object.entries(catalog)) {
      assert.ok(text.length > 0, `${tag} ${key}`);
      assert.deepEqual(placeholders(text), placeholders(english[key]), `${tag} ${key}`);
    }
  }
});

test('every key the page names is in the catalog', () => {
  const source = ['app.js', 'run.js', 'output.js', 'state.js', 'view.js', 'detail.js', 'ui.js', 'report.js', 'text.js']
    .map((file) => readFileSync(new URL(file, web), 'utf8'))
    .join('\n');
  const named = new Set();
  // t('key'), { key: 'key' }, pageError('key'), notify('key'), and key tables.
  for (const match of source.matchAll(/'([A-Za-z]+\.[A-Za-z0-9_.]+)'/g)) named.add(match[1]);
  for (const match of source.matchAll(/\bt\('([A-Za-z]+)'/g)) named.add(match[1]);
  const missing = [...named].filter((key) => !(key in catalogs.en) && !key.startsWith('senbei.'));
  assert.deepEqual(missing, []);
  assert.ok(named.size > 120, String(named.size));
});

test('messages follow the page language, engine messages only when it matches', () => {
  // No catalog is loaded here, so `t` returns the key and the language is `en`.
  assert.equal(t('missing.key'), 'missing.key');
  const engine = { text: 'English', local: '日本語' };
  assert.equal(show(engine), '日本語');
  assert.equal(technical(engine), 'English');
  assert.equal(show(engine, 'ja'), 'English');
  assert.equal(technical(engine, 'ja'), null);
  assert.equal(show({ text: 'English', local: null }), 'English');
  assert.equal(technical({ text: 'English', local: null }), null);
  const page = { key: 'web.over_limit', vars: { size: '1', limit: '2' }, text: 'x', tech: 'raw' };
  assert.equal(show(page, 'ja'), 'web.over_limit');
  assert.equal(technical(page), 'raw');
  // A message that names its own language is not bound to its job's.
  assert.equal(show({ text: 'English', local: '日本語', lang: 'ja' }), 'English');
  assert.equal(show({ text: 'English', local: 'Local', lang: 'en' }, 'ja'), 'Local');
});

test('a run covers the picked rows, else the selection, else every input', () => {
  reset();
  const files = makeGroup('files', '');
  const folder = makeGroup('folder', 'game');
  const [a, b] = ['a.exe', 'b.dll'].map((path) => makeItem(files, candidate(path), 1));
  const pack = makeItem(folder, candidate('app.apk'), 1);
  pack.kind = 'package';
  pack.container = { kind: 'apk', archives: [{ label: '', targets: [{ path: 'lib/x.so', entry: { size: 1 } }] }] };
  pack.entries = makeEntries(pack);
  const lib = makeItem(folder, candidate('lib/y.so'), 1);
  files.items.push(a, b);
  folder.items.push(pack, lib);
  state.groups = [files, folder];

  assert.deepEqual(targets(), [a, b, pack, lib]);
  state.selected = folder.id;
  assert.deepEqual(targets(), [pack, lib]);
  // An entry stands for its package.
  state.selected = pack.entries[0].id;
  assert.deepEqual(targets(), [pack]);
  // Picked rows run in list order, and the shown row is not added to them.
  state.multi = [lib.id, a.id];
  state.selected = b.id;
  assert.deepEqual(targets(), [a, lib]);
  assert.equal(find(pack.entries[0].id).item, pack.entries[0]);
  assert.equal(find('nothing'), null);
  reset();
});

test('rows read as the workbench writes them', async () => {
  await english();
  reset();
  const group = makeGroup('files', '');
  const make = (path, extra) => Object.assign(makeItem(group, candidate(path), 10), extra);

  const dll = make('bin/Plugin.dll', { kind: 'pe', pre: profile() });
  assert.equal(typeTag(dll), 'PE32+ DLL');
  assert.deepEqual(rowState(dll), { dot: null, label: 'Not run yet', tone: null, extra: null, time: null });
  dll.notProtected = true;
  assert.equal(rowState(dll).label, 'Not protected');

  dll.state = 'ok';
  dll.durationMs = 1420;
  dll.result = resultOf({ status: 'recovered', profile: profile({ selected: 'exe_style' }) });
  assert.deepEqual(rowState(dll), { dot: 'ok', label: 'Recovered', tone: 'ok', extra: 'Unpacked', time: '1.42 s' });
  dll.state = 'running';
  assert.deepEqual(rowState(dll), { dot: 'info', label: 'Running…', tone: 'info', extra: null, time: null });
  dll.state = 'queued';
  assert.equal(rowState(dll).label, 'Queued');
  dll.state = 'cancelled';
  assert.equal(rowState(dll).label, 'Will not run');

  assert.equal(typeTag(make('lib/libil2cpp.so', { kind: 'so' })), 'ELF64 AArch64');
  assert.equal(typeTag(make('global-metadata.dat', { kind: 'metadata', metadataVersion: 31 })), 'il2cpp metadata v31');
  assert.equal(typeTag(make('app.xapk', { kind: 'package', container: { kind: 'xapk' } })), 'XAPK');
  // A package that could not be listed, and a file that is no target.
  assert.equal(typeTag(make('broken.apk', { kind: 'package' })), 'APK');
  assert.equal(typeTag(make('notes.txt', {})), 'TXT');
  assert.equal(typeTag(make('README', {})), '?');
});

test('log lines read in the page language', async () => {
  await english();
  const lines = [
    [{ type: 'run-started', n: 3 }, 'Unpack started · inputs: 3'],
    [{ type: 'scan', n: 35, s: 35 }, 'Scan finished: candidates 35, non-targets skipped 35'],
    [{ type: 'input-started', i: 2, n: 3, path: 'game/a.dll' }, 'Input 2/3: game/a.dll'],
    [{ type: 'companion', name: 'a.dll._' }, 'Companion paired: a.dll._'],
    [{ type: 'step', i: 1, of: 9, key: null, title: 'Custom step' }, 'Step 1/9: Custom step'],
    [{ type: 'step', i: null, of: null, key: null, title: 'Alone' }, 'Alone'],
    [{ type: 'detail', text: 'info[0] key = 0x1' }, 'info[0] key = 0x1'],
    [{ type: 'stage', stage: 'recovery', status: 'ok', durationMs: 461, detail: null }, 'Recovery: OK (461 ms)'],
    [{ type: 'stage', stage: 'detection', status: 'ok', durationMs: null, detail: null }, 'Detection: OK'],
    [
      { type: 'stage', stage: 'recovery', status: 'failed', durationMs: 0, detail: { text: 'bad header', local: null }, lang: 'en' },
      'Recovery: Failed — bad header',
    ],
    [{ type: 'message', message: { text: 'careful', local: null }, lang: 'en' }, 'careful'],
    [{ type: 'entry', path: 'lib/x.so', outcome: 'entryStatus.restored' }, 'Entry lib/x.so: Restored'],
    [{ type: 'finished', outcome: 'status.ok', durationMs: 1420 }, 'Finished: Recovered (1.42 s)'],
    [{ type: 'summary', counts: { ok: 3, suspect: 0, failed: 1, skipped: 2 } }, '3 recovered · 0 suspect · 1 failed · 2 skipped'],
  ];
  for (const [line, text] of lines) assert.equal(lineText(line), text);
});

test('the frame follows the selection and what has run', async () => {
  await english();
  reset();
  assert.ok(view.detail().includes('Drop protected files here'));
  const group = makeGroup('folder', 'game');
  const item = Object.assign(makeItem(group, candidate('bin/Plugin.dll'), 10), { kind: 'pe', pre: profile() });
  group.items.push(item);
  state.groups = [group];

  assert.ok(view.topbar().includes('>▶</span> Unpack all'));
  assert.ok(view.detail().includes('Select an input or a group on the left.'));
  // The filter chips wait for the first result.
  assert.equal(view.chips(), '');
  assert.deepEqual(view.listRows().map((row) => row.key), [group.id, item.id]);

  state.selected = group.id;
  assert.ok(view.topbar().includes('>▶</span> Unpack (1)'));
  const pending = view.detail();
  for (const text of ['Summary', 'Folder scan', 'Non-targets skipped', 'Overview', 'Log']) assert.ok(pending.includes(text), text);
  assert.ok(!pending.includes('Export JSON'));

  item.state = 'ok';
  item.durationMs = 6;
  item.result = resultOf({ status: 'recovered', profile: profile() }, [{ path: 'bin/Plugin.unpack.dll' }]);
  assert.ok(view.chips().includes('Recovered'));
  assert.ok(view.detail().includes('Export text'));
  state.selected = item.id;
  const done = view.detail();
  for (const text of ['Recognition', 'Recovery routes', 'Stages', 'Identity', 'PE32+ DLL', shownPath('game/bin/Plugin.dll'), 'Unpacked · 6 ms']) {
    assert.ok(done.includes(text), text);
  }
  state.filter = 'failed';
  assert.deepEqual(view.listRows().map((row) => row.key), ['none']);
  reset();
});

test('the folder picker explains the fallback before a folder is chosen', async () => {
  await english();
  reset();
  state.settingsTab = 'general';
  const hint = view.esc(t('web.out_folder_help'));
  for (const [lang, catalog] of Object.entries(catalogs)) {
    assert.ok(catalog['web.out_folder_help'].includes('senbei-remaining.*.zip'), lang);
  }
  for (const [html, id] of [[view.outMenu(true), 'out-folder-help'], [view.settings(true), 'set-output-help']]) {
    assert.ok(html.includes(`aria-describedby="${id}"`));
    assert.ok(html.includes(`id="${id}">${hint}</p>`));
  }
  for (const html of [view.outMenu(false), view.settings(false)]) {
    assert.ok(!html.includes(hint));
    assert.ok(html.includes(view.esc(t('web.out_unsupported'))));
  }
  reset();
});

test('the Overview and text export agree when a package has no targets', async () => {
  await english();
  reset();
  const group = makeGroup('files', '');
  const item = Object.assign(makeItem(group, candidate('empty.apk'), 1), {
    kind: 'package',
    state: 'skipped',
    container: { kind: 'apk', archives: [{ label: '', entryCount: 1, targets: [] }], problems: [] },
    entries: [],
  });
  group.items.push(item);
  state.groups = [group];
  state.selected = item.id;
  assert.ok(view.detail().includes(t('pkg.no_targets')));
  assert.ok(reportText([item]).includes(t('pkg.no_targets')));
  assert.ok(!reportText([item]).includes(t('ov.no_routes')));
  reset();
});

test('package inventory identifies which archive holds each candidate', async () => {
  await english();
  reset();
  const group = makeGroup('files', '');
  const item = Object.assign(makeItem(group, candidate('app.xapk'), 2), {
    kind: 'package',
    state: 'ok',
    container: {
      kind: 'xapk',
      archives: ['', 'split.apk'].map((label) => ({
        label,
        targets: [{ path: 'lib/plugin.so', entry: { size: 1 } }],
      })),
    },
  });
  item.entries = makeEntries(item);
  group.items.push(item);
  state.groups = [group];
  state.selected = item.id;
  state.tab = 'entries';
  for (const name of ['app.xapk', 'split.apk']) {
    assert.ok(view.detail().includes(shownPath(`${name}::lib/plugin.so`)));
  }
  reset();
});

test('names and messages from files are never markup', async () => {
  await english();
  reset();
  const hostile = '<img src=x onerror=alert(1)>"\'&';
  const message = { text: hostile, local: hostile };
  const group = makeGroup('folder', hostile);
  const add = (path, extra) => {
    const item = Object.assign(makeItem(group, candidate(path), 10), extra);
    group.items.push(item);
    return item;
  };
  const outputs = [
    { path: hostile, sha256: hostile, saved: hostile },
    { path: hostile, sha256: hostile, embedded: true, saveFailed: hostile, refused: true },
    { path: hostile, saveFailed: hostile },
  ];
  const everyLine = [
    { type: 'run-started', n: hostile },
    { type: 'scan', n: hostile, s: hostile },
    { type: 'scan-incomplete' },
    { type: 'input-started', i: hostile, n: hostile, path: hostile },
    { type: 'companion', name: hostile },
    { type: 'step', i: 1, of: 2, key: null, title: hostile, lang: 'en' },
    { type: 'step', i: null, of: null, key: hostile, title: hostile, lang: 'en' },
    { type: 'detail', text: hostile },
    { type: 'stage', stage: hostile, status: hostile, durationMs: 5, detail: message, lang: 'en' },
    { type: 'message', message, lang: 'en' },
    { type: 'entry', path: hostile, outcome: hostile },
    { type: 'finished', outcome: hostile, durationMs: 5 },
    { type: 'summary', counts: { ok: hostile, suspect: hostile, failed: hostile, skipped: hostile } },
    { type: hostile, text: hostile },
  ].map((line, index) => ({ at: 1000 + index, level: ['info', 'step', 'detail', 'warn', 'error'][index % 5], ...line }));

  const hostileProfile = {
    observed: { platform: hostile, format: hostile, kind: hostile, metadata_version: hostile },
    evidence: [hostile],
    recognition: hostile,
    static_validation: 'warnings',
    selected: hostile,
  };
  const info = {
    profile: hostileProfile,
    routes: [{ layout: hostile, outcome: hostile, errors: [{ text: `${hostile}2`, local: null }], warnings: [message] }],
    warnings: [{ text: `${hostile}3`, local: null }],
    errors: [{ text: `${hostile}4`, local: hostile }],
    findings: [{ severity: 'fatal', message: `${hostile}5` }],
    note: { text: `${hostile}6`, local: null },
    metadata: { version: hostile, remapped: hostile, identity: { raw_version: hostile, layout: hostile, capabilities: {} } },
    elf: { sections: hostile, segments: 1, dynamic_symbols: hostile, dynamic_relocations: 1, pltgot_relocations: hostile },
  };

  const recovered = add(`${hostile}/${hostile}.dll`, {
    kind: 'pe',
    pre: hostileProfile,
    state: 'suspect',
    durationMs: 5,
    companion: { state: 'unmatched', name: hostile },
    log: everyLine,
    result: { ...resultOf({ ...info, status: 'recovered', suspect: true }, outputs), companionUsed: true, companionSize: 3, companionSha256: hostile, inputSha256: hostile },
  });
  const failed = add(`${hostile}.so`, {
    kind: 'so',
    state: 'failed',
    durationMs: 5,
    log: everyLine,
    error: message,
    result: resultOf({ ...info, status: 'failed', error: { text: `${hostile}7`, local: hostile } }),
  });
  const skipped = add(`${hostile}.dat`, {
    kind: 'metadata',
    metadataVersion: hostile,
    state: 'skipped',
    log: everyLine,
    result: resultOf({ ...info, status: 'unchanged' }),
  });
  const unread = add(`${hostile}.apk`, { kind: 'package', entries: [], identityError: message });
  const pending = add(`${hostile}.exe`, { kind: 'pe', pre: hostileProfile, companion: { state: 'spliced', name: hostile } });
  const plain = add(hostile, { notProtected: true });
  const pendingPack = add(`${hostile}.xapk`, { kind: 'package' });
  const pack = add(`${hostile}.apks`, { kind: 'package', state: 'failed', durationMs: 5, log: everyLine, error: message });
  for (const item of [pendingPack, pack]) {
    item.container = {
      kind: hostile,
      archives: [
        {
          label: '',
          entryCount: hostile,
          identity: [hostile, hostile],
          targets: [
            { path: `${hostile}/${hostile}.so`, entry: { size: 1 } },
            { path: `${hostile}/global-metadata.dat`, entry: { size: 2 } },
          ],
        },
        { label: hostile, entryCount: 2, identity: null, targets: [{ path: `lib/${hostile}.so`, entry: { size: 3 } }] },
      ],
      problems: [{ path: hostile, message: hostile }],
    };
    item.entries = makeEntries(item);
  }
  const [restored, broken, other] = pack.entries;
  Object.assign(restored, { state: 'ok', result: resultOf({ ...info, status: 'recovered' }, outputs) });
  Object.assign(broken, { state: 'failed', metadataVersion: hostile, error: message, result: resultOf({ ...info, status: 'failed' }) });
  Object.assign(other, { state: 'skipped', result: resultOf({ status: 'not_protected' }) });
  group.lastRun = { inputs: 3, index: 3, durationMs: 15, running: false, log: everyLine, finished: [] };
  group.stats = { skipped: 1, walkErrors: 2, probeErrors: 3 };
  state.groups = [group];
  state.out = { mode: 'folder', dir: { name: hostile } };
  state.notice = { key: 'web.saved', vars: { path: hostile }, tone: 'warn' };

  const rendered = [];
  const draw = () => {
    for (const tab of ['overview', 'entries', 'log']) {
      state.tab = tab;
      rendered.push(view.detail());
    }
    rendered.push(view.list(), view.topbar(), view.status(), view.chips());
  };
  const rows = [group, recovered, failed, skipped, unread, pending, plain, pendingPack, pack, ...pack.entries];
  for (const row of rows) {
    state.selected = row.id;
    state.multi = [recovered.id, row.id];
    state.showNonTargets = !state.showNonTargets;
    draw();
    rendered.push(view.rowMenu(row.id, { kind: 'item', runnable: true, busy: false }));
  }
  // A scan in progress, then a run with one input in each state it can have.
  group.scanning = true;
  state.scans = [{ group }];
  state.selected = group.id;
  draw();
  group.scanning = false;
  state.scans = [];
  recovered.state = 'running';
  failed.state = 'queued';
  skipped.state = 'cancelled';
  state.run = {
    total: 3,
    done: 1,
    current: recovered,
    step: { i: 1, of: 2, key: null, title: hostile },
    started: performance.now(),
    stopping: true,
    keep: recovered,
    begun: new Set(),
    groups: new Map(),
  };
  group.lastRun.running = true;
  for (const row of [group, recovered, failed, skipped]) {
    state.selected = row.id;
    draw();
  }
  state.search = hostile;
  draw();
  rendered.push(view.outMenu(true), view.outMenu(false), view.settings(true), view.legal(false), view.inputsFrame());

  assert.ok(find(other.id));
  assert.ok(rendered.length > 60);
  for (const html of rendered) {
    const at = html.indexOf('<img src=x');
    assert.equal(at, -1, html.slice(Math.max(0, at - 200), at + 80));
    assert.ok(!/onerror=alert\(1\)>"/.test(html));
  }
  const all = rendered.join('');
  assert.ok(all.includes('&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;'));
  // The text report is plain text: the name is in it as it is.
  assert.ok(reportText(group.items).includes(hostile));
  reset();
});
