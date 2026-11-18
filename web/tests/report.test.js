import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  REPORT_SCHEMA,
  REPORT_SCHEMA_VERSION,
  buildReport,
  closingLines,
  companionLine,
  engineLines,
  fileReport,
  fileStamp,
  finishedLine,
  messagePlan,
  ranAsModule,
  reportFileName,
  serializeReport,
  stagesOf,
} from '../report.js';

const message = (text, local = null) => ({ text, local });

function recovered(overrides = {}) {
  return {
    name: 'Game.exe',
    relPath: 'bin/Game.exe',
    kind: 'pe',
    state: 'ok',
    size: 1000,
    pre: { recognition: 'recognized' },
    error: null,
    result: {
      info: {
        status: 'recovered',
        profile: { static_validation: 'clean', recognition: 'recognized' },
        error: null,
        note: null,
        warnings: [],
        errors: [],
        findings: [],
        metadata: null,
        elf: null,
        log: [
          { ms: 1, step: 'Decrypt', i: 1, of: 2 },
          { ms: 2, detail: 'key=0x1' },
          { ms: 5, step: 'Rebuild', i: 2, of: 2 },
        ],
      },
      durationMs: 12.6,
      lang: 'en',
      retried: false,
      companionUsed: false,
      inputSha256: 'aa',
      outputs: [{ path: 'bin/Game.unpack.exe', size: 2000, sha256: 'bb', embedded: false, saved: null }],
    },
    ...overrides,
  };
}

const stageList = (item) => stagesOf(item).map((stage) => [stage.stage, stage.status]);

test('every message is shown once, where a reader looks for it', () => {
  const item = recovered();
  item.result.info.warnings = [message('same'), message('other')];
  item.result.info.errors = [message('same')];
  // Why nothing was needed belongs to the recovery stage, not here.
  item.result.info.note = message('note');
  const plan = messagePlan(item);
  assert.deepEqual(plan.validation, []);
  assert.deepEqual(plan.top.map((entry) => [entry.tone, entry.message.text]), [
    ['err', 'same'],
    ['warn', 'other'],
  ]);
});

test('static check findings go with the validation verdict', () => {
  const item = recovered({ state: 'suspect' });
  const info = item.result.info;
  info.profile.static_validation = 'warnings';
  info.findings = [
    { severity: 'warning', message: 'import table is empty' },
    { severity: 'fatal', message: 'entry point outside the image' },
  ];
  info.warnings = [message('import table is empty')];
  info.error = message('top level');
  const plan = messagePlan(item);
  assert.deepEqual(plan.top.map((entry) => entry.message.text), ['top level']);
  assert.deepEqual(plan.validation.map((entry) => [entry.tone, entry.message.text]), [
    ['warn', 'import table is empty'],
    ['err', 'entry point outside the image'],
  ]);
});

test('a page error is shown for an input with no result', () => {
  const item = recovered({ state: 'failed', result: null, error: message('could not read') });
  assert.deepEqual(messagePlan(item).top, [{ tone: 'err', message: item.error }]);
  assert.deepEqual(messagePlan(null), { top: [], validation: [] });
});

test('a Windows module records every stage, a library and metadata what they have', () => {
  const kept = ['output_write', 'skipped'];
  const item = recovered();
  assert.deepEqual(stageList(item), [['detection', 'ok'], ['recovery', 'ok'], ['static_validation', 'ok'], kept]);
  assert.equal(stagesOf(item)[1].durationMs, 13);

  item.result.info.suspect = true;
  assert.deepEqual(stageList(item)[2], ['static_validation', 'failed']);

  const library = recovered({ kind: 'so' });
  assert.deepEqual(stageList(library), [['recovery', 'ok'], ['static_validation', 'ok'], kept]);
  const metadata = recovered({ kind: 'metadata' });
  assert.deepEqual(stageList(metadata), [['recovery', 'ok'], kept]);
});

test('the job that ran decides what an input is taken for', () => {
  // A library that turned out to be an ordinary one was told so as a module.
  const library = recovered({ kind: 'so', state: 'failed' });
  library.result.op = 'pe';
  library.result.info.status = 'failed';
  library.result.info.error = message('not a protected file');
  assert.equal(ranAsModule(library), true);
  assert.equal(stagesOf(library)[0].detail, library.result.info.error);

  assert.equal(ranAsModule(recovered()), true);
  assert.equal(ranAsModule(recovered({ kind: null })), true);
  assert.equal(ranAsModule(recovered({ kind: 'so' })), false);
  assert.equal(ranAsModule(recovered({ kind: 'metadata' })), false);
  assert.equal(ranAsModule(recovered({ kind: 'package' })), false);
});

test('an output is written only when a folder was chosen for it', () => {
  const item = recovered();
  assert.deepEqual(stageList(item).at(-1), ['output_write', 'skipped']);
  assert.equal(stagesOf(item).at(-1).detail, null);

  item.result.outputs[0].saved = 'unpack/bin/Game.unpack.exe';
  const written = stagesOf(item).at(-1);
  assert.deepEqual([written.stage, written.status], ['output_write', 'ok']);
  assert.deepEqual(written.detail, { text: 'unpack/bin/Game.unpack.exe', path: true });

  // A successful write must not hide a refusal to write a second output.
  item.result.outputs.push({ saveFailed: 'unpack/bin/Plugin.unpack.dll' });
  assert.deepEqual(stageList(item).at(-1), ['output_write', 'failed']);
});

test('an input that did not recover records the one stage that says why', () => {
  const failed = recovered({ state: 'failed' });
  failed.result.info.status = 'failed';
  failed.result.info.error = message('not a protected file');
  assert.deepEqual(stagesOf(failed), [
    { stage: 'recovery', status: 'failed', durationMs: null, detail: failed.result.info.error },
  ]);
  // A library's failure is in its messages, not in the stage.
  const library = recovered({ kind: 'so', state: 'failed' });
  library.result.info.status = 'failed';
  library.result.info.error = message('bad segment');
  assert.equal(stagesOf(library)[0].detail, null);

  // A file run on its own says how long the look took; one of a folder, why
  // it needed nothing.
  const unchanged = recovered({ kind: 'metadata', state: 'skipped' });
  unchanged.result.info.status = 'unchanged';
  unchanged.result.info.note = message('already plain');
  unchanged.result.outputs = [];
  assert.deepEqual(stagesOf(unchanged), [{ stage: 'recovery', status: 'skipped', durationMs: 13, detail: null }]);
  unchanged.group = { kind: 'folder' };
  assert.deepEqual(stagesOf(unchanged), [
    { stage: 'recovery', status: 'skipped', durationMs: null, detail: unchanged.result.info.note },
  ]);

  const unread = recovered({ state: 'failed', result: null, error: message('could not read') });
  assert.deepEqual(stagesOf(unread), [
    { stage: 'recovery', status: 'failed', durationMs: null, detail: unread.error },
  ]);
  assert.deepEqual(stagesOf(recovered({ state: 'pending', result: null })), []);
  assert.deepEqual(stagesOf(recovered({ kind: 'package' })), []);
  assert.deepEqual(stagesOf(null), []);
});

test('the engine lines keep their order and count time from the start of the job', () => {
  const info = recovered().result.info;
  info.log.push({ truncated: true });
  const lines = engineLines(info, 1000, 'ja');
  assert.deepEqual(lines.map((line) => [line.at, line.level, line.type]), [
    [1001, 'step', 'step'],
    [1002, 'detail', 'detail'],
    [1005, 'step', 'step'],
    [1005, 'detail', 'detail'],
  ]);
  assert.deepEqual(lines[0], { at: 1001, level: 'step', type: 'step', i: 1, of: 2, key: null, title: 'Decrypt', lang: 'ja' });
  assert.equal(lines[1].text, 'key=0x1');
  assert.equal(lines[3].text, '…');
  assert.deepEqual(engineLines(null, 0, 'en'), []);
});

test('a log closes with the stages, the messages, the entries, and the outcome', () => {
  const item = recovered({ durationMs: 12.6 });
  item.result.info.warnings = [message('careful', 'attention')];
  const lines = closingLines(item, 5000, { key: 'status.ok', tone: 'ok' });
  assert.deepEqual(lines.map((line) => [line.level, line.type]), [
    ['info', 'stage'],
    ['info', 'stage'],
    ['info', 'stage'],
    ['info', 'stage'],
    ['warn', 'message'],
    ['info', 'finished'],
  ]);
  assert.ok(lines.every((line) => line.at === 5000));
  assert.equal(lines[1].stage, 'recovery');
  assert.equal(lines[1].lang, 'en');
  assert.equal(lines[3].stage, 'output_write');
  assert.equal(lines[4].message.local, 'attention');
  assert.deepEqual(lines[5], { at: 5000, level: 'info', type: 'finished', outcome: 'status.ok', durationMs: 12.6 });

  const failed = recovered({ state: 'failed', result: null, error: message('could not read') });
  const closing = closingLines(failed, 1, { key: 'status.error', tone: 'err' });
  assert.deepEqual(closing.map((line) => [line.level, line.type]), [
    ['error', 'stage'],
    ['error', 'message'],
    ['error', 'finished'],
  ]);

  const entries = [
    { path: 'lib/a.so', key: 'entryStatus.restored', tone: 'ok' },
    { path: 'lib/b.so', key: 'entryStatus.error', tone: 'err' },
  ];
  const packed = closingLines({ kind: 'package', durationMs: 7, result: null, error: null }, 2, { key: 'status.error', tone: 'err' }, entries);
  assert.deepEqual(packed.map((line) => [line.level, line.type, line.path ?? null]), [
    ['info', 'entry', 'lib/a.so'],
    ['error', 'entry', 'lib/b.so'],
    ['error', 'finished', null],
  ]);
  assert.equal(packed[1].outcome, 'entryStatus.error');
});

test('the lines of a group log name the outcome and the companion', () => {
  const item = recovered();
  assert.deepEqual(finishedLine(item, 9, { key: 'status.suspect', tone: 'warn' }), {
    at: 9,
    level: 'warn',
    type: 'finished',
    outcome: 'status.suspect',
    durationMs: 12.6,
  });
  assert.deepEqual(companionLine(item, 3), { at: 3, level: 'info', type: 'companion', name: 'Game.exe._' });
});

test('a file report carries the engine profile verbatim', () => {
  const item = recovered();
  const report = fileReport(item);
  assert.equal(report.path, 'bin/Game.exe');
  assert.equal(report.status, 'ok');
  assert.deepEqual(report.input, { size: 1000, sha256: 'aa' });
  assert.equal(report.duration_ms, 13);
  assert.equal(report.profile, item.result.info.profile);
  assert.deepEqual(report.outputs, [
    { path: 'bin/Game.unpack.exe', size: 2000, sha256: 'bb', embedded_metadata: false },
  ]);
  assert.equal(report.error, null);
  assert.ok(!('container' in report));

  const pending = fileReport(recovered({ state: 'pending', result: null }));
  assert.deepEqual(pending.profile, { recognition: 'recognized' });
  assert.deepEqual(pending.outputs, []);
  assert.equal(pending.duration_ms, null);
  assert.equal(pending.input.sha256, null);
});

test('a package reports its archives and each entry', () => {
  const entry = recovered({ name: 'libil2cpp.so', relPath: 'lib/arm64-v8a/libil2cpp.so', kind: 'so' });
  const item = {
    name: 'app.xapk',
    relPath: 'app.xapk',
    kind: 'package',
    state: 'ok',
    size: 5000,
    result: null,
    error: null,
    container: {
      kind: 'xapk',
      archives: [
        { label: '', entryCount: 3, targets: [], identity: null },
        { label: 'base.apk', entryCount: 40, targets: [{}, {}], identity: ['org.example.app', '12'] },
      ],
    },
    entries: [entry],
  };
  const report = fileReport(item);
  assert.deepEqual(report.container, {
    kind: 'xapk',
    archives: [
      { path: null, entries: 3, candidates: 0, package: null, version: null },
      { path: 'base.apk', entries: 40, candidates: 2, package: 'org.example.app', version: '12' },
    ],
  });
  assert.equal(report.entries.length, 1);
  assert.equal(report.entries[0].path, 'lib/arm64-v8a/libil2cpp.so');
});

test('the report counts inputs by state and serializes stably', () => {
  const report = buildReport(
    [recovered(), recovered({ state: 'failed', result: null, error: message('bad') }), recovered({ state: 'pending', result: null })],
    { generatedAt: '2026-01-02T03:04:05.678Z', version: '9.9.9', limitBytes: 1024 },
  );
  assert.equal(report.schema, REPORT_SCHEMA);
  assert.equal(report.schema_version, REPORT_SCHEMA_VERSION);
  assert.deepEqual(report.tool, { name: 'senbei-web', version: '9.9.9' });
  assert.deepEqual(report.summary, { inputs: 3, recovered: 1, suspect: 0, failed: 1, skipped: 0 });
  assert.equal(report.files[1].error, 'bad');
  const serialized = serializeReport(report);
  assert.ok(serialized.endsWith('}\n'));
  assert.deepEqual(JSON.parse(serialized), report);
  // No bytes and no page objects leak into the report.
  assert.ok(!serialized.includes('"blob"'));
});

test('report file names are safe and sortable', () => {
  assert.equal(fileStamp('2026-01-02T03:04:05.678Z'), '20260102-030405');
  assert.equal(reportFileName('bin/My Game (1).exe', '2026-01-02T03:04:05Z'), 'My_Game_1_.exe.20260102-030405.report.json');
  assert.equal(reportFileName(null, '2026-01-02T03:04:05Z'), 'senbei.20260102-030405.report.json');
  assert.equal(reportFileName('...', null), 'senbei.report.json');
  assert.equal(reportFileName('a.exe', '2026-01-02T03:04:05Z', 'txt'), 'a.exe.20260102-030405.report.txt');
});

test('an input that could not be examined reports why', () => {
  const item = recovered({ state: 'pending', result: null, identityError: message('unsafe entry path') });
  assert.equal(fileReport(item).error, 'unsafe entry path');
  // A package's time is its own: it has no job of its own to time.
  assert.equal(fileReport(recovered({ durationMs: 41.4 })).duration_ms, 41);
});
