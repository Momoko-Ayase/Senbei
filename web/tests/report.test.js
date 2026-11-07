// Node tests for the pure frontend helpers in web/report.js.
//
// Run with: node --test web/tests/
// No dependencies: `node:test` and `node:assert/strict` are built in.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_INPUT_LIMIT_BYTES,
  MAX_INPUT_LIMIT_MIB,
  MIN_INPUT_LIMIT_MIB,
  REPORT_SCHEMA,
  REPORT_SCHEMA_VERSION,
  buildFileReport,
  buildReport,
  describeFindings,
  describeObserved,
  describeStages,
  formatBytes,
  groupByModule,
  integrityStatus,
  isCompanionName,
  parseLimitMiB,
  planReadBudget,
  reportFileName,
  serializeReport,
  sortFindings,
} from '../report.js';

const MiB = 1024 * 1024;
const file = (name, size) => ({ name, size });

test('parseLimitMiB keeps a usable typed value and rejects the rest', () => {
  assert.equal(parseLimitMiB('128'), 128 * MiB);
  assert.equal(parseLimitMiB(' 64 '), 64 * MiB);
  assert.equal(parseLimitMiB('8'), MIN_INPUT_LIMIT_MIB * MiB);
  assert.equal(parseLimitMiB(String(MAX_INPUT_LIMIT_MIB)), MAX_INPUT_LIMIT_MIB * MiB);
});

test('parseLimitMiB falls back for empty, junk, and out-of-range input', () => {
  for (const raw of [undefined, null, '', '   ', 'abc', '12abc', '-4', '0', '7', '4097', 'Infinity']) {
    assert.equal(parseLimitMiB(raw), DEFAULT_INPUT_LIMIT_BYTES, `raw=${String(raw)}`);
  }
  const custom = 32 * MiB;
  assert.equal(parseLimitMiB('', custom), custom);
  assert.equal(parseLimitMiB('999999', custom), custom);
});

test('formatBytes scales through the units', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(999), '999 B');
  assert.equal(formatBytes(1024), '1.0 KiB');
  assert.equal(formatBytes(3 * MiB), '3.0 MiB');
  assert.equal(formatBytes(1.5 * 1024 * MiB), '1.50 GiB');
  assert.equal(formatBytes(-1), '0 B');
  assert.equal(formatBytes(Number.NaN), '0 B');
});

test('companion detection and base naming', () => {
  assert.equal(isCompanionName('game.exe._'), true);
  assert.equal(isCompanionName('game.exe'), false);
  assert.equal(isCompanionName(undefined), false);
  assert.equal(groupByModule([file('a.exe', 1)]).length, 1);
});

test('groupByModule sums a module and its companion into one budget unit', () => {
  const groups = groupByModule([
    file('game.exe', 10 * MiB),
    file('game.exe._', 90 * MiB),
    file('other.dll', 5 * MiB),
  ]);
  assert.equal(groups.length, 2);
  const game = groups.find((group) => group.base === 'game.exe');
  assert.equal(game.bytes, 100 * MiB);
  assert.equal(game.companion, true);
  assert.deepEqual(game.names.sort(), ['game.exe', 'game.exe._']);
  const other = groups.find((group) => group.base === 'other.dll');
  assert.equal(other.companion, false);
});

test('groupByModule ignores junk entries instead of throwing', () => {
  const groups = groupByModule([null, {}, { name: '' }, { name: 'x.exe' }, file('y.exe', -5)]);
  assert.deepEqual(groups.map((group) => group.base).sort(), ['x.exe', 'y.exe']);
  assert.equal(groups.find((group) => group.base === 'y.exe').bytes, 0);
  assert.deepEqual(groupByModule(undefined), []);
});

test('planReadBudget blocks a module whose base+companion exceed the limit', () => {
  const plan = planReadBudget(
    [file('game.exe', 10 * MiB), file('game.exe._', 90 * MiB), file('small.dll', 4 * MiB)],
    64 * MiB,
  );
  assert.equal(plan.limitBytes, 64 * MiB);
  assert.equal(plan.overLimit, true);
  assert.deepEqual([...plan.blocked], ['game.exe']);
  assert.deepEqual(plan.allowed, ['small.dll']);
  assert.equal(plan.guidance.length, 1);
  assert.match(plan.guidance[0], /Skipped game\.exe \(100\.0 MiB with companion\)/);
  assert.match(plan.guidance[0], /64\.0 MiB input limit/);
});

test('planReadBudget flags modules near the limit but still allows them', () => {
  const plan = planReadBudget([file('app.dll', 40 * MiB)], 64 * MiB);
  assert.deepEqual([...plan.blocked], []);
  assert.deepEqual(plan.nearLimit, ['app.dll']);
  assert.deepEqual(plan.allowed, ['app.dll']);
  assert.match(plan.guidance[0], /Unpacking holds the input/);
  assert.match(plan.guidance[1], /Near the 64\.0 MiB limit: app\.dll/);
});

test('planReadBudget allows the whole set when nothing is oversized', () => {
  const plan = planReadBudget([file('a.exe', 2 * MiB), file('b.dll', 3 * MiB)], 64 * MiB);
  assert.equal(plan.overLimit, false);
  assert.deepEqual(plan.allowed.sort(), ['a.exe', 'b.dll']);
  assert.match(plan.guidance[0], /Staged inputs total 5\.0 MiB/);
});

test('planReadBudget guidance is best-effort, never a peak-RSS claim', () => {
  const plan = planReadBudget([file('a.exe', 8 * MiB)], 64 * MiB);
  const text = plan.guidance.join(' ');
  assert.match(text, /several times this figure/);
  assert.doesNotMatch(text, /peak|guarantee|exactly/i);
});

test('planReadBudget with an empty or invalid limit uses the default', () => {
  const plan = planReadBudget([file('a.exe', 1 * MiB)], Number.NaN);
  assert.equal(plan.limitBytes, DEFAULT_INPUT_LIMIT_BYTES);
  assert.deepEqual(planReadBudget([], 64 * MiB).guidance, []);
});

test('planReadBudget with no entries blocks and allows nothing', () => {
  const plan = planReadBudget([], 64 * MiB);
  assert.equal(plan.totalBytes, 0);
  assert.equal(plan.overLimit, false);
  assert.deepEqual(plan.allowed, []);
  assert.deepEqual(plan.guidance, []);
});

test('sortFindings puts fatal first and is stable within a severity', () => {
  const sorted = sortFindings([
    { severity: 'warning', message: 'w1' },
    { severity: 'fatal', message: 'f1' },
    { severity: 'warning', message: 'w2' },
    { severity: 'fatal', message: 'f2' },
  ]);
  assert.deepEqual(sorted.map((finding) => finding.message), ['f1', 'f2', 'w1', 'w2']);
});

test('sortFindings normalizes unknown severities to warning and drops junk', () => {
  const sorted = sortFindings([
    { severity: 'FATAL', message: 'upper' },
    { severity: 'fatal', message: 'lower' },
    null,
    { message: 'no severity' },
  ]);
  assert.deepEqual(sorted, [
    { severity: 'fatal', message: 'lower' },
    { severity: 'warning', message: 'upper' },
    { severity: 'warning', message: 'no severity' },
  ]);
});

test('integrityStatus separates clean, warnings, and failed', () => {
  assert.equal(integrityStatus([]), 'clean');
  assert.equal(integrityStatus(undefined), 'clean');
  assert.equal(integrityStatus([{ severity: 'warning', message: 'w' }]), 'warnings');
  assert.equal(
    integrityStatus([
      { severity: 'warning', message: 'w' },
      { severity: 'fatal', message: 'f' },
    ]),
    'failed',
  );
});

test('buildFileReport maps a success row without inventing protection claims', () => {
  const report = buildFileReport('game.exe', {
    state: 'ok',
    kind: 'native-dll',
    outputName: 'game.unpack.exe',
    inputBytes: 100 * MiB,
    outputBytes: 120 * MiB,
    companionUsed: true,
    retried: true,
    findings: [{ severity: 'warning', message: 'no base relocations' }],
    profile: { format_version: 1, recovery: 'succeeded' },
    preRecoveryProfile: { format_version: 1, recognition: 'recognized' },
  });
  assert.equal(report.status, 'recovered');
  assert.equal(report.output_name, 'game.unpack.exe');
  assert.equal(report.companion_used, true);
  assert.equal(report.forced_exe_retry, true);
  assert.equal(report.integrity.status, 'warnings');
  assert.equal(report.integrity.findings.length, 1);
  assert.equal(report.error, null);
  assert.equal(report.profile.format_version, 1);
  assert.equal(report.pre_recovery_profile.recognition, 'recognized');
});

test('buildFileReport keeps metadata integrity at not_run when the transform remapped', () => {
  const report = buildFileReport('global-metadata.dat', {
    state: 'ok',
    kind: 'metadata',
    outputName: 'global-metadata.unpack.dat',
    findings: [],
    profile: {
      format_version: 1,
      observed: { platform: 'il2cpp_metadata', metadata_version: 31 },
      evidence: ['validated_metadata_transform'],
      recognition: 'recognized',
      recovery: 'succeeded',
      // The PE static check does not apply to metadata output.
      static_validation: 'not_run',
    },
  });
  assert.equal(report.status, 'recovered');
  assert.equal(report.integrity.status, 'not_run');
  assert.equal(report.integrity.findings.length, 0);
});

test('buildFileReport keeps metadata integrity at not_run when already clean', () => {
  const report = buildFileReport('global-metadata.dat', {
    state: 'ok',
    kind: 'metadata',
    findings: [],
    profile: {
      format_version: 1,
      observed: { platform: 'il2cpp_metadata', metadata_version: 31 },
      recognition: 'not_recognized',
      recovery: 'not_attempted',
      static_validation: 'not_run',
      warnings: ['metadata is already de-obfuscated; no tokens were rewritten'],
    },
  });
  assert.equal(report.status, 'recovered');
  assert.equal(report.integrity.status, 'not_run');
  assert.doesNotMatch(serializeReport({ files: [report] }), /"status": "clean"/);
});

test('buildFileReport does not fabricate clean for metadata without a profile', () => {
  const report = buildFileReport('global-metadata.dat', {
    state: 'ok',
    kind: 'metadata',
    findings: [],
    profile: null,
  });
  assert.equal(report.integrity.status, 'not_run');
  assert.equal(report.profile, null);
});

test('buildFileReport keeps the PE finding fallback when the profile has no verdict', () => {
  const fallback = buildFileReport('plain.dll', {
    state: 'ok',
    kind: 'native-dll',
    findings: [{ severity: 'warning', message: 'no base relocations' }],
    profile: { format_version: 1, recovery: 'succeeded' },
  });
  assert.equal(fallback.integrity.status, 'warnings');

  const clean = buildFileReport('plain.exe', {
    state: 'ok',
    kind: 'native-exe',
    findings: [],
    profile: null,
  });
  assert.equal(clean.integrity.status, 'clean');
});

test('buildFileReport prefers the profile verdict over row findings', () => {
  const warned = buildFileReport('app.exe', {
    state: 'ok',
    kind: 'native-exe',
    findings: [],
    profile: { format_version: 1, static_validation: 'warnings' },
  });
  assert.equal(warned.integrity.status, 'warnings');

  const failed = buildFileReport('app.exe', {
    state: 'ok',
    kind: 'native-exe',
    findings: [{ severity: 'fatal', message: 'unmapped entry point' }],
    profile: { format_version: 1, static_validation: 'failed' },
  });
  assert.equal(failed.integrity.status, 'failed');
  assert.equal(failed.integrity.findings[0].severity, 'fatal');
});

test('buildFileReport keeps the failure profile and error for a failed row', () => {
  const report = buildFileReport('bad.dll', {
    state: 'err',
    error: 'not a CrackProof-protected file',
    findings: [{ severity: 'fatal', message: 'unmapped entry point' }],
    profile: { format_version: 1, recovery: 'failed', errors: ['boom'] },
  });
  assert.equal(report.status, 'failed');
  assert.equal(report.error, 'not a CrackProof-protected file');
  assert.equal(report.integrity.status, 'not_run');
  assert.equal(report.integrity.findings[0].severity, 'fatal');
  assert.equal(report.profile.recovery, 'failed');
});

test('buildFileReport marks a budget-blocked row as blocked, not failed', () => {
  const report = buildFileReport('huge.exe', { state: 'blocked', error: 'above input limit' });
  assert.equal(report.status, 'blocked');
  assert.equal(report.error, 'above input limit');
  assert.equal(report.integrity.status, 'not_run');
});

test('buildFileReport leaves a staged row pending with no error', () => {
  const report = buildFileReport('x.exe', { state: 'staged' });
  assert.equal(report.status, 'pending');
  assert.equal(report.error, null);
  assert.equal(report.kind, null);
});

test('buildReport skips companion rows and counts statuses', () => {
  const entries = new Map([
    ['a.exe', { state: 'ok', findings: [] }],
    ['b.dll', { state: 'err', error: 'np' }],
    ['c.dll', { state: 'blocked', error: 'big' }],
    ['d.exe', { state: 'staged' }],
    ['a.exe._', { state: 'staged' }],
  ]);
  const report = buildReport(entries, {
    generatedAt: '2026-11-05T12:34:56.789Z',
    limitBytes: 64 * MiB,
  });
  assert.equal(report.schema, REPORT_SCHEMA);
  assert.equal(report.schema_version, REPORT_SCHEMA_VERSION);
  assert.equal(report.generated_at, '2026-11-05T12:34:56.789Z');
  assert.equal(report.input_limit_bytes, 64 * MiB);
  assert.deepEqual(report.summary, { files: 4, recovered: 1, failed: 1, blocked: 1 });
  assert.deepEqual(report.files.map((entry) => entry.name), ['a.exe', 'b.dll', 'c.dll', 'd.exe']);
});

test('serializeReport is stable and newline-terminated', () => {
  const report = buildReport(new Map(), { generatedAt: null });
  const text = serializeReport(report);
  assert.ok(text.endsWith('\n'));
  assert.equal(text, `${JSON.stringify(report, null, 2)}\n`);
  assert.equal(serializeReport(report), text);
});

test('reportFileName is filesystem-safe and stamped', () => {
  assert.equal(
    reportFileName('game.exe', '2026-11-05T12:34:56.789Z'),
    'game.20261105-123456.report.json',
  );
  assert.equal(reportFileName('game.exe._', '2026-11-05T12:34:56.789Z'),
    'game.20261105-123456.report.json');
  assert.equal(reportFileName(null, '2026-11-05T12:34:56.789Z'),
    'senbei-20261105-123456.report.json');
  assert.equal(reportFileName('game.exe', null), 'game.report.json');
  assert.equal(reportFileName(null, null), 'senbei-report.json');
  assert.doesNotMatch(reportFileName('a b.exe', '2026-11-05T12:34:56.789Z'), /[:\\/\s]/);
});

test('describeObserved never claims protection from a metadata magic match', () => {
  const text = describeObserved({
    observed: {
      platform: 'il2cpp_metadata',
      format: 'il2cpp_metadata',
      kind: null,
      metadata_version: 31,
      external_companion: false,
    },
    evidence: [],
    recognition: 'recognized',
  });
  assert.equal(text, 'v31 · format only, not a protection verdict');
  assert.doesNotMatch(text, /protected|recognized|CrackProof/);
});

test('describeObserved lists PE target facts and evidence', () => {
  const text = describeObserved({
    observed: {
      platform: 'windows_pe',
      format: 'pe32_plus',
      kind: 'native_dll',
      metadata_version: null,
      external_companion: true,
    },
    evidence: ['header_magic', 'companion_spliced'],
  });
  assert.equal(
    text,
    'PE32+ · native DLL · external companion · header magic, companion spliced',
  );
});

test('describeObserved tolerates an absent profile', () => {
  assert.equal(describeObserved(null), '');
  assert.equal(describeObserved(undefined), '');
  assert.equal(describeObserved({}), '');
});

test('describeStages reports candidate outcomes and the static check', () => {
  const lines = describeStages({
    recovery: 'succeeded',
    candidates: [
      { layout: 'dll', outcome: 'rejected', warnings: [], errors: ['bad'] },
      { layout: 'exe_style', outcome: 'succeeded', warnings: [], errors: [] },
    ],
    selected: 'exe_style',
    static_validation: 'warnings',
  });
  assert.deepEqual(lines, [
    'DLL layout: rejected',
    'EXE-style layout: succeeded — selected',
    'static check with warnings',
  ]);
});

test('describeStages handles metadata routes and a failed check', () => {
  const lines = describeStages({
    recovery: 'failed',
    candidates: [{ layout: 'metadata_structural', outcome: 'failed' }],
    selected: null,
    static_validation: 'failed',
  });
  assert.deepEqual(lines, ['metadata structural: failed', 'static check failed']);
  assert.deepEqual(describeStages(null), []);
});

test('describeFindings labels severity', () => {
  assert.deepEqual(
    describeFindings([
      { severity: 'warning', message: 'w' },
      { severity: 'fatal', message: 'f' },
    ]),
    ['fatal: f', 'warning: w'],
  );
  assert.deepEqual(describeFindings(undefined), []);
});

test('describeStages omits the PE static check for metadata profiles', () => {
  const lines = describeStages({
    observed: { platform: 'il2cpp_metadata' },
    recovery: 'succeeded',
    candidates: [{ layout: 'metadata_structural', outcome: 'succeeded' }],
    selected: 'metadata_structural',
    static_validation: 'not_run',
  });
  assert.deepEqual(lines, ['metadata structural: succeeded — selected']);
});

test('describeStages only shows a static check that actually ran', () => {
  const recovered = describeStages({
    observed: { platform: 'windows_pe' },
    recovery: 'succeeded',
    candidates: [{ layout: 'exe_style', outcome: 'succeeded' }],
    selected: 'exe_style',
    static_validation: 'clean',
  });
  assert.deepEqual(recovered, ['EXE-style layout: succeeded — selected', 'static check clean']);

  // No check ran: the failure line already carries the reason, so a "not run"
  // entry would be noise.
  const failed = describeStages({
    observed: { platform: 'windows_pe' },
    recovery: 'blocked',
    candidates: [{ layout: 'exe_style', outcome: 'not_attempted' }],
    selected: null,
    static_validation: 'not_run',
  });
  assert.deepEqual(failed, ['EXE-style layout: not attempted']);
});

test('describeObserved can omit the kind it repeats from the row label', () => {
  const profile = {
    observed: {
      platform: 'windows_pe',
      format: 'pe32_plus',
      kind: 'native_dll',
      external_companion: false,
    },
    evidence: ['header_magic'],
  };
  assert.equal(
    describeObserved(profile, { includeKind: false }),
    'PE32+ · header magic',
  );
  assert.equal(describeObserved(profile), 'PE32+ · native DLL · header magic');
});

test('buildFileReport carries the forced-EXE retry and failure profile', () => {
  const report = buildFileReport('shell.dll', {
    state: 'err',
    retried: true,
    error: 'structurally invalid layout candidate',
    profile: {
      format_version: 1,
      candidates: [
        { layout: 'dll', outcome: 'failed' },
        { layout: 'exe_style', outcome: 'rejected' },
      ],
      recovery: 'failed',
    },
  });
  assert.equal(report.forced_exe_retry, true);
  assert.equal(report.profile.candidates[1].outcome, 'rejected');
  assert.equal(report.status, 'failed');
});
