import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  MAX_LIMIT_MIB,
  MIN_LIMIT_MIB,
  ModuleContext,
  candidateKind,
  embeddedMetadataPath,
  escapesRoot,
  formatBytes,
  formatClock,
  formatCount,
  formatDuration,
  isCompanionName,
  isNestedPackage,
  isOutputDir,
  isPackageTarget,
  languageFor,
  localClock,
  looseAppRoot,
  outName,
  parseLimitMiB,
  safeEntryPath,
  shortHash,
  sniff,
  stateOf,
} from '../model.js';
import { VERSION } from '../state.js';

const MIB = 1024 * 1024;

test('a folder scan opens only the names that can be targets', () => {
  assert.equal(candidateKind('bin/Game.EXE'), 'pe');
  assert.equal(candidateKind('plugin.dll'), 'pe');
  assert.equal(candidateKind('lib/arm64-v8a/libil2cpp.so'), 'so');
  assert.equal(candidateKind('Data/Global-Metadata.dat'), 'metadata');
  assert.equal(candidateKind('app.apk'), 'package');
  assert.equal(candidateKind('app.apks'), 'package');
  assert.equal(candidateKind('app.xapk'), 'package');
  for (const name of ['data.unity3d', 'sharedassets0.assets', 'level.dat', 'movie.mp4', 'noext', 'a.dll._']) {
    assert.equal(candidateKind(name), null, name);
  }
});

test('companion payloads are recognised by name', () => {
  assert.ok(isCompanionName('Game.exe._'));
  assert.ok(isCompanionName('plugin.DLL._'));
  assert.ok(!isCompanionName('plugin.dll'));
  assert.ok(!isCompanionName('libil2cpp.so._'));
  assert.ok(!isCompanionName('._'));
});

test('a previous output tree is not entered', () => {
  assert.ok(isOutputDir('unpack'));
  assert.ok(isOutputDir('Unpack'));
  assert.ok(!isOutputDir('unpacked'));
});

test('sniff reads the magic of each input kind', () => {
  const elf = new Uint8Array(64);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
  elf[18] = 0xb7;
  assert.deepEqual(sniff(elf), { zip: false, metadata: false, mz: false, elf64Aarch64: true });
  elf[18] = 0x3e;
  assert.equal(sniff(elf).elf64Aarch64, false);
  assert.equal(sniff(new Uint8Array([0x4d, 0x5a, 0x90])).mz, true);
  assert.equal(sniff(new Uint8Array([0x50, 0x4b, 3, 4])).zip, true);
  assert.equal(sniff(new Uint8Array([0xaf, 0x1b, 0xb1, 0xfa])).metadata, true);
  assert.deepEqual(sniff(new Uint8Array()), { zip: false, metadata: false, mz: false, elf64Aarch64: false });
});

test('outputs are named as the native tools name them', () => {
  assert.equal(outName('Game.exe'), 'Game.unpack.exe');
  assert.equal(outName('lib/arm64-v8a/libil2cpp.so'), 'lib/arm64-v8a/libil2cpp.unpack.so');
  assert.equal(outName('a.b/noext'), 'a.b/noext.unpack');
  assert.equal(outName('global-metadata.dat'), 'global-metadata.unpack.dat');
  assert.equal(
    embeddedMetadataPath('app.apk/lib/arm64-v8a/libil2cpp.unpack.so'),
    'app.apk/lib/arm64-v8a/global-metadata.unpack.dat',
  );
  assert.equal(embeddedMetadataPath('libil2cpp.unpack.so'), 'global-metadata.unpack.dat');
});

test('loose Android files are paired only through their application layout', () => {
  assert.equal(looseAppRoot('lib/arm64-v8a/libil2cpp.so', 'so'), '');
  assert.equal(looseAppRoot('game/lib/arm64-v8a/libil2cpp.so', 'so'), 'game');
  assert.equal(looseAppRoot('game/LIB/arm64-v8a/libil2cpp.so', 'so'), 'game');
  assert.equal(looseAppRoot('game/libil2cpp.so', 'so'), null);
  assert.equal(looseAppRoot('game/assets/bin/Data/Managed/Metadata/global-metadata.dat', 'metadata'), 'game');
  assert.equal(looseAppRoot('assets/global-metadata.dat', 'metadata'), '');
  assert.equal(looseAppRoot('game/global-metadata.dat', 'metadata'), null);
  assert.equal(looseAppRoot('game/Game.exe', 'pe'), null);
});

test('package entry names that leave the package are refused', () => {
  assert.equal(safeEntryPath('lib/arm64-v8a/libil2cpp.so'), 'lib/arm64-v8a/libil2cpp.so');
  assert.equal(safeEntryPath('./lib//x.so'), 'lib/x.so');
  assert.equal(safeEntryPath('lib\\x.so'), 'lib/x.so');
  for (const name of ['../x.so', 'lib/../../x.so', '/abs/x.so', 'C:/x.so', 'c:x.so', '', '.', 'a\0b', null]) {
    assert.equal(safeEntryPath(name), null, String(name));
  }
});

test('only libraries and metadata are read from a package', () => {
  assert.ok(isPackageTarget('lib/arm64-v8a/libmain.so'));
  assert.ok(isPackageTarget('assets/bin/Data/Managed/Metadata/global-metadata.dat'));
  assert.ok(!isPackageTarget('classes.dex'));
  assert.ok(!isPackageTarget('assets/Game.exe'));
  assert.ok(!isPackageTarget('base.apk'));
  assert.ok(isNestedPackage('splits/base.apk'));
  assert.ok(!isNestedPackage('inner.xapk'));
});

test('the limit setting accepts whole MiB in its range', () => {
  assert.equal(parseLimitMiB('64'), 64 * MIB);
  assert.equal(parseLimitMiB(' 64.4 '), 64 * MIB);
  assert.equal(parseLimitMiB(String(MIN_LIMIT_MIB)), MIN_LIMIT_MIB * MIB);
  assert.equal(parseLimitMiB(String(MAX_LIMIT_MIB)), MAX_LIMIT_MIB * MIB);
  const fallback = 123;
  for (const raw of ['', null, 'abc', '0', '-5', String(MIN_LIMIT_MIB - 1), String(MAX_LIMIT_MIB + 1), 'Infinity']) {
    assert.equal(parseLimitMiB(raw, fallback), fallback, String(raw));
  }
});

test('the page language follows the browser languages', () => {
  assert.equal(languageFor(['fr-FR', 'ja-JP']), 'ja');
  assert.equal(languageFor(['zh-TW']), 'zh-TW');
  assert.equal(languageFor(['zh-HK']), 'zh-TW');
  assert.equal(languageFor(['zh-Hant-CN']), 'zh-TW');
  assert.equal(languageFor(['zh']), 'zh-CN');
  assert.equal(languageFor(['zh_Hans_TW']), 'zh-CN');
  assert.equal(languageFor(['ko-KR']), 'ko');
  assert.equal(languageFor(['de']), 'en');
  assert.equal(languageFor(undefined), 'en');
});

test('a report maps to the state its input is shown in', () => {
  assert.equal(stateOf({ status: 'recovered', profile: { static_validation: 'clean' } }), 'ok');
  assert.equal(stateOf({ status: 'recovered', suspect: true, profile: {} }), 'suspect');
  assert.equal(stateOf({ status: 'recovered', profile: { static_validation: 'warnings' } }), 'suspect');
  assert.equal(stateOf({ status: 'recovered', profile: { static_validation: 'failed' } }), 'suspect');
  for (const status of ['unchanged', 'unsupported', 'not_protected']) {
    assert.equal(stateOf({ status }), 'skipped');
  }
  assert.equal(stateOf({ status: 'failed' }), 'failed');
  assert.equal(stateOf(null), 'failed');
});

test('module 0x0C binds only when an application has exactly one', () => {
  const context = new ModuleContext();
  assert.equal(context.count, 0);
  assert.equal(context.module, null);
  context.add(new Uint8Array([1, 2, 3]));
  context.add(new Uint8Array([1, 2, 3]));
  context.add(new Uint8Array());
  context.add(null);
  assert.equal(context.count, 1);
  assert.deepEqual(context.module, new Uint8Array([1, 2, 3]));
  context.add(new Uint8Array([1, 2, 4]));
  assert.equal(context.count, 2);
  assert.equal(context.module, null);
});

test('sizes, durations, counts, and hashes are written as the workbench writes them', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(1023), '1023 B');
  assert.equal(formatBytes(1536), '1.5 KiB');
  assert.equal(formatBytes(5 * MIB), '5.0 MiB');
  assert.equal(formatBytes(3 * 1024 * MIB), '3.00 GiB');
  assert.equal(formatBytes(NaN), '0 B');
  assert.equal(formatDuration(12.4), '12 ms');
  assert.equal(formatDuration(999.6), '1.00 s');
  assert.equal(formatDuration(3700), '3.70 s');
  assert.equal(formatDuration(125_000), '125.00 s');
  assert.equal(formatDuration(-1), '');
  assert.equal(formatClock(0), '0:00.0');
  assert.equal(formatClock(1499), '0:01.4');
  assert.equal(formatClock(61_950), '1:01.9');
  assert.equal(formatClock(-5), '0:00.0');
  assert.equal(formatCount(0), '0');
  assert.equal(formatCount(999), '999');
  assert.equal(formatCount(12345), '12,345');
  assert.equal(formatCount(1234567), '1,234,567');
  assert.equal(formatCount(null), '');
  const sha256 = '66b8232752ea82ba0123456789abcdef0123456789abcdef0123456775aa29ff';
  assert.equal(shortHash(sha256), '66b8232752ea82ba…75aa29ff');
  assert.equal(shortHash('short'), 'short');
  assert.equal(shortHash(null), '');
  assert.equal(localClock(new Date(2026, 0, 2, 3, 4, 5, 6).getTime()), '03:04:05.006');
  assert.equal(localClock(new Date(2026, 0, 2, 13, 46, 42, 936).getTime()), '13:46:42.936');
});

test('an entry name that would leave its package is told apart from the rest', () => {
  for (const name of ['../escape.so', 'lib/../../x.so', '/abs/libil2cpp.so', 'C:/x.so', 'c:\\x.so', '\\\\host\\x.so', 'a\0b.so']) {
    assert.ok(escapesRoot(name), name);
  }
  for (const name of ['lib/arm64-v8a/libil2cpp.so', 'lib/./x.so', 'a/../b.so', 'assets/..hidden/x.so', '']) {
    assert.ok(!escapesRoot(name), name);
  }
});

test('the page shows the version of the engine it ships', () => {
  const manifest = readFileSync(new URL('../../senbei-wasm/Cargo.toml', import.meta.url), 'utf8');
  const version = /^version\s*=\s*"([^"]+)"/m.exec(manifest)?.[1];
  assert.equal(VERSION, version);
});
