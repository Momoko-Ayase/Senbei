import assert from 'node:assert/strict';
import { test } from 'node:test';

import { collect, fileListRoot, walkEntry, walkFileList } from '../scan.js';
import { UnsafeEntry, inventory } from '../package.js';
import { entrySource } from '../zip.js';
import { bytesOf, makeZip, text } from './archives.js';

// ---------- fakes for the browser's folder objects ----------

/** A dropped `FileSystemDirectoryEntry` that lists in batches of two. */
function entryOf(name, tree, opened) {
  const children = Object.entries(tree).map(([child, value]) =>
    typeof value === 'object'
      ? entryOf(child, value, opened)
      : { name: child, isDirectory: false, file: (done) => (opened.push(child), done({ name: child })) },
  );
  return {
    name,
    isDirectory: true,
    createReader() {
      let at = 0;
      return {
        readEntries(done, failed) {
          if (tree.broken === 'unreadable') return failed(new Error('denied'));
          const batch = children.slice(at, at + 2);
          at += batch.length;
          return done(batch);
        },
      };
    },
  };
}

const TREE = {
  'Game.exe': 'file',
  'Game.exe._': 'file',
  'data.unity3d': 'file',
  unpack: { 'Game.unpack.exe': 'file' },
  Game_Data: {
    'global-metadata.dat': 'file',
    'level0.assets': 'file',
    Plugins: { 'steam.dll': 'file', Unpack: { 'steam.unpack.dll': 'file' } },
  },
  lib: { 'arm64-v8a': { 'libil2cpp.so': 'file' } },
  'bundle.xapk': 'file',
};

// Path order, whatever order the browser listed the folder in.
const EXPECTED = [
  ['Game.exe', 'pe'],
  ['Game_Data/Plugins/steam.dll', 'pe'],
  ['Game_Data/global-metadata.dat', 'metadata'],
  ['bundle.xapk', 'package'],
  ['lib/arm64-v8a/libil2cpp.so', 'so'],
];

const found = (scan) => scan.candidates.map((candidate) => [candidate.path, candidate.kind]);

test('a dropped directory entry is walked without opening a file, across batches', async () => {
  const opened = [];
  const scan = await collect(walkEntry(entryOf('game', TREE, opened)));
  assert.deepEqual(found(scan), EXPECTED);
  assert.deepEqual([...scan.companions.keys()], ['Game.exe._']);
  assert.deepEqual(opened, []);
  assert.deepEqual(await scan.candidates[0].open(), { name: 'Game.exe' });
  assert.deepEqual(opened, ['Game.exe']);
  assert.deepEqual(await scan.companions.get('Game.exe._')(), { name: 'Game.exe._' });
});

test('a folder input lists paths under the picked folder', async () => {
  const files = [
    'game/Game_Data/Plugins/steam.dll',
    'game/Game.exe',
    'game/Game.exe._',
    'game/unpack/Game.unpack.exe',
    'game/Game_Data/Plugins/Unpack/steam.unpack.dll',
    'game/readme.txt',
  ].map((path) => ({ name: path.split('/').pop(), webkitRelativePath: path }));
  assert.equal(fileListRoot(files), 'game');
  assert.equal(fileListRoot([]), '');
  const scan = await collect(walkFileList(files));
  assert.deepEqual(found(scan), [
    ['Game.exe', 'pe'],
    ['Game_Data/Plugins/steam.dll', 'pe'],
  ]);
  assert.equal(await scan.candidates[1].open(), files[0]);
});

test('an unreadable directory is reported and the walk goes on', async () => {
  const errors = [];
  const tree = { a: { 'x.dll': 'file' }, b: { broken: 'unreadable' }, 'c.exe': 'file' };
  const scan = await collect(walkEntry(entryOf('game', tree, []), (error) => errors.push(error.message)));
  assert.deepEqual(found(scan), [
    ['a/x.dll', 'pe'],
    ['c.exe', 'pe'],
  ]);
  assert.deepEqual(errors, ['denied']);
});

test('a scan can be stopped', async () => {
  const controller = new AbortController();
  controller.abort();
  const scan = await collect(walkEntry(entryOf('game', TREE, [])), controller.signal);
  assert.deepEqual(scan.candidates, []);
});

// ---------- packages ----------

const identify = async (bytes, truncated) => (truncated ? null : text(bytes).split(':'));

function apk(manifest, extra = []) {
  return makeZip([
    { name: 'AndroidManifest.xml', data: manifest, deflate: true },
    { name: 'classes.dex', data: 'dex' },
    { name: 'lib/arm64-v8a/libil2cpp.so', data: 'library', deflate: true },
    { name: 'lib/arm64-v8a/libmain.so', data: 'main' },
    { name: 'assets/bin/Data/Managed/Metadata/global-metadata.dat', data: 'metadata' },
    { name: 'assets/data.unity3d', data: 'bulk' },
    ...extra,
  ]);
}

test('a package lists its manifest identity and only its targets', async () => {
  const result = await inventory(apk('org.example.app:7'), 'dir/app.apk', identify);
  assert.equal(result.kind, 'apk');
  assert.equal(result.archives.length, 1);
  const [archive] = result.archives;
  assert.equal(archive.label, '');
  assert.equal(archive.entryCount, 6);
  assert.deepEqual(archive.identity, ['org.example.app', '7']);
  assert.deepEqual(archive.targets.map((target) => target.path), [
    'lib/arm64-v8a/libil2cpp.so',
    'lib/arm64-v8a/libmain.so',
    'assets/bin/Data/Managed/Metadata/global-metadata.dat',
  ]);
  assert.deepEqual(result.problems, []);
});

test('a package with an entry name that would leave it is refused whole', async () => {
  for (const name of ['../evil.so', '/abs/evil.so', 'lib/../../notes.txt']) {
    const blob = apk('org.example.app:7', [{ name, data: 'x' }]);
    await assert.rejects(inventory(blob, 'app.apk', identify), UnsafeEntry, name);
  }
  // A package inside a bundle is held to the same rule.
  const split = makeZip([{ name: '../escape.so', data: 'x' }]);
  const bundle = makeZip([{ name: 'split.apk', data: await bytesOf(split) }]);
  await assert.rejects(inventory(bundle, 'game.xapk', identify), UnsafeEntry);
});

test('repeated names and directory entries are not targets', async () => {
  const blob = apk('org.example.app:7', [
    { name: 'lib/arm64-v8a/libmain.so', data: 'second' },
    { name: 'lib/arm64-v8a/', data: '' },
    { name: 'lib/./arm64-v8a/libil2cpp.so', data: 'same path, written another way' },
  ]);
  const [archive] = (await inventory(blob, 'app.apk', identify)).archives;
  assert.deepEqual(archive.targets.map((target) => target.path), [
    'lib/arm64-v8a/libil2cpp.so',
    'lib/arm64-v8a/libmain.so',
    'assets/bin/Data/Managed/Metadata/global-metadata.dat',
  ]);
});

test('a bundle is descended one level into its packages', async () => {
  const base = apk('org.example.app:7');
  const split = makeZip([
    { name: 'AndroidManifest.xml', data: 'org.example.app:7' },
    { name: 'lib/arm64-v8a/libextra.so', data: 'extra' },
    { name: 'inner.apk', data: 'never opened' },
  ]);
  const bundle = makeZip([
    { name: 'manifest.json', data: '{}' },
    { name: 'base.apk', data: await bytesOf(base) },
    { name: 'config.arm64_v8a.apk', data: await bytesOf(split), deflate: true },
    { name: 'broken.apk', data: 'not a zip at all, but long enough to look' },
    { name: 'lib/arm64-v8a/libtop.so', data: 'top' },
  ]);
  const result = await inventory(bundle, 'game.XAPK', identify);
  assert.equal(result.kind, 'xapk');
  assert.deepEqual(result.archives.map((archive) => archive.label), ['', 'base.apk', 'config.arm64_v8a.apk']);
  assert.equal(result.archives[0].identity, null);
  assert.deepEqual(result.archives[0].targets.map((target) => target.path), ['lib/arm64-v8a/libtop.so']);
  assert.deepEqual(result.archives[1].identity, ['org.example.app', '7']);
  assert.deepEqual(result.archives[2].targets.map((target) => target.path), ['lib/arm64-v8a/libextra.so']);
  assert.deepEqual(result.problems.map((problem) => problem.path), ['broken.apk']);

  // A target is read through its own archive, also when that one was stored.
  const [target] = result.archives[1].targets;
  const source = await entrySource(result.archives[1].blob, target.entry);
  assert.equal(source.size, 'library'.length);
});

test('a nested package over the limit is a problem, not a read', async () => {
  const split = makeZip([{ name: 'lib/arm64-v8a/libextra.so', data: 'extra'.repeat(100) }]);
  const bundle = makeZip([{ name: 'split.apk', data: await bytesOf(split), deflate: true }]);
  const result = await inventory(bundle, 'game.apks', identify, { maxNestedBytes: 10 });
  assert.equal(result.archives.length, 1);
  assert.equal(result.problems.length, 1);
});

test('a manifest that cannot be read leaves the package unnamed', async () => {
  const failing = async () => {
    throw new Error('bad manifest');
  };
  const [archive] = (await inventory(apk('x:y'), 'app.apk', failing)).archives;
  assert.equal(archive.identity, null);
  assert.equal(archive.targets.length, 3);
});
