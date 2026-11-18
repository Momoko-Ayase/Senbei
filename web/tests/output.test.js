import assert from 'node:assert/strict';
import { test } from 'node:test';

import { FolderWriter, downloadArchive } from '../output.js';
import { state } from '../state.js';
import { entryBlob, entrySource, openZip } from '../zip.js';

function directory(writes, { rejectZip = false, rejectLog = false, same = false } = {}, prefix = '') {
  return {
    isSameEntry: async () => same,
    getDirectoryHandle: async (name) => directory(writes, { rejectZip, rejectLog, same }, `${prefix}${name}/`),
    async getFileHandle(name) {
      if (name.toLowerCase().endsWith('.dll')) throw new TypeError('file name refused');
      if (rejectZip && name.endsWith('.zip')) throw new Error('archive write denied');
      if (rejectLog && name.endsWith('.log')) throw new Error('log write denied');
      return {
        async createWritable() {
          let content;
          return {
            async write(blob) {
              if (name.endsWith('.error')) throw new TypeError('write failed after opening the file');
              content = blob;
            },
            async close() { writes.set(`${prefix}${name}`, content); },
            async abort() {},
          };
        },
      };
    },
  };
}

const output = (path, content) => ({ path, blob: new Blob([content]) });
const fixedDate = new Date('2026-01-02T03:04:05.678Z');

function record(group, ...outputs) {
  return { group, result: { outputs }, log: [] };
}

test('ZIP downloads include the full log for every input, even a failure with no output', async () => {
  const group = { kind: 'files' };
  const recovered = record(group, output('app.unpack.exe', 'recovered image'));
  const failed = record(group);
  recovered.log.push({ at: fixedDate.getTime(), level: 'detail', text: 'engine step detail' });
  failed.log.push({ at: fixedDate.getTime(), level: 'error', text: 'unreadable input' });
  state.logLevel = 'problems';
  try {
    const { name, blob } = await downloadArchive([recovered, failed], fixedDate);
    assert.equal(name, 'senbei-unpack.20260102-030405.zip');
    const { entries } = await openZip(blob);
    assert.deepEqual(entries.map((entry) => entry.name), ['app.unpack.exe', 'senbei-20260102-030405.log']);
    const log = await entryBlob(await entrySource(blob, entries[1]), 1024);
    assert.match(await log.text(), /engine step detail\n.*unreadable input/);
  } finally {
    state.logLevel = 'all';
  }
});

test('folder output includes an unfiltered log even when no files were recovered', async () => {
  const writes = new Map();
  const writer = new FolderWriter(directory(writes));
  const group = { kind: 'files' };
  const failed = record(group);
  failed.log.push({ at: fixedDate.getTime(), level: 'detail', text: 'engine step detail' });
  failed.log.push({ at: fixedDate.getTime(), level: 'error', text: 'unreadable input' });
  await writer.saveLog([record(group)], fixedDate);
  assert.equal(writes.size, 0);
  state.logLevel = 'problems';
  try {
    await writer.saveLog([failed], fixedDate);
    assert.deepEqual([...writes.keys()], ['unpack/senbei-20260102-030405-678.log']);
    assert.match(await [...writes.values()][0].text(), /engine step detail\n.*unreadable input/);
  } finally {
    state.logLevel = 'all';
  }
});

test('a failed log write leaves recovery outputs and their logs intact', async () => {
  const writes = new Map();
  const writer = new FolderWriter(directory(writes, { rejectLog: true }));
  const file = output('app.unpack.exe', 'exe bytes');
  const item = record({ kind: 'files' }, file);
  item.log.push({ at: fixedDate.getTime(), level: 'detail', text: 'engine step detail' });
  await writer.save(item);
  await writer.saveLog([item], fixedDate);
  assert.deepEqual([...writes.keys()], ['unpack/app.unpack.exe']);
  assert.equal(file.saved, 'unpack/app.unpack.exe');
  assert.equal(item.log[0].text, 'engine step detail');
  assert.equal(state.notice.key, 'web.save_failed');
});

test('folder writes keep allowed files and group refused names in one ZIP', async () => {
  const writes = new Map();
  const root = directory(writes, { same: true });
  const writer = new FolderWriter(root);
  const group = { kind: 'folder', name: 'source', handle: root, lastRun: { log: [] } };
  const exe = output('app.unpack.exe', 'exe bytes');
  const dll = output('lib/plugin.unpack.dll', 'first DLL');
  const another = output('lib/Plugin.unpack.DLL', 'second DLL');
  const input = record(group, exe, dll);
  const entryParent = record(group);
  const entry = { ...record(group, another), parent: entryParent };
  await writer.save(input);
  await writer.save(entry);
  assert.deepEqual([...writes.keys()], ['unpack/app.unpack.exe']);
  assert.equal(await writes.get(exe.saved).text(), 'exe bytes');
  assert.equal(dll.refused, true);
  await writer.finish(fixedDate);
  const archive = 'unpack/senbei-remaining.20260102-030405-678.zip';
  assert.deepEqual([...writes.keys()], ['unpack/app.unpack.exe', archive]);
  for (const item of [dll, another]) {
    assert.equal(item.saved, archive);
    assert.equal(item.saveFailed, null);
    assert.equal(item.refused, false);
  }
  const zip = writes.get(archive);
  const { entries } = await openZip(zip);
  assert.deepEqual(entries.map((entry) => entry.name), ['lib/plugin.unpack.dll', 'lib/Plugin.unpack (2).DLL']);
  for (const [i, expected] of ['first DLL', 'second DLL'].entries()) {
    const recovered = await entryBlob(await entrySource(zip, entries[i]), 1024);
    assert.equal(await recovered.text(), expected);
  }
  for (const owner of [input, entryParent, group.lastRun]) {
    assert.equal(owner.log.length, 1);
    assert.equal(owner.log[0].status, 'ok');
  }
});

test('a failed write after opening the file is not a name refusal', async () => {
  const writes = new Map();
  const writer = new FolderWriter(directory(writes));
  const file = output('blocked.error', 'bytes');
  await writer.save(record({ kind: 'files' }, file));
  await writer.finish(fixedDate);
  assert.equal(writes.size, 0);
  assert.equal(file.saveFailed, 'unpack/blocked.error');
  assert.equal(file.refused, false);
});

test('if the folder refuses the fallback archive, the original stays downloadable', async () => {
  const writes = new Map();
  const writer = new FolderWriter(directory(writes, { rejectZip: true }));
  const file = output('plugin.unpack.dll', 'bytes');
  const item = record({ kind: 'files' }, file);
  await writer.save(item);
  await writer.finish(fixedDate);
  assert.equal(writes.size, 0);
  assert.equal(file.saved, null);
  assert.equal(file.refused, true);
  assert.match(file.saveFailed, /\.zip$/);
  assert.equal(item.log[0].status, 'failed');
  assert.equal(await file.blob.text(), 'bytes');
});
