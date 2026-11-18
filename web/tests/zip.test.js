import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  ZipError,
  buildZip,
  crc32,
  entryBlob,
  entrySource,
  openZip,
  readEntryPrefix,
} from '../zip.js';
import { bytesOf, makeZip, text } from './archives.js';

test('crc32 matches the standard check value and continues across chunks', () => {
  const bytes = new TextEncoder().encode('123456789');
  assert.equal(crc32(bytes), 0xcbf43926);
  assert.equal(crc32(bytes.subarray(4), crc32(bytes.subarray(0, 4))), 0xcbf43926);
});

test('a built archive reads back with the same names and bytes', async () => {
  const files = [
    { path: 'lib/arm64-v8a/libil2cpp.unpack.so', blob: new Blob(['library']) },
    { path: '日本語/メタ.dat', blob: new Blob([new Uint8Array([0, 1, 2, 255])]) },
    { path: 'empty.bin', blob: new Blob([]) },
  ];
  const archive = await buildZip(files, new Date(2026, 0, 2, 3, 4, 6));
  assert.equal(archive.type, 'application/zip');
  const { entries } = await openZip(archive);
  assert.deepEqual(entries.map((entry) => entry.name), files.map((file) => file.path));
  for (const [index, entry] of entries.entries()) {
    assert.equal(entry.method, 0);
    const source = await entrySource(archive, entry);
    const blob = await entryBlob(source, 1 << 20);
    assert.deepEqual(await bytesOf(blob), await bytesOf(files[index].blob));
  }
});

test('a deflated entry is inflated and checked', async () => {
  const body = 'senbei '.repeat(2000);
  const archive = makeZip([{ name: 'a.txt', data: body, deflate: true }]);
  const { entries } = await openZip(archive);
  assert.equal(entries[0].method, 8);
  assert.ok(entries[0].compressedSize < entries[0].size);
  const source = await entrySource(archive, entries[0]);
  assert.equal(text(await bytesOf(await entryBlob(source, 1 << 20))), body);
  const prefix = await readEntryPrefix(source, 10);
  assert.equal(text(prefix.bytes), body.slice(0, 10));
  assert.equal(prefix.truncated, true);
  const whole = await readEntryPrefix(source, 1 << 20);
  assert.equal(whole.bytes.length, body.length);
  assert.equal(whole.truncated, false);
});

test('an entry that does not match its checksum or size is refused', async () => {
  const wrongCrc = makeZip([{ name: 'a', data: 'abcdef', deflate: true, crc: 1 }]);
  let source = await entrySource(wrongCrc, (await openZip(wrongCrc)).entries[0]);
  await assert.rejects(entryBlob(source, 1 << 20), /checksum/);

  // The directory declares fewer bytes than the entry inflates to.
  const longer = makeZip([{ name: 'a', data: 'abcdef'.repeat(100), deflate: true, size: 10 }]);
  source = await entrySource(longer, (await openZip(longer)).entries[0]);
  await assert.rejects(entryBlob(source, 1 << 20), /longer than its declared size/);
  // A bounded read never takes more than the declared size either.
  assert.equal((await readEntryPrefix(source, 1 << 20)).bytes.length, 10);

  const over = makeZip([{ name: 'a', data: 'abcdef' }]);
  source = await entrySource(over, (await openZip(over)).entries[0]);
  await assert.rejects(entryBlob(source, 3), /over the 3-byte limit/);
});

test('encrypted entries and unknown compression are refused', async () => {
  const locked = makeZip([{ name: 'a', data: 'abc', encrypted: true }]);
  const [entry] = (await openZip(locked)).entries;
  assert.equal(entry.encrypted, true);
  await assert.rejects(entrySource(locked, entry), ZipError);
  await assert.rejects(entrySource(locked, { ...entry, encrypted: false, method: 12 }), /unsupported compression/);
});

test('an entry that points outside the file is refused', async () => {
  const archive = makeZip([{ name: 'a', data: 'abc' }]);
  const [entry] = (await openZip(archive)).entries;
  await assert.rejects(entrySource(archive, { ...entry, headerOffset: archive.size }), ZipError);
  await assert.rejects(
    entrySource(archive, { ...entry, compressedSize: 1 << 20, size: 1 << 20 }),
    /outside the file/,
  );
});

test('a file that is not an archive, or declares too much, is refused', async () => {
  await assert.rejects(openZip(new Blob(['short'])), ZipError);
  await assert.rejects(openZip(new Blob([new Uint8Array(100)])), /end-of-directory/);
  const archive = makeZip([
    { name: 'a', data: '1' },
    { name: 'b', data: '2' },
  ]);
  await assert.rejects(openZip(archive, { maxEntries: 1 }), /over the limit/);
  await assert.rejects(openZip(archive, { maxDirectoryBytes: 10 }), /over the limit/);
  // An entry count the directory cannot hold.
  const bytes = await bytesOf(archive);
  new DataView(bytes.buffer).setUint16(bytes.length - 22 + 10, 500, true);
  await assert.rejects(openZip(new Blob([bytes])), /shorter than its entry count/);
});

test('ZIP64 directory records are followed', async () => {
  const archive = makeZip([{ name: 'big.bin', data: 'payload' }]);
  const bytes = await bytesOf(archive);
  const end = bytes.length - 22;
  const view = new DataView(bytes.buffer);
  const directorySize = view.getUint32(end + 12, true);
  const directoryOffset = view.getUint32(end + 16, true);

  const record = new DataView(new ArrayBuffer(56));
  record.setUint32(0, 0x06064b50, true);
  record.setBigUint64(4, 44n, true);
  record.setBigUint64(24, 1n, true);
  record.setBigUint64(32, 1n, true);
  record.setBigUint64(40, BigInt(directorySize), true);
  record.setBigUint64(48, BigInt(directoryOffset), true);
  const locator = new DataView(new ArrayBuffer(20));
  locator.setUint32(0, 0x07064b50, true);
  locator.setBigUint64(8, BigInt(end), true);
  locator.setUint32(16, 1, true);
  const tail = bytes.slice(end);
  const tailView = new DataView(tail.buffer);
  tailView.setUint16(8, 0xffff, true);
  tailView.setUint16(10, 0xffff, true);
  tailView.setUint32(12, 0xffffffff, true);
  tailView.setUint32(16, 0xffffffff, true);

  const zip64 = new Blob([bytes.subarray(0, end), record.buffer, locator.buffer, tail]);
  const { entries } = await openZip(zip64);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'big.bin');
  const source = await entrySource(zip64, entries[0]);
  assert.equal(text(await bytesOf(await entryBlob(source, 100))), 'payload');
});
