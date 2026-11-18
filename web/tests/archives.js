// Hand-built ZIP archives for the tests, so that a test can state exactly
// what an archive declares, including what a well-behaved writer never would.

import { deflateRawSync } from 'node:zlib';
import { crc32 } from '../zip.js';

const encoder = new TextEncoder();

/**
 * Build an archive from `files`.
 *
 * Each file is `{ name, data, deflate, flags, crc, size, encrypted }`. `data`
 * is a string or bytes. `crc` and `size` override what the directory declares.
 */
export function makeZip(files) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const file of files) {
    const name = encoder.encode(file.name);
    const data = typeof file.data === 'string' ? encoder.encode(file.data) : (file.data ?? new Uint8Array());
    const stored = file.deflate ? new Uint8Array(deflateRawSync(data)) : data;
    const flags = (file.flags ?? 0x800) | (file.encrypted ? 1 : 0);
    const crc = file.crc ?? crc32(data);
    const size = file.size ?? data.length;

    const local = new DataView(new ArrayBuffer(30 + name.length));
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, flags, true);
    local.setUint16(8, file.deflate ? 8 : 0, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, stored.length, true);
    local.setUint32(22, size, true);
    local.setUint16(26, name.length, true);
    new Uint8Array(local.buffer).set(name, 30);

    const record = new DataView(new ArrayBuffer(46 + name.length));
    record.setUint32(0, 0x02014b50, true);
    record.setUint16(4, 20, true);
    record.setUint16(6, 20, true);
    record.setUint16(8, flags, true);
    record.setUint16(10, file.deflate ? 8 : 0, true);
    record.setUint32(16, crc, true);
    record.setUint32(20, stored.length, true);
    record.setUint32(24, size, true);
    record.setUint16(28, name.length, true);
    record.setUint32(42, offset, true);
    new Uint8Array(record.buffer).set(name, 46);

    parts.push(local.buffer, stored);
    central.push(record.buffer);
    offset += local.byteLength + stored.length;
  }
  const directorySize = central.reduce((sum, record) => sum + record.byteLength, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, files.length, true);
  end.setUint16(10, files.length, true);
  end.setUint32(12, directorySize, true);
  end.setUint32(16, offset, true);
  return new Blob([...parts, ...central, end.buffer]);
}

export async function bytesOf(blob) {
  return new Uint8Array(await blob.arrayBuffer());
}

export const text = (bytes) => new TextDecoder().decode(bytes);
