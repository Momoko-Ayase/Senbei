// ZIP over `Blob`: read a package's directory and single entries without
// reading the package, and write the "download all" archive without copying
// the outputs.
//
// Reading never trusts a size the archive declares. An entry is inflated by
// the browser's own `DecompressionStream`, and every consumer of that stream
// stops at the declared size, so a malformed entry cannot grow past it.

const EOCD = 0x06054b50;
const EOCD64 = 0x06064b50;
const EOCD64_LOCATOR = 0x07064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const U32_MAX = 0xffffffff;

/** A package that cannot be read as a ZIP archive. */
export class ZipError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ZipError';
  }
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/** CRC-32 of `bytes`, continuing from `crc` (0 to start). */
export function crc32(bytes, crc = 0) {
  let c = ~crc >>> 0;
  for (let i = 0; i < bytes.length; i += 1) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

async function view(blob, start, length) {
  if (start < 0 || length < 0 || start + length > blob.size) {
    throw new ZipError('archive record lies outside the file');
  }
  return new DataView(await blob.slice(start, start + length).arrayBuffer());
}

function u64(data, offset) {
  const value = data.getBigUint64(offset, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new ZipError('archive offset is out of range');
  return Number(value);
}

function decodeName(bytes, utf8) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    if (utf8) throw new ZipError('entry name is not valid UTF-8');
    // A legacy code page. Only ASCII names are ever matched, so a byte-wise
    // reading is enough to keep such an entry distinct and listed.
    return Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  }
}

/**
 * Read the central directory of `blob`.
 *
 * Returns `{ entries }` in directory order. Each entry is
 * `{ name, method, encrypted, crc, compressedSize, size, headerOffset, directory }`.
 * Nothing but the directory is read. `limits.maxEntries` and
 * `limits.maxDirectoryBytes` are checked before the directory is.
 */
export async function openZip(blob, limits = {}) {
  const maxEntries = limits.maxEntries ?? 100_000;
  const maxDirectoryBytes = limits.maxDirectoryBytes ?? 64 * 1024 * 1024;
  if (blob.size < 22) throw new ZipError('file is too short to be a ZIP archive');

  const tailLength = Math.min(blob.size, 22 + 0xffff);
  const tailStart = blob.size - tailLength;
  const tail = await view(blob, tailStart, tailLength);
  let at = -1;
  for (let i = tailLength - 22; i >= 0; i -= 1) {
    if (tail.getUint32(i, true) === EOCD && i + 22 + tail.getUint16(i + 20, true) <= tailLength) {
      at = i;
      break;
    }
  }
  if (at < 0) throw new ZipError('end-of-directory record not found');
  const eocdOffset = tailStart + at;
  if (tail.getUint16(at + 4, true) !== 0 && tail.getUint16(at + 4, true) !== 0xffff) {
    throw new ZipError('multi-disk archives are not supported');
  }
  let count = tail.getUint16(at + 10, true);
  let directorySize = tail.getUint32(at + 12, true);
  let directoryOffset = tail.getUint32(at + 16, true);
  let directoryEnd = eocdOffset;

  if (count === 0xffff || directorySize === U32_MAX || directoryOffset === U32_MAX) {
    if (eocdOffset < 20) throw new ZipError('ZIP64 locator is missing');
    const locator = await view(blob, eocdOffset - 20, 20);
    if (locator.getUint32(0, true) !== EOCD64_LOCATOR) throw new ZipError('ZIP64 locator is missing');
    const recordOffset = u64(locator, 8);
    const record = await view(blob, recordOffset, 56);
    if (record.getUint32(0, true) !== EOCD64) throw new ZipError('ZIP64 directory record is missing');
    count = u64(record, 32);
    directorySize = u64(record, 40);
    directoryOffset = u64(record, 48);
    directoryEnd = recordOffset;
  }
  if (count > maxEntries) {
    throw new ZipError(`archive declares ${count} entries, over the limit of ${maxEntries}`);
  }
  if (directorySize > maxDirectoryBytes) {
    throw new ZipError(`archive directory is ${directorySize} bytes, over the limit`);
  }
  if (directoryOffset + directorySize > directoryEnd) {
    throw new ZipError('archive directory lies outside the file');
  }
  if (count * 46 > directorySize) throw new ZipError('archive directory is shorter than its entry count');

  const directory = await view(blob, directoryOffset, directorySize);
  const bytes = new Uint8Array(directory.buffer);
  const entries = [];
  let cursor = 0;
  for (let index = 0; index < count; index += 1) {
    if (cursor + 46 > directorySize || directory.getUint32(cursor, true) !== CENTRAL) {
      throw new ZipError(`directory entry ${index} is malformed`);
    }
    const flags = directory.getUint16(cursor + 8, true);
    const nameLength = directory.getUint16(cursor + 28, true);
    const extraLength = directory.getUint16(cursor + 30, true);
    const commentLength = directory.getUint16(cursor + 32, true);
    const next = cursor + 46 + nameLength + extraLength + commentLength;
    if (next > directorySize) throw new ZipError(`directory entry ${index} is truncated`);
    let compressedSize = directory.getUint32(cursor + 20, true);
    let size = directory.getUint32(cursor + 24, true);
    let headerOffset = directory.getUint32(cursor + 42, true);

    // ZIP64: the 64-bit values follow in this order, each present only when
    // its 32-bit field is saturated.
    let extra = cursor + 46 + nameLength;
    const extraEnd = extra + extraLength;
    while (extra + 4 <= extraEnd) {
      const id = directory.getUint16(extra, true);
      const length = directory.getUint16(extra + 2, true);
      let field = extra + 4;
      const fieldEnd = field + length;
      if (fieldEnd > extraEnd) break;
      if (id === 0x0001) {
        const take = () => {
          if (field + 8 > fieldEnd) throw new ZipError(`directory entry ${index} has a short ZIP64 field`);
          const value = u64(directory, field);
          field += 8;
          return value;
        };
        if (size === U32_MAX) size = take();
        if (compressedSize === U32_MAX) compressedSize = take();
        if (headerOffset === U32_MAX) headerOffset = take();
      }
      extra = fieldEnd;
    }

    const name = decodeName(bytes.subarray(cursor + 46, cursor + 46 + nameLength), (flags & 0x800) !== 0);
    entries.push({
      name,
      method: directory.getUint16(cursor + 10, true),
      encrypted: (flags & 0x1) !== 0,
      crc: directory.getUint32(cursor + 16, true),
      compressedSize,
      size,
      headerOffset,
      directory: name.endsWith('/'),
    });
    cursor = next;
  }
  return { entries };
}

/**
 * Locate one entry's data.
 *
 * Returns `{ blob, method, size, crc }`, where `blob` is the entry's stored
 * bytes as a slice of the archive. Only the entry's 30-byte local header is
 * read. An encrypted entry, or a compression method other than stored and
 * deflate, is refused.
 */
export async function entrySource(blob, entry) {
  if (entry.encrypted) throw new ZipError(`entry ${entry.name} is encrypted`);
  if (entry.method !== 0 && entry.method !== 8) {
    throw new ZipError(`entry ${entry.name} uses unsupported compression method ${entry.method}`);
  }
  if (entry.method === 0 && entry.size !== entry.compressedSize) {
    throw new ZipError(`stored entry ${entry.name} declares two different sizes`);
  }
  const header = await view(blob, entry.headerOffset, 30);
  if (header.getUint32(0, true) !== LOCAL) throw new ZipError(`entry ${entry.name} has no local header`);
  const start = entry.headerOffset + 30 + header.getUint16(26, true) + header.getUint16(28, true);
  if (start + entry.compressedSize > blob.size) {
    throw new ZipError(`entry ${entry.name} lies outside the file`);
  }
  return {
    blob: blob.slice(start, start + entry.compressedSize),
    method: entry.method,
    size: entry.size,
    crc: entry.crc,
  };
}

/** The entry's bytes as a stream, inflated when it is deflated. */
export function entryStream(source) {
  const stream = source.blob.stream();
  return source.method === 8 ? stream.pipeThrough(new DecompressionStream('deflate-raw')) : stream;
}

/**
 * Read at most `limit` bytes from the start of an entry.
 *
 * Returns `{ bytes, truncated }`. `truncated` says the entry is longer than
 * what was read. Nothing past `limit` is inflated.
 */
export async function readEntryPrefix(source, limit) {
  const wanted = Math.min(limit, source.size);
  const bytes = new Uint8Array(wanted);
  let length = 0;
  const reader = entryStream(source).getReader();
  try {
    while (length < wanted) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = Math.min(value.length, wanted - length);
      bytes.set(value.subarray(0, take), length);
      length += take;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return { bytes: bytes.subarray(0, length), truncated: source.size > limit };
}

/**
 * A whole entry as a `Blob`, checked against its declared size and CRC.
 *
 * A stored entry is returned as a slice of the archive, with nothing read but
 * what the CRC check streams through. `limit` bounds the declared size.
 */
export async function entryBlob(source, limit) {
  if (source.size > limit) {
    throw new ZipError(`entry is ${source.size} bytes, over the ${limit}-byte limit`);
  }
  const parts = [];
  let length = 0;
  let crc = 0;
  const reader = entryStream(source).getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > source.size) {
      reader.cancel().catch(() => {});
      throw new ZipError('entry is longer than its declared size');
    }
    crc = crc32(value, crc);
    if (source.method !== 0) parts.push(value);
  }
  if (length !== source.size) throw new ZipError('entry is shorter than its declared size');
  if (crc !== source.crc) throw new ZipError('entry does not match its checksum');
  return source.method === 0 ? source.blob : new Blob(parts);
}

async function blobCrc(blob) {
  let crc = 0;
  const reader = blob.stream().getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return crc;
    crc = crc32(value, crc);
  }
}

function dosTime(date) {
  const year = Math.max(1980, Math.min(2107, date.getFullYear()));
  return {
    time: (date.getHours() << 11) | (date.getMinutes() << 5) | (date.getSeconds() >> 1),
    date: ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate(),
  };
}

/**
 * Build an uncompressed ZIP archive of `files` (`{ path, blob }` each).
 *
 * The result references the given blobs; only the headers are new bytes.
 * Sizes or offsets past 4 GiB, and more than 65,535 files, use ZIP64 records.
 */
export async function buildZip(files, now = new Date()) {
  const stamp = dosTime(now);
  const encoder = new TextEncoder();
  const parts = [];
  const central = [];
  let offset = 0;

  for (const file of files) {
    const name = encoder.encode(file.path);
    const size = file.blob.size;
    const crc = await blobCrc(file.blob);
    const big = size >= U32_MAX;
    const farAway = offset >= U32_MAX;

    const localExtra = big ? 20 : 0;
    const local = new DataView(new ArrayBuffer(30 + name.length + localExtra));
    local.setUint32(0, LOCAL, true);
    local.setUint16(4, big ? 45 : 20, true);
    local.setUint16(6, 0x800, true);
    local.setUint16(10, stamp.time, true);
    local.setUint16(12, stamp.date, true);
    local.setUint32(14, crc, true);
    local.setUint32(18, big ? U32_MAX : size, true);
    local.setUint32(22, big ? U32_MAX : size, true);
    local.setUint16(26, name.length, true);
    local.setUint16(28, localExtra, true);
    new Uint8Array(local.buffer).set(name, 30);
    if (big) {
      local.setUint16(30 + name.length, 0x0001, true);
      local.setUint16(32 + name.length, 16, true);
      local.setBigUint64(34 + name.length, BigInt(size), true);
      local.setBigUint64(42 + name.length, BigInt(size), true);
    }

    const extraLength = big || farAway ? 4 + (big ? 16 : 0) + (farAway ? 8 : 0) : 0;
    const record = new DataView(new ArrayBuffer(46 + name.length + extraLength));
    record.setUint32(0, CENTRAL, true);
    record.setUint16(4, 45, true);
    record.setUint16(6, big || farAway ? 45 : 20, true);
    record.setUint16(8, 0x800, true);
    record.setUint16(12, stamp.time, true);
    record.setUint16(14, stamp.date, true);
    record.setUint32(16, crc, true);
    record.setUint32(20, big ? U32_MAX : size, true);
    record.setUint32(24, big ? U32_MAX : size, true);
    record.setUint16(28, name.length, true);
    record.setUint16(30, extraLength, true);
    record.setUint32(42, farAway ? U32_MAX : offset, true);
    new Uint8Array(record.buffer).set(name, 46);
    if (extraLength) {
      let field = 46 + name.length;
      record.setUint16(field, 0x0001, true);
      record.setUint16(field + 2, extraLength - 4, true);
      field += 4;
      if (big) {
        record.setBigUint64(field, BigInt(size), true);
        record.setBigUint64(field + 8, BigInt(size), true);
        field += 16;
      }
      if (farAway) record.setBigUint64(field, BigInt(offset), true);
    }

    parts.push(local.buffer, file.blob);
    central.push(record.buffer);
    offset += local.byteLength + size;
  }

  const directoryOffset = offset;
  const directorySize = central.reduce((sum, record) => sum + record.byteLength, 0);
  parts.push(...central);
  const count = files.length;
  if (count > 0xffff || directorySize >= U32_MAX || directoryOffset >= U32_MAX) {
    const record = new DataView(new ArrayBuffer(56 + 20));
    record.setUint32(0, EOCD64, true);
    record.setBigUint64(4, 44n, true);
    record.setUint16(12, 45, true);
    record.setUint16(14, 45, true);
    record.setBigUint64(24, BigInt(count), true);
    record.setBigUint64(32, BigInt(count), true);
    record.setBigUint64(40, BigInt(directorySize), true);
    record.setBigUint64(48, BigInt(directoryOffset), true);
    record.setUint32(56, EOCD64_LOCATOR, true);
    record.setBigUint64(64, BigInt(directoryOffset + directorySize), true);
    record.setUint32(72, 1, true);
    parts.push(record.buffer);
  }
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, EOCD, true);
  end.setUint16(8, Math.min(count, 0xffff), true);
  end.setUint16(10, Math.min(count, 0xffff), true);
  end.setUint32(12, Math.min(directorySize, U32_MAX), true);
  end.setUint32(16, Math.min(directoryOffset, U32_MAX), true);
  parts.push(end.buffer);
  return new Blob(parts, { type: 'application/zip' });
}
