// App packages: what is in one, and where its libraries and metadata are.
//
// A package is listed from its ZIP directory. The manifest is read first, to
// name the application its entries belong to, and only `.so` and
// `global-metadata.dat` entries are ever read after that. An `.apks` or
// `.xapk` bundle is descended one level, into the `.apk` files it holds.

import { entryBlob, entrySource, openZip, readEntryPrefix } from './zip.js';
import { baseName, escapesRoot, isNestedPackage, isPackageTarget, safeEntryPath } from './model.js';

/** The manifest's `<manifest>` start tag is read from at most this much. */
const MANIFEST_PROBE = 4 * 1024 * 1024;

const isRootManifest = (path) => path.toLowerCase() === 'androidmanifest.xml';

/** A package holds an entry whose name would leave the package. */
export class UnsafeEntry extends Error {
  constructor() {
    super('unsafe entry path in package');
    this.name = 'UnsafeEntry';
  }
}

/**
 * List one archive: its targets and the application its manifest names.
 *
 * `label` is the archive's path inside its bundle, or `''` for the package
 * itself. `identify(bytes, truncated)` reads a manifest. Throws
 * [`UnsafeEntry`] for an archive with an entry name that leaves it.
 */
async function listArchive(blob, label, identify, limits) {
  const { entries } = await openZip(blob, limits);
  const archive = { label, blob, entryCount: entries.length, identity: null, targets: [], nested: [] };
  let manifest = null;
  const seen = new Set();
  for (const entry of entries) {
    if (entry.directory) continue;
    if (escapesRoot(entry.name)) throw new UnsafeEntry();
    const path = safeEntryPath(entry.name);
    // A name that is not a clean path, or one seen before, is never read.
    if (!path || seen.has(path)) continue;
    seen.add(path);
    if (isRootManifest(path)) manifest ??= entry;
    else if (isPackageTarget(path)) archive.targets.push({ path, entry });
    else if (isNestedPackage(path)) archive.nested.push({ path, entry });
  }
  if (manifest) {
    try {
      const source = await entrySource(blob, manifest);
      const { bytes, truncated } = await readEntryPrefix(source, MANIFEST_PROBE);
      archive.identity = await identify(bytes, truncated);
    } catch {
      // A manifest that cannot be read names nothing; the package is isolated.
    }
  }
  return archive;
}

/**
 * Inventory a package file.
 *
 * Returns `{ kind, archives, problems }`. `archives[0]` is the package itself
 * and the rest are the `.apk` files of a bundle. Each archive has `label`,
 * `blob`, `entryCount`, `identity` (`[package, version]` or `null`), and
 * `targets` (`{ path, entry }`). `problems` lists nested packages that could
 * not be opened. Nothing but directories and manifests is read, except a
 * nested package that is deflated inside its bundle, which is inflated within
 * `limits.maxNestedBytes`. Throws [`UnsafeEntry`] when the package or a
 * package in it holds an entry name that leaves it.
 */
export async function inventory(file, name, identify, limits = {}) {
  const kind = baseName(name).split('.').pop().toLowerCase();
  const top = await listArchive(file, '', identify, limits);
  const archives = [top];
  const problems = [];
  if (kind !== 'apk') {
    for (const nested of top.nested) {
      try {
        const source = await entrySource(file, nested.entry);
        // A stored entry is a slice of the bundle; nothing is copied.
        const blob = source.method === 0
          ? source.blob
          : await entryBlob(source, limits.maxNestedBytes ?? Infinity);
        archives.push(await listArchive(blob, nested.path, identify, limits));
      } catch (error) {
        if (error instanceof UnsafeEntry) throw error;
        problems.push({ path: nested.path, message: String(error?.message ?? error) });
      }
    }
  }
  return { kind, archives, problems };
}

/** The format version of a metadata entry, read from its first eight bytes. */
export async function entryMetadataVersion(source) {
  const { bytes } = await readEntryPrefix(source, 8);
  if (bytes.length < 8) return null;
  return new DataView(bytes.buffer, bytes.byteOffset, 8).getUint32(4, true);
}
