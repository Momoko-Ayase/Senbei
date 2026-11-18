// Rules the page shares with the native front ends: which names a folder scan
// opens, how outputs are named, and which loose Android files belong to one
// application. No DOM and no I/O, so `web/tests/` runs these under Node.

/** Smallest file a folder scan opens. A protected module needs this many bytes. */
export const MIN_SIZE = 4128;

/** Bytes read from the start of a file to classify it. */
export const PREFIX_SIZE = 8192;

export const METADATA_NAME = 'global-metadata.dat';

const MIB = 1024 * 1024;

/**
 * The input limit: default, and the range the setting accepts, in MiB. The
 * engine itself refuses an input or an output over 1 GiB.
 */
export const DEFAULT_LIMIT_MIB = 512;
export const MIN_LIMIT_MIB = 8;
export const MAX_LIMIT_MIB = 1024;

/** Bytes for a limit typed in MiB, or `fallback` when it is not in range. */
export function parseLimitMiB(raw, fallback = DEFAULT_LIMIT_MIB * MIB) {
  const text = String(raw ?? '').trim();
  if (text === '') return fallback;
  const mib = Number(text);
  if (!Number.isFinite(mib) || mib < MIN_LIMIT_MIB || mib > MAX_LIMIT_MIB) return fallback;
  return Math.round(mib) * MIB;
}

export function baseName(path) {
  const slash = path.lastIndexOf('/');
  return slash < 0 ? path : path.slice(slash + 1);
}

export function dirName(path) {
  const slash = path.lastIndexOf('/');
  return slash < 0 ? '' : path.slice(0, slash);
}

/** Reserve an archive path, disambiguating names on case-insensitive disks. */
export function uniquePath(path, taken) {
  let unique = path;
  const dot = path.lastIndexOf('.');
  const slash = path.lastIndexOf('/');
  for (let n = 2; taken.has(unique.toLowerCase()); n += 1) {
    unique = dot > slash ? `${path.slice(0, dot)} (${n})${path.slice(dot)}` : `${path} (${n})`;
  }
  taken.add(unique.toLowerCase());
  return unique;
}

/**
 * Order two paths as the native scan lists them: component by component, so a
 * folder's files stay together, and by code unit within a component.
 */
export function comparePaths(a, b) {
  const left = a.split('/');
  const right = b.split('/');
  for (let index = 0; index < left.length && index < right.length; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return left.length - right.length;
}

function extension(name) {
  const dot = name.lastIndexOf('.');
  return dot < 0 ? '' : name.slice(dot + 1).toLowerCase();
}

/** True for the external payload of a module: `<name>.exe._` or `<name>.dll._`. */
export function isCompanionName(name) {
  return name.endsWith('._') && ['exe', 'dll'].includes(extension(name.slice(0, -2)));
}

/**
 * What a folder scan takes a file name for: `pe`, `so`, `package`,
 * `metadata`, or `null` for a name it never opens.
 */
export function candidateKind(name) {
  const file = baseName(name);
  if (file.toLowerCase() === METADATA_NAME) return 'metadata';
  switch (extension(file)) {
    case 'exe':
    case 'dll':
      return 'pe';
    case 'so':
      return 'so';
    case 'apk':
    case 'apks':
    case 'xapk':
      return 'package';
    default:
      return null;
  }
}

/** True for a directory a scan does not enter: a previous output tree. */
export function isOutputDir(name) {
  return name.toLowerCase() === 'unpack';
}

/** What the first bytes of a file say it is. */
export function sniff(prefix) {
  const at = (i) => prefix[i] ?? -1;
  return {
    zip: at(0) === 0x50 && at(1) === 0x4b && at(2) === 0x03 && at(3) === 0x04,
    metadata: at(0) === 0xaf && at(1) === 0x1b && at(2) === 0xb1 && at(3) === 0xfa,
    mz: at(0) === 0x4d && at(1) === 0x5a,
    elf64Aarch64:
      at(0) === 0x7f && at(1) === 0x45 && at(2) === 0x4c && at(3) === 0x46 &&
      at(4) === 2 && at(5) === 1 && at(18) === 0xb7 && at(19) === 0,
  };
}

/** `app.exe` becomes `app.unpack.exe`; a name with no dot gets `.unpack` appended. */
export function outName(path) {
  const dir = dirName(path);
  const file = baseName(path);
  const dot = file.lastIndexOf('.');
  const renamed = dot < 0 ? `${file}.unpack` : `${file.slice(0, dot)}.unpack${file.slice(dot)}`;
  return dir ? `${dir}/${renamed}` : renamed;
}

/** Where a library's embedded metadata goes: beside the restored library. */
export function embeddedMetadataPath(restoredPath) {
  const dir = dirName(restoredPath);
  const name = outName(METADATA_NAME);
  return dir ? `${dir}/${name}` : name;
}

/**
 * The application a loose Android file belongs to, or `null` when its path
 * does not say.
 *
 * `<root>/lib/<abi>/<name>.so` and `<root>/assets/**\/global-metadata.dat`
 * share `<root>`. Anything else is on its own: a metadata blob is never paired
 * with a library from somewhere else in the scan.
 */
export function looseAppRoot(relPath, kind) {
  const parts = relPath.split('/');
  if (kind === 'so') {
    if (parts.length < 3 || parts[parts.length - 3].toLowerCase() !== 'lib') return null;
    return parts.slice(0, -3).join('/');
  }
  if (kind === 'metadata') {
    const dirs = parts.slice(0, -1).map((part) => part.toLowerCase());
    const assets = dirs.lastIndexOf('assets');
    return assets < 0 ? null : parts.slice(0, assets).join('/');
  }
  return null;
}

/**
 * True for a package entry name that would leave the package: absolute, with
 * a drive, holding a NUL, or climbing above the package root with `..`. A
 * package with such an entry is refused as a whole, as the native front ends
 * refuse it.
 */
export function escapesRoot(name) {
  if (typeof name !== 'string' || name.includes('\0')) return true;
  const normal = name.replace(/\\/g, '/');
  if (normal.startsWith('/') || /^[A-Za-z]:/.test(normal)) return true;
  let depth = 0;
  for (const part of normal.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (depth === 0) return true;
      depth -= 1;
    } else {
      depth += 1;
    }
  }
  return false;
}

/**
 * A package entry name as a safe relative path, or `null` for one that must
 * not be used: absolute, with a drive, or climbing out with `..`.
 */
export function safeEntryPath(name) {
  if (typeof name !== 'string' || name === '' || name.includes('\0')) return null;
  const normal = name.replace(/\\/g, '/');
  if (normal.startsWith('/') || /^[A-Za-z]:/.test(normal)) return null;
  const parts = [];
  for (const part of normal.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') return null;
    parts.push(part);
  }
  return parts.length === 0 ? null : parts.join('/');
}

/** True for a package entry the page reads: a library or a metadata blob. */
export function isPackageTarget(path) {
  const kind = candidateKind(path);
  return kind === 'so' || kind === 'metadata';
}

/** True for an app package nested one level inside a bundle. */
export function isNestedPackage(path) {
  return extension(baseName(path)) === 'apk';
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < MIB) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * MIB) return `${(bytes / MIB).toFixed(1)} MiB`;
  return `${(bytes / (1024 * MIB)).toFixed(2)} GiB`;
}

/** A duration as the workbench writes it: `15 ms` or `1.42 s`. */
export function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '';
  const whole = Math.round(ms);
  return whole >= 1000 ? `${(whole / 1000).toFixed(2)} s` : `${whole} ms`;
}

/** `0:01.4`: minutes, seconds, and tenths, for a running clock. */
export function formatClock(elapsedMs) {
  const tenths = Math.floor(Math.max(0, elapsedMs) / 100);
  const seconds = String(Math.floor(tenths / 10) % 60).padStart(2, '0');
  return `${Math.floor(tenths / 600)}:${seconds}.${tenths % 10}`;
}

/** `12,345`: a count with thousands separators. */
export function formatCount(value) {
  return String(value ?? '').replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/** `head…tail` of a hash for display. */
export function shortHash(sha256) {
  const text = String(sha256 ?? '');
  return text.length <= 24 ? text : `${text.slice(0, 16)}…${text.slice(-8)}`;
}

/** `13:46:42.936`: the local time of day of a log line. */
export function localClock(epochMs) {
  const date = new Date(epochMs);
  const two = (value) => String(value).padStart(2, '0');
  return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}.${String(date.getMilliseconds()).padStart(3, '0')}`;
}

/** The catalog language for a list of browser language tags. */
export function languageFor(tags) {
  for (const tag of tags ?? []) {
    const parts = String(tag).toLowerCase().replace(/_/g, '-').split('-');
    switch (parts[0]) {
      case 'en':
        return 'en';
      case 'ja':
        return 'ja';
      case 'ko':
        return 'ko';
      case 'zh': {
        const rest = parts.slice(1);
        if (rest.includes('hant')) return 'zh-TW';
        if (rest.includes('hans')) return 'zh-CN';
        return rest.some((part) => ['tw', 'hk', 'mo'].includes(part)) ? 'zh-TW' : 'zh-CN';
      }
      default:
    }
  }
  return 'en';
}

/**
 * How an input is shown after a job, from the engine's report.
 *
 * `ok` and `suspect` both have output. `skipped` covers an input that needed
 * nothing: not protected, an already canonical metadata blob, or a metadata
 * version left untouched by design.
 */
export function stateOf(info) {
  switch (info?.status) {
    case 'recovered': {
      const validation = info.profile?.static_validation;
      return info.suspect || validation === 'warnings' || validation === 'failed' ? 'suspect' : 'ok';
    }
    case 'unchanged':
    case 'unsupported':
    case 'not_protected':
      return 'skipped';
    default:
      return 'failed';
  }
}

/** Modules `0x0C` collected for one application, kept apart by content. */
export class ModuleContext {
  #modules = [];

  add(bytes) {
    if (!bytes?.length) return;
    const same = (other) =>
      other.length === bytes.length && other.every((value, index) => value === bytes[index]);
    if (!this.#modules.some(same)) this.#modules.push(bytes);
  }

  /** The distinct modules seen. A metadata blob binds only when this is one. */
  get count() {
    return this.#modules.length;
  }

  /** The single module, or `null` when there is none or more than one. */
  get module() {
    return this.#modules.length === 1 ? this.#modules[0] : null;
  }
}
