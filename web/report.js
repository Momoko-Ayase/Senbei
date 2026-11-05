// Pure helpers for the browser frontend: input memory budgeting and JSON
// report shaping. No DOM, no network, no clock reads — every function is a
// pure transform so `web/tests/` can exercise it under Node.

/** Practical default ceiling for one staged input set (base + companion). */
export const DEFAULT_INPUT_LIMIT_BYTES = 256 * 1024 * 1024;

/** The limit control accepts this range; outside it the field is ignored. */
export const MIN_INPUT_LIMIT_MIB = 8;
export const MAX_INPUT_LIMIT_MIB = 4096;

/** Version of the browser report envelope this module emits. */
export const REPORT_SCHEMA = 'senbei.browser-report';
export const REPORT_SCHEMA_VERSION = 1;

const MIB = 1024 * 1024;

/**
 * Parse the limit input (MiB) into bytes.
 *
 * Empty, non-numeric, or out-of-range input falls back to `fallback` so a
 * half-typed value never changes the active budget mid-session.
 */
export function parseLimitMiB(raw, fallback = DEFAULT_INPUT_LIMIT_BYTES) {
  const text = String(raw ?? '').trim();
  if (text === '') return fallback;
  const mib = Number(text);
  if (!Number.isFinite(mib)) return fallback;
  if (mib < MIN_INPUT_LIMIT_MIB || mib > MAX_INPUT_LIMIT_MIB) return fallback;
  return Math.round(mib) * MIB;
}

/** Human byte size with one decimal for MiB/GiB steps. */
export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < MIB) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * MIB) return `${(bytes / MIB).toFixed(1)} MiB`;
  return `${(bytes / (1024 * MIB)).toFixed(2)} GiB`;
}

/** True for the `<module>._` companion suffix. */
export function isCompanionName(name) {
  return typeof name === 'string' && name.endsWith('._');
}

/** Base module name for a companion, or the name itself. */
export function baseName(name) {
  return isCompanionName(name) ? name.slice(0, -2) : name;
}

/**
 * Group staged entries into one budget unit per base module.
 *
 * A companion (`X._`) and its base (`X`) are read together by the unpack
 * path, so they must be measured together; measuring them separately would
 * let a 200 MiB pair pass a 200 MiB limit and then read 400 MiB.
 *
 * `entries` accepts `{ name, size }` objects or `File`-like values with
 * `name` and `size`.
 */
export function groupByModule(entries) {
  const groups = new Map();
  for (const entry of entries ?? []) {
    const name = entry?.name;
    if (typeof name !== 'string' || name === '') continue;
    const size = Number(entry.size);
    const base = baseName(name);
    const group = groups.get(base) ?? { base, bytes: 0, names: [], companion: false };
    group.bytes += Number.isFinite(size) && size > 0 ? size : 0;
    group.names.push(name);
    if (isCompanionName(name)) group.companion = true;
    groups.set(base, group);
  }
  return [...groups.values()];
}

/**
 * Decide whether the staged set may be read into memory.
 *
 * This runs from `File.size` metadata BEFORE any `arrayBuffer()` call. It is a
 * best-effort guard, not a peak-RSS guarantee: unpacking holds the input, the
 * recovered image, and the pipeline's own scratch buffers at once, so the real
 * peak is a multiple of the bytes measured here.
 *
 * Returns the blocked modules, the modules that compile a warning, and the
 * combined-size guidance strings the UI shows verbatim.
 */
export function planReadBudget(entries, limitBytes, options = {}) {
  const limit = Number.isFinite(limitBytes) && limitBytes > 0
    ? limitBytes
    : DEFAULT_INPUT_LIMIT_BYTES;
  const warnFactor = options.warnFactor ?? 0.5;
  const groups = groupByModule(entries);
  const totalBytes = groups.reduce((sum, group) => sum + group.bytes, 0);
  const blocked = [];
  const oversized = [];
  for (const group of groups) {
    if (group.bytes > limit) blocked.push(group);
    else if (group.bytes >= limit * warnFactor) oversized.push(group);
  }
  const overLimit = groups.length > 0 && totalBytes > limit;
  const blockedBases = blocked.map((group) => group.base);
  const blockedNames = new Set(blocked.flatMap((group) => group.names));
  const guidance = [];
  if (blocked.length > 0) {
    for (const group of blocked) {
      guidance.push(
        `Skipped ${group.base} (${formatBytes(group.bytes)} with companion)` +
          ` — above the ${formatBytes(limit)} input limit.`,
      );
    }
  } else if (overLimit) {
    guidance.push(
      `Staged inputs total ${formatBytes(totalBytes)}, above the ` +
        `${formatBytes(limit)} limit. Unpack them one at a time, or raise the limit.`,
    );
  } else if (totalBytes > 0) {
    guidance.push(
      `Staged inputs total ${formatBytes(totalBytes)}. Unpacking holds the ` +
        'input, the recovered image, and pipeline scratch buffers together, so ' +
        'transient memory use is several times this figure.',
    );
    if (oversized.length > 0) {
      const names = oversized.map((group) => group.base).join(', ');
      guidance.push(`Near the ${formatBytes(limit)} limit: ${names}.`);
    }
  }
  return {
    limitBytes: limit,
    totalBytes,
    overLimit,
    warnFactor,
    groups,
    /** Base module names that must not be read (their companion goes with them). */
    blocked: blockedBases,
    /** Base module names that fit but are at least `warnFactor` of the limit. */
    nearLimit: oversized.map((group) => group.base),
    guidance,
    /** Base module names that may be read. */
    allowed: groups
      .filter((group) => !blockedNames.has(group.base))
      .map((group) => group.base),
  };
}

/** Sort findings fatal-first while keeping the checker's order within a class. */
export function sortFindings(findings) {
  const weight = (finding) => (finding?.severity === 'fatal' ? 0 : 1);
  return (findings ?? [])
    .filter((finding) => finding && typeof finding.message === 'string')
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) => weight(a.finding) - weight(b.finding) || a.index - b.index)
    .map(({ finding }) => ({
      severity: finding.severity === 'fatal' ? 'fatal' : 'warning',
      message: finding.message,
    }));
}

/** `clean` / `warnings` / `failed` for a finding list. */
export function integrityStatus(findings) {
  const list = sortFindings(findings);
  if (list.length === 0) return 'clean';
  return list.some((finding) => finding.severity === 'fatal') ? 'failed' : 'warnings';
}

/** The profile's own final static-check verdict, or `null` when absent. */
export function profileIntegrityStatus(profile) {
  const value = profile?.static_validation;
  return value === 'clean' || value === 'warnings' || value === 'failed' || value === 'not_run'
    ? value
    : null;
}

/**
 * Integrity verdict for a recovered row.
 *
 * The profile records the check that actually ran, so it wins whenever it has
 * a value. That matters for metadata: its transform is validated by the
 * metadata adapter and the PE static check does not apply, so the profile says
 * `not_run` — reporting `clean` there would invent a check that never
 * happened. Without a profile, metadata still falls back to `not_run`; a PE
 * row falls back to its findings, as before.
 */
export function recoveredIntegrityStatus(entry, findings) {
  const fromProfile = profileIntegrityStatus(entry?.profile);
  if (fromProfile !== null) return fromProfile;
  if (entry?.kind === 'metadata') return 'not_run';
  return integrityStatus(findings);
}

/**
 * Per-file report entry.
 *
 * `entry` is the app's row state: `{ state, kind, outputName, inputBytes,
 * outputBytes, findings, profile, preRecoveryProfile, companionUsed, retried,
 * error, note }`. The full protection profile object (snake_case,
 * `format_version`) is embedded verbatim under `profile` and
 * `pre_recovery_profile`; only the browser envelope is versioned here.
 */
export function buildFileReport(name, entry, options = {}) {
  const state = entry?.state ?? 'staged';
  const status = state === 'ok'
    ? 'recovered'
    : state === 'err'
      ? 'failed'
      : state === 'blocked'
        ? 'blocked'
        : 'pending';
  const findings = sortFindings(entry?.findings);
  const report = {
    name,
    output_name: entry?.outputName ?? null,
    status,
    kind: entry?.kind ?? null,
    input_bytes: Number.isFinite(entry?.inputBytes) ? entry.inputBytes : null,
    output_bytes: Number.isFinite(entry?.outputBytes) ? entry.outputBytes : null,
    companion_used: entry?.companionUsed === true,
    forced_exe_retry: entry?.retried === true,
    profile: entry?.profile ?? null,
    pre_recovery_profile: entry?.preRecoveryProfile ?? null,
    integrity: {
      status: status === 'recovered'
        ? recoveredIntegrityStatus(entry, findings)
        : 'not_run',
      findings,
    },
    error: status === 'failed' || status === 'blocked' ? (entry?.error ?? null) : null,
  };
  if (options.includeNotes && entry?.note) report.note = entry.note;
  return report;
}

/**
 * All-files report envelope. `generatedAt` is passed in so the helper stays
 * pure and the tests are deterministic.
 */
export function buildReport(entries, options = {}) {
  const files = [];
  for (const [name, entry] of entries ?? []) {
    if (isCompanionName(name)) continue;
    files.push(buildFileReport(name, entry, options));
  }
  const recovered = files.filter((file) => file.status === 'recovered').length;
  const failed = files.filter((file) => file.status === 'failed').length;
  const blocked = files.filter((file) => file.status === 'blocked').length;
  return {
    schema: REPORT_SCHEMA,
    schema_version: REPORT_SCHEMA_VERSION,
    generated_at: options.generatedAt ?? null,
    input_limit_bytes: Number.isFinite(options.limitBytes) ? options.limitBytes : null,
    summary: { files: files.length, recovered, failed, blocked },
    files,
  };
}

/** Serialize a report deterministically (2-space indent, trailing newline). */
export function serializeReport(report) {
  return `${JSON.stringify(report, null, 2)}\n`;
}

/**
 * Download file name for a report.
 *
 * `generatedAt` is an ISO timestamp; only `YYYYMMDD-HHMMSS` survives, so the
 * name is filesystem-safe on Windows and stable across time zones.
 */
export function reportFileName(name, generatedAt) {
  const stamp = String(generatedAt ?? '')
    .replace(/\D/g, '')
    .slice(0, 14)
    .replace(/^(\d{8})(\d{6})$/, '$1-$2');
  if (!name) return stamp ? `senbei-${stamp}.report.json` : 'senbei-report.json';
  const base = baseName(name).replace(/\.(exe|dll|dat)$/i, '');
  // Windows/macOS-safe: no path separators, colons, or spaces.
  const stem = base.replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'senbei';
  return stamp ? `${stem}.${stamp}.report.json` : `${stem}.report.json`;
}

// --- Profile presentation -------------------------------------------------
//
// The profile reports only observed facts. These helpers must never turn a
// magic-byte match into a protection claim: `recognition` says whether the
// header key table matched, `recovery` whether a route produced an image, and
// `static_validation` whether that image passed the structural checks.

const FORMAT_LABEL = {
  pe32: 'PE32',
  pe32_plus: 'PE32+',
  elf64_aarch64: 'ELF64 AArch64',
  il2cpp_metadata: 'il2cpp metadata',
};

const KIND_LABEL = {
  native_exe: 'native EXE',
  managed_exe: 'managed EXE',
  native_dll: 'native DLL',
  managed_dll: 'managed DLL',
};

const LAYOUT_LABEL = {
  dll: 'DLL layout',
  exe_style: 'EXE-style layout',
  android_staged: 'Android staged',
  metadata_structural: 'metadata structural',
  metadata_seeded: 'metadata seeded',
  metadata_method_indices: 'metadata method indices',
};

const EVIDENCE_LABEL = {
  header_magic: 'header magic',
  external_companion_declaration: 'external companion declared',
  companion_spliced: 'companion spliced',
  private_section: 'private loader section',
  aes_schedule: 'AES schedule',
  validated_metadata_transform: 'metadata transform validated',
};

function humanize(value) {
  return String(value ?? '').replace(/_/g, ' ');
}

/**
 * One-line description of an observed target, used before recovery runs.
 *
 * For metadata the text says explicitly that the version identifies a format,
 * not a protection.
 */
export function describeObserved(profile, options = {}) {
  if (!profile || typeof profile !== 'object') return '';
  const observed = profile.observed ?? {};
  if (observed.platform === 'il2cpp_metadata') {
    // The format name is already the row's kind label, so repeat only the
    // version. The disclaimer is mandatory: identify() matches a format
    // header, and a format header is not evidence of protection.
    const version = observed.metadata_version != null
      ? `v${observed.metadata_version}`
      : 'version unknown';
    return `${version} · format only, not a protection verdict`;
  }
  const parts = [];
  const format = FORMAT_LABEL[observed.format] ?? humanize(observed.format);
  if (format) parts.push(format);
  if (options.includeKind !== false) {
    const kind = KIND_LABEL[observed.kind] ?? humanize(observed.kind);
    if (kind) parts.push(kind);
  }
  if (observed.external_companion) parts.push('external companion');
  const head = parts.join(' · ');
  const evidence = (profile.evidence ?? [])
    .map((value) => EVIDENCE_LABEL[value] ?? humanize(value))
    .join(', ');
  if (head && evidence) return `${head} · ${evidence}`;
  return head || evidence;
}

/**
 * Route/validation lines for a finished (or failed) recovery.
 *
 * The PE static check does not apply to metadata output, so its
 * `static check not run` line is omitted for metadata profiles rather than
 * shown as a missing step.
 */
export function describeStages(profile) {
  if (!profile || typeof profile !== 'object') return [];
  const lines = [];
  const selected = profile.selected ? (LAYOUT_LABEL[profile.selected] ?? humanize(profile.selected)) : null;
  if (Array.isArray(profile.candidates)) {
    for (const attempt of profile.candidates) {
      if (!attempt || typeof attempt !== 'object') continue;
      const layout = LAYOUT_LABEL[attempt.layout] ?? humanize(attempt.layout);
      const outcome = humanize(attempt.outcome);
      const suffix = selected && attempt.layout === profile.selected ? ' — selected' : '';
      lines.push(`${layout}: ${outcome}${suffix}`);
    }
  }
  // Only a run of the static check is worth a line. `not_run` covers both the
  // failed recovery (no image to check) and metadata output (the PE check does
  // not apply), and in both cases the row's status already says so.
  const validation = profile.static_validation;
  if (validation && validation !== 'not_run') {
    const label = validation === 'clean'
      ? 'static check clean'
      : validation === 'warnings'
        ? 'static check with warnings'
        : 'static check failed';
    lines.push(label);
  }
  return lines;
}

/** Severity-labelled integrity lines: fatal first, then warnings. */
export function describeFindings(findings) {
  return sortFindings(findings).map(
    (finding) => `${finding.severity === 'fatal' ? 'fatal' : 'warning'}: ${finding.message}`,
  );
}
