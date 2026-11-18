// What the page says about a finished input: the messages it shows, its
// stages, its log, and the JSON report. Pure transforms over the page's item
// records, so `web/tests/` runs them under Node.
//
// An item record is `{ name, relPath, kind, state, size, pre, result, error,
// container, entries }`. `result` is `{ info, lang, durationMs, retried,
// companionUsed, inputSha256, outputs }`, where `info` is the engine's report
// for the job and each output is `{ path, size, sha256, embedded, saved,
// saveFailed }`.
//
// A log line is `{ at, level, type, ... }`: `at` in milliseconds since the
// epoch, `level` one of `info`, `step`, `detail`, `warn`, `error`, and the
// rest by `type`. Lines stay structured so the log reads in whatever language
// the page is in when it is shown.

import { baseName } from './model.js';

export const REPORT_SCHEMA = 'senbei.browser-report';
export const REPORT_SCHEMA_VERSION = 2;

const messageText = (message) => message?.text ?? '';

/**
 * Every message an input reports, each exactly once, where a reader looks.
 *
 * Returns `{ top, validation }`, both lists of `{ tone, message }` with `tone`
 * one of `err`, `warn`, `info`. When the static check found something, the
 * profile's messages are its findings and go to `validation`; everything else
 * goes to `top`. A message is `{ text, local }`. Why an input needed nothing
 * is not a message: its recovery stage says so.
 */
export function messagePlan(item) {
  const info = item?.result?.info;
  const validation = [];
  const top = [];
  const shown = new Set();
  const push = (list, tone, message) => {
    const text = messageText(message);
    if (!text || shown.has(text)) return;
    shown.add(text);
    list.push({ tone, message });
  };
  if (item?.error) push(top, 'err', item.error);
  if (!info) return { top, validation };
  const verdict = info.profile?.static_validation;
  const findings = verdict === 'warnings' || verdict === 'failed';
  if (info.error) push(top, 'err', info.error);
  for (const finding of info.findings ?? []) {
    push(findings ? validation : top, finding.severity === 'fatal' ? 'err' : 'warn', {
      text: finding.message,
      local: null,
    });
  }
  for (const message of info.errors ?? []) push(findings ? validation : top, 'err', message);
  for (const message of info.warnings ?? []) push(findings ? validation : top, 'warn', message);
  return { top, validation };
}

/**
 * True when an input's last run went through the Windows pipeline. That is
 * every module, and every file that is no target at all: the pipeline is what
 * tells such a file so.
 */
export const ranAsModule = (item) =>
  item?.result?.op ? item.result.op === 'pe' : !['so', 'metadata', 'package'].includes(item?.kind);

/**
 * The stages of a finished input, as the workbench records them:
 * `{ stage, status, durationMs, detail }` with `stage` one of `detection`,
 * `recovery`, `static_validation`, `output_write` and `status` one of `ok`,
 * `skipped`, `failed`. `detail` is a message or `null`.
 *
 * A Windows module records all of its stages; a library and a metadata blob
 * record recovery and what followed it. A failure records the one stage that
 * failed. An output that was kept for download was not written anywhere, so
 * its `output_write` is `skipped`.
 */
export function stagesOf(item) {
  const result = item?.result;
  const info = result?.info;
  const stage = (name, status, extra) => ({ stage: name, status, durationMs: null, detail: null, ...extra });
  if (!info) return item?.error ? [stage('recovery', 'failed', { detail: item.error })] : [];
  if (item.kind === 'package') return [];
  const windows = ranAsModule(item);
  const spent = Math.round(result.durationMs ?? 0);
  switch (info.status) {
    case 'recovered': {
      const stages = windows ? [stage('detection', 'ok')] : [];
      stages.push(stage('recovery', 'ok', { durationMs: spent }));
      if (item.kind !== 'metadata') {
        stages.push(stage('static_validation', windows && info.suspect ? 'failed' : 'ok'));
      }
      const outputs = result.outputs ?? [];
      const saved = outputs.find((output) => output.saved);
      if (outputs.some((output) => output.saveFailed)) stages.push(stage('output_write', 'failed'));
      else if (saved) stages.push(stage('output_write', 'ok', { detail: { text: saved.saved, path: true } }));
      // A refused name is queued for the folder ZIP; that write logs its
      // outcome separately once the archive is complete.
      else if (outputs.some((output) => !output.refused)) stages.push(stage('output_write', 'skipped'));
      return stages;
    }
    case 'unchanged':
      // A file run on its own records how long the look took; one of a folder
      // records why it needed nothing.
      return [
        stage('recovery', 'skipped', item.group?.kind === 'folder' ? { detail: info.note ?? null } : { durationMs: spent }),
      ];
    case 'unsupported':
    case 'not_protected':
      return [stage('recovery', 'skipped', { detail: info.note ?? null })];
    default:
      return [stage('recovery', 'failed', { detail: windows ? (info.error ?? null) : null })];
  }
}

const LEVEL_OF = { err: 'error', warn: 'warn' };

/**
 * The engine's own lines of one job: its steps and their details.
 *
 * `began` is when the job started, as milliseconds since the epoch; every
 * line's `at` is counted from it. `lang` is the language the job ran in, which
 * a step title without a catalog name is written in.
 */
export function engineLines(info, began, lang) {
  const lines = [];
  let last = 0;
  for (const line of info?.log ?? []) {
    last = line.ms ?? last;
    const at = began + last;
    if (line.step !== undefined) {
      lines.push({
        at,
        level: 'step',
        type: 'step',
        i: line.i ?? null,
        of: line.of ?? null,
        key: line.key ?? null,
        title: line.step,
        lang,
      });
    } else if (line.detail !== undefined) {
      lines.push({ at, level: 'detail', type: 'detail', text: line.detail });
    } else if (line.truncated) {
      lines.push({ at, level: 'detail', type: 'detail', text: '…' });
    }
  }
  return lines;
}

/**
 * The lines that close an input's log at `at`: its stages, its messages, the
 * entries of a package, and the outcome.
 *
 * `outcome` is `{ key, tone }` for the input, and `entries` lists the package
 * entries a run acted on as `{ path, key, tone }`.
 */
export function closingLines(item, at, outcome, entries = []) {
  const lang = item.result?.lang;
  const lines = [];
  for (const stage of stagesOf(item)) {
    lines.push({ at, level: stage.status === 'failed' ? 'error' : 'info', type: 'stage', lang, ...stage });
  }
  const plan = messagePlan(item);
  for (const { tone, message } of [...plan.top, ...plan.validation]) {
    lines.push({ at, level: LEVEL_OF[tone] ?? 'info', type: 'message', message, lang });
  }
  for (const entry of entries) {
    lines.push({
      at,
      level: entry.tone === 'err' ? 'error' : 'info',
      type: 'entry',
      path: entry.path,
      outcome: entry.key,
    });
  }
  lines.push(finishedLine(item, at, outcome));
  return lines;
}

/** The line that says how an input ended and how long it took. */
export function finishedLine(item, at, outcome) {
  return {
    at,
    level: LEVEL_OF[outcome.tone] ?? 'info',
    type: 'finished',
    outcome: outcome.key,
    durationMs: item.durationMs ?? item.result?.durationMs ?? 0,
  };
}

/** The line that names the companion a module was paired with. */
export function companionLine(item, at) {
  return { at, level: 'info', type: 'companion', name: `${baseName(item.relPath)}._` };
}

/** One input's entry in the JSON report. */
export function fileReport(item) {
  const result = item.result ?? null;
  const info = result?.info ?? null;
  // A package has no job of its own; its time is that of its entries.
  const duration = item.durationMs ?? result?.durationMs;
  const report = {
    name: item.name,
    path: item.relPath,
    kind: item.kind,
    status: item.state,
    input: { size: item.size ?? null, sha256: result?.inputSha256 ?? null },
    companion_used: result?.companionUsed === true,
    forced_exe_retry: result?.retried === true,
    duration_ms: Number.isFinite(duration) ? Math.round(duration) : null,
    outputs: (result?.outputs ?? []).map((output) => ({
      path: output.path,
      size: output.size,
      sha256: output.sha256 ?? null,
      embedded_metadata: output.embedded === true,
    })),
    // The engine's profile, verbatim. Before a run it is the pre-recovery one.
    profile: info?.profile ?? item.pre ?? null,
    findings: info?.findings ?? [],
    metadata: info?.metadata ?? null,
    restored_elf: info?.elf ?? null,
    error: messageText(item.error) || messageText(item.identityError) || messageText(info?.error) || null,
  };
  if (item.container) {
    report.container = {
      kind: item.container.kind,
      archives: item.container.archives.map((archive) => ({
        path: archive.label || null,
        entries: archive.entryCount,
        candidates: archive.targets.length,
        package: archive.identity?.[0] ?? null,
        version: archive.identity?.[1] ?? null,
      })),
    };
    report.entries = (item.entries ?? []).map(fileReport);
  }
  return report;
}

/** The report for `items`. `generatedAt` is passed in so this stays pure. */
export function buildReport(items, options = {}) {
  const files = items.map(fileReport);
  const count = (state) => files.filter((file) => file.status === state).length;
  return {
    schema: REPORT_SCHEMA,
    schema_version: REPORT_SCHEMA_VERSION,
    tool: { name: 'senbei-web', version: options.version ?? null },
    generated_at: options.generatedAt ?? null,
    input_limit_bytes: Number.isFinite(options.limitBytes) ? options.limitBytes : null,
    summary: {
      inputs: files.length,
      recovered: count('ok'),
      suspect: count('suspect'),
      failed: count('failed'),
      skipped: count('skipped'),
    },
    files,
  };
}

/** Two-space JSON with a trailing newline. */
export function serializeReport(report) {
  return `${JSON.stringify(report, null, 2)}\n`;
}

/** `YYYYMMDD-HHMMSS` from an ISO timestamp, for file names. */
export function fileStamp(generatedAt) {
  return String(generatedAt ?? '')
    .replace(/\D/g, '')
    .slice(0, 14)
    .replace(/^(\d{8})(\d{6})$/, '$1-$2');
}

/**
 * A report's file name: safe on every filesystem, stable across time zones.
 * `extension` is `json` for the report and `txt` for its text form.
 */
export function reportFileName(name, generatedAt, extension = 'json') {
  const stamp = fileStamp(generatedAt);
  const stem = name
    ? baseName(name).replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^[_.]+|[_.]+$/g, '') || 'senbei'
    : 'senbei';
  return stamp ? `${stem}.${stamp}.report.${extension}` : `${stem}.report.${extension}`;
}
