// Running recoveries: the order they run in, one job for each input or
// package entry, the logs they leave, and writing outputs to a chosen folder.

import { language, t } from './i18n.js';
import {
  archiveAppKey,
  changed,
  fullPath,
  isDone,
  outcomeOf,
  state,
  targetEntries,
  timeOf,
} from './state.js';
import {
  MIN_SIZE,
  ModuleContext,
  embeddedMetadataPath,
  formatBytes,
  looseAppRoot,
  outName,
  sniff,
  stateOf,
} from './model.js';
import { EngineStopped, Prober, runJob } from './engine.js';
import { FolderWriter } from './output.js';
import { closingLines, companionLine, engineLines, finishedLine } from './report.js';
import { shownPath } from './ui.js';

/** A message the page raised: its catalog key, and what the system said. */
export function pageError(key, vars, tech) {
  return { key, vars, text: t(key, vars), tech: tech ? String(tech) : undefined };
}

// ---------- one job ----------

/** A library entry this small is probed in the shared worker before a job. */
const QUICK_PROBE_BYTES = 32 * 1024 * 1024;

function appKeyOf(target) {
  if (target.isEntry) return archiveAppKey(target.parent, target.archive);
  // Picked files carry no path, so the ones added together are one application.
  if (target.group.kind === 'files') return `files:${target.group.id}`;
  const root = looseAppRoot(target.relPath, target.kind);
  return root === null ? `alone:${target.id}` : `loose:${target.group.id}:${root}`;
}

function contextOf(target) {
  const key = appKeyOf(target);
  let context = state.contexts.get(key);
  if (!context) {
    context = new ModuleContext();
    state.contexts.set(key, context);
  }
  return context;
}

function outputPath(target) {
  if (!target.isEntry) return outName(target.relPath);
  const inside = outName(target.target.path);
  const label = target.archive.label;
  return `${target.parent.relPath}/${label ? `${label}/` : ''}${inside}`;
}

/** The outcome of a target that needs no job: the engine has nothing to restore. */
function notTarget(profile = null) {
  return {
    op: null,
    info: {
      status: 'not_protected',
      kind: null,
      error: null,
      note: null,
      profile,
      routes: [],
      warnings: [],
      errors: [],
      findings: [],
      suspect: false,
      companion: false,
      metadata: null,
      elf: null,
      log: [],
    },
    image: null,
    embedded: null,
    moduleBytes: null,
    identity: null,
  };
}

/** An error that carries the message the page shows for it. */
function failure(page) {
  const error = new Error(page.text);
  error.page = page;
  return error;
}

const overLimit = (size) =>
  failure(pageError('web.over_limit', { size: formatBytes(size), limit: formatBytes(state.limitBytes) }));

/**
 * Recover one input or package entry.
 *
 * Resolves to `{ outcome, companion, retried }`: the job's outcome, the
 * companion file that was passed, and whether the other route was tried. `on`
 * is given to the job, with `on.retry` called before a second attempt;
 * `prober` answers the quick checks on package entries.
 */
async function attempt(target, lang, on, prober) {
  if (target.kind === 'package') {
    // A package that could not be listed fails as it failed then. One that
    // holds nothing to probe needs nothing.
    if (target.identityError) throw failure(target.identityError);
    return { outcome: notTarget() };
  }
  if (target.size > state.limitBytes) throw overLimit(target.size);
  let input;
  let version = target.metadataVersion;
  if (target.isEntry) {
    const { entrySource, readEntryPrefix } = await import('./zip.js');
    input = await entrySource(target.archive.blob, target.target.entry);
    const magic = sniff((await readEntryPrefix(input, 20)).bytes);
    if (target.kind === 'so') {
      if (target.size < MIN_SIZE || !magic.elf64Aarch64) return { outcome: notTarget() };
      if (target.size <= QUICK_PROBE_BYTES) {
        const profile = await prober.library(input, target.size);
        if (profile?.recognition === 'not_recognized') return { outcome: notTarget(profile) };
      }
    } else {
      if (!magic.metadata) return { outcome: notTarget() };
      version = await (await import('./package.js')).entryMetadataVersion(input);
      target.metadataVersion = version;
    }
  } else {
    input = await target.open();
  }

  if (target.kind === 'so') {
    if (target.isEntry) return { outcome: await runJob({ op: 'so', input, lang }, on) };
    // A file that turns out to be an ordinary library is told so the way any
    // other file is, below. Its outcome is not shown before that.
    const protectedOnly = (outcome) => outcome.info.status !== 'not_protected' && on.result?.(outcome);
    const outcome = await runJob({ op: 'so', input, lang }, { ...on, result: protectedOnly });
    if (outcome.info.status !== 'not_protected') return { outcome };
    on.retry?.();
  }

  if (target.kind === 'metadata') {
    // Only a v24 blob is bound to module 0x0C of its application.
    const context = version === 24 ? state.contexts.get(appKeyOf(target)) : null;
    const request = {
      op: 'metadata',
      input,
      moduleBytes: context?.module ?? null,
      conflicting: context?.count ?? 0,
      lang,
    };
    return { outcome: await runJob(request, on) };
  }

  // Anything else is tried as a Windows module, which is also how a file that
  // is no target at all is told so.
  const openCompanion = target.group.companions.get(`${target.relPath}._`);
  const companion = openCompanion ? await openCompanion() : null;
  if (companion && companion.size > state.limitBytes) throw overLimit(companion.size);
  const request = { op: 'pe', input, companion, forceExe: false, lang };
  try {
    return { outcome: await runJob(request, on), companion };
  } catch (error) {
    const dll = (target.peKind ?? '').endsWith('dll');
    if (!(error instanceof EngineStopped && error.trap && dll)) throw error;
    // The DLL route trapped. The EXE-only route is the other one to try.
    on.retry?.();
    return { outcome: await runJob({ ...request, forceExe: true }, on), companion, retried: true };
  }
}

// ---------- outputs ----------

function writerForOutput() {
  return state.out.mode === 'folder' && state.out.dir ? new FolderWriter(state.out.dir) : null;
}

/** Write what's already in the tab; a new folder gets even previously saved outputs. */
export async function saveAll(items, fresh) {
  const writer = writerForOutput();
  if (!writer || state.run || state.saving) return;
  state.saving = true;
  changed();
  try {
    for (const item of items) {
      await writer.save(item, fresh);
      for (const entry of item.entries ?? []) await writer.save(entry, fresh);
    }
    await writer.finish();
    await writer.saveLog(items);
  } finally {
    state.saving = false;
    changed();
  }
}

// ---------- a run ----------

/** The jobs of an input: itself, or each entry of a package. */
const leavesOf = (item) => (item.kind === 'package' && item.entries.length ? item.entries : [item]);

/**
 * The order the jobs of `items` run in.
 *
 * Inputs run in list order, each with its jobs together. A metadata blob is
 * the exception: it may need module `0x0C` of its application, so it waits
 * until every library of that application in this run has been restored.
 */
function schedule(items) {
  const libraries = new Map();
  const count = (leaf, by) => {
    const key = appKeyOf(leaf);
    libraries.set(key, (libraries.get(key) ?? 0) + by);
  };
  for (const item of items) for (const leaf of leavesOf(item)) if (leaf.kind === 'so') count(leaf, 1);
  const now = [];
  const later = [];
  for (const item of items) {
    const leaves = leavesOf(item);
    for (const leaf of leaves) {
      if (leaf.kind === 'metadata') continue;
      now.push(leaf);
      if (leaf.kind === 'so') count(leaf, -1);
    }
    for (const leaf of leaves) {
      if (leaf.kind !== 'metadata') continue;
      (libraries.get(appKeyOf(leaf)) > 0 ? later : now).push(leaf);
    }
  }
  return [...now, ...later];
}

/** How a package reads once its entries ran: failed, restored, or left alone. */
function packageState(item) {
  const has = (...states) => item.entries.some((entry) => states.includes(entry.state));
  if (has('failed')) return 'failed';
  return has('ok', 'suspect') ? 'ok' : 'skipped';
}

function beginInput(run, input) {
  const groupRun = run.groups.get(input.group);
  const at = Date.now();
  groupRun.index += 1;
  input.state = 'running';
  input.error = null;
  input.durationMs = null;
  input.clock = performance.now();
  const started = {
    at,
    level: 'info',
    type: 'input-started',
    i: groupRun.index,
    n: groupRun.inputs,
    path: shownPath(fullPath(input)),
  };
  // An input's own log starts like the run it is part of.
  input.log = [{ at, level: 'info', type: 'run-started', n: groupRun.inputs }, started];
  groupRun.log.push(started);
  run.begun.add(input);
}

function finishInput(run, input) {
  const groupRun = run.groups.get(input.group);
  const at = Date.now();
  let entries = [];
  if (input.kind === 'package' && input.entries.length) {
    input.durationMs = performance.now() - input.clock;
    input.state = packageState(input);
    entries = targetEntries(input).map((entry) => ({
      path: shownPath(entry.target.path),
      ...outcomeOf(entry),
    }));
  } else if (input.result?.companionUsed) {
    input.log.splice(2, 0, companionLine(input, input.log[1].at));
  }
  // An input that ended without an outcome did not finish its work.
  if (!isDone(input)) input.state = 'failed';
  const outcome = outcomeOf(input);
  input.log.push(...closingLines(input, at, outcome, entries));
  groupRun.log.push(finishedLine(input, at, outcome));
  groupRun.durationMs += timeOf(input) ?? 0;
  groupRun.finished.push(input);
  run.done += 1;
  if (run.current === input) {
    run.current = null;
    run.step = null;
  }
}

async function runLeaf(run, leaf, input, prober, writer) {
  const lang = language();
  const clock = performance.now();
  const mark = input.log.length;
  let heard = null;
  if (run.current !== input) run.started = clock;
  run.current = input;
  run.step = null;
  leaf.state = 'running';
  leaf.error = null;
  leaf.result = null;
  changed();

  const settle = (outcome) => {
    const { info } = outcome;
    const outputs = [];
    const path = outputPath(leaf);
    const add = (blob, at, embedded) =>
      outputs.push({ path: at, blob, size: blob.size, sha256: null, embedded, saved: null, saveFailed: null, refused: false });
    if (outcome.image) add(outcome.image, path, false);
    if (outcome.embedded) add(outcome.embedded, embeddedMetadataPath(path), true);
    leaf.result = {
      info,
      lang,
      // The job that gave the outcome: `pe`, `so`, `metadata`, or `null`.
      op: outcome.op ?? null,
      durationMs: performance.now() - clock,
      retried: false,
      companionUsed: info.companion === true,
      companionSize: null,
      companionSha256: null,
      inputSha256: null,
      outputs,
    };
    leaf.state = stateOf(info);
    // The engine's own lines, with their details, replace the ones heard
    // while it ran. Its clock started when its first step did.
    const lines = info.log ?? [];
    const first = lines.find((line) => line.step !== undefined)?.ms ?? 0;
    const last = lines.reduce((ms, line) => line.ms ?? ms, 0);
    input.log.length = mark;
    input.log.push(...engineLines(info, heard === null ? Date.now() - last : heard - first, lang));
    if (outcome.moduleBytes) contextOf(leaf).add(outcome.moduleBytes);
    run.step = null;
    changed();
  };
  const on = {
    step: (step) => {
      const at = Date.now();
      heard ??= at;
      run.step = step;
      input.log.push({
        at,
        level: 'step',
        type: 'step',
        i: step.i ?? null,
        of: step.of ?? null,
        key: step.key ?? null,
        title: step.title,
        lang,
      });
      changed();
    },
    retry: () => {
      input.log.length = mark;
      heard = null;
      run.step = null;
    },
    // The outcome is shown as soon as it is known; its digests follow.
    result: settle,
  };

  try {
    const done = await attempt(leaf, lang, on, prober);
    if (!leaf.result) settle(done.outcome);
    const result = leaf.result;
    result.retried = done.retried === true;
    result.companionSize = result.companionUsed ? (done.companion?.size ?? null) : null;
    const identity = done.outcome.identity;
    if (identity) {
      result.inputSha256 = identity.input;
      result.companionSha256 = identity.companion;
      for (const output of result.outputs) {
        output.sha256 = output.embedded ? identity.embedded : identity.image;
      }
    }
    if (writer) await writer.save(leaf);
  } catch (error) {
    // Once the outcome is known, a later failure costs only the digests.
    if (!leaf.result) {
      leaf.state = 'failed';
      const memory = error instanceof EngineStopped || /not enough memory/i.test(error?.message ?? '');
      leaf.error =
        error?.page ??
        pageError(memory ? 'web.engine_stopped' : 'web.read_failed', null, error?.message ?? error);
    }
  }
  if (!leaf.isEntry) leaf.durationMs = leaf.result?.durationMs ?? performance.now() - clock;
  run.step = null;
  changed();
}

/**
 * Run `items`, one job at a time. Every input is run again, whatever its last
 * run found. Resolves when the run has ended.
 */
export async function startRun(items) {
  if (state.run || state.saving || state.scans.length || items.length === 0) return;
  const writer = writerForOutput();
  const plan = schedule(items);
  const left = new Map(items.map((item) => [item, leavesOf(item).length]));
  const run = {
    total: items.length,
    done: 0,
    current: null,
    step: null,
    started: performance.now(),
    stopping: false,
    /** The input a stop lets finish. */
    keep: null,
    begun: new Set(),
    groups: new Map(),
  };
  const at = Date.now();
  for (const item of items) {
    // An earlier result stands until the input is reached.
    item.prior = isDone(item) ? item.state : null;
    item.state = 'queued';
    let groupRun = run.groups.get(item.group);
    if (!groupRun) {
      groupRun = { inputs: 0, index: 0, durationMs: 0, running: true, log: [], finished: [] };
      run.groups.set(item.group, groupRun);
      item.group.lastRun = groupRun;
    }
    groupRun.inputs += 1;
  }
  for (const [group, groupRun] of run.groups) {
    groupRun.log.push({ at, level: 'info', type: 'run-started', n: groupRun.inputs });
    // A run of a whole folder reports what the folder's scan found.
    if (group.kind === 'folder' && groupRun.inputs === group.items.length) {
      groupRun.log.push({ at, level: 'info', type: 'scan', n: group.items.length, s: group.stats.skipped });
      groupRun.scanned = true;
    }
  }
  state.run = run;
  state.notice = null;
  changed();

  const prober = new Prober();
  try {
    for (const leaf of plan) {
      const input = leaf.parent ?? leaf;
      if (run.stopping && input !== run.keep) continue;
      if (!run.begun.has(input)) beginInput(run, input);
      await runLeaf(run, leaf, input, prober, writer);
      left.set(input, left.get(input) - 1);
      if (left.get(input) === 0) finishInput(run, input);
    }
  } finally {
    prober.close();
    for (const item of items) {
      if (item.state === 'queued') {
        // The run never reached it: what it was before still stands.
        item.state = item.prior ?? 'cancelled';
      } else if (item.state === 'running') {
        // Stopped part way through a package: it ends with what ran.
        finishInput(run, item);
      }
      delete item.prior;
      delete item.clock;
    }
    if (writer) await writer.finish();
    const ended = Date.now();
    for (const [group, groupRun] of run.groups) {
      const { stats } = group;
      if (groupRun.scanned && stats.walkErrors + stats.probeErrors > 0) {
        groupRun.log.push({ at: ended, level: 'warn', type: 'scan-incomplete' });
      }
      const counts = { ok: 0, suspect: 0, failed: 0, skipped: 0 };
      for (const item of groupRun.finished) if (isDone(item)) counts[item.state] += 1;
      groupRun.log.push({ at: ended, level: 'info', type: 'summary', counts });
      groupRun.running = false;
    }
    // Unstarted inputs can still have logs from an earlier run.
    if (writer) await writer.saveLog([...run.begun]);
    state.run = null;
    changed();
  }
}

/** Stop the run once the input in progress has finished. */
export function cancelRun() {
  const run = state.run;
  if (!run || run.stopping) return;
  run.stopping = true;
  run.keep = run.current;
  changed();
}
