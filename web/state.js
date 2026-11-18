// What the page holds, and the questions the views ask of it.

import { DEFAULT_LIMIT_MIB, baseName, candidateKind, dirName } from './model.js';

export const VERSION = '1.4.0';

export const state = {
  /** Added inputs: one group for loose files, one for each folder. */
  groups: [],
  /** Id of the group, input, or package entry the detail pane shows. */
  selected: null,
  /** Ids picked with Ctrl or Cmd; when not empty, a run takes these. */
  multi: [],
  filter: 'all',
  search: '',
  tab: 'overview',
  logLevel: 'all',
  collapsed: new Set(),
  /** Keys of the folded parts of the detail pane that were opened. */
  unfolded: new Set(),
  /** The entries tab also lists entries that are not targets. */
  showNonTargets: false,
  /**
   * The run in progress: `{ total, done, current, step, started, stopping,
   * keep, begun, groups }`. `current` is the input being processed and `step`
   * the engine step it is at.
   */
  run: null,
  /** Folder and file scans in progress, each `{ group, controller }`. */
  scans: [],
  /** Where outputs go: kept for download, or also written into `dir`. */
  out: { mode: 'downloads', dir: null },
  /** Outputs from an earlier run are being written to the chosen folder. */
  saving: false,
  limitBytes: DEFAULT_LIMIT_MIB * 1024 * 1024,
  settingsTab: 'general',
  /** On a narrow window, whether the detail pane is the one shown. */
  showDetail: false,
  /** Module `0x0C` images by application. */
  contexts: new Map(),
  /** A line the status bar shows until the next action. */
  notice: null,
};

let nextId = 1;
export const newId = (prefix) => `${prefix}${nextId++}`;

let listener = () => {};

/** Call `callback` whenever the state changed and the page must redraw. */
export const onChange = (callback) => {
  listener = callback;
};

/** Say that the state changed. */
export const changed = () => listener();

/** Show a catalog message in the status bar, or clear it with no key. */
export function notify(key, vars, tone) {
  state.notice = key ? { key, vars, tone } : null;
  changed();
}

// ---------- records ----------

/** A group of inputs: the loose files, or one folder. */
export function makeGroup(kind, name, handle = null) {
  return {
    id: newId('g'),
    kind,
    name,
    handle,
    items: [],
    scanning: false,
    found: 0,
    stats: { skipped: 0, walkErrors: 0, probeErrors: 0 },
    /** Companion payloads by path, each a function that opens the file. */
    companions: new Map(),
    /** The last run over this group: `{ inputs, index, durationMs, running, log }`. */
    lastRun: null,
  };
}

/**
 * One input. `state` is `pending`, `queued`, `running`, `cancelled`, or one of
 * the outcomes `ok`, `suspect`, `failed`, `skipped`.
 */
export function makeItem(group, candidate, size) {
  return {
    id: newId('i'),
    group,
    name: baseName(candidate.path),
    relPath: candidate.path,
    open: candidate.open,
    size,
    kind: 'other',
    /** The pre-recovery profile, when a probe produced one. */
    pre: null,
    peKind: null,
    metadataVersion: null,
    notProtected: false,
    state: 'pending',
    result: null,
    error: null,
    /** The log and the duration of the last run. */
    log: null,
    durationMs: null,
    container: null,
    entries: null,
  };
}

/** The entries of a package that a run probes. */
export function makeEntries(item) {
  return item.container.archives.flatMap((archive) =>
    archive.targets.map((target) => ({
      id: newId('e'),
      isEntry: true,
      parent: item,
      group: item.group,
      archive,
      target,
      name: baseName(target.path),
      relPath: archive.label ? `${archive.label}/${target.path}` : target.path,
      kind: candidateKind(target.path),
      size: target.entry.size,
      pre: null,
      metadataVersion: null,
      state: 'pending',
      result: null,
      error: null,
    })),
  );
}

// ---------- questions ----------

export const allItems = () => state.groups.flatMap((group) => group.items);

/** The current batch owns its destination until its last write. */
export const outputBusy = () => state.run !== null || state.saving;

/** The group, input, or entry with `id`. */
export function find(id) {
  for (const group of state.groups) {
    if (group.id === id) return { group };
    for (const item of group.items) {
      if (item.id === id) return { item };
      const entry = item.entries?.find((candidate) => candidate.id === id);
      if (entry) return { item: entry };
    }
  }
  return null;
}

/** True once an input has the outcome of a run. */
export const isDone = (item) => ['ok', 'suspect', 'failed', 'skipped'].includes(item.state);

/** True while an input waits for a run that was started, or is in it. */
export const isBusy = (item) => item.state === 'queued' || item.state === 'running';

/** True when anything is selected, so a run covers the selection. */
export const hasSelection = () => state.multi.length > 0 || state.selected !== null;

/**
 * The inputs a run covers: the picked rows, else the selection, else every
 * input. A group stands for all of its inputs and an entry for its package.
 */
export function targets() {
  const picked = state.multi.length ? state.multi : state.selected ? [state.selected] : null;
  if (!picked) return allItems();
  const chosen = new Set();
  for (const id of picked) {
    const found = find(id);
    if (found?.group) for (const item of found.group.items) chosen.add(item);
    else if (found?.item) chosen.add(found.item.parent ?? found.item);
  }
  // Group order, whatever order the rows were picked in.
  return allItems().filter((item) => chosen.has(item));
}

/**
 * The path a row stands for: the folder's name, then the path inside it. An
 * entry is its package, then its path inside the archive that holds it.
 */
export function fullPath(item) {
  if (item.isEntry) return `${fullPath(item.parent)} › ${item.target.path}`;
  return item.group?.kind === 'folder' ? `${item.group.name}/${item.relPath}` : item.relPath;
}

/** How long the last run of an input took, in milliseconds. */
export const timeOf = (item) => item.durationMs ?? item.result?.durationMs ?? null;

const TONE = { ok: 'ok', suspect: 'warn', failed: 'err', skipped: 'skip' };

/** How a finished input reads: `{ tone, key }`, `key` being a catalog key. */
export function outcomeOf(item) {
  const tone = TONE[item.state] ?? 'skip';
  if (item.isEntry) {
    const key = item.state === 'failed'
      ? 'entryStatus.error'
      : isNonTarget(item)
        ? 'entryStatus.not_target'
        : item.state === 'skipped'
          ? 'entryStatus.unchanged'
          : 'entryStatus.restored';
    // An entry reads as restored, failed, or left alone; it has no suspect tone.
    return { tone: item.state === 'ok' || item.state === 'suspect' ? 'ok' : tone, key };
  }
  const key = { ok: 'status.ok', suspect: 'status.suspect', failed: 'status.error' }[item.state]
    ?? 'status.skipped';
  return { tone, key };
}

/** True for a package entry that turned out not to be a target. */
export const isNonTarget = (entry) => entry.result?.info?.status === 'not_protected';

/** The entries of a package a run acted on: restored, unchanged, or failed. */
export const targetEntries = (item) =>
  (item.entries ?? []).filter((entry) => isDone(entry) && !isNonTarget(entry));

/** Counts of finished inputs by outcome. */
export function counts(items) {
  const result = { all: items.length, ok: 0, suspect: 0, failed: 0, skipped: 0 };
  for (const item of items) if (isDone(item)) result[item.state] += 1;
  return result;
}

/** Every output kept in this tab, with the input it came from. */
export function allOutputs(items = allItems()) {
  const outputs = [];
  for (const item of items) {
    for (const source of [item, ...(item.entries ?? [])]) {
      for (const output of source.result?.outputs ?? []) outputs.push({ item: source, output });
    }
  }
  return outputs;
}

/** An output's path in the downloaded archive: under its folder's name. */
export function archivePath(item, output) {
  const group = item.group;
  return group.kind === 'folder' ? `${group.name}/${output.path}` : output.path;
}

/** The application context of a package archive's entries. */
export function archiveAppKey(item, archive) {
  if (!archive.identity) return `pkg:${item.id}:${archive.label}`;
  const set = item.container.kind === 'apk' ? `dir:${dirName(item.relPath)}` : `bundle:${item.id}`;
  return `pkg:${item.group.id}:${set}:${archive.identity[0]}:${archive.identity[1]}`;
}
