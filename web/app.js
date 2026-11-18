// The page: adding inputs, scanning folders, and handing results back. What is
// shown is in `view.js` and `detail.js`, what is held is in `state.js`, and
// running the recoveries is in `run.js`.

import { LANGUAGES, language, loadLanguage, t } from './i18n.js';
import {
  VERSION,
  allItems,
  allOutputs,
  find,
  fullPath,
  isBusy,
  makeEntries,
  makeGroup,
  makeItem,
  onChange,
  outputBusy,
  state,
  targets,
} from './state.js';
import * as view from './view.js';
import { shownPath } from './ui.js';
import {
  DEFAULT_LIMIT_MIB,
  MIN_SIZE,
  PREFIX_SIZE,
  baseName,
  candidateKind,
  isCompanionName,
  languageFor,
  parseLimitMiB,
  sniff,
} from './model.js';
import { Prober, loadEngine } from './engine.js';
import { downloadArchive } from './output.js';
import { collect, fileListRoot, walkEntry, walkFileList } from './scan.js';
import { buildReport, reportFileName, serializeReport } from './report.js';
import { cancelRun, pageError, saveAll, startRun } from './run.js';

const $ = (id) => document.getElementById(id);
const el = {
  topbar: $('topbar'),
  main: $('main'),
  inputs: $('inputs'),
  detail: $('detail'),
  status: $('status'),
  cancel: $('cancel'),
  menu: $('menu'),
  dragover: $('dragover'),
  legal: $('legal'),
  settings: $('settings'),
  pickFiles: $('pick-files'),
  pickFolder: $('pick-folder'),
  chips: null,
  list: null,
  search: null,
  clear: null,
};

// ---------- settings that outlive the tab ----------

const STORE = { language: 'senbei.language', limit: 'senbei.limit-mib', legal: 'senbei.legal-accepted' };

function stored(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function store(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage can be off; the setting then lasts for this visit.
  }
}

let accepted = stored(STORE.legal) === '1';

// ---------- rendering ----------

const shown = new WeakMap();

function focusKey(node) {
  const { act, id } = node.dataset ?? {};
  if (act) return `[data-act="${act}"]${id ? `[data-id="${CSS.escape(id)}"]` : ''}`;
  return node.id ? `#${CSS.escape(node.id)}` : null;
}

/** Set a region's HTML when it changed, keeping the focus where it was. */
function put(node, html) {
  if (shown.get(node) === html) return false;
  const focus = node.contains(document.activeElement) ? focusKey(document.activeElement) : null;
  node.innerHTML = html;
  shown.set(node, html);
  if (focus) node.querySelector(focus)?.focus();
  return true;
}

const listed = new WeakMap();

/**
 * Set a list's rows, each `{ key, html }` with one element of HTML.
 *
 * While rows keep their places only the ones that changed are replaced, so a
 * click on a row is not lost to a run that updates another row many times a
 * second, and a long list is not rebuilt for one change.
 */
function putRows(node, rows) {
  const before = listed.get(node);
  listed.set(node, rows);
  const kept =
    before &&
    before.length <= rows.length &&
    node.childElementCount === before.length &&
    before.every((row, index) => row.key === rows[index].key);
  if (!kept) {
    put(node, rows.map((row) => row.html).join(''));
    return;
  }
  let child = node.firstElementChild;
  for (let index = 0; index < before.length; index += 1) {
    const next = child.nextElementSibling;
    if (before[index].html !== rows[index].html) {
      const focused = child === document.activeElement;
      child.insertAdjacentHTML('afterend', rows[index].html);
      const fresh = child.nextElementSibling;
      child.remove();
      if (focused) fresh.focus();
    }
    child = next;
  }
  if (rows.length > before.length) {
    node.insertAdjacentHTML('beforeend', rows.slice(before.length).map((row) => row.html).join(''));
  }
  shown.delete(node);
}

const canPickFolder = () => typeof window.showDirectoryPicker === 'function';

let frameLanguage = null;
let detailKey = null;

function render() {
  put(el.topbar, view.topbar());
  el.main.classList.toggle('blank', state.groups.length === 0);
  el.main.classList.toggle('show-detail', state.showDetail);
  if (frameLanguage !== language()) {
    frameLanguage = language();
    el.inputs.innerHTML = view.inputsFrame();
    el.chips = $('chips');
    el.list = $('list');
    el.search = $('search');
    el.clear = $('clear');
    el.search.value = state.search;
    listed.delete(el.list);
  }
  el.clear.disabled = outputBusy();
  for (const control of el.settings.querySelectorAll('#set-output, [data-act="reset"]')) {
    control.disabled = outputBusy();
  }
  put(el.chips, view.chips());
  el.chips.hidden = el.chips.childElementCount === 0;
  putRows(el.list, view.listRows());

  // A re-render of the same view keeps its scroll position.
  const key = `${state.selected}|${state.tab}`;
  const top = key === detailKey ? (el.detail.querySelector('.scroll')?.scrollTop ?? 0) : 0;
  if (put(el.detail, view.detail()) && top) {
    const body = el.detail.querySelector('.scroll');
    if (body) body.scrollTop = top;
  }
  detailKey = key;
  renderStatus();
  $('dragover-title').textContent = t('drag.title');
}

function renderStatus() {
  put(el.status, view.status());
  // The button stays in the document while the line beside it is redrawn, so
  // a click on it always lands.
  el.cancel.hidden = state.run === null;
  el.cancel.disabled = state.run?.stopping === true;
  el.cancel.textContent = t('run.cancel');
}

let scheduled = false;

/** Render once, after the changes of this turn. */
function invalidate() {
  if (scheduled) return;
  scheduled = true;
  queueMicrotask(() => {
    scheduled = false;
    render();
  });
}

onChange(invalidate);

// The clock of a running input moves between the events that redraw the page.
setInterval(() => {
  if (state.run) renderStatus();
}, 100);

// ---------- adding inputs ----------

const prober = new Prober();
let scanChain = Promise.resolve();
let packages = null;

const packageModule = () => (packages ??= import('./package.js'));

/** True for the picked-files group once it holds nothing a later file could use. */
const isSpent = (group) =>
  group.kind === 'files' && group.items.length === 0 && group.companions.size === 0 && !group.scanning;

function filesGroup() {
  let group = state.groups.find((candidate) => candidate.kind === 'files');
  if (!group) {
    group = makeGroup('files', '');
    state.groups.unshift(group);
  }
  return group;
}

/** Where a module's header starts; a companion begins with a copy of it. */
const HEADER_OFFSET = 4096;
const HEADER_PROBE = 32;

/**
 * What the `._` file beside a module is to it: `{ state, name }`, with `state`
 * one of `absent`, `spliced`, `unmatched`, `unreadable`. A companion is this
 * module's payload when it starts with the module's own `header` bytes.
 */
async function companionOf(group, path, header) {
  const name = `${baseName(path)}._`;
  const open = group.companions.get(`${path}._`);
  if (!open) return { state: 'absent', name };
  try {
    const file = await open();
    const head = new Uint8Array(await file.slice(0, HEADER_PROBE).arrayBuffer());
    const same =
      head.length === HEADER_PROBE &&
      header.length === HEADER_PROBE &&
      head.every((byte, index) => byte === header[index]);
    return { state: same ? 'spliced' : 'unmatched', name };
  } catch {
    return { state: 'unreadable', name };
  }
}

/**
 * Decide what one file is.
 *
 * Returns `{ item }` for an input to list, `{ skipped: true }` for a file that
 * was probed and is not a target, and `{}` for one too small to probe. A file
 * the user picked is always listed, and is told by what it holds whatever its
 * name; a file a folder scan found is listed only when it is a target.
 */
async function classify(group, candidate, file, explicit) {
  const item = makeItem(group, candidate, file.size);
  // A file that is no target is known by its name and size alone.
  const plain = () => {
    item.kind = null;
    item.notProtected = true;
    return explicit ? { item } : { skipped: true };
  };
  if (file.size < MIN_SIZE && !explicit) return {};

  const prefix = new Uint8Array(await file.slice(0, PREFIX_SIZE).arrayBuffer());
  const magic = sniff(prefix);
  const named = (kind) => explicit || candidate.kind === kind;

  if (magic.zip && candidate.kind === 'package') {
    // Every app package is listed; what it holds is known once it has run.
    item.kind = 'package';
    item.entries = [];
    const { inventory, UnsafeEntry } = await packageModule();
    try {
      item.container = await inventory(
        file,
        candidate.path,
        (bytes, truncated) => prober.manifest(bytes, truncated),
        { maxNestedBytes: state.limitBytes * 4 },
      );
      item.entries = makeEntries(item);
    } catch (error) {
      item.identityError = error instanceof UnsafeEntry
        ? await prober.unsafeEntry(shownPath(fullPath(item)), language())
        : pageError('web.read_failed', null, error?.message ?? error);
    }
    return { item };
  }
  if (magic.metadata && named('metadata')) {
    item.kind = 'metadata';
    item.pre = (await prober.prefix(prefix)).profile;
    item.metadataVersion = prefix.length >= 8 ? new DataView(prefix.buffer).getUint32(4, true) : null;
    return { item };
  }
  if (magic.mz && named('pe')) {
    const reply = await prober.prefix(prefix);
    item.kind = 'pe';
    item.pre = reply.profile;
    item.peKind = reply.kind;
    item.header = prefix.slice(HEADER_OFFSET, HEADER_OFFSET + HEADER_PROBE);
    item.companion = await companionOf(group, candidate.path, item.header);
    if (reply.kind) return { item };
    // A module without the protection keeps what its header says it is.
    item.notProtected = true;
    return explicit ? { item } : { skipped: true };
  }
  if (magic.elf64Aarch64 && named('so')) {
    item.kind = 'so';
    // A library over the limit is not read here; it stays a candidate.
    if (file.size > state.limitBytes) return { item };
    item.pre = await prober.library(file, file.size);
    if (item.pre?.recognition !== 'not_recognized') return { item };
    item.pre = null;
  }
  return plain();
}

/** The identity of a picked file, by which the same file is not listed twice. */
const fileKey = (file) => `${file.name}|${file.size}|${file.lastModified}`;

async function runScan(scan, candidates, source) {
  const { group } = scan;
  const { signal } = scan.controller;
  let list = candidates;
  if (!list) {
    const walk = source.walk(() => {
      group.stats.walkErrors += 1;
    });
    const found = await collect(walk, signal);
    list = found.candidates;
    for (const [path, open] of found.companions) group.companions.set(path, open);
  }
  let first = true;
  for (const candidate of list) {
    if (signal.aborted) return;
    let item = null;
    try {
      const file = await candidate.open();
      const outcome = await classify(group, candidate, file, source.explicit);
      if (signal.aborted) return;
      item = outcome.item ?? null;
      if (outcome.skipped) group.stats.skipped += 1;
    } catch (error) {
      if (signal.aborted) return;
      if (source.explicit) {
        // A picked file that cannot be examined is still listed, with why.
        item = makeItem(group, candidate, 0);
        item.identityError = pageError('web.read_failed', null, error?.message ?? error);
      } else {
        group.stats.probeErrors += 1;
      }
    }
    if (item) {
      item.fileKey = candidate.key ?? null;
      group.items.push(item);
      group.found += 1;
      // Added files show the first of them, unless an input is already shown.
      if (first && source.explicit && !find(state.selected)?.item) {
        state.selected = item.id;
        state.multi = [];
      }
      first = false;
    }
    invalidate();
  }
}

function startScan(group, candidates, source) {
  const scan = { group, controller: new AbortController() };
  state.scans.push(scan);
  group.scanning = true;
  if (!source.explicit) {
    // An added folder is shown at once, while its scan runs.
    state.selected = group.id;
    state.multi = [];
  }
  state.notice = null;
  invalidate();
  scanChain = scanChain
    .then(() => runScan(scan, candidates, source))
    .catch((error) => console.error(error))
    .then(() => {
      state.scans = state.scans.filter((other) => other !== scan);
      group.scanning = state.scans.some((other) => other.group === group);
      // The probe worker is not kept between scans.
      if (state.scans.length === 0) prober.close();
      if (isSpent(group)) dropGroup(group);
      invalidate();
    });
}

/** Look again at the companions of modules that were added before them. */
async function repair(group, names) {
  for (const item of group.items) {
    if (item.kind !== 'pe' || !item.header || !names.has(`${item.relPath}._`)) continue;
    item.companion = await companionOf(group, item.relPath, item.header);
  }
  invalidate();
}

function addFiles(files) {
  if (files.length === 0) return;
  const group = filesGroup();
  const known = new Set(group.items.map((item) => item.fileKey));
  const candidates = [];
  const companions = new Set();
  for (const file of files) {
    const open = async () => file;
    if (isCompanionName(file.name)) {
      group.companions.set(file.name, open);
      companions.add(file.name);
    } else if (!known.has(fileKey(file))) {
      known.add(fileKey(file));
      candidates.push({ path: file.name, kind: candidateKind(file.name), open, key: fileKey(file) });
    }
  }
  if (companions.size) repair(group, companions);
  startScan(group, candidates, { explicit: true });
}

function addFolder(name, walk, handle = null) {
  const group = makeGroup('folder', name || '/', handle);
  state.groups.push(group);
  startScan(group, null, { explicit: false, walk });
}

/** The group of a folder that was dropped before, when the browser can tell. */
async function sameFolder(handle) {
  for (const group of state.groups) {
    if (group.handle && (await group.handle.isSameEntry(handle).catch(() => false))) return group;
  }
  return null;
}

/** What a drop holds. Called inside the drop handler, where the items are live. */
function takeDrop(transfer) {
  return [...(transfer?.items ?? [])]
    .filter((item) => item.kind === 'file')
    .map((item) => ({
      handle: item.getAsFileSystemHandle ? item.getAsFileSystemHandle().catch(() => null) : null,
      entry: item.webkitGetAsEntry?.() ?? null,
      file: item.getAsFile(),
    }));
}

async function addDropped(taken) {
  const files = [];
  for (const { handle, entry, file } of taken) {
    if (entry?.isDirectory) {
      // The entry lists the folder: see `scan.js`. The handle, where the
      // browser gives one, only tells whether two folders are the same.
      const dropped = handle ? await handle : null;
      const directory = dropped?.kind === 'directory' ? dropped : null;
      const again = directory ? await sameFolder(directory) : null;
      if (again) select(again.id);
      else addFolder(entry.name, (onError) => walkEntry(entry, onError), directory);
    } else if (file) {
      files.push(file);
    }
  }
  addFiles(files);
}

// ---------- removing inputs ----------

function dropGroup(group) {
  for (const scan of state.scans) if (scan.group === group) scan.controller.abort();
  state.groups = state.groups.filter((other) => other !== group);
}

/** Drop what the selection held of rows that are gone. */
function forget() {
  state.multi = state.multi.filter((id) => find(id));
  if (state.selected && !find(state.selected)) {
    state.selected = null;
    state.showDetail = false;
  }
}

/** Remove the group, or the input, with `id`. An entry stands for its package. */
function remove(id) {
  const current = id && find(id);
  if (!current || outputBusy()) return;
  if (current.group) {
    dropGroup(current.group);
  } else {
    const item = current.item.parent ?? current.item;
    const group = item.group;
    group.items = group.items.filter((other) => other !== item);
    if (isSpent(group)) dropGroup(group);
  }
  forget();
  invalidate();
}

function clearAll() {
  if (outputBusy()) return;
  for (const group of [...state.groups]) dropGroup(group);
  state.contexts.clear();
  state.unfolded.clear();
  state.selected = null;
  state.multi = [];
  state.showDetail = false;
  state.filter = 'all';
  state.search = '';
  if (el.search) el.search.value = '';
  state.tab = 'overview';
  state.notice = null;
  invalidate();
}

// ---------- handing results back ----------

function download(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

async function downloadAll() {
  const archive = await downloadArchive(allItems());
  if (archive) download(archive.blob, archive.name);
}

/** The inputs an export covers and the name it goes by: the selection's. */
function exportScope() {
  const current = state.selected && find(state.selected);
  const item = current?.item ? (current.item.parent ?? current.item) : null;
  const items = item ? [item] : current?.group ? current.group.items : allItems();
  const name = item ? item.name : current?.group?.kind === 'folder' ? current.group.name : null;
  return { items, name };
}

function exportReport() {
  const { items, name } = exportScope();
  const generatedAt = new Date().toISOString();
  const report = buildReport(items, { generatedAt, version: VERSION, limitBytes: state.limitBytes });
  download(
    new Blob([serializeReport(report)], { type: 'application/json' }),
    reportFileName(name, generatedAt),
  );
}

async function exportText() {
  const { items, name } = exportScope();
  const { reportText } = await import('./text.js');
  download(
    new Blob([reportText(items)], { type: 'text/plain;charset=utf-8' }),
    reportFileName(name, new Date().toISOString(), 'txt'),
  );
}

/** Ask for the folder outputs are written to. Resolves to whether one was chosen. */
async function chooseOutputFolder() {
  if (outputBusy()) return false;
  let dir;
  try {
    dir = await window.showDirectoryPicker({ mode: 'readwrite' });
  } catch {
    return false;
  }
  if (outputBusy()) return false;
  state.out = { mode: 'folder', dir };
  invalidate();
  // Results that are already here are written too, wherever they went before.
  await saveAll(allItems(), true);
  return true;
}

function setOutput(mode) {
  if (outputBusy()) return;
  state.out = { ...state.out, mode };
  invalidate();
  if (mode === 'folder') saveAll(allItems(), false);
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return;
  }
  if (!button) return;
  const label = button.textContent;
  button.textContent = '✓';
  setTimeout(() => {
    if (button.isConnected) button.textContent = label;
  }, 900);
}

// ---------- menus and dialogs ----------

function closeMenu() {
  el.menu.innerHTML = '';
}

function openMenu(html, x, y) {
  el.menu.innerHTML = `<div class="ctx" role="menu">${html}</div>`;
  const box = el.menu.firstElementChild;
  const { width, height } = box.getBoundingClientRect();
  box.style.left = `${Math.max(8, Math.min(x, window.innerWidth - width - 8))}px`;
  box.style.top = `${Math.max(8, Math.min(y, window.innerHeight - height - 8))}px`;
  box.querySelector('button:not(:disabled)')?.focus();
}

function showDialog(dialog) {
  if (dialog.open) return;
  dialog.classList.add('opening');
  dialog.showModal();
  // Commit the transparent starting state after the dialog enters the top
  // layer. This also works in browsers without CSS @starting-style.
  dialog.getBoundingClientRect();
  dialog.classList.remove('opening');
}

function openLegal() {
  el.legal.innerHTML = view.legal(accepted);
  showDialog(el.legal);
}

function drawSettings() {
  el.settings.innerHTML = view.settings(canPickFolder());
}

function openSettings() {
  drawSettings();
  showDialog(el.settings);
}

/** Keep the backdrop modal until its fade finishes, then let the browser restore focus. */
async function closeDialog(dialog) {
  if (!dialog.open || dialog.inert) return false;
  dialog.inert = true;
  const fade = dialog.getAnimations().find((animation) => animation.transitionProperty === 'opacity');
  if (fade) await fade.finished.catch(() => {});
  dialog.close();
  dialog.inert = false;
  return true;
}

async function setLanguage(tag, remember = true) {
  await loadLanguage(tag);
  if (remember) store(STORE.language, language());
  document.title = 'Senbei';
  if (el.legal.open) el.legal.innerHTML = view.legal(accepted);
  if (el.settings.open) drawSettings();
  closeMenu();
  render();
}

/**
 * Show the row with `id`. With `toggle`, as with Ctrl or Cmd held, the row
 * joins or leaves the rows a run takes; a group is never one of those.
 */
function select(id, toggle = false) {
  const current = find(id);
  if (!current) return;
  if (toggle && !current.group) {
    const shownNow = state.selected;
    if (shownNow && !state.multi.includes(shownNow) && find(shownNow)?.item) state.multi.push(shownNow);
    const at = state.multi.indexOf(id);
    if (at >= 0) state.multi.splice(at, 1);
    else state.multi.push(id);
  } else {
    state.multi = [];
  }
  state.selected = id;
  state.showDetail = true;
  invalidate();
}

/** True while inputs cannot be run or removed. */
const busy = () => outputBusy() || state.scans.length > 0;

const actions = {
  'add-files': () => el.pickFiles.click(),
  'add-folder': () => el.pickFolder.click(),
  run: () => startRun(targets()),
  'run-item': (node) => {
    closeMenu();
    const item = find(node.dataset.id)?.item;
    if (item) startRun([item.parent ?? item]);
  },
  cancel: cancelRun,
  select: (node, event) => select(node.dataset.id, el.list.contains(node) && (event.ctrlKey || event.metaKey)),
  toggle: (node) => {
    const id = node.dataset.id;
    if (!state.collapsed.delete(id)) state.collapsed.add(id);
    invalidate();
  },
  'show-entries': (node) => {
    state.multi = [];
    state.selected = node.dataset.id;
    state.tab = 'entries';
    state.showNonTargets = true;
    state.showDetail = true;
    invalidate();
  },
  filter: (node) => {
    state.filter = node.dataset.filter;
    invalidate();
  },
  tab: (node) => {
    state.tab = node.dataset.tab;
    invalidate();
  },
  loglevel: (node) => {
    state.logLevel = node.dataset.level;
    invalidate();
  },
  back: () => {
    state.showDetail = false;
    invalidate();
  },
  copy: (node) => copyText(node.dataset.text, node),
  'copy-log': (node) => copyText(view.logText(), node),
  'copy-path': (node) => {
    closeMenu();
    const item = find(node.dataset.id)?.item;
    if (item) copyText(shownPath(fullPath(item)));
  },
  download: (node) => {
    const output = find(node.dataset.id)?.item?.result?.outputs[Number(node.dataset.n)];
    if (output) download(output.blob, baseName(output.path));
  },
  'download-all': () => downloadAll(),
  export: exportReport,
  'export-text': () => exportText(),
  remove: (node) => {
    closeMenu();
    remove(node.dataset.id);
  },
  clear: clearAll,
  'out-menu': (node) => {
    const box = node.getBoundingClientRect();
    openMenu(view.outMenu(canPickFolder()), box.right - 330, box.bottom + 4);
  },
  'out-downloads': () => {
    closeMenu();
    setOutput('downloads');
  },
  'out-folder': () => {
    closeMenu();
    setOutput('folder');
  },
  'out-choose': () => {
    closeMenu();
    chooseOutputFolder();
  },
  settings: openSettings,
  'settings-tab': (node) => {
    state.settingsTab = node.dataset.tab;
    drawSettings();
  },
  'close-settings': () => closeDialog(el.settings),
  'show-legal': async () => {
    if (await closeDialog(el.settings)) openLegal();
  },
  'close-legal': () => closeDialog(el.legal),
  accept: () => {
    accepted = true;
    store(STORE.legal, '1');
    closeDialog(el.legal);
    warmUp();
  },
  reset: async () => {
    if (outputBusy()) return;
    store(STORE.language, null);
    store(STORE.limit, null);
    state.limitBytes = DEFAULT_LIMIT_MIB * 1024 * 1024;
    state.out = { mode: 'downloads', dir: null };
    await setLanguage(languageFor(navigator.languages), false);
  },
};

const changes = {
  language: (node) => setLanguage(node.value),
  limit: (node) => {
    state.limitBytes = parseLimitMiB(node.value, state.limitBytes);
    store(STORE.limit, String(Math.round(state.limitBytes / (1024 * 1024))));
    drawSettings();
  },
  output: async (node) => {
    if (node.value === 'choose') await chooseOutputFolder();
    else setOutput(node.value);
    if (el.settings.open) drawSettings();
  },
  'non-targets': (node) => {
    state.showNonTargets = node.checked;
    invalidate();
  },
};

// ---------- events ----------

document.addEventListener('click', (event) => {
  // A folded part stays as it was left when its view is drawn again: the
  // click is about to open or close it.
  const folded = event.target.closest?.('details[data-fold] > summary')?.parentElement;
  if (folded?.open) state.unfolded.delete(folded.dataset.fold);
  else if (folded) state.unfolded.add(folded.dataset.fold);
  const node = event.target.closest?.('[data-act]');
  if (!el.menu.contains(event.target) && node?.dataset.act !== 'out-menu') closeMenu();
  if (!node || node.disabled) return;
  actions[node.dataset.act]?.(node, event);
});

document.addEventListener('change', (event) => {
  const node = event.target.closest?.('[data-change]');
  if (node) changes[node.dataset.change]?.(node);
});

document.addEventListener('input', (event) => {
  if (event.target.id !== 'search') return;
  state.search = event.target.value;
  invalidate();
});

const typing = (event) => Boolean(event.target.closest?.('input, select, textarea'));

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    closeMenu();
    return;
  }
  if (!accepted || el.legal.open || el.settings.open) return;
  if ((event.ctrlKey || event.metaKey) && !event.altKey && event.key.toLowerCase() === 'o') {
    event.preventDefault();
    el.pickFiles.click();
    return;
  }
  if (event.key === 'Delete' && !typing(event) && !busy()) {
    // The key removes an input, never a whole group.
    const item = state.selected && find(state.selected)?.item;
    if (item && !item.isEntry) remove(item.id);
    return;
  }
  const node = event.target.closest?.('[tabindex][data-act]');
  if (!node) return;
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    node.click();
  } else if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && el.list?.contains(node)) {
    event.preventDefault();
    const rows = [...el.list.querySelectorAll('[data-act="select"]')];
    const next = rows[rows.indexOf(node) + (event.key === 'ArrowDown' ? 1 : -1)];
    if (next) {
      next.focus();
      // Moving through the list selects without leaving it on a narrow window.
      state.selected = next.dataset.id;
      state.multi = [];
      invalidate();
    }
  }
});

document.addEventListener('contextmenu', (event) => {
  const node = event.target.closest?.('#list [data-act="select"]');
  if (!node) return;
  event.preventDefault();
  const id = node.dataset.id;
  const current = find(id);
  if (!current) return;
  const item = current.item;
  const options = {
    kind: current.group ? 'group' : item.isEntry ? 'entry' : 'item',
    runnable: Boolean(item) && (item.isEntry || !item.notProtected) && !isBusy(item.parent ?? item),
    busy: busy(),
  };
  openMenu(view.rowMenu(id, options), event.clientX, event.clientY);
});

window.addEventListener('resize', closeMenu);

el.pickFiles.addEventListener('change', () => {
  const files = [...el.pickFiles.files];
  el.pickFiles.value = '';
  addFiles(files);
});

el.pickFolder.addEventListener('change', () => {
  const files = [...el.pickFolder.files];
  el.pickFolder.value = '';
  if (files.length === 0) return;
  // A browser that cannot pick a folder hands over plain files instead.
  if (files.some((file) => file.webkitRelativePath)) addFolder(fileListRoot(files), () => walkFileList(files));
  else addFiles(files);
});

// Route Escape through the fade; the first-use notice still requires acceptance.
for (const dialog of [el.settings, el.legal]) {
  dialog.addEventListener('cancel', (event) => {
    event.preventDefault();
    if (dialog !== el.legal || accepted) closeDialog(dialog);
  });
}

let dragDepth = 0;
const hasFiles = (event) => [...(event.dataTransfer?.types ?? [])].includes('Files');
const canDrop = () => accepted && !el.settings.open && !el.legal.open;

window.addEventListener('dragenter', (event) => {
  if (!canDrop() || !hasFiles(event)) return;
  event.preventDefault();
  dragDepth += 1;
  el.dragover.hidden = false;
});
window.addEventListener('dragover', (event) => {
  if (canDrop() && hasFiles(event)) event.preventDefault();
});
window.addEventListener('dragleave', () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) el.dragover.hidden = true;
});
window.addEventListener('drop', (event) => {
  dragDepth = 0;
  el.dragover.hidden = true;
  if (!hasFiles(event)) return;
  event.preventDefault();
  if (canDrop()) addDropped(takeDrop(event.dataTransfer));
});

window.addEventListener('beforeunload', (event) => {
  // Results live in this tab only.
  if (state.run || allOutputs().length) {
    event.preventDefault();
    event.returnValue = '';
  }
});

// ---------- start ----------

/** Fetch and compile the engine while the page is idle, before it is needed. */
function warmUp() {
  const start = () => loadEngine().catch(() => {});
  if (window.requestIdleCallback) requestIdleCallback(start, { timeout: 3000 });
  else setTimeout(start, 300);
}

async function start() {
  state.limitBytes = parseLimitMiB(stored(STORE.limit));
  const wanted = stored(STORE.language);
  const known = LANGUAGES.some(([code]) => code === wanted);
  await setLanguage(known ? wanted : languageFor(navigator.languages), false);
  if (accepted) warmUp();
  else openLegal();
}

start();
