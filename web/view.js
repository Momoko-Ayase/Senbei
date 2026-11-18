// The frame of the page: the top bar, the inputs pane, the status bar, the
// menus, and the dialogs. Every function returns HTML for one region, from the
// state alone; `app.js` puts it in the document and handles the events. The
// detail pane is in `detail.js`.

import { LANGUAGES, language, show, t } from './i18n.js';
import {
  VERSION,
  allItems,
  allOutputs,
  counts,
  fullPath,
  hasSelection,
  isDone,
  isNonTarget,
  outputBusy,
  state,
  targets,
} from './state.js';
import { MAX_LIMIT_MIB, MIN_LIMIT_MIB, formatClock } from './model.js';
import { dot, esc, groupName, modeLabel, rowState, shownPath, stepText, tag, typeTag } from './ui.js';

export { esc, groupName } from './ui.js';
export { detail, logText } from './detail.js';

// ---------- inputs ----------

const selectable = (id, selected) =>
  `data-act="select" data-id="${id}" tabindex="0" role="option" aria-selected="${selected}"`;

const isSelected = (id) => state.selected === id || state.multi.includes(id);

const caret = (id, open) =>
  `<span class="caret" data-act="toggle" data-id="${id}">${open ? '▼' : '▶'}</span>`;

function rowHtml(item, withCaret) {
  const row = rowState(item);
  const selected = isSelected(item.id);
  const open = !state.collapsed.has(item.id);
  const label = `<span class="st${row.tone ? ` c-${row.tone}` : ''}">${esc(row.label)}</span>`;
  const extra = row.extra ? `<span>·</span><span class="ex">${esc(row.extra)}</span>` : '';
  const time = row.time ? `<span class="time">${esc(row.time)}</span>` : '';
  return (
    `<div class="row${item.isEntry ? ' nested' : ''}${selected ? ' selected' : ''}" ${selectable(item.id, selected)} title="${esc(shownPath(fullPath(item)))}">` +
    `${withCaret ? caret(item.id, open) : ''}${dot(row.dot)}` +
    `<span class="name">${esc(item.name)}</span>${tag(typeTag(item))}` +
    `<span class="meta">${label}${extra}<span class="spacer"></span>${time}</span></div>`
  );
}

const matches = (name, needle) => needle === '' || name.toLowerCase().includes(needle);

/** An input's rows: its own, then the entries of a package under it. */
function itemRows(item, needle) {
  const entries = (item.entries ?? []).filter(isDone);
  // A search lists every entry it matches; otherwise only the targets show.
  const shown = entries.filter((entry) => (needle ? matches(entry.name, needle) : !isNonTarget(entry)));
  const others = needle ? 0 : entries.filter(isNonTarget).length;
  const rows = [{ key: item.id, html: rowHtml(item, shown.length > 0 || others > 0) }];
  if (state.collapsed.has(item.id)) return rows;
  for (const entry of shown) rows.push({ key: entry.id, html: rowHtml(entry, false) });
  if (others) {
    rows.push({
      key: `others:${item.id}`,
      html:
        `<div class="row others" data-act="show-entries" data-id="${item.id}" tabindex="0" role="button">` +
        `${esc(t('EntriesOthers', { n: others }))}</div>`,
    });
  }
  return rows;
}

function groupHead(group, shown) {
  const selected = state.selected === group.id;
  const folder = group.kind === 'folder';
  const path = folder ? shownPath(`${group.name}/`) : '';
  let sub = '';
  if (group.scanning) {
    sub = `<span class="gsub c-info">${esc(t('GroupScanning', { n: group.found }))}</span>`;
  } else if (folder) {
    sub = `<span class="gsub">${esc(group.lastRun ? `${modeLabel()} · ${path}` : path)}</span>`;
  }
  return (
    `<div class="group-h${selected ? ' selected' : ''}" ${selectable(group.id, selected)}${path ? ` title="${esc(path)}"` : ''}>` +
    `${caret(group.id, !state.collapsed.has(group.id))}` +
    `<span class="gname">${esc(groupName(group))}</span>` +
    `<span class="gcount">${group.scanning ? group.found : shown}</span>${sub}</div>`
  );
}

/** The parts of the inputs pane that stay put while its list changes. */
export function inputsFrame() {
  const search = esc(t('inputs.search'));
  return (
    `<div class="inputs-head"><div class="title"><span>${esc(t('inputs.title'))}</span>` +
    `<button class="ghost" id="clear" data-act="clear">${esc(t('inputs.clear'))}</button></div>` +
    `<div class="chips" id="chips"></div>` +
    `<input type="search" class="search" id="search" placeholder="${search}" aria-label="${search}"></div>` +
    `<div class="list" id="list" role="listbox" aria-multiselectable="true" aria-label="${esc(t('inputs.title'))}"></div>`
  );
}

/** The filter chips. There are none until an input has a result. */
export function chips() {
  const items = allItems();
  if (!items.some(isDone)) return '';
  const count = counts(items);
  return ['all', 'ok', 'suspect', 'failed', 'skipped']
    .map((key) => {
      const on = state.filter === key;
      return (
        `<button class="chip${on ? ' on' : ''}" data-act="filter" data-filter="${key}" aria-pressed="${on}">` +
        `${esc(t(`filter.${key}`))}<span class="n">${count[key]}</span></button>`
      );
    })
    .join('');
}

/**
 * The rows of the inputs list, each `{ key, html }` with one element of HTML,
 * so the page can replace only the rows that changed.
 */
export function listRows() {
  const needle = state.search.trim().toLowerCase();
  const filtering = state.filter !== 'all' || needle !== '';
  // A filter chip hides the inputs that finished some other way; an input
  // that has not run stays.
  const visible = (item) =>
    !(state.filter !== 'all' && isDone(item) && item.state !== state.filter) &&
    (matches(item.name, needle) || (item.entries ?? []).some((entry) => matches(entry.name, needle)));
  const rows = [];
  for (const group of state.groups) {
    const items = group.items.filter(visible);
    if (filtering && items.length === 0 && !group.scanning) continue;
    rows.push({ key: group.id, html: groupHead(group, items.length) });
    if (!state.collapsed.has(group.id)) for (const item of items) rows.push(...itemRows(item, needle));
  }
  if (rows.length === 0) rows.push({ key: 'none', html: `<p class="faint">${esc(t('inputs.none'))}</p>` });
  return rows;
}

/** The inputs list as one piece of HTML. */
export const list = () => listRows().map((row) => row.html).join('');

// ---------- top bar and status bar ----------

/** Where outputs go, as the output chip and the settings name it. */
const outputLabel = () =>
  state.out.mode === 'folder' ? shownPath(`${state.out.dir.name}/unpack`) : t('web.out_downloads');

/** True while nothing can be run: a run or a scan is in progress. */
const busy = () => outputBusy() || state.scans.length > 0;

export function topbar() {
  const count = targets().length;
  const label = hasSelection() ? t('TbUnpackN', { n: count }) : t('tb.unpack.all');
  const idle = !busy() && count > 0;
  return (
    `<div class="brand"><img src="assets/icon-32.png" width="26" height="26" alt="">` +
    `<span class="word">Senbei</span><span class="ver">${VERSION}</span></div>` +
    `<button data-act="add-files" title="Ctrl+O">${esc(t('tb.add_files'))}</button>` +
    `<button data-act="add-folder">${esc(t('tb.add_folder'))}</button><span class="sep"></span>` +
    `<button class="primary" data-act="run" title="${esc(t('web.unpack_tip'))}"${idle ? '' : ' disabled'}><span class="ico">▶</span> ${esc(label)}</button>` +
    `<button data-act="download-all"${allOutputs().length ? '' : ' disabled'}>${esc(t('web.download_all'))}</button>` +
    `<span class="spacer"></span>` +
    `<button class="out-chip" data-act="out-menu" title="${esc(t('web.out_tip'))}" aria-haspopup="menu"${outputBusy() ? ' disabled' : ''}>` +
    `<span>${esc(t('tb.output'))}</span><b>${esc(outputLabel())}</b><span class="faint">▾</span></button>` +
    `<button class="gear" data-act="settings" title="${esc(t('tb.settings'))}" aria-label="${esc(t('tb.settings'))}">⚙</button>`
  );
}

/** The status line. The Cancel button beside it is the page's own. */
export function status() {
  const run = state.run;
  if (run) {
    const total = Math.max(run.total, run.done);
    const percent = total === 0 ? 0 : Math.round((run.done / total) * 100);
    const current = run.current
      ? `<span class="cur mono">${esc(run.current.name)}</span>` +
        `${run.step ? `<span class="step">${esc(stepText(run.step))}</span>` : ''}` +
        `<span class="clock faint">${formatClock(performance.now() - run.started)}</span>`
      : '';
    return (
      `<span class="c-info">●</span><b>${esc(t('tb.unpack'))}</b>` +
      `<div class="progress" role="progressbar" aria-label="${esc(t('run.progress'))}" aria-valuemin="0" aria-valuemax="${total}" aria-valuenow="${run.done}">` +
      `<div style="width:${percent}%"></div></div><span>${run.done} / ${total}</span>${current}` +
      `<span class="spacer"></span>` +
      `${run.stopping ? `<span class="c-warn">${esc(t('run.stopping'))}</span>` : ''}`
    );
  }
  if (state.scans.length) {
    const group = state.scans[0].group;
    return `<span class="c-info">●</span><span>${esc(t('ScanStatus', { p: groupName(group), n: group.found }))}</span>`;
  }
  const notice = state.notice
    ? `<span class="notice${state.notice.tone ? ` c-${state.notice.tone}` : ''}">${esc(show(state.notice))}</span>`
    : '';
  return `<span class="c-ok">●</span><span>${esc(t('status.ready'))}</span>${notice}`;
}

// ---------- menus ----------

function choice(act, on, label, sub) {
  return (
    `<button class="ctx-item" data-act="${act}" role="menuitemradio" aria-checked="${on}">` +
    `<span class="radio">${on ? '●' : '○'}</span><span><span>${esc(label)}</span>` +
    `${sub ? `<span class="sub mono">${esc(sub)}</span>` : ''}</span></button>`
  );
}

/** The output menu. `canPick` says this browser can write to a folder. */
export function outMenu(canPick) {
  const folder = state.out.dir;
  const choices =
    choice('out-downloads', state.out.mode === 'downloads', t('web.out_downloads')) +
    (folder
      ? choice('out-folder', state.out.mode === 'folder', t('settings.output_recent'), shownPath(`${folder.name}/unpack`))
      : '');
  const pick = canPick
    ? `<button class="ctx-item" data-act="out-choose" role="menuitem" aria-describedby="out-folder-help"><span class="radio"></span><span>${esc(t('settings.output_choose'))}</span></button>` +
      `<p class="ctx-note" id="out-folder-help">${esc(t('web.out_folder_help'))}</p>`
    : `<p class="ctx-note">${esc(t('web.out_unsupported'))}</p>`;
  return `${choices}<div class="ctx-sep"></div>${pick}`;
}

/**
 * The menu of a row. `kind` is `item`, `entry`, or `group`; `runnable` says
 * the row can be unpacked, and `busy` that a run is in progress.
 */
export function rowMenu(id, { kind, runnable, busy }) {
  const item = (act, label, disabled, shortcut = '') =>
    `<button class="ctx-item" data-act="${act}" data-id="${id}" role="menuitem"${disabled ? ' disabled' : ''}>` +
    `<span>${esc(label)}</span>${shortcut ? `<span class="kbd">${shortcut}</span>` : ''}</button>`;
  const sep = '<div class="ctx-sep"></div>';
  const remove = item('remove', t('menu.remove'), busy, kind === 'item' ? 'Del' : '');
  if (kind === 'group') return remove;
  const top = item('run-item', t('tb.unpack'), busy || !runnable) + sep + item('copy-path', t('menu.copy_path'), false);
  return kind === 'entry' ? top : top + sep + remove;
}

// ---------- dialogs ----------

function languageSelect(id) {
  const options = LANGUAGES.map(
    ([code, name]) => `<option value="${code}"${code === language() ? ' selected' : ''}>${name}</option>`,
  );
  return `<select id="${id}" data-change="language" aria-label="${esc(t('settings.language'))}">${options.join('')}</select>`;
}

/** The legal notice. Until it is accepted it is the only thing to act on. */
export function legal(accepted) {
  // The four paragraphs are the catalog's own HTML: they carry <strong>.
  const text = ['legal.p1', 'legal.p2', 'legal.p3', 'legal.p4'].map((key) => `<p>${t(key)}</p>`);
  const close = accepted
    ? `<button class="primary" data-act="close-legal">${esc(t('settings.done'))}</button>`
    : `<button class="primary" data-act="accept">${esc(t('legal.accept'))}</button>`;
  return (
    `<div class="modal-h"><img src="assets/icon-32.png" width="24" height="24" alt=""><h2>${esc(t('legal.title'))}</h2>` +
    `<span class="spacer"></span>${languageSelect('legal-language')}</div>` +
    `<div class="modal-b">${text.join('')}</div><div class="modal-f"><span class="spacer"></span>${close}</div>`
  );
}

/** A settings row: its label, its control, and an optional help line. */
function field(id, label, control, help) {
  const name = id ? `<label for="${id}">${esc(label)}</label>` : `<span class="flabel">${esc(label)}</span>`;
  const helpId = id ? ` id="${id}-help"` : '';
  return (
    `<div class="field">${name}<div><div class="control">${control}</div>` +
    `${help ? `<p class="help"${helpId}>${esc(help)}</p>` : ''}</div></div>`
  );
}

function settingsPane(canPick) {
  if (state.settingsTab === 'memory') {
    const mib = Math.round(state.limitBytes / (1024 * 1024));
    return field(
      'set-limit',
      t('web.limit'),
      `<input type="number" id="set-limit" data-change="limit" min="${MIN_LIMIT_MIB}" max="${MAX_LIMIT_MIB}" step="1" value="${mib}"><span>MiB</span>`,
      t('web.limit_help'),
    );
  }
  if (state.settingsTab === 'about') {
    return (
      `<div class="about"><img src="assets/icon-128.png" width="72" height="72" alt=""><div><div class="word">Senbei</div>` +
      `<div class="dim">${esc(t('AboutVersion', { v: VERSION }))}</div></div></div><p class="dim">${esc(t('about.desc'))}</p>` +
      field(null, t('about.license'), '<a href="LICENSE" target="_blank" rel="noopener">AGPL-3.0-only</a>') +
      field(
        null,
        t('about.source'),
        '<a class="mono" href="https://github.com/Momoko-Ayase/Senbei" target="_blank" rel="noopener">github.com/Momoko-Ayase/Senbei</a>',
      ) +
      `<div><button data-act="show-legal">${esc(t('about.legal'))}</button></div>`
    );
  }
  const option = (value, label, on) => `<option value="${value}"${on ? ' selected' : ''}>${esc(label)}</option>`;
  const folder = state.out.dir;
  const output =
    `<select id="set-output" data-change="output" aria-describedby="set-output-help"${outputBusy() ? ' disabled' : ''}>` +
    option('downloads', t('web.out_downloads'), state.out.mode === 'downloads') +
    (folder ? option('folder', shownPath(`${folder.name}/unpack`), state.out.mode === 'folder') : '') +
    (canPick ? option('choose', t('settings.output_choose'), false) : '') +
    `</select>`;
  const outputHelp = t(canPick ? 'web.out_folder_help' : 'web.out_unsupported');
  return (
    field('set-language', t('settings.language'), languageSelect('set-language')) +
    field('set-output', t('settings.output'), output, outputHelp)
  );
}

/** The settings dialog. `canPick` says this browser can write to a folder. */
export function settings(canPick) {
  const nav = ['general', 'memory', 'about'].map((key) => {
    const on = state.settingsTab === key;
    return `<button class="nav${on ? ' on' : ''}" data-act="settings-tab" data-tab="${key}" role="tab" aria-selected="${on}">${esc(t(`settings.tab_${key}`))}</button>`;
  });
  return (
    `<div class="modal-h"><h2>${esc(t('settings.title'))}</h2><span class="spacer"></span>` +
    `<button class="ghost" data-act="close-settings" aria-label="${esc(t('settings.done'))}">✕</button></div>` +
    `<div class="set-body"><nav class="set-nav" role="tablist">${nav.join('')}</nav>` +
    `<div class="set-pane" role="tabpanel">${settingsPane(canPick)}</div></div>` +
    `<div class="modal-f"><button class="ghost" data-act="reset"${outputBusy() ? ' disabled' : ''}>${esc(t('settings.reset'))}</button><span class="spacer"></span>` +
    `<button class="primary" data-act="close-settings">${esc(t('settings.done'))}</button></div>`
  );
}
