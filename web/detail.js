// The detail pane: what the selected group, input, or entry is, and what its
// last run found. Every function returns HTML from the state alone.

import { show, t, tv } from './i18n.js';
import {
  counts,
  find,
  fullPath,
  isBusy,
  isDone,
  isNonTarget,
  outcomeOf,
  state,
  targetEntries,
  timeOf,
} from './state.js';
import { baseName, candidateKind, dirName, formatBytes, formatCount, formatDuration, localClock } from './model.js';
import { messagePlan, ranAsModule, stagesOf } from './report.js';
import {
  card,
  dot,
  esc,
  faint,
  fold,
  formatLabel,
  grid,
  groupName,
  hash,
  kv,
  messages,
  modeLabel,
  mono,
  note,
  pill,
  routeOf,
  rowState,
  shownPath,
  statePill,
  stepText,
  stepTitle,
  tag,
  typeTag,
} from './ui.js';

// ---------- shell ----------

const TAB_LABEL = { overview: 'tab.overview', entries: 'tab.entries', log: 'tab.log' };

/** The tab a view with `tabs` shows: the chosen one, or its first. */
const activeTab = (tabs) => (tabs.includes(state.tab) ? state.tab : tabs[0]);

/**
 * The head of a detail view: title row, path line, and tabs. `badge` gives a
 * count to show beside a tab; `exports` adds the export buttons.
 */
function head({ title, tagText = '', pills = '', path = '', tabs = [], badge = {}, exports = false }) {
  const shown = activeTab(tabs);
  const tab = (key) => {
    const count = badge[key] == null ? '' : `<span class="badge">${badge[key]}</span>`;
    return (
      `<button class="tab${shown === key ? ' on' : ''}" data-act="tab" data-tab="${key}" role="tab" aria-selected="${shown === key}">` +
      `${esc(t(TAB_LABEL[key]))}${count}</button>`
    );
  };
  const actions = exports
    ? `<span class="dacts"><button class="ghost" data-act="export">${esc(t('detail.export_json'))}</button>` +
      `<button class="ghost" data-act="export-text">${esc(t('detail.export_text'))}</button></span>`
    : '';
  return (
    `<div class="dhead${tabs.length ? '' : ' notabs'}"><div class="dtitle">` +
    `<button class="back" data-act="back" aria-label="${esc(t('inputs.title'))}">←</button>` +
    `<h2 title="${esc(title)}">${esc(title)}</h2>${tagText ? tag(tagText) : ''}${pills}` +
    `<span class="spacer"></span>${actions}</div>` +
    `${path ? `<div class="dpath mono" title="${esc(path)}">${esc(path)}</div>` : ''}` +
    `${tabs.length ? `<div class="tabs" role="tablist">${tabs.map(tab).join('')}</div>` : ''}</div>`
  );
}

/**
 * The body under a head, on the panel colour. A padded body scrolls as a
 * whole; the other kind lays out its own parts, one of which scrolls.
 */
const body = (html, padded = true) =>
  padded ? `<div class="dbody scroll"><div class="pad">${html}</div></div>` : `<div class="dbody flush">${html}</div>`;

/**
 * A table. Each column is `[label, width]`, with `'num'` as a third member
 * for right-aligned numbers; the one column without a width takes what the
 * others leave. `tall` rows have room for two lines.
 */
function table(columns, rows, tall = false) {
  // Columns are 8 apart: half of the gap is on each side of a cell, and the
  // table's two edges have none.
  const GAP = 8;
  const last = columns.length - 1;
  const outer = (width, index) => width + (index === 0 || index === last ? GAP / 2 : GAP);
  const grow = columns.findIndex(([, width]) => width == null);
  const fixed = columns.reduce((sum, [, width], index) => sum + (width == null ? 0 : outer(width, index)), 0);
  const cols = columns.map(([, width], index) =>
    width == null ? '<col>' : `<col style="width:${outer(width, index)}px">`,
  );
  const heads = columns.map(
    ([label, , kind]) => `<th${kind === 'num' ? ' class="num"' : ''}>${esc(label)}</th>`,
  );
  return (
    `<div class="tbl-wrap"><table class="t grow-${grow + 1}${tall ? ' tall' : ''}" style="min-width:${fixed + 120}px">` +
    `<colgroup>${cols.join('')}</colgroup><thead><tr>${heads.join('')}</tr></thead>` +
    `<tbody>${rows.join('')}</tbody></table></div>`
  );
}

const toned = (value, tone) => `<span class="c-${tone}">${esc(value)}</span>`;

/** A count that takes its tone only when it is not zero. */
const countText = (count, tone) => (count > 0 ? toned(count, tone) : String(count));

/** A count with thousands separators, as HTML. */
const counted = (value) => esc(formatCount(value));

// ---------- log ----------

const LEVEL_LABEL = { info: 'log.lv_info', step: 'log.lv_step', warn: 'log.lv_warn', error: 'log.lv_error' };
const LEVEL_TONE = { info: 'c-skip', step: 'c-info', warn: 'c-warn', error: 'c-err' };
const LOG_LEVELS = [
  ['all', 'log.f_all'],
  ['nosteps', 'log.f_nosteps'],
  ['problems', 'log.f_problems'],
];

function stageText(line) {
  let text = `${tv('stage', line.stage)}: ${tv('stageStatus', line.status)}`;
  if (line.durationMs > 0) text += ` (${formatDuration(line.durationMs)})`;
  const detail = line.detail ? show(line.detail, line.lang) : '';
  return detail ? `${text} — ${detail}` : text;
}

/** The text of one log line, in the page language. */
export function lineText(line) {
  switch (line.type) {
    case 'run-started':
      return t('LogRunStarted', { mode: t('tb.unpack'), n: line.n });
    case 'scan':
      return t('LogScan', { n: line.n, s: line.s });
    case 'scan-incomplete':
      return t('batch.scan_incomplete');
    case 'input-started':
      return t('LogInputStarted', { i: line.i, n: line.n, p: line.path });
    case 'companion':
      return t('LogCompanion', { p: line.name });
    case 'step': {
      const title = stepTitle(line);
      return line.i == null ? title : t('LogStep', { i: line.i, n: line.of, s: title });
    }
    case 'stage':
      return stageText(line);
    case 'message':
      return show(line.message, line.lang);
    case 'entry':
      return t('LogEntry', { p: line.path, o: t(line.outcome) });
    case 'finished':
      return t('LogInputFinished', { o: t(line.outcome), t: formatDuration(line.durationMs) });
    case 'summary':
      return t('LogSummary', line.counts);
    default:
      return line.text ?? '';
  }
}

function keep(line) {
  if (state.logLevel === 'nosteps') return line.level !== 'step' && line.level !== 'detail';
  if (state.logLevel === 'problems') return line.level === 'warn' || line.level === 'error';
  return true;
}

const levelLabel = (line) => (LEVEL_LABEL[line.level] ? t(LEVEL_LABEL[line.level]) : '');

/** Log lines without a bar of their own. `scrolls` gives them their own scroll. */
function logBox(lines, scrolls = false) {
  const rows = lines.filter(keep).map(
    (line) =>
      `<div class="logline${line.level === 'detail' ? ' detail' : ''}"><span class="ts">${localClock(line.at)}</span>` +
      `<span class="lv ${LEVEL_TONE[line.level] ?? ''}">${esc(levelLabel(line))}</span>` +
      `<span class="tx">${esc(lineText(line))}</span></div>`,
  );
  return `<div class="log${scrolls ? ' scroll' : ''}">${rows.join('')}</div>`;
}

/** The log tab: a filter bar and the lines below it. */
function logTab(lines) {
  const levels = LOG_LEVELS.map(
    ([key, label]) =>
      `<button class="${state.logLevel === key ? 'on' : ''}" data-act="loglevel" data-level="${key}" aria-pressed="${state.logLevel === key}">${esc(t(label))}</button>`,
  );
  return (
    `<div class="logbar"><div class="seg">${levels.join('')}</div><span class="spacer"></span>` +
    `<button class="ghost" data-act="copy-log">${esc(t('log.copy'))}</button></div>${logBox(lines, true)}`
  );
}

/** The log the selection has: a group's last run, or an input's. */
function selectedLog() {
  const current = state.selected && find(state.selected);
  if (current?.group) return current.group.lastRun?.log ?? [];
  return current?.item?.log ?? [];
}

/** Log lines as plain text, independent of what's selected or filtered. */
export function formatLog(lines) {
  return lines.map((line) => `${localClock(line.at)} ${levelLabel(line).padEnd(6)} ${lineText(line)}\n`).join('');
}

/** The visible log as plain text, for the clipboard. */
export function logText() {
  return formatLog(selectedLog().filter(keep));
}

// ---------- stages ----------

const STAGE_ICON = { ok: ['✓', 'ok'], skipped: ['–', 'skip'], failed: ['✕', 'err'], blocked: ['⏸', 'warn'] };
const ARROW = '<span class="arrow">→</span>';

function stageChip({ icon = '', tone = 'skip', name, duration = '', status = '', detail = '', dimmed = false }) {
  return (
    `<div class="stage${dimmed ? ' dimmed' : ''}"><div class="sname">` +
    `${icon ? `<span class="c-${tone}${icon === '✓' ? ' sicon' : ''}">${icon}</span>` : ''}<span>${esc(name)}</span>` +
    `${duration ? `<span class="sdur">${esc(duration)}</span>` : ''}</div>` +
    `${status ? `<div class="sstat c-${tone}">${esc(status)}</div>` : ''}` +
    `${detail ? `<div class="sdet">${esc(detail)}</div>` : ''}</div>`
  );
}

/** The stages of a finished input. `shown` holds the messages already on the page. */
function stagesCard(item, shown) {
  const stages = stagesOf(item);
  if (stages.length === 0) return '';
  const lang = item.result?.lang;
  const chips = stages.map((stage) => {
    const [icon, tone] = STAGE_ICON[stage.status];
    // A path is in the identity card, and a message the page shows is above.
    const hidden = !stage.detail || stage.detail.path || shown.has(stage.detail.text);
    return stageChip({
      icon,
      tone,
      name: tv('stage', stage.stage),
      duration: stage.durationMs > 0 ? formatDuration(stage.durationMs) : '',
      status: tv('stageStatus', stage.status),
      detail: hidden ? '' : show(stage.detail, lang),
    });
  });
  return card(t('ov.stages'), `<div class="stages">${chips.join(ARROW)}</div>`, { wide: true });
}

/** The stages of a running input: where it is, and what is still to come. */
function progressCard(step) {
  const detected = Boolean(step);
  const chips = [
    stageChip({
      icon: detected ? '✓' : '●',
      tone: detected ? 'ok' : 'info',
      name: tv('stage', 'detection'),
      status: detected ? tv('stageStatus', 'ok') : t('run.running'),
    }),
    stageChip({ icon: '●', tone: 'info', name: tv('stage', 'recovery'), status: stepText(step), dimmed: !detected }),
    stageChip({ name: tv('stage', 'static_validation'), dimmed: true }),
    stageChip({ name: tv('stage', 'output_write'), dimmed: true }),
  ];
  return card(t('run.progress'), `<div class="stages">${chips.join(ARROW)}</div>`, { wide: true });
}

// ---------- groups ----------

const groupPath = (group) => (group.kind === 'folder' ? shownPath(`${group.name}/`) : '');

function groupTable(group) {
  const rows = group.items.map((item) => {
    // The same state the inputs pane shows for this row.
    const row = rowState(item);
    let route = '';
    if (isDone(item)) {
      // A package that could not be listed has no targets to count.
      route = item.kind === 'package' && item.container
        ? t('EntriesSummary', { n: targetEntries(item).length })
        : (routeOf(item) ?? '—');
    }
    return (
      `<tr data-act="select" data-id="${item.id}" tabindex="0"><td class="c-dot">${dot(row.dot)}</td>` +
      `<td>${esc(item.name)}</td><td>${tag(typeTag(item))}</td>` +
      `<td class="${row.tone ? `c-${row.tone}` : 'faint'}">${esc(row.label)}</td>` +
      `<td>${esc(route)}</td><td class="num">${esc(row.time ?? '')}</td></tr>`
    );
  });
  const columns = [
    ['', 18],
    [t('col.name')],
    [t('col.type'), 130],
    [t('col.outcome'), 130],
    [t('col.route'), 210],
    [t('col.time'), 80, 'num'],
  ];
  return table(columns, rows);
}

function scanningDetail(group) {
  const scan = card(
    t('batch.scan'),
    kv([[t('scan.found'), String(group.found)]]) + note(t('batch.scan_note')),
    { wide: true },
  );
  return (
    head({ title: groupName(group), pills: pill('info', t('scan.running')), path: groupPath(group) }) +
    body(grid([scan]))
  );
}

function groupDetail(group) {
  if (group.scanning) return scanningDetail(group);
  const run = group.lastRun;
  const hasResults = group.items.some(isDone);
  const pills = run?.running ? pill('info', t('run.running')) : run ? pill('info', modeLabel()) : '';
  const tabs = ['overview', 'log'];
  const top = head({ title: groupName(group), pills, path: groupPath(group), tabs, exports: hasResults });
  if (activeTab(tabs) === 'log') return top + body(logTab(run?.log ?? []), false);

  const count = counts(group.items);
  const spent = group.items.reduce((sum, item) => sum + (isDone(item) ? (timeOf(item) ?? 0) : 0), 0);
  const duration = run?.durationMs > 0 ? run.durationMs : spent;
  const { stats } = group;
  const incomplete = stats.walkErrors + stats.probeErrors > 0;
  const cards = [];
  if (incomplete) {
    const blocks = [{ tone: 'warn', message: { key: 'batch.scan_incomplete' } }];
    cards.push(card(t('ov.messages'), messages(blocks), { wide: true }));
  }
  cards.push(
    card(
      t('batch.summary'),
      kv([
        [t('batch.inputs'), String(count.all)],
        [t('filter.ok'), toned(count.ok, 'ok')],
        [t('filter.suspect'), countText(count.suspect, 'warn')],
        [t('filter.failed'), countText(count.failed, 'err')],
        [t('filter.skipped'), String(count.skipped)],
      ]),
      // Nothing has run yet: no time to show.
      { aside: hasResults || duration > 0 ? esc(formatDuration(duration)) : '' },
    ),
  );
  if (group.kind === 'folder') {
    cards.push(
      card(
        t('batch.scan'),
        kv([
          [t('batch.non_target'), String(stats.skipped)],
          [t('batch.walk_errors'), countText(stats.walkErrors, 'warn')],
          [t('batch.probe_errors'), countText(stats.probeErrors, 'warn')],
        ]) + note(t('batch.scan_note')),
      ),
    );
  }
  cards.push(card(t('batch.inputs'), groupTable(group), { wide: true }));
  return top + body(grid(cards));
}

// ---------- inputs not yet run ----------

/** Lines stacked in one value cell. */
const stack = (lines) => `<div class="stack">${lines.filter(Boolean).map((line) => `<div>${line}</div>`).join('')}</div>`;

function companionRow(item) {
  const companion = item.companion;
  if (!companion || companion.state === 'absent') return null;
  const state = companion.state === 'spliced' ? t('companion.paired') : tv('companion', companion.state);
  return [t('ov.companion'), `<span>${esc(state)}</span><span>·</span>${mono(companion.name)}`];
}

/** What a light look at a file found, before anything ran. */
function identifiedRows(item) {
  const size = [t('ov.source'), esc(formatBytes(item.size))];
  if (item.identityError) return item.size ? [size] : [];
  switch (item.kind) {
    case 'package': {
      const container = item.container;
      const named = container.archives.find((archive) => archive.identity);
      return [
        [t('pkg.kind'), esc(container.kind.toUpperCase())],
        named && [t('pkg.package'), `${mono(named.identity[0])}${faint(named.identity[1])}`],
        [t('pkg.entries'), counted(container.archives[0].entryCount)],
        [t('pkg.candidates'), counted(item.entries.length)],
      ];
    }
    case 'pe': {
      const observed = item.pre?.observed;
      return [
        [t('ov.platform'), esc(tv('platform', observed?.platform ?? 'windows_pe'))],
        [t('ov.format'), mono(formatLabel(observed?.format))],
        observed?.kind && [t('ov.kind'), esc(tv('kind', observed.kind))],
        size,
        companionRow(item),
      ];
    }
    case 'metadata':
      return [
        [t('ov.platform'), esc(tv('platform', 'il2cpp_metadata'))],
        item.metadataVersion != null && [t('ov.metadata_version'), esc(item.metadataVersion)],
        size,
      ];
    case 'so':
      return [
        [t('ov.platform'), esc(tv('platform', 'android_elf'))],
        [t('ov.format'), mono(formatLabel('elf64_aarch64'))],
        size,
      ];
    default:
      return [size];
  }
}

function actionsCard(item) {
  const blocked = item.notProtected || state.run !== null || state.scans.length > 0;
  return card(
    t('pending.next'),
    `<div class="action"><button class="primary" data-act="run-item" data-id="${item.id}"${blocked ? ' disabled' : ''}>${esc(t('tb.unpack'))}</button>` +
      `<span class="dim">${esc(t('web.unpack_desc'))}</span></div>` +
      (item.notProtected ? note(t('pending.not_protected_note')) : ''),
  );
}

function pendingDetail(item) {
  const top = head({
    title: item.name,
    tagText: typeTag(item),
    pills: statePill(item),
    path: shownPath(fullPath(item)),
    tabs: ['overview'],
  });
  const cards = [];
  if (item.identityError) {
    const blocks = [{ tone: 'err', message: item.identityError }];
    cards.push(card(t('ov.messages'), messages(blocks), { wide: true }));
  }
  cards.push(card(t('pending.identified'), kv(identifiedRows(item))), actionsCard(item));
  return top + body(grid(cards));
}

// ---------- running inputs ----------

function runDetail(item) {
  const top = head({
    title: item.name,
    tagText: typeTag(item),
    pills: statePill(item),
    path: shownPath(fullPath(item)),
  });
  if (item.state === 'cancelled') return top + body(note(t('run.cancelled_note')));
  const run = state.run;
  if (item.state !== 'running' || !run) return top + body('');
  // The step belongs to the input being worked on; a package that waits for
  // another input's library shows only what it has logged.
  const cards = [
    progressCard(run.current === item ? run.step : null),
    card(t('tab.log'), logBox(item.log ?? []), { wide: true }),
  ];
  return top + body(grid(cards));
}

// ---------- results ----------

function recognitionCard(item) {
  const profile = item.result?.info?.profile ?? null;
  const observed = profile?.observed;
  const known = profile && (profile.recognition !== 'not_attempted' || observed?.format);
  const metadata = observed?.platform === 'il2cpp_metadata';
  // A run that stopped before it read the format still has the format the
  // file's header showed when it was added.
  const header = item.pre?.observed?.format ?? (item.kind === 'so' ? 'elf64_aarch64' : null);
  const evidence = profile?.evidence ?? [];
  const rows = [
    [t('ov.platform'), known ? esc(tv('platform', observed.platform)) : '—'],
    !metadata && [t('ov.format'), mono(formatLabel(observed?.format ?? header))],
    observed?.kind && [t('ov.kind'), esc(tv('kind', observed.kind))],
    [
      t('ov.evidence'),
      evidence.length
        ? `<span class="flags">${evidence.map((name) => pill('skip', tv('evidence', name))).join('')}</span>`
        : faint(t('ov.no_evidence')),
    ],
  ];
  // An input the page gave up on before the engine saw it was not looked at.
  const aside = esc(tv('recognition', profile?.recognition ?? 'not_attempted'));
  return card(t('ov.recognition'), kv(rows), { aside });
}

const OUTCOME_TONE = { succeeded: 'ok', not_attempted: 'skip' };

/** The routes a run tried. `shown` holds the messages already on the page. */
function routesCard(item, shown) {
  const info = item.result?.info;
  const routes = info?.routes ?? [];
  if (routes.length === 0) return card(t('ov.routes'), faint(t('ov.no_routes')));
  const rows = routes.map((route) => {
    const selected = route.layout === info.profile?.selected;
    const reasons = [
      ...(route.errors ?? []).map((message) => ({ tone: 'err', message })),
      ...(route.warnings ?? []).map((message) => ({ tone: 'warn', message })),
    ].filter(({ message }) => !shown.has(message.text));
    return (
      `<div class="route"><div class="rhead"><span>${esc(tv('layout', route.layout))}</span>` +
      `${selected ? `<span class="star">★ ${esc(t('ov.selected'))}</span>` : ''}<span class="spacer"></span>` +
      `${pill(OUTCOME_TONE[route.outcome] ?? 'err', tv('outcome', route.outcome))}</div>` +
      `${reasons.length ? messages(reasons, item.result.lang) : ''}</div>`
    );
  });
  return card(t('ov.routes'), rows.join(''));
}

const VALIDATION_TONE = { clean: 'ok', warnings: 'warn', failed: 'err' };

function validationCard(item, plan) {
  const profile = item.result?.info?.profile;
  if (!profile) return '';
  const status = profile.static_validation;
  let why;
  if (status === 'warnings' || status === 'failed') why = t(`ov.validation_${status}`);
  else if (profile.observed?.platform === 'il2cpp_metadata' && status !== 'clean') why = t('ov.validation_metadata');
  else return '';
  const found = plan.validation.length ? messages(plan.validation, item.result.lang) : '';
  return card(t('ov.validation'), `${note(why)}${found}`, {
    aside: pill(VALIDATION_TONE[status] ?? 'skip', tv('validation', status)),
  });
}

/** One output: where it is kept, and the button that hands it over. */
function outputValue(item, output, index) {
  let kept = '';
  if (output.saved) {
    kept = `<span class="c-ok">${esc(t('web.saved', { path: shownPath(output.saved) }))}</span>`;
  } else if (output.refused) {
    kept = `<span class="c-warn">${esc(t('web.save_refused', { name: baseName(output.path) }))}</span>`;
  } else if (output.saveFailed) {
    kept = `<span class="c-err">${esc(t('web.save_failed', { path: shownPath(output.saveFailed) }))}</span>`;
  }
  return stack([
    `${mono(shownPath(output.path))}${output.embedded ? ` ${tag(t('web.embedded_metadata'))}` : ''}`,
    `<span class="orow"><span>${esc(formatBytes(output.size))}</span>` +
      `<button class="ghost" data-act="download" data-id="${item.id}" data-n="${index}">${esc(t('web.download'))}</button></span>`,
    kept,
  ]);
}

function identityCard(item) {
  const result = item.result;
  // A library or a metadata blob is identified by what it was restored to.
  // Anything else went through the Windows pipeline, which reads the whole
  // input before it decides, so even a failure knows what it read.
  const windows = ranAsModule(item);
  const read = windows && result?.inputSha256;
  if (result?.info?.status !== 'recovered' && !read) return '';
  const image = result.outputs.find((output) => !output.embedded);
  let companion = null;
  // Only a file named as a module has a `._` file to look for.
  if (windows && candidateKind(item.relPath) === 'pe') {
    const name = `<span class="mono faint">${esc(`${baseName(item.relPath)}._`)}</span>`;
    if (result.companionUsed) {
      const size = result.companionSize == null ? '' : ` · ${formatBytes(result.companionSize)}`;
      companion = stack([esc(`${tv('companion', 'spliced')}${size}`), hash(result.companionSha256), name]);
    } else if (item.companion && item.companion.state !== 'absent') {
      companion = stack([esc(tv('companion', item.companion.state)), name]);
    } else {
      companion = esc(tv('companion', 'absent'));
    }
  }
  const rows = [
    [t('ov.source'), stack([esc(formatBytes(item.size)), hash(result.inputSha256)])],
    companion && [t('ov.companion'), companion],
    image && [t('ov.recovered'), stack([esc(formatBytes(image.size)), hash(image.sha256)])],
    ...result.outputs.map((output, index) => [t('ov.output'), outputValue(item, output, index)]),
  ];
  return card(t('ov.identity'), kv(rows));
}

const yesNo = (value) => (value ? toned(t('common.yes'), 'ok') : faint(t('common.no')));

function metadataCard(metadata) {
  const identity = metadata.identity;
  const caps = identity?.capabilities;
  const rows = [
    [t('ov.metadata_version'), esc(identity?.raw_version ?? metadata.version ?? '—')],
    identity && [t('ov.metadata_layout'), esc(tv('metaLayout', identity.layout))],
    caps && [t('ov.cap_seeded'), yesNo(caps.seeded_method_tokens)],
    caps && [t('ov.cap_structural'), yesNo(caps.structural_method_tokens)],
    caps && [t('ov.cap_indices'), yesNo(caps.method_index_restore)],
    caps && [t('ov.cap_context'), yesNo(caps.method_index_requires_context)],
  ];
  return card(t('ov.metadata'), kv(rows));
}

function elfCard(elf) {
  const count = (value) => (value == null ? '—' : counted(value));
  return card(
    t('ov.restored_elf'),
    kv([
      [t('ov.format'), mono(formatLabel('elf64_aarch64'))],
      [t('ov.elf_sections'), `${count(elf.sections)} · ${count(elf.segments)}`],
      [t('ov.elf_symbols'), count(elf.dynamic_symbols)],
      [t('ov.elf_relocs'), `${count(elf.dynamic_relocations)} · ${count(elf.pltgot_relocations)}`],
    ]),
  );
}

/** The path line of a finished input: where it is, how it ran, how long. */
const lastRunLine = (item) =>
  `${shownPath(fullPath(item))} · ${t('DetailLastRun', { mode: modeLabel(), t: formatDuration(timeOf(item) ?? 0) })}`;

function itemOverview(item) {
  const info = item.result?.info;
  const lang = item.result?.lang;
  const plan = messagePlan(item);
  const shown = new Set([...plan.top, ...plan.validation].map(({ message }) => message.text));
  const cards = [];
  if (plan.top.length) {
    cards.push(card(t('ov.messages'), messages(plan.top, lang, item.state === 'skipped'), { wide: true }));
  }
  cards.push(recognitionCard(item), routesCard(item, shown), stagesCard(item, shown));
  cards.push(validationCard(item, plan), identityCard(item));
  if (info?.metadata) cards.push(metadataCard(info.metadata));
  if (info?.elf) cards.push(elfCard(info.elf));
  return grid(cards);
}

function itemDetail(item) {
  const pills = [statePill(item)];
  if (item.result?.companionUsed) pills.push(pill('info', t('companion.spliced_pill')));
  const tabs = ['overview', 'log'];
  const top = head({
    title: item.name,
    tagText: typeTag(item),
    pills: pills.join(''),
    path: lastRunLine(item),
    tabs,
    exports: true,
  });
  if (activeTab(tabs) === 'log') return top + body(logTab(item.log ?? []), false);
  return top + body(itemOverview(item));
}

// ---------- packages ----------

/** Where an entry is: the archive that holds it, then its folder. */
function entryPlace(item, entry) {
  const source = entry.archive.label ? baseName(entry.archive.label) : item.name;
  const folder = dirName(entry.target.path);
  return `${source} › ${folder ? shownPath(`${folder}/`) : ''}`;
}

const remappedOf = (entry) => entry.result?.info?.metadata?.remapped ?? null;

function entryTable(item, entries) {
  // A column no shown entry has a value for is left out.
  const routes = entries.some((entry) => routeOf(entry) || remappedOf(entry) != null);
  const outputs = entries.some((entry) => entry.result?.outputs?.length);
  const columns = [['', 18], [t('col.name'), 240], [t('col.type'), 120], [t('col.status'), 110]];
  if (routes) columns.push([t('col.route'), 170]);
  if (outputs) columns.push([t('ov.output'), 170]);
  // The last column takes what the others leave.
  columns.push([columns.pop()[0]]);
  const rows = entries.map((entry) => {
    const { tone, key } = outcomeOf(entry);
    const remapped = remappedOf(entry);
    let cells =
      `<td class="c-dot">${dot(tone)}</td>` +
      `<td class="two"><div class="mono">${esc(entry.name)}</div><div class="place">${esc(entryPlace(item, entry))}</div></td>` +
      `<td>${tag(typeTag(entry))}</td><td class="c-${tone}">${esc(t(key))}</td>`;
    if (routes) {
      cells +=
        `<td class="two"><div>${esc(routeOf(entry) ?? '')}</div>` +
        `${remapped == null ? '' : `<div class="place">${esc(t('EntriesRemapped', { n: formatCount(remapped) }))}</div>`}</td>`;
    }
    if (outputs) cells += `<td class="mono">${esc(shownPath(entry.result?.outputs?.[0]?.path ?? ''))}</td>`;
    return `<tr data-act="select" data-id="${entry.id}" tabindex="0">${cells}</tr>`;
  });
  return table(columns, rows, true);
}

const ENTRY_TONE = { 'entryStatus.restored': 'ok', 'entryStatus.error': 'err' };

function packageOverview(item) {
  const container = item.container;
  const done = item.entries.filter(isDone);
  const cards = [];
  const blocks = container.problems.map((problem) => ({
    tone: 'warn',
    message: { text: `${problem.path}: ${problem.message}` },
  }));
  if (item.error) blocks.unshift({ tone: 'err', message: item.error });
  if (blocks.length) cards.push(card(t('ov.messages'), messages(blocks), { wide: true }));

  const nested = container.archives.slice(1).map((archive) => archive.label);
  cards.push(
    card(
      t('pkg.title'),
      kv([
        [t('pkg.kind'), esc(container.kind.toUpperCase())],
        [t('pkg.entries'), counted(container.archives[0].entryCount)],
        [t('pkg.candidates'), counted(item.entries.length)],
        nested.length > 0 && [t('pkg.nested'), stack(nested.map((label) => mono(label)))],
      ]) + note(t('pkg.note')),
    ),
  );
  const tally = new Map();
  for (const entry of done) {
    const { key } = outcomeOf(entry);
    tally.set(key, (tally.get(key) ?? 0) + 1);
  }
  const results = ['entryStatus.restored', 'entryStatus.unchanged', 'entryStatus.error', 'entryStatus.not_target']
    .filter((key) => tally.has(key))
    .map((key) => [t(key), ENTRY_TONE[key] ? toned(tally.get(key), ENTRY_TONE[key]) : String(tally.get(key))]);
  cards.push(card(t('pkg.result'), kv(results)));

  // A bundle's manifests are those of the packages in it.
  const manifests = container.archives.length > 1 ? container.archives.slice(1) : container.archives;
  const rows = manifests.map(
    (archive) =>
      `<tr><td class="mono">${esc(archive.label ? baseName(archive.label) : item.name)}</td>` +
      `<td>${archive.identity ? mono(archive.identity[0]) : faint(t('pkg.unnamed'))}</td>` +
      `<td class="mono">${esc(archive.identity?.[1] ?? '')}</td></tr>`,
  );
  const columns = [[t('col.source'), 220], [t('pkg.package'), 260], [t('pkg.version')]];
  cards.push(
    card(t('pkg.manifests'), table(columns, rows), {
      wide: true,
      aside: String(manifests.length),
    }),
  );
  const found = targetEntries(item);
  cards.push(
    found.length
      ? card(t('pkg.targets'), entryTable(item, found), { wide: true })
      : card(null, note(t('pkg.no_targets')), { wide: true }),
  );
  return grid(cards);
}

function entriesTab(item) {
  const done = item.entries.filter(isDone);
  const others = done.filter(isNonTarget).length;
  let shown = done.filter((entry) => state.showNonTargets || !isNonTarget(entry));
  if (shown.length === 0) shown = done;
  const names = item.entries.map((entry) => `${entry.archive.label || item.relPath}::${entry.target.path}`);
  return (
    `<label class="check"><input type="checkbox" data-change="non-targets"${state.showNonTargets ? ' checked' : ''}>` +
    `<span class="dim">${esc(t('EntriesShowNonTargets', { n: others }))}</span></label>` +
    entryTable(item, shown) +
    fold(
      'inv',
      `inv:${item.id}`,
      esc(t('PkgInventory', { n: names.length })),
      `<pre class="well mono">${esc(names.map(shownPath).join('\n'))}</pre>`,
    )
  );
}

function packageDetail(item) {
  const named = item.container.archives.find((archive) => archive.identity);
  const pills = statePill(item) + (named ? pill('skip', named.identity[0]) : '');
  const tabs = ['overview', 'entries', 'log'];
  const top = head({
    title: item.name,
    tagText: typeTag(item),
    pills,
    path: lastRunLine(item),
    tabs,
    badge: { entries: item.entries.length },
    exports: true,
  });
  const shown = activeTab(tabs);
  if (shown === 'log') return top + body(logTab(item.log ?? []), false);
  return top + body(shown === 'entries' ? entriesTab(item) : packageOverview(item));
}

function entryDetail(entry) {
  const result = entry.result;
  const info = result?.info;
  const { tone, key } = outcomeOf(entry);
  const plan = messagePlan(entry);
  const blocks = [...plan.top, ...plan.validation];
  const image = result?.outputs.find((output) => !output.embedded);
  const version = info?.metadata?.version ?? entry.metadataVersion;
  const remapped = remappedOf(entry);
  // What an entry is, is known once it was probed: one that is no target has
  // only its name.
  const kind = isNonTarget(entry) ? null : entry.kind === 'so' ? 'shared_library' : 'metadata';
  const rows = [
    [t('col.status'), toned(t(key), tone)],
    kind && [t('col.type'), esc(tv('entryKind', kind))],
    routeOf(entry) && [t('col.route'), esc(routeOf(entry))],
    kind === 'metadata' && version != null && [t('ov.metadata_version'), esc(version)],
    remapped != null && [t('entries.remapped_label'), counted(remapped)],
    result?.inputSha256 && [t('ov.source'), hash(result.inputSha256)],
    image && [t('ov.recovered'), stack([esc(formatBytes(image.size)), hash(image.sha256)])],
    ...(result?.outputs ?? []).map((output, index) => [t('ov.output'), outputValue(entry, output, index)]),
  ];
  // The label column is as wide for one entry as for any other.
  const labels = ['col.status', 'col.type', 'col.route', 'ov.metadata_version', 'entries.remapped_label', 'ov.source', 'ov.recovered', 'ov.output'];
  const cards = [];
  if (blocks.length) {
    cards.push(card(t('ov.messages'), messages(blocks, result?.lang, entry.state === 'skipped'), { wide: true }));
  }
  cards.push(card(t('entries.title'), kv(rows, labels.map((label) => t(label)))));
  if (info?.elf) cards.push(elfCard(info.elf));
  const top = head({
    title: entry.name,
    tagText: typeTag(entry),
    pills: pill(tone, t(key)),
    path: shownPath(fullPath(entry)),
    tabs: ['overview'],
  });
  return top + body(grid(cards));
}

// ---------- dispatch ----------

function empty() {
  const kinds = ['.exe', '.dll', '.exe._ / .dll._', 'global-metadata.dat', '.so', '.apk', '.apks', '.xapk', t('empty.folders')];
  return (
    `<div class="empty"><div class="drop"><img src="assets/icon-128.png" width="84" height="84" alt="">` +
    `<h2>${esc(t('empty.title'))}</h2>` +
    `<div class="kinds">${kinds.map((kind) => `<span class="tag mono">${esc(kind)}</span>`).join('')}</div>` +
    `<div class="acts"><button class="primary" data-act="add-files">${esc(t('tb.add_files'))}</button>` +
    `<button data-act="add-folder">${esc(t('tb.add_folder'))}</button></div>` +
    `<p class="faint">${esc(t('empty.local'))}</p></div></div>`
  );
}

const pick = () => `<div class="pick faint">${esc(t('detail.pick'))}</div>`;

/** The detail pane for the selection. */
export function detail() {
  if (state.groups.length === 0) return empty();
  const current = state.selected && find(state.selected);
  if (!current) return pick();
  if (current.group) return groupDetail(current.group);
  let item = current.item;
  if (item.isEntry) {
    if (isDone(item) && !isBusy(item.parent)) return entryDetail(item);
    // An entry that is running again is shown as its package.
    item = item.parent;
  }
  if (isBusy(item) || item.state === 'cancelled') return runDetail(item);
  if (!isDone(item)) return pendingDetail(item);
  // A package that could not be listed is shown as the input that failed.
  return item.kind === 'package' && item.container ? packageDetail(item) : itemDetail(item);
}
