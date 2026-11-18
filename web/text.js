// The text form of a report: what the overview and the log of each input say,
// as plain lines in the page language. Loaded when a text export is asked for.

import { show, t, tv } from './i18n.js';
import { fullPath, isDone, outcomeOf, targetEntries } from './state.js';
import { baseName, formatBytes, formatDuration, localClock } from './model.js';
import { messagePlan, stagesOf } from './report.js';
import { lineText } from './detail.js';
import { formatLabel, routeOf, rowState, shownPath, typeTag } from './ui.js';

const LEVEL = { info: 'log.lv_info', step: 'log.lv_step', warn: 'log.lv_warn', error: 'log.lv_error' };
const MARK = { err: '✕', warn: '!', info: 'i' };

const sized = (size, sha256) => (sha256 ? `${formatBytes(size)} · SHA-256 ${sha256}` : formatBytes(size));

/** The lines for the outputs of an input or entry, at `depth`. */
function outputLines(add, depth, source) {
  for (const output of source.result?.outputs ?? []) {
    add(depth, `${t('ov.output')}: ${shownPath(output.path)} · ${sized(output.size, output.sha256)}`);
  }
}

function recoveryLines(add, item) {
  const result = item.result;
  const info = result?.info;
  const profile = info?.profile;
  if (profile) {
    const observed = profile.observed ?? {};
    add(1, `${t('ov.recognition')}: ${tv('recognition', profile.recognition)}`);
    if (observed.platform) add(2, `${t('ov.platform')}: ${tv('platform', observed.platform)}`);
    if (observed.format) add(2, `${t('ov.format')}: ${formatLabel(observed.format)}`);
    if (observed.kind) add(2, `${t('ov.kind')}: ${tv('kind', observed.kind)}`);
    const evidence = (profile.evidence ?? []).map((name) => tv('evidence', name));
    add(2, `${t('ov.evidence')}: ${evidence.length ? evidence.join(', ') : t('ov.no_evidence')}`);
  }
  const routes = info?.routes ?? [];
  add(1, `${t('ov.routes')}:${routes.length ? '' : ` ${t('ov.no_routes')}`}`);
  for (const route of routes) {
    const selected = route.layout === profile?.selected ? ` ★ ${t('ov.selected')}` : '';
    add(2, `${tv('layout', route.layout)}: ${tv('outcome', route.outcome)}${selected}`);
    for (const message of [...(route.errors ?? []), ...(route.warnings ?? [])]) add(3, show(message, result.lang));
  }
  const stages = stagesOf(item).map((stage) => {
    const time = stage.durationMs > 0 ? ` (${formatDuration(stage.durationMs)})` : '';
    return `${tv('stage', stage.stage)}: ${tv('stageStatus', stage.status)}${time}`;
  });
  if (stages.length) add(1, `${t('ov.stages')}: ${stages.join(' → ')}`);
  if (profile) add(1, `${t('ov.validation')}: ${tv('validation', profile.static_validation)}`);
  if (info?.status !== 'recovered') return;
  add(1, `${t('ov.source')}: ${sized(item.size, result.inputSha256)}`);
  if (result.companionUsed) {
    const size = result.companionSize == null ? '' : ` · ${sized(result.companionSize, result.companionSha256)}`;
    add(1, `${t('ov.companion')}: ${tv('companion', 'spliced')} · ${baseName(item.relPath)}._${size}`);
  }
  outputLines(add, 1, item);
}

function inputLines(item) {
  const lines = [];
  const add = (depth, text) => lines.push(`${'  '.repeat(depth)}${text}`);
  const row = rowState(item);
  add(0, shownPath(fullPath(item)));
  add(1, [row.label, row.extra, row.time].filter(Boolean).join(' · '));
  add(1, `${t('col.type')}: ${typeTag(item)}`);
  if (item.identityError) add(1, `${MARK.err} ${show(item.identityError)}`);
  if (!isDone(item)) return lines;

  const plan = messagePlan(item);
  for (const { tone, message } of [...plan.top, ...plan.validation]) {
    add(1, `${MARK[tone] ?? MARK.info} ${show(message, item.result?.lang)}`);
  }
  if (item.kind === 'package' && item.container) {
    const entries = targetEntries(item);
    if (!entries.length) add(1, t('pkg.no_targets'));
    for (const entry of entries) {
      const route = routeOf(entry);
      add(1, `${shownPath(entry.target.path)}: ${t(outcomeOf(entry).key)}${route ? ` · ${route}` : ''}`);
      outputLines(add, 2, entry);
    }
  } else {
    recoveryLines(add, item);
  }
  if (item.log?.length) {
    add(1, `${t('tab.log')}:`);
    for (const line of item.log) {
      const level = LEVEL[line.level] ? t(LEVEL[line.level]) : '';
      add(2, `${localClock(line.at)} ${level.padEnd(6)} ${lineText(line)}`);
    }
  }
  return lines;
}

/** The text report for `items`, one block for each input. */
export function reportText(items) {
  return `${items.map((item) => inputLines(item).join('\n')).join('\n\n')}\n`;
}
