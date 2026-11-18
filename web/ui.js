// Small pieces every view is built from, and how an input is labelled.

import { show, t, technical, tv } from './i18n.js';
import { isNonTarget, outcomeOf, state, timeOf } from './state.js';
import { formatDuration, shortHash } from './model.js';

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** `value` as text that is safe inside an element or a quoted attribute. */
export const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ESCAPES[ch]);

export const pill = (tone, text) => `<span class="pill ${tone}">${esc(text)}</span>`;
export const tag = (text) => `<span class="tag">${esc(text)}</span>`;
export const note = (text) => `<p class="note">${esc(text)}</p>`;
export const dim = (text) => `<span class="dim">${esc(text)}</span>`;
export const faint = (text) => `<span class="faint">${esc(text)}</span>`;
export const mono = (text) => `<span class="mono">${esc(text)}</span>`;

/** A status dot; no tone draws a hollow one. */
export const dot = (tone) => `<span class="dot ${tone ? `bg-${tone}` : 'hollow'}"></span>`;

/**
 * A two-column list. Each row is `[label, html]`; falsy rows are left out.
 * `sized` holds labels the label column is wide enough for although they are
 * not shown, so that the column is the same in every view of one kind.
 */
export function kv(rows, sized = []) {
  // The labels that only take up room sit, without height, in the first one.
  const room = sized.map((label) => `<span class="room" aria-hidden="true">${esc(label)}</span>`).join('');
  const cells = rows
    .filter(Boolean)
    .map(([key, value], index) => `<div class="k">${esc(key)}${index === 0 ? room : ''}</div><div class="v">${value}</div>`);
  return `<div class="kv">${cells.join('')}</div>`;
}

/** A card. `title` may be `null`; `aside` is HTML at the right of the title. */
export function card(title, body, options = {}) {
  const aside = options.aside ? `<span class="aside">${options.aside}</span>` : '';
  const head = title === null ? '' : `<h3>${esc(title)}${aside}</h3>`;
  return `<section class="card${options.wide ? ' wide' : ''}">${head}${body}</section>`;
}

/**
 * A two-column grid of cards. A card left alone in its row takes the row, so
 * the grid has no empty half.
 */
export function grid(cards) {
  const wide = (html) => html.startsWith('<section class="card wide"');
  const out = cards.filter(Boolean);
  let run = 0;
  for (let index = 0; index <= out.length; index += 1) {
    if (index < out.length && !wide(out[index])) {
      run += 1;
      continue;
    }
    if (run % 2 === 1) out[index - 1] = out[index - 1].replace('class="card"', 'class="card wide"');
    run = 0;
  }
  return out.length ? `<div class="cards">${out.join('')}</div>` : '';
}

/** Text with `` `code` `` spans set in monospace, as engine messages write names. */
export function codeSpans(text) {
  const parts = String(text ?? '').split('`');
  if (parts.length < 3) return esc(text);
  return parts
    .map((part, index) => (index % 2 === 1 ? `<code>${esc(part)}</code>` : esc(part)))
    .join('');
}

const MESSAGE_ICON = { err: '✕', warn: '!', info: 'i' };

/**
 * A part that is folded until its header is clicked. `key` names it, so that
 * it stays as it was left when the view is drawn again; `summary` and `body`
 * are HTML.
 */
export const fold = (kind, key, summary, body) =>
  `<details class="fold ${kind}" data-fold="${esc(key)}"${state.unfolded.has(key) ? ' open' : ''}>` +
  `<summary>${summary}</summary>${body}</details>`;

/**
 * Message blocks for a list of `{ tone, message }`. `lang` is the language the
 * messages' job ran in. `quiet` shows every block as plain information.
 */
export function messages(plan, lang, quiet = false) {
  const rows = plan.map(({ tone, message }) => {
    const kind = quiet ? 'info' : tone;
    const more = technical(message, lang);
    const detail = more
      ? fold('tech', `tech:${more}`, esc(t('detail.technical')), `<pre class="mono">${esc(more)}</pre>`)
      : '';
    return (
      `<div class="msg ${kind}"><span class="c-${kind}">${MESSAGE_ICON[kind] ?? 'i'}</span>` +
      `<div><div>${codeSpans(show(message, lang))}</div>${detail}</div></div>`
    );
  });
  return `<div class="msgs">${rows.join('')}</div>`;
}

/** A hash, shortened, with the whole of it as the tooltip and a copy button. */
export function hash(sha256) {
  if (!sha256) return '';
  return (
    `<span class="hash"><span class="mono" title="${esc(sha256)}">${esc(shortHash(sha256))}</span>` +
    `<button class="ghost copy" data-act="copy" data-text="${esc(sha256)}">${esc(t('detail.copy'))}</button></span>`
  );
}

const WINDOWS = /win/i.test(globalThis.navigator?.userAgentData?.platform ?? globalThis.navigator?.platform ?? '');

/** A path as this system writes it: with backslashes on Windows. */
export const shownPath = (path) => (WINDOWS ? String(path ?? '').replace(/\//g, '\\') : String(path ?? ''));

// ---------- labels ----------

/** A group's title: the folder's name, or the name of the loose-files group. */
export const groupName = (group) => (group.kind === 'files' ? t('group.files') : group.name);

/** What a run is called once it has finished: the page only unpacks. */
export const modeLabel = () => t('mode.unpack');

/**
 * A step's title in the page language. A step the catalog names is worded by
 * the catalog; any other keeps the title its job gave it.
 */
export function stepTitle(step) {
  if (!step?.key) return step?.title ?? '';
  const key = `step.${step.key}`;
  const text = t(key);
  return text === key ? step.title : text;
}

/** A step with its position, as the status bar and the progress card show it. */
export function stepText(step) {
  if (!step) return '';
  const title = stepTitle(step);
  return step.i == null ? title : t('RunStep', { i: step.i, n: step.of, s: title });
}

const FORMATS = { pe32: 'PE32', pe32_plus: 'PE32+', elf64_aarch64: 'ELF64 AArch64' };

/** A binary format as the workbench writes it. */
export const formatLabel = (format) => FORMATS[format] ?? (format ? String(format).replace(/_/g, ' ') : '—');

function extensionTag(name) {
  const dot = name.lastIndexOf('.');
  return dot < 0 ? '?' : name.slice(dot + 1).toUpperCase();
}

const metadataTag = (version) => t('TagMetadata', { v: version ?? '?' });

/** The tag an observed target gives, when it names a format or a version. */
function observedTag(observed, version) {
  if (!observed) return null;
  if (observed.platform === 'il2cpp_metadata') return metadataTag(observed.metadata_version ?? version);
  if (!observed.format) return null;
  const format = formatLabel(observed.format);
  return observed.kind ? `${format} ${tv('kindShort', observed.kind)}` : format;
}

/** The tag an input had when it was added, from what its first bytes said. */
function identityTag(item) {
  switch (item.kind) {
    case 'metadata':
      return metadataTag(item.metadataVersion);
    case 'so':
      return FORMATS.elf64_aarch64;
    case 'package':
      return item.container ? item.container.kind.toUpperCase() : null;
    default:
      return observedTag(item.pre?.observed);
  }
}

/**
 * The short type of an input or entry, as its row's tag. A run that failed
 * before it read the format keeps the tag the file had when it was added.
 */
export function typeTag(item) {
  const info = item.result?.info;
  if (item.isEntry) {
    // An entry that turned out to be no target is known by its name alone.
    if (isNonTarget(item)) return extensionTag(item.name);
    return item.kind === 'metadata'
      ? metadataTag(info?.metadata?.version ?? item.metadataVersion)
      : FORMATS.elf64_aarch64;
  }
  const known = item.kind === 'package' ? null : observedTag(info?.profile?.observed, info?.metadata?.version);
  return known ?? identityTag(item) ?? extensionTag(item.name);
}

/**
 * The route a finished input or entry took, or `null`. An entry names the
 * transform that ran on a metadata blob, also one it left as it was; a
 * library inside a package has one route only, so none is named for it.
 */
export function routeOf(item) {
  const info = item.result?.info;
  if (item.isEntry && item.kind === 'so') return null;
  const route = item.isEntry ? (info?.metadata?.layout ?? info?.profile?.selected) : info?.profile?.selected;
  return route ? tv('layout', route) : null;
}

/**
 * How a row reads: `{ dot, label, tone, extra, time }`. `dot` and `tone` are a
 * tone name or `null`; `extra` follows the label and `time` ends the line.
 */
export function rowState(item) {
  const plain = (key) => ({ dot: null, label: t(key), tone: null, extra: null, time: null });
  switch (item.state) {
    case 'running':
      return { ...plain('run.running'), dot: 'info', tone: 'info' };
    case 'queued':
      return plain('run.queued');
    case 'cancelled':
      return plain('run.will_not_run');
    case 'pending':
      return plain(item.notProtected ? 'pending.not_protected' : 'pending.not_run');
    default: {
      const { tone, key } = outcomeOf(item);
      const time = item.isEntry ? null : timeOf(item);
      return {
        dot: tone,
        label: t(key),
        tone,
        extra: item.isEntry ? routeOf(item) : t('mode.unpack'),
        time: time == null ? null : formatDuration(time),
      };
    }
  }
}

/** The pill of an input's state, for the detail head. */
export function statePill(item) {
  const row = rowState(item);
  return pill(row.tone ?? 'skip', row.label);
}
