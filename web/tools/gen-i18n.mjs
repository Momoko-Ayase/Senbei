// Generate the page's language catalogs.
//
//   node web/tools/gen-i18n.mjs            write web/i18n/<lang>.js
//   node web/tools/gen-i18n.mjs --check    exit 1 when a written file is stale
//
// The desktop GUI's catalogs (`senbei-gui/src/text/<lang>.rs`) hold the
// approved wording, and the page shows the same workbench, so its text is
// taken from them and never retyped. Only the entries the page uses are
// copied: the research, hex, and compare views are not in the browser. Wording
// that exists only in the browser is in `web/i18n/web-strings.json`.
//
// An entry that takes no arguments is named by its catalog key
// (`tb.add_files`). An entry with arguments has no key in the Rust catalog and
// is named by its variant (`TbUnpackN`); its `{n}` placeholders are kept.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const textDir = path.resolve(webDir, '../senbei-gui/src/text');

/** Page language tag, and the Rust module holding it. */
export const LANGUAGES = [
  ['en', 'en'],
  ['zh-CN', 'zh_cn'],
  ['zh-TW', 'zh_tw'],
  ['ja', 'ja'],
  ['ko', 'ko'],
];

/** Catalog keys the page uses. A trailing `.` takes every key under it. */
const KEYS = [
  'tb.add_files', 'tb.add_folder', 'tb.unpack', 'tb.unpack.all', 'tb.output', 'tb.settings',
  'empty.', 'drag.title', 'inputs.', 'filter.', 'group.files', 'mode.unpack',
  'menu.copy_path', 'menu.remove',
  'pending.not_run', 'pending.not_protected', 'pending.identified', 'pending.next',
  'pending.not_protected_note',
  'scan.', 'run.', 'step.',
  'detail.pick', 'detail.export_json', 'detail.export_text', 'detail.copy', 'detail.technical',
  'companion.', 'tab.overview', 'tab.entries', 'tab.log', 'batch.', 'pkg.',
  'entries.title', 'entries.remapped_label',
  'col.name', 'col.type', 'col.outcome', 'col.route', 'col.time', 'col.status', 'col.source',
  'common.', 'ov.', 'log.', 'status.',
  'legal.title', 'legal.p1', 'legal.p2', 'legal.p3', 'legal.p4', 'legal.accept',
  'settings.title', 'settings.tab_general', 'settings.tab_memory', 'settings.tab_about',
  'settings.language', 'settings.output', 'settings.output_recent', 'settings.output_choose',
  'settings.reset', 'settings.done', 'about.',
  'entryStatus.restored', 'entryStatus.not_target', 'entryStatus.unchanged', 'entryStatus.error',
  'entryKind.', 'recognition.', 'outcome.', 'validation.',
  'stage.detection', 'stage.recovery', 'stage.static_validation', 'stage.output_write',
  'stageStatus.', 'metaLayout.',
  'evidence.', 'platform.', 'kind.', 'kindShort.', 'layout.',
];

/** Keys under a prefix above that belong to views the page does not have. */
const NOT_SHOWN = ['ov.provenance', 'ov.open_folder', 'status.recognized'];

/** Entries with arguments the page uses, by variant name. */
const VARIANTS = [
  'TbUnpackN', 'GroupScanning', 'ScanStatus', 'RunStep', 'DetailLastRun',
  'PkgInventory', 'EntriesOthers', 'EntriesSummary', 'EntriesShowNonTargets', 'EntriesRemapped',
  'LogRunStarted', 'LogScan', 'LogInputStarted', 'LogCompanion', 'LogStep', 'LogEntry',
  'LogInputFinished', 'LogSummary',
  'AboutVersion', 'TagMetadata',
];

/** The value of a Rust string literal body (the text between the quotes). */
function unescape(body, formatted) {
  let out = '';
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch === '\\') {
      const next = body[i + 1];
      i += 1;
      if (next === 'n') out += '\n';
      else if (next === 't') out += '\t';
      else if (next === '"' || next === '\\' || next === "'") out += next;
      else if (next === 'u') {
        const close = body.indexOf('}', i);
        out += String.fromCodePoint(parseInt(body.slice(i + 2, close), 16));
        i = close;
      } else throw new Error(`unsupported escape \\${next}`);
    } else if (formatted && (ch === '{' || ch === '}') && body[i + 1] === ch) {
      // `{{` and `}}` are literal braces in a format string.
      out += ch;
      i += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

/** Variant name to catalog key, for the entries that have one. */
function catalogKeys() {
  const source = readFileSync(path.join(textDir, 'catalog.rs'), 'utf8');
  const keys = new Map();
  for (const match of source.matchAll(/^\s*"([^"]+)" => Text::(\w+),$/gm)) {
    keys.set(match[2], match[1]);
  }
  return keys;
}

/** Variant name to `{ text, formatted }` for one language. */
function catalogText(module) {
  const source = readFileSync(path.join(textDir, `${module}.rs`), 'utf8');
  const arm = /^\s*Text::(\w+)(?: \{[^}]*\})? => (format!\()?"((?:[^"\\]|\\.)*)"\)?\.into\(\),$/gm;
  const text = new Map();
  for (const match of source.matchAll(arm)) {
    const formatted = match[2] !== undefined;
    text.set(match[1], unescape(match[3], formatted));
  }
  return text;
}

function wanted(key) {
  if (NOT_SHOWN.includes(key)) return false;
  return KEYS.some((entry) => (entry.endsWith('.') ? key.startsWith(entry) : key === entry));
}

/** The catalog module source for one language. */
export function generate(tag, module) {
  const keys = catalogKeys();
  const text = catalogText(module);
  const catalog = {};
  for (const [variant, key] of keys) {
    if (!wanted(key)) continue;
    if (!text.has(variant)) throw new Error(`${module}.rs has no text for ${variant}`);
    catalog[key] = text.get(variant);
  }
  for (const entry of KEYS) {
    const found = Object.keys(catalog).some((key) =>
      entry.endsWith('.') ? key.startsWith(entry) : key === entry);
    if (!found) throw new Error(`no catalog key matches ${entry}`);
  }
  for (const variant of VARIANTS) {
    if (!text.has(variant)) throw new Error(`${module}.rs has no text for ${variant}`);
    catalog[variant] = text.get(variant);
  }
  const web = JSON.parse(readFileSync(path.join(webDir, 'i18n/web-strings.json'), 'utf8'));
  for (const [key, languages] of Object.entries(web)) {
    if (typeof languages[tag] !== 'string') throw new Error(`${key} has no ${tag} text`);
    catalog[key] = languages[tag];
  }
  const lines = Object.entries(catalog).map(
    ([key, value]) => `  ${JSON.stringify(key)}: ${JSON.stringify(value)},`,
  );
  return [
    '// Generated by web/tools/gen-i18n.mjs from senbei-gui/src/text and',
    '// web/i18n/web-strings.json. Edit the wording there and run the generator.',
    'export default {',
    ...lines,
    '};',
    '',
  ].join('\n');
}

function main() {
  const check = process.argv.includes('--check');
  let stale = false;
  for (const [tag, module] of LANGUAGES) {
    const file = path.join(webDir, 'i18n', `${tag}.js`);
    const source = generate(tag, module);
    if (!check) {
      writeFileSync(file, source);
      continue;
    }
    let current = null;
    try {
      current = readFileSync(file, 'utf8');
    } catch {
      // A missing file is stale.
    }
    if (current !== source) {
      console.error(`${path.relative(process.cwd(), file)} is stale; run web/tools/gen-i18n.mjs`);
      stale = true;
    }
  }
  if (stale) process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
