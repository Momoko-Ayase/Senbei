// The page's text: one language catalog, loaded on demand.
//
// The catalogs in `i18n/` are generated from the desktop GUI's approved
// wording (see `tools/gen-i18n.mjs`). Only the active language is fetched.

export const LANGUAGES = [
  ['en', 'English'],
  ['zh-CN', '简体中文'],
  ['zh-TW', '繁體中文'],
  ['ja', '日本語'],
  ['ko', '한국어'],
];

let catalog = {};
let active = 'en';

/** The active language tag. */
export const language = () => active;

/** Fetch and switch to `tag`. An unknown tag falls back to English. */
export async function loadLanguage(tag) {
  const known = LANGUAGES.some(([code]) => code === tag) ? tag : 'en';
  catalog = (await import(`./i18n/${known}.js`)).default;
  active = known;
  document.documentElement.lang = known;
}

/** The text for `key`, with `{name}` placeholders filled from `vars`. */
export function t(key, vars) {
  const text = catalog[key] ?? key;
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (match, name) => (name in vars ? String(vars[name]) : match));
}

/** The label of a report value such as `layout.exe_style`. */
export function tv(prefix, value) {
  if (value === null || value === undefined) return '—';
  return catalog[`${prefix}.${value}`] ?? String(value).replace(/_/g, ' ');
}

/**
 * A message in the page language.
 *
 * A message the page raised carries its catalog `key`. An engine message
 * carries its English `text` and, in `local`, its wording in the language it
 * was made in: `lang`, or the message's own `lang` when it has one. After a
 * language switch only the English is right.
 */
export function show(message, lang = active) {
  if (message?.key) return t(message.key, message.vars);
  if ((message?.lang ?? lang) !== active) return message?.text ?? '';
  return message?.local ?? message?.text ?? '';
}

/** The part of a message its page-language wording leaves out, if any. */
export function technical(message, lang = active) {
  if (message?.tech) return message.tech;
  if (message?.key || (message?.lang ?? lang) !== active) return null;
  return message?.local && message.local !== message.text ? message.text : null;
}
