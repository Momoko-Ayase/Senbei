// Stage the static site: the files the page loads, and nothing else.
//
//   node web/tools/stage.mjs <dist>
//
// Run after `wasm-pack build --target web --out-dir ../web/pkg`. The CI
// artifact and the release deployment are both made from this directory, so
// the list of what ships is here once.

import { cpSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Paths under `web/` that make up the site. */
export function siteFiles() {
  const top = readdirSync(web).filter(
    (name) => name.endsWith('.js') || ['index.html', 'style.css', 'LICENSE'].includes(name),
  );
  const catalogs = readdirSync(path.join(web, 'i18n'))
    .filter((name) => name.endsWith('.js'))
    .map((name) => `i18n/${name}`);
  const assets = readdirSync(path.join(web, 'assets')).map((name) => `assets/${name}`);
  const engine = ['pkg/senbei_wasm.js', 'pkg/senbei_wasm_bg.wasm'];
  return [...top, ...catalogs, ...assets, ...engine].sort();
}

function main() {
  const dist = process.argv[2];
  if (!dist) {
    console.error('usage: stage.mjs <dist>');
    process.exit(2);
  }
  for (const file of siteFiles()) {
    const from = path.join(web, file);
    if (!existsSync(from)) {
      console.error(`${file} is missing; build senbei-wasm into web/pkg first`);
      process.exit(1);
    }
    const to = path.join(dist, file);
    mkdirSync(path.dirname(to), { recursive: true });
    cpSync(from, to);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
