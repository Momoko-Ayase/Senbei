// Writes for one batch of outputs, all going to the same chosen folder.

import { formatLog } from './detail.js';
import { uniquePath } from './model.js';
import { fileStamp } from './report.js';
import { allOutputs, archivePath, notify } from './state.js';
import { shownPath } from './ui.js';

const inputLog = (items) => formatLog(items.flatMap((item) => item.log ?? []));
const logBlob = (text) => new Blob([text], { type: 'text/plain;charset=utf-8' });
const folderStamp = (date) => `${fileStamp(date.toISOString())}-${String(date.getUTCMilliseconds()).padStart(3, '0')}`;

/** Bundle the retained outputs and their complete input logs for download. */
export async function downloadArchive(items, now = new Date()) {
  const outputs = allOutputs(items);
  if (!outputs.length) return null;
  const stamp = fileStamp(now.toISOString());
  const logPath = `senbei-${stamp}.log`;
  const log = logBlob(inputLog(items));
  const taken = new Set([logPath]);
  const files = outputs.map(({ item, output }) => ({
    path: uniquePath(archivePath(item, output), taken),
    blob: output.blob,
  }));
  files.push({ path: logPath, blob: log });
  const { buildZip } = await import('./zip.js');
  return { blob: await buildZip(files, now), name: `senbei-unpack.${stamp}.zip` };
}

/** Write to a chosen folder; return false if the browser refused the file name. */
async function writeFile(root, path, blob) {
  const parts = path.split('/');
  let directory = root;
  for (const part of parts.slice(0, -1)) {
    directory = await directory.getDirectoryHandle(part, { create: true });
  }
  let file;
  try {
    file = await directory.getFileHandle(parts.at(-1), { create: true });
  } catch (error) {
    // Chromium refuses some names, including .dll, here. Do not treat a
    // failure to open the directory or write the bytes as a name refusal.
    if (error instanceof TypeError) return false;
    throw error;
  }
  const writable = await file.createWritable();
  try {
    await writable.write(blob);
    await writable.close();
  } catch (error) {
    await writable.abort().catch(() => {});
    throw error;
  }
  return true;
}

function saved(output, path) {
  output.saved = path;
  output.saveFailed = null;
  output.refused = false;
}

export class FolderWriter {
  #root;
  #refused = [];

  constructor(root) {
    this.#root = root;
  }

  async save(item, fresh = false) {
    const outputs = item.result?.outputs ?? [];
    if (!outputs.length) return;
    const root = this.#root;
    // A scan of the chosen folder itself keeps the paths inside that folder.
    const handle = item.group.handle;
    const own = handle ? await root.isSameEntry(handle).catch(() => false) : false;
    for (const output of outputs) {
      if (!fresh && output.saved) continue;
      const name = own ? output.path : archivePath(item, output);
      const path = `unpack/${name}`;
      output.saved = null;
      output.saveFailed = null;
      output.refused = false;
      try {
        if (await writeFile(root, path, output.blob)) {
          saved(output, path);
          notify('web.saved', { path: shownPath(path) });
        } else {
          output.refused = true;
          this.#refused.push({ item, name, output });
        }
      } catch {
        output.saveFailed = path;
        notify('web.save_failed', { path: shownPath(path) }, 'err');
      }
    }
  }

  /** Save the unfiltered input logs beside the outputs, even if recovery failed. */
  async saveLog(items, now = new Date()) {
    const text = inputLog(items);
    if (!text) return;
    const path = `unpack/senbei-${folderStamp(now)}.log`;
    try {
      if (await writeFile(this.#root, path, logBlob(text))) return;
    } catch {
      // The log remains available in the tab.
    }
    notify('web.save_failed', { path: shownPath(path) }, 'err');
  }

  /** Store refused files in one archive, retaining paths relative to unpack/. */
  async finish(now = new Date()) {
    const refused = this.#refused;
    this.#refused = [];
    if (!refused.length) return;
    const path = `unpack/senbei-remaining.${folderStamp(now)}.zip`;
    let written = false;
    try {
      const { buildZip } = await import('./zip.js');
      const taken = new Set();
      const files = refused.map(({ name, output }) => ({ path: uniquePath(name, taken), blob: output.blob }));
      written = await writeFile(this.#root, path, await buildZip(files, now));
    } catch {
      // Retain the original blobs: the browser can still download them.
    }
    const parents = new Set();
    const groups = new Set();
    for (const { item, output } of refused) {
      if (written) saved(output, path);
      else output.saveFailed = path;
      const parent = item.parent ?? item;
      parents.add(parent);
      groups.add(parent.group);
    }
    const line = {
      at: Date.now(),
      level: written ? 'info' : 'error',
      type: 'stage',
      stage: 'output_write',
      status: written ? 'ok' : 'failed',
      detail: { text: shownPath(path), path: true },
    };
    for (const item of parents) item.log?.push(line);
    for (const group of groups) group.lastRun?.log.push(line);
    notify(written ? 'web.saved' : 'web.save_failed', { path: shownPath(path) }, written ? undefined : 'err');
  }
}
