// Folder walking for the two ways a browser hands over a whole folder: a
// dropped directory entry, and the file list of a folder input.
//
// A `FileSystemDirectoryHandle` is not walked. Chromium leaves some names out
// of a handle's listing and refuses to open them by name (`.dll` among them),
// so a scan through one would miss protected modules without a sign of it.
//
// A walk opens nothing. It yields a path and a way to get the `File`, and the
// scan asks for the file only when the name is one it probes, so bulk assets
// are never opened.

import { candidateKind, comparePaths, isCompanionName, isOutputDir } from './model.js';

function readBatch(reader) {
  return new Promise((resolve, reject) => reader.readEntries(resolve, reject));
}

/**
 * Walk a dropped `FileSystemDirectoryEntry`. Yields `{ path, open }` for every
 * file, with `path` relative to the entry. `onError` is called for each
 * directory that could not be listed.
 */
export async function* walkEntry(directory, onError, prefix = '') {
  const reader = directory.createReader();
  const folders = [];
  try {
    // `readEntries` returns the listing in batches and an empty one at the end.
    for (;;) {
      const batch = await readBatch(reader);
      if (batch.length === 0) break;
      for (const entry of batch) {
        const path = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory) {
          if (!isOutputDir(entry.name)) folders.push([path, entry]);
        } else {
          yield { path, open: () => new Promise((resolve, reject) => entry.file(resolve, reject)) };
        }
      }
    }
  } catch (error) {
    onError?.(error);
  }
  for (const [path, entry] of folders) yield* walkEntry(entry, onError, path);
}

/**
 * Walk the `FileList` of a folder input. Each file's `webkitRelativePath`
 * starts with the picked folder's name, which is dropped.
 */
export function* walkFileList(files) {
  for (const file of files) {
    const parts = (file.webkitRelativePath || file.name).split('/');
    const inside = parts.slice(1);
    if (inside.length === 0) continue;
    if (inside.slice(0, -1).some(isOutputDir)) continue;
    yield { path: inside.join('/'), open: async () => file };
  }
}

/** The name of the folder a folder input picked. */
export function fileListRoot(files) {
  const first = files[0];
  return first ? (first.webkitRelativePath || first.name).split('/')[0] : '';
}

/**
 * Sort a walk into what the scan probes.
 *
 * Returns `{ candidates, companions }`: the files whose names are targets, in
 * path order whatever order the browser listed them in, and the companion
 * payloads by path. Every other file is passed over without being opened.
 * `signal` stops the walk.
 */
export async function collect(walk, signal) {
  const candidates = [];
  const companions = new Map();
  for await (const file of walk) {
    if (signal?.aborted) break;
    const name = file.path.slice(file.path.lastIndexOf('/') + 1);
    if (isCompanionName(name)) {
      companions.set(file.path, file.open);
      continue;
    }
    const kind = candidateKind(name);
    if (kind) candidates.push({ path: file.path, kind, open: file.open });
  }
  candidates.sort((a, b) => comparePaths(a.path, b.path));
  return { candidates, companions };
}
