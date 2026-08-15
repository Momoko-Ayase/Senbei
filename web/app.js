import init, { detect, deobfuscate_metadata } from './pkg/senbei_web.js';

const dropzone = document.getElementById('dropzone');
const picker = document.getElementById('picker');
const fileList = document.getElementById('files');
const actions = document.getElementById('actions');
const unpackBtn = document.getElementById('unpack-btn');
const clearBtn = document.getElementById('clear-btn');
const legalOverlay = document.getElementById('legal-overlay');
const legalAccept = document.getElementById('legal-accept');
const legalLink = document.getElementById('legal-link');

await init();

// --- Legal gate: the page is unusable until the notice is acknowledged. ---
legalAccept.addEventListener('click', () => legalOverlay.remove());
legalLink.addEventListener('click', (e) => {
  e.preventDefault();
  if (!document.getElementById('legal-overlay')) {
    document.body.appendChild(legalOverlay);
  }
});

// --- File list: one row per module. Companions (`X._`) never get their own ---
// --- row once their base module `X` is present — they show as a badge on   ---
// --- the base row. Rows are black while staged, show an animated blue      ---
// --- progress bar while unpacking, and turn green (success) or red         ---
// --- (failure) at the end; success rows gain a download button.            ---

// --- Row DOM is updated INCREMENTALLY: rows are created once and patched  ---
// --- in place. Rebuilding the list on every change would restart the      ---
// --- entrance animation of every row and reset the unpack shimmer.        ---

/** name -> {
 *   file: File,
 *   kind: string|undefined,   // detect() result; undefined for `._` files
 *   state: 'staged'|'working'|'ok'|'err',
 *   bytes: Uint8Array|null,   // unpacked output (state 'ok')
 *   note: string,             // status line (kind, suspect issues, error)
 *   suspect: boolean,
 * } */
const files = new Map();

/** name -> row <li> element (companions merged into their base have none) */
const rowEls = new Map();

const KIND_LABEL = {
  'native-exe': 'protected native EXE',
  'managed-exe': 'protected managed EXE',
  'native-dll': 'protected native DLL',
  'managed-dll': 'protected managed DLL',
  metadata: 'il2cpp metadata',
};

const COMPANION_SVG =
  '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">' +
  '<path d="M6.5 9.5a3 3 0 0 0 4.24 0l2-2a3 3 0 1 0-4.24-4.24l-1 1" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
  '<path d="M9.5 6.5a3 3 0 0 0-4.24 0l-2 2a3 3 0 1 0 4.24 4.24l1-1" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';

const DOWNLOAD_SVG =
  '<svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true">' +
  '<path d="M8 1v9m0 0L4.5 6.5M8 10l3.5-3.5M2 12.5V14h12v-1.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';

dropzone.addEventListener('click', () => picker.click());
dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') picker.click();
});
picker.addEventListener('change', () => {
  stageFiles(picker.files);
  picker.value = '';
});
dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('over');
});
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('over'));
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('over');
  stageFiles(e.dataTransfer.files);
});

async function stageFiles(list) {
  // Snapshot synchronously: `picker.files` and `dataTransfer.files` are LIVE
  // lists — clearing the picker or returning from the drop event empties
  // them, so an await before this point silently drops every file after the
  // first.
  const snapshot = [...list];
  for (const file of snapshot) {
    // Detection only needs the file header (key table at offset 4096 plus
    // the PE header fields); read a small slice, not the whole file.
    const head = new Uint8Array(await file.slice(0, 65536).arrayBuffer());
    // Companions are ciphertext fragments; detect() only makes sense on the
    // base module, so skip it for `._` files.
    const kind = file.name.endsWith('._') ? undefined : detect(head);
    const old = files.get(file.name);
    files.set(file.name, {
      file,
      kind,
      state: 'staged',
      bytes: null,
      note: '',
      suspect: false,
    }); // same name re-dropped: replace
    // A re-dropped file restarts as staged; drop any stale row/output.
    if (old) removeRow(file.name, true);
  }
  render();
}

/** Insert `.unpack` before the final extension: `app.exe` -> `app.unpack.exe`. */
function outName(name) {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? `${name.slice(0, dot)}.unpack${name.slice(dot)}` : `${name}.unpack`;
}

function statusText(name, entry) {
  if (name.endsWith('._')) {
    return `companion — needs ${name.slice(0, -2)}`;
  }
  switch (entry.state) {
    case 'staged':
      return entry.kind === undefined
        ? 'not recognized — will be skipped'
        : KIND_LABEL[entry.kind] ?? entry.kind;
    case 'working':
      return 'unpacking…';
    case 'ok':
    case 'err':
      return entry.note;
  }
}

function buildRow(name) {
  const li = document.createElement('li');
  li.className = 'file staged';
  li.dataset.name = name;

  const bar = document.createElement('div');
  bar.className = 'bar';
  li.appendChild(bar);

  const row = document.createElement('div');
  row.className = 'row';

  const label = document.createElement('span');
  label.className = 'name';
  label.textContent = name;
  row.appendChild(label);

  const badge = document.createElement('span');
  badge.className = 'badge companion';
  badge.innerHTML = COMPANION_SVG;
  badge.hidden = true;
  row.appendChild(badge);

  const status = document.createElement('span');
  status.className = 'status';
  row.appendChild(status);

  const dl = document.createElement('a');
  dl.className = 'dl';
  dl.innerHTML = DOWNLOAD_SVG;
  dl.hidden = true;
  row.appendChild(dl);

  const rm = document.createElement('button');
  rm.type = 'button';
  rm.className = 'remove';
  rm.textContent = '×';
  rm.title = `Remove ${name}`;
  rm.addEventListener('click', () => {
    // A companion belongs to its base module: removing the base removes the
    // companion too.
    files.delete(name);
    if (!name.endsWith('._')) files.delete(`${name}._`);
    render();
  });
  row.appendChild(rm);

  li.appendChild(row);
  return li;
}

function updateRow(li, name, entry) {
  const isCompanion = name.endsWith('._');
  li.className =
    `file ${entry.state}` + (entry.suspect && entry.state === 'ok' ? ' suspect' : '');

  const badge = li.querySelector('.badge');
  const hasCompanion = isCompanion || files.has(`${name}._`);
  badge.hidden = !hasCompanion;
  if (hasCompanion) {
    badge.title = isCompanion
      ? 'external companion (._)'
      : `companion loaded: ${name}._`;
  }

  li.querySelector('.status').textContent = statusText(name, entry);

  const dl = li.querySelector('.dl');
  const downloadable = entry.state === 'ok' && entry.bytes;
  dl.hidden = !downloadable;
  if (downloadable) {
    if (dl._bytesFor !== entry.bytes) {
      if (dl.href) URL.revokeObjectURL(dl.href);
      dl.href = URL.createObjectURL(
        new Blob([entry.bytes], { type: 'application/octet-stream' }),
      );
      dl._bytesFor = entry.bytes;
    }
    dl.download = outName(name);
    dl.title = `Download ${outName(name)}`;
  }
}

function removeRow(name, instant) {
  const li = rowEls.get(name);
  if (!li) return;
  rowEls.delete(name);
  // Release the download blob. Object URLs are roots: without this an unpacked
  // 100 MB image stays resident for the life of the page every time a row is
  // removed or the list is cleared.
  const dl = li.querySelector('.dl');
  if (dl?.href) {
    URL.revokeObjectURL(dl.href);
    dl.removeAttribute('href');
    dl._bytesFor = null;
  }
  if (instant) {
    li.remove();
    return;
  }
  // Fade AND collapse: without the height/margin transition the rows below
  // would hold position during the fade and then snap up on removal. The
  // end state must be inline too — an inline start value would otherwise
  // beat the stylesheet's `.leaving { max-height: 0 }`.
  li.style.maxHeight = `${li.offsetHeight}px`;
  void li.offsetHeight; // reflow: give the transition a concrete start value
  li.classList.add('leaving');
  li.style.maxHeight = '0px';
  setTimeout(() => li.remove(), 230);
}

function render() {
  // Create/update rows in Map order; companions whose base is staged merge
  // into the base row (no row of their own).
  const wanted = [];
  for (const [name] of files) {
    if (name.endsWith('._') && files.has(name.slice(0, -2))) continue;
    wanted.push(name);
  }
  const wantedSet = new Set(wanted);

  // Removals first: departed rows are marked leaving (and dropped from
  // rowEls) BEFORE the ordering loop, so the loop treats them as transparent
  // and never reorders siblings around them (that would snap, not slide).
  for (const name of [...rowEls.keys()]) {
    if (!wantedSet.has(name)) removeRow(name, false);
  }

  // In-place ordering: only rows that are out of position are moved, so
  // running animations (entrance, shimmer) are never restarted by a render.
  // Rows mid-leave-animation (no longer in rowEls) are skipped and keep
  // their spot — reordering siblings around them would make them snap
  // instead of sliding with the collapse.
  let cursor = fileList.firstChild;
  for (const name of wanted) {
    let li = rowEls.get(name);
    if (!li) {
      li = buildRow(name);
      rowEls.set(name, li);
    }
    updateRow(li, name, files.get(name));
    while (cursor && !rowEls.has(cursor.dataset.name)) {
      cursor = cursor.nextSibling;
    }
    if (li === cursor) {
      cursor = cursor.nextSibling;
    } else {
      fileList.insertBefore(li, cursor);
    }
  }

  const unpackable = [...files].some(
    ([name, e]) =>
      !name.endsWith('._') && e.kind !== undefined && e.state === 'staged',
  );
  unpackBtn.disabled = !unpackable;
  actions.hidden = files.size === 0;
}

clearBtn.addEventListener('click', () => {
  files.clear();
  render();
});

/**
 * Run one unpack in a disposable Web Worker (fresh wasm instance per call —
 * see worker.js). Buffers are transferred, so the inputs are neutered on the
 * main thread afterwards; callers re-read from the File for a retry.
 */
function runUnpack(inputBytes, compBytes, forceExe) {
  return new Promise((resolve) => {
    const w = new Worker('worker.js', { type: 'module' });
    w.onmessage = (e) => {
      w.terminate();
      resolve(e.data);
    };
    w.onerror = (e) => {
      w.terminate();
      resolve({ ok: false, trap: true, message: e.message || 'worker error' });
    };
    const transfer = [inputBytes.buffer, ...(compBytes ? [compBytes.buffer] : [])];
    w.postMessage({ input: inputBytes, companion: compBytes ?? null, forceExe }, transfer);
  });
}

async function unpackModule(name, entry) {
  const compEntry = files.get(`${name}._`);
  const read = (f) => f.arrayBuffer().then((b) => new Uint8Array(b));

  let input = await read(entry.file);
  let comp = compEntry ? await read(compEntry.file) : undefined;
  let r = await runUnpack(input, comp, false);

  const isExe = entry.kind === 'native-exe' || entry.kind === 'managed-exe';
  if (!r.ok && r.trap && !isExe) {
    // The DLL-routing probe trapped (panics can't be caught in wasm). Retry
    // once with the forced-EXE pipeline in a fresh worker — this mirrors the
    // CLI's dll-first/exe-fallback outcome for EXE-shell-layout DLLs.
    input = await read(entry.file);
    comp = compEntry ? await read(compEntry.file) : undefined;
    r = await runUnpack(input, comp, true);
  }

  if (!r.ok) {
    entry.state = 'err';
    entry.note = r.trap
      ? 'unpack failed (internal trap) — this Crackproof layout may be unsupported'
      : r.message;
    return;
  }
  entry.state = 'ok';
  entry.bytes = r.bytes;
  entry.suspect = r.suspect;
  entry.note =
    (r.companion ? 'spliced from ._ companion; ' : '') +
    `kind: ${r.kind}` +
    (r.suspect ? ` — SUSPECT: ${r.issues.join('; ')}` : '');
}

unpackBtn.addEventListener('click', async () => {
  unpackBtn.disabled = true;
  clearBtn.disabled = true;
  try {
    for (const [name, entry] of files) {
      if (name.endsWith('._') || entry.state !== 'staged') continue;

      if (entry.kind === undefined) {
        entry.state = 'err';
        entry.note = 'not recognized as Crackproof-protected — skipped';
        render();
        continue;
      }

      entry.state = 'working';
      render();
      try {
        if (entry.kind === 'metadata') {
          const bytes = new Uint8Array(await entry.file.arrayBuffer());
          const r = deobfuscate_metadata(bytes);
          if (r.remapped === 0) {
            entry.state = 'err';
            entry.note = `metadata already clean (v${r.version}, ${r.methods} methods) — nothing to do`;
          } else {
            entry.state = 'ok';
            entry.bytes = r.bytes;
            entry.note = `${r.remapped}/${r.methods} method tokens remapped across ${r.modules} modules`;
          }
        } else {
          await unpackModule(name, entry);
        }
      } catch (e) {
        entry.state = 'err';
        entry.note = e instanceof Error ? e.message : String(e);
      }
      render();
    }
  } finally {
    clearBtn.disabled = false;
    render();
  }
});
