import init, { detect, inspect_profile_json } from './pkg/senbei_wasm.js';
import {
  DEFAULT_INPUT_LIMIT_BYTES,
  MAX_INPUT_LIMIT_MIB,
  MIN_INPUT_LIMIT_MIB,
  buildReport,
  describeFindings,
  describeObserved,
  describeStages,
  formatBytes,
  parseLimitMiB,
  planReadBudget,
  reportFileName,
  serializeReport,
} from './report.js';

const dropzone = document.getElementById('dropzone');
const picker = document.getElementById('picker');
const fileList = document.getElementById('files');
const actions = document.getElementById('actions');
const unpackBtn = document.getElementById('unpack-btn');
const clearBtn = document.getElementById('clear-btn');
const exportBtn = document.getElementById('export-btn');
const limitInput = document.getElementById('limit-mib');
const limitHint = document.getElementById('limit-hint');
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
 *   state: 'staged'|'working'|'ok'|'err'|'blocked',
 *   bytes: Uint8Array|null,   // unpacked output (state 'ok')
 *   note: string,             // status line (kind, suspect issues, error)
 *   suspect: boolean,
 *   findings: Array<{severity,message}>,  // integrity defects
 *   profile: object|null,     // post-recovery profile (or the failure profile)
 *   preRecoveryProfile: object|null,      // inspect_profile_json() result
 *   retried: boolean,         // forced-EXE retry ran
 *   companionUsed: boolean,   // output was spliced from a `._` payload
 *   error: string|null,
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
  'android-package':
    'Android app package — the web build cannot unpack these yet; use the senbei CLI',
  'android-so':
    'Android AArch64 library — the web build cannot unpack these yet; use the senbei CLI',
};

// Android targets are recognized by extension so the row can explain the
// situation instead of reporting a protected file as unrecognized: the
// Android pipeline is filesystem orchestration (senbei-io) with no wasm
// build, so these files need the CLI. The pseudo-kinds are labels only —
// they never reach the worker.
const ANDROID_KIND = {
  apk: 'android-package',
  apks: 'android-package',
  xapk: 'android-package',
  so: 'android-so',
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

// --- Input budget ---------------------------------------------------------
//
// Every read is guarded from `File.size` BEFORE `arrayBuffer()` runs, so an
// oversized input never becomes a large allocation in the first place. The
// limit is a practical guard, not a memory measurement: see the warning text.

let limitBytes = DEFAULT_INPUT_LIMIT_BYTES;

limitInput.min = String(MIN_INPUT_LIMIT_MIB);
limitInput.max = String(MAX_INPUT_LIMIT_MIB);

/** Static explanation shown when no staged input needs attention. */
const LIMIT_BASE_HINT =
  `Modules above the limit are skipped before their bytes are read. ` +
  'Unpacking keeps the input, the recovered image, and pipeline buffers in ' +
  'memory together, so it needs several times the file size.';

function applyLimit() {
  limitBytes = parseLimitMiB(limitInput.value, limitBytes);
  render();
}

limitInput.addEventListener('change', () => {
  limitInput.value = String(Math.round(limitBytes / (1024 * 1024)));
  applyLimit();
});
limitInput.addEventListener('input', () => {
  // Only react to a value that is actually usable, so typing never flips the
  // budget on a partial number.
  if (parseLimitMiB(limitInput.value, null) !== null) applyLimit();
});

/** Latest budget plan for the staged set (recomputed by render()). */
let budgetPlan = null;

/** Entries measured for the budget: base module + its `._` companion. */
function stagedSizes() {
  return [...files].map(([name, entry]) => ({ name, size: entry.file.size }));
}

/** True when `name` must be skipped under the current budget. */
function isBlocked(name) {
  if (!budgetPlan) return false;
  return budgetPlan.blocked.includes(name);
}

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
    // base module, so skip it for `._` files. Android targets short-circuit
    // detect() as well: an ELF/zip never classifies as a protected PE, and
    // the row must carry the android pseudo-kind for its status line.
    const ext = file.name.slice(file.name.lastIndexOf('.') + 1).toLowerCase();
    const kind = file.name.endsWith('._')
      ? undefined
      : (ANDROID_KIND[ext] ?? detect(head));
    const old = files.get(file.name);
    files.set(file.name, {
      file,
      kind,
      state: 'staged',
      bytes: null,
      note: '',
      suspect: false,
      findings: [],
      profile: null,
      preRecoveryProfile: readPreRecoveryProfile(file.name.endsWith('._') ? undefined : head),
      retried: false,
      companionUsed: false,
      error: null,
    }); // same name re-dropped: replace
    // A re-dropped file restarts as staged; drop any stale row/output.
    if (old) removeRow(file.name, true);
  }
  render();
}

/**
 * Pre-recovery profile from the header slice.
 *
 * This is pure presentation: it reports the observed target (`PE32+ · native
 * DLL · header magic`) and never turns a metadata magic match into a
 * protection claim. Returns `null` for companions and for anything the core
 * cannot describe.
 */
function readPreRecoveryProfile(head) {
  if (!head) return null;
  try {
    const parsed = JSON.parse(inspect_profile_json(head));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/** Insert `.unpack` before the final extension: `app.exe` -> `app.unpack.exe`. */
function outName(name) {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? `${name.slice(0, dot)}.unpack${name.slice(dot)}` : `${name}.unpack`;
}

/**
 * Staged status line: the observed header facts, which is what the profile can
 * say before any recovery runs. The kind label is only a fallback, because
 * `describeObserved` already names the format and kind.
 */
function stagedStatus(entry) {
  const label = KIND_LABEL[entry.kind] ?? entry.kind;
  if (entry.kind === 'metadata') {
    // The kind label names the file type; `observed` carries the version and
    // the format-only disclaimer.
    const observed = describeObserved(entry.preRecoveryProfile);
    return observed ? `${label} — ${observed}` : label;
  }
  // A PE profile already names the format and kind, so dropping the kind from
  // it avoids "protected native DLL — PE32+ · native DLL".
  const observed = describeObserved(entry.preRecoveryProfile, { includeKind: false });
  return observed ? `${label} — ${observed}` : label;
}

function statusText(name, entry) {
  if (name.endsWith('._')) {
    return `companion — needs ${name.slice(0, -2)}`;
  }
  switch (entry.state) {
    case 'staged':
      if (entry.kind === undefined) return 'not recognized — will be skipped';
      if (isBlocked(name)) return 'above the input limit — will be skipped';
      return stagedStatus(entry);
    case 'working':
      return entry.kind === 'metadata' ? 'de-obfuscating…' : 'unpacking…';
    case 'ok':
    case 'err':
    case 'blocked':
      return entry.note;
  }
}

/**
 * Details block: profile stages and severity-labelled findings.
 *
 * The row's status line already carries the failure text, so the details list
 * it only when it adds something the summary does not.
 */
function detailLines(entry) {
  return [...describeStages(entry.profile), ...describeFindings(entry.findings)];
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

  const report = document.createElement('button');
  report.type = 'button';
  report.className = 'report';
  report.textContent = '{}';
  report.title = `Export a JSON report for ${name}`;
  report.addEventListener('click', () => exportOne(name));
  row.appendChild(report);

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

  const details = document.createElement('ul');
  details.className = 'details';
  details.hidden = true;
  li.appendChild(details);

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

  const details = li.querySelector('.details');
  const lines = detailLines(entry);
  details.hidden = lines.length === 0;
  if (lines.length > 0) {
    // Rebuild only when the text actually changed: writing identical children
    // every render would restart the row's entrance animation.
    const key = lines.join('\n');
    if (details.dataset.key !== key) {
      details.replaceChildren(
        ...lines.map((line) => {
          const item = document.createElement('li');
          item.textContent = line;
          if (line.startsWith('fatal:')) item.className = 'fatal';
          else if (line.startsWith('warning:')) item.className = 'warning';
          return item;
        }),
      );
      details.dataset.key = key;
    }
  }

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
    dl.download = entry.outputName ?? outName(name);
    dl.title = `Download ${dl.download}`;
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
  budgetPlan = planReadBudget(stagedSizes(), limitBytes);

  // Raising the limit must un-block rows the previous limit skipped: a
  // `blocked` row is a budget verdict, not a result, so it returns to
  // `staged` once it fits again and the user can press Unpack.
  for (const [name, entry] of files) {
    if (entry.state === 'blocked' && !isBlocked(name)) {
      entry.state = 'staged';
      entry.error = null;
      entry.note = '';
    }
  }

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
  // instead of slide with the collapse.
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
      !name.endsWith('._') &&
      e.kind !== undefined &&
      !e.kind.startsWith('android-') &&
      e.state === 'staged',
  );
  unpackBtn.disabled = !unpackable;
  actions.hidden = files.size === 0;

  // The hint reflects the current staged set: the budget's own guidance when
  // it has something to say, otherwise the standing explanation.
  if (budgetPlan && budgetPlan.guidance.length > 0) {
    limitHint.textContent = budgetPlan.guidance.join(' ');
    limitHint.classList.toggle('warn', budgetPlan.blocked.length > 0);
  } else {
    limitHint.textContent = LIMIT_BASE_HINT;
    limitHint.classList.remove('warn');
  }
}

clearBtn.addEventListener('click', () => {
  files.clear();
  render();
});

/**
 * Run one job in a disposable Web Worker (fresh wasm instance per call — see
 * worker.js). Buffers are transferred, so the inputs are neutered on the main
 * thread afterwards; callers re-read from the File for a retry.
 *
 * `job` is read eagerly, but `read()` only runs after the caller has checked
 * the budget: no `arrayBuffer()` call happens here.
 */
function runJob(job) {
  return new Promise((resolve) => {
    const w = new Worker('worker.js', { type: 'module' });
    w.onmessage = (e) => {
      w.terminate();
      resolve(e.data);
    };
    w.onerror = (e) => {
      w.terminate();
      // A worker that fails to load (404, syntax error) reports no trap: the
      // retry below must not rerun an identical broken job.
      resolve({ ok: false, trap: false, message: e.message || 'worker error', profile: null });
    };
    const transfer = [job.input.buffer, ...(job.companion ? [job.companion.buffer] : [])];
    w.postMessage(job, transfer);
  });
}

/** Read a File only after the budget check has allowed it. */
async function readFile(file) {
  return new Uint8Array(await file.arrayBuffer());
}

/**
 * Apply one worker reply to a row, keeping the failure profile and error.
 *
 * The profile is stored even when the job failed: it names the route that ran
 * and why it was rejected, which is what the exported report needs.
 */
function applyReply(entry, r) {
  entry.profile = r.profile ?? entry.profile;
  if (!r.ok) {
    entry.state = 'err';
    entry.error = r.message ?? r.error ?? 'unpack failed';
    entry.findings = [];
    entry.note = r.trap
      ? 'unpack failed (internal trap) — this Crackproof layout may be unsupported'
      : entry.error;
    return false;
  }
  entry.findings = (r.issues ?? []).map((message, index) => ({
    severity: r.severities?.[index] === 'fatal' ? 'fatal' : 'warning',
    message,
  }));
  entry.suspect = r.suspect === true;
  entry.companionUsed = r.companion === true;
  entry.error = null;
  return true;
}

async function unpackModule(name, entry) {
  const compEntry = files.get(`${name}._`);

  let input = await readFile(entry.file);
  let comp = compEntry ? await readFile(compEntry.file) : undefined;
  let r = await runJob({ mode: 'unpack', input, companion: comp ?? null, forceExe: false });
  let retried = false;

  const isExe = entry.kind === 'native-exe' || entry.kind === 'managed-exe';
  if (!r.ok && r.trap && !isExe) {
    // The DLL-routing probe trapped (panics can't be caught in wasm). Retry
    // once with the forced-EXE pipeline in a fresh worker — this mirrors the
    // CLI's dll-first/exe-fallback outcome for EXE-shell-layout DLLs.
    input = await readFile(entry.file);
    comp = compEntry ? await readFile(compEntry.file) : undefined;
    r = await runJob({ mode: 'unpack', input, companion: comp ?? null, forceExe: true });
    retried = true;
  }
  entry.retried = retried;

  if (!applyReply(entry, r)) return;
  entry.state = 'ok';
  entry.bytes = r.bytes;
  entry.outputBytes = r.bytes.byteLength;
  entry.outputName = outName(name);
  const parts = [];
  if (r.companion || comp) parts.push('spliced from ._ companion');
  parts.push(`kind: ${r.kind}`);
  if (retried) parts.push('forced-EXE retry');
  if (entry.suspect) {
    // The per-finding text lives in the details list; the status line only
    // has to say how serious it is.
    const fatal = entry.findings.filter((finding) => finding.severity === 'fatal').length;
    const warnings = entry.findings.length - fatal;
    const counts = [
      fatal > 0 ? `${fatal} fatal` : null,
      warnings > 0 ? `${warnings} warning${warnings === 1 ? '' : 's'}` : null,
    ].filter(Boolean).join(', ');
    parts.push(`${r.fatal ? 'FAILED static check' : 'suspect'} (${counts})`);
  }
  entry.note = parts.join(' — ');
}

async function unpackMetadata(name, entry) {
  const input = await readFile(entry.file);
  const r = await runJob({ mode: 'metadata', input });
  if (!applyReply(entry, r)) return;
  const report = r.metadata ?? {};
  if (report.remapped === 0) {
    entry.state = 'err';
    entry.error =
      `metadata already clean (v${report.version}, ${report.methods} methods) — nothing to do`;
    entry.note = entry.error;
    return;
  }
  entry.state = 'ok';
  entry.bytes = r.bytes;
  entry.outputBytes = r.bytes.byteLength;
  entry.outputName = outName(name);
  entry.note =
    `${report.remapped}/${report.methods} method tokens remapped across ${report.modules} modules`;
}

unpackBtn.addEventListener('click', async () => {
  unpackBtn.disabled = true;
  clearBtn.disabled = true;
  try {
    for (const [name, entry] of files) {
      if (name.endsWith('._') || entry.state !== 'staged') continue;

      if (entry.kind === undefined) {
        entry.state = 'err';
        entry.error = 'not recognized as Crackproof-protected — skipped';
        entry.note = entry.error;
        render();
        continue;
      }

      // Android rows are informational only (no wasm pipeline); their staged
      // status line already says to use the CLI.
      if (entry.kind.startsWith('android-')) continue;

      // Budget gate. Runs before any read of the module body: `entry.file`
      // has not been touched for bytes yet. A blocked module keeps its
      // companion paired; only its own read is skipped.
      if (isBlocked(name)) {
        entry.state = 'blocked';
        entry.error =
          `${name} is above the ${formatBytes(limitBytes)} input limit — raise the limit to unpack it`;
        entry.note = entry.error;
        render();
        continue;
      }

      entry.state = 'working';
      render();
      entry.inputBytes = entry.file.size + (files.get(`${name}._`)?.file.size ?? 0);
      try {
        if (entry.kind === 'metadata') {
          await unpackMetadata(name, entry);
        } else {
          await unpackModule(name, entry);
        }
      } catch (e) {
        entry.state = 'err';
        entry.error = e instanceof Error ? e.message : String(e);
        entry.note = entry.error;
      }
      render();
    }
  } finally {
    clearBtn.disabled = false;
    render();
  }
});

// --- JSON export ----------------------------------------------------------

function downloadJson(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  // Revoke on the next task: revoking synchronously can cancel the download
  // in some browsers.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function generatedAt() {
  return new Date().toISOString();
}

/**
 * Per-row export: one file's report in the same envelope as the all-files
 * export, so a consumer parses one shape. The row's companion is included as
 * `companion_used` only — the companion has no report of its own.
 */
function exportOne(name) {
  const entry = files.get(name);
  if (!entry) return;
  const at = generatedAt();
  downloadJson(
    reportFileName(name, at),
    serializeReport(buildReport(new Map([[name, entry]]), {
      generatedAt: at,
      limitBytes,
      includeNotes: true,
    })),
  );
}

exportBtn.addEventListener('click', () => {
  const at = generatedAt();
  downloadJson(
    reportFileName(null, at),
    serializeReport(buildReport(files, { generatedAt: at, limitBytes, includeNotes: true })),
  );
});

// Paint the initial state so the limit hint and the action row are consistent
// before anything is staged.
render();
