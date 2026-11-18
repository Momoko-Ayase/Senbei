// The recovery engine, off the main thread.
//
// The page starts one of these for each job and ends it when the job is done.
// A Rust panic is a trap in WebAssembly and a trapped instance cannot be used
// again, so no instance outlives its job; ending the worker also returns the
// instance's memory, which a recovery grows to a few times the input size.
// Scanning uses a worker that answers several small requests and is replaced
// after a trap.
//
// Every request is `{ id, op, ... }` and every reply carries the same `id`.
// The first request also carries `wasm`, the compiled WebAssembly module the
// page shares between workers so that it is fetched and compiled once.

import init, {
  InputBuffer,
  detect,
  inspect_profile_json,
  manifest_identity,
  probe_library,
  restore_library,
  restore_metadata,
  unpack_pe,
  unsafe_package_entry,
} from './pkg/senbei_wasm.js';
import { crc32, entryStream } from './zip.js';

let ready = null;

/**
 * Copy one input into the instance.
 *
 * `source` is a `Blob`, or a package entry `{ blob, method, size, crc }` that
 * is inflated on the way in and checked against its declared size and CRC.
 * The input is never held as a whole on the JS side.
 */
async function load(source) {
  const entry = source instanceof Blob ? null : source;
  const size = entry ? entry.size : source.size;
  const buffer = new InputBuffer(size);
  const reader = (entry ? entryStream(entry) : source.stream()).getReader();
  let crc = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      // `append` refuses bytes past the declared size, so a malformed entry
      // cannot grow the buffer.
      buffer.append(value);
      if (entry) crc = crc32(value, crc);
    }
  } catch (error) {
    reader.cancel().catch(() => {});
    buffer.free();
    throw error;
  }
  if (buffer.length !== size) {
    buffer.free();
    throw new Error('input is shorter than its declared size');
  }
  if (entry && crc !== entry.crc) {
    buffer.free();
    throw new Error('package entry does not match its checksum');
  }
  return buffer;
}

/** A copy of a view of the instance's memory, as a `Blob` the page can keep. */
function blobOf(view) {
  return view && view.length > 0 ? new Blob([view]) : null;
}

/**
 * The SHA-256 of a blob in hexadecimal, or `null` where the browser offers no
 * digest: `crypto.subtle` exists only in a secure context.
 */
async function digestOf(blob) {
  if (!self.crypto?.subtle) return null;
  const digest = await self.crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function recover(id, request) {
  const input = await load(request.input);
  let companion = null;
  let outcome = null;
  try {
    const onStep = (title, i, of, key) => self.postMessage({ id, type: 'step', title, i, of, key });
    if (request.op === 'pe') {
      // `unpack_pe` takes the companion buffer over and frees it.
      companion = request.companion ? await load(request.companion) : null;
      const taken = companion;
      companion = null;
      outcome = unpack_pe(input, taken ?? undefined, request.forceExe === true, request.lang, onStep);
    } else if (request.op === 'so') {
      outcome = restore_library(input, request.lang, onStep);
    } else {
      outcome = restore_metadata(
        input,
        request.moduleBytes ?? undefined,
        request.conflicting ?? 0,
        request.lang,
      );
    }
    const info = JSON.parse(outcome.info);
    // Each view is copied into a Blob before the next call into the module.
    const image = blobOf(outcome.image());
    const embedded = blobOf(outcome.embedded_metadata());
    const module = outcome.take_module() ?? null;
    self.postMessage({ id, type: 'result', info, image, embedded, module });
    if (info.status !== 'not_protected') {
      // Hashing reads every byte again, so it follows the result instead of
      // delaying it.
      self.postMessage({
        id,
        type: 'identity',
        input: input.sha256(),
        image: image ? outcome.image_sha256() : null,
        embedded: embedded ? outcome.embedded_metadata_sha256() ?? null : null,
        // The engine gave its copy of the companion back, so the file is read
        // once more for its digest, and only when it was the one spliced in.
        companion: info.companion && request.companion
          ? await digestOf(request.companion).catch(() => null)
          : null,
      });
    }
    self.postMessage({ id, type: 'done' });
  } finally {
    outcome?.free();
    companion?.free();
    input.free();
  }
}

async function handle(request) {
  const { id, op } = request;
  if (op === 'prefix') {
    const kind = detect(request.bytes) ?? null;
    const profile = JSON.parse(inspect_profile_json(request.bytes));
    self.postMessage({ id, type: 'done', kind, profile });
  } else if (op === 'probe-so') {
    const input = await load(request.input);
    try {
      self.postMessage({ id, type: 'done', profile: JSON.parse(probe_library(input)) });
    } finally {
      input.free();
    }
  } else if (op === 'manifest') {
    const identity = manifest_identity(request.bytes, request.truncated === true) ?? null;
    self.postMessage({ id, type: 'done', identity });
  } else if (op === 'unsafe-entry') {
    const message = JSON.parse(unsafe_package_entry(request.package, request.lang));
    self.postMessage({ id, type: 'done', message });
  } else {
    await recover(id, request);
  }
}

self.onmessage = async (event) => {
  const request = event.data;
  try {
    ready ??= init({ module_or_path: request.wasm });
    await ready;
    await handle(request);
  } catch (error) {
    self.postMessage({
      id: request.id,
      type: 'error',
      // A trap leaves the instance unusable. The page ends this worker and,
      // for a DLL, tries the other route in a new one.
      trap: error instanceof WebAssembly.RuntimeError,
      message: String(error?.message ?? error),
    });
  }
};
