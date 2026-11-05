// One-shot worker: each job runs in a fresh worker with its own wasm instance.
// Two reasons:
//
// 1. UI stays responsive — unpacking a 100 MB+ module (or rewriting a large
//    `global-metadata.dat`) blocks for seconds.
// 2. Trap isolation — the senbei DLL-first routing probe relies on
//    catch_unwind to reject EXE-shell-layout DLLs, and panics cannot be
//    caught in WebAssembly: the probe traps the whole call. A trap kills
//    this worker's message handler, which the main thread observes and
//    retries with the forced-EXE pipeline in a NEW worker (the trapped
//    instance is never reused). That reproduces the CLI's
//    dll-first/exe-fallback routing without a catchable panic.
//
// Every reply carries the recovery profile (see `profile_json`), including
// failures: the page shows which route ran and why it was rejected.

import init, {
  deobfuscate_metadata_reported,
  unpack_file_reported,
} from './pkg/senbei_wasm.js';

let ready = null;

/** Parse the profile JSON into a plain object for structured cloning. */
function profileOf(doc) {
  if (!doc) return null;
  try {
    return JSON.parse(doc);
  } catch {
    return null;
  }
}

/** Post a failure reply, keeping the trap flag the main thread retries on. */
function postFailure(err, profile) {
  const trap = err instanceof WebAssembly.RuntimeError;
  self.postMessage({
    ok: false,
    trap,
    message: String(err?.message ?? err),
    profile,
  });
}

self.onmessage = async (e) => {
  const { mode, input, companion, forceExe } = e.data;
  let profile = null;
  try {
    ready ??= init();
    await ready;

    if (mode === 'metadata') {
      const r = deobfuscate_metadata_reported(input);
      profile = profileOf(r.profile_json);
      const bytes = r.bytes;
      self.postMessage(
        {
          ok: r.ok,
          mode: 'metadata',
          metadata: {
            version: r.version,
            methods: r.methods,
            remapped: r.remapped,
            modules: r.modules,
          },
          error: r.error ?? null,
          profile,
          bytes,
        },
        r.ok ? [bytes.buffer] : [],
      );
      return;
    }

    const r = unpack_file_reported(input, companion ?? undefined, forceExe === true);
    profile = profileOf(r.profile_json);
    const bytes = r.bytes;
    self.postMessage(
      {
        ok: r.ok,
        mode: 'unpack',
        kind: r.kind,
        suspect: r.suspect,
        issues: r.issues,
        severities: r.severities,
        fatal: r.fatal,
        companion: r.companion,
        error: r.error ?? null,
        profile,
        bytes,
      },
      r.ok ? [bytes.buffer] : [],
    );
  } catch (err) {
    postFailure(err, profile);
  }
};
