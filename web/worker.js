// One-shot unpack worker: each unpack runs in a fresh worker with its own
// wasm instance. Two reasons:
//
// 1. UI stays responsive — unpacking a 100 MB+ module blocks for seconds.
// 2. Trap isolation — the senbei DLL-first routing probe relies on
//    catch_unwind to reject EXE-shell-layout DLLs, and panics cannot be
//    caught in WebAssembly: the probe traps the whole call. A trap kills
//    this worker's message handler, which the main thread observes and
//    retries with the forced-EXE pipeline in a NEW worker (the trapped
//    instance is never reused). That reproduces the CLI's
//    dll-first/exe-fallback routing without a catchable panic.

import init, { unpack_file, unpack_file_force_exe } from './pkg/senbei_wasm.js';

let ready = null;

self.onmessage = async (e) => {
  const { input, companion, forceExe } = e.data;
  try {
    ready ??= init();
    await ready;
    const r = forceExe
      ? unpack_file_force_exe(input, companion ?? undefined)
      : unpack_file(input, companion ?? undefined);
    const bytes = r.bytes;
    self.postMessage(
      {
        ok: true,
        kind: r.kind,
        suspect: r.suspect,
        issues: r.issues,
        companion: r.companion,
        bytes,
      },
      [bytes.buffer],
    );
  } catch (err) {
    const trap = err instanceof WebAssembly.RuntimeError;
    self.postMessage({ ok: false, trap, message: String(err?.message ?? err) });
  }
};
