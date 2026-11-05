// Native/WASM parity driver. Reads a JSON job list on stdin and prints one
// JSON result per job on stdout. The Rust test starts `node` with this file.
//
// Job:   { "op": "detect" | "unpack" | "unpack_force_exe" | "metadata",
//          "input": "<path>", "companion": "<path>|null" }
// Result: { "ok": true, "kind": ..., "bytes": <n>, "sha256": ...,
//           "suspect": ..., "issues": [...], "remapped": ... }
//      or { "ok": false, "error": "..." }
//
// The wasm package directory is argv[2] (wasm-pack --target nodejs output).
//
// Isolation: every job runs in a *fresh Node Worker thread* and that worker is
// terminated before the next job starts. This matches the browser binding's
// disposable-worker architecture: WebAssembly cannot recover from a trap in the
// same instance, and a Rust result handle must not survive into the next job.
// Worker threads get their own module registry, so requiring the wasm package
// inside a worker instantiates a new module each time. Jobs are processed
// strictly sequentially so the JSON-lines output order matches the input order.
//
// A per-job timeout (SENBEI_WASM_PARITY_TIMEOUT_MS, default 120000) bounds a
// hung call; on expiry the worker is terminated and the job reports an error.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// Runs in a worker: one job, one freshly instantiated module.
function runJob(pkgDir, job) {
  const require = createRequire(import.meta.url);
  const wasm = require(path.join(pkgDir, "senbei_wasm.js"));
  let handle;
  try {
    if (job.op === "detect") {
      const bytes = readFileSync(job.input);
      return { ok: true, kind: wasm.detect(bytes) ?? null };
    }
    if (job.op === "unpack" || job.op === "unpack_force_exe") {
      const input = readFileSync(job.input);
      const companion = job.companion ? readFileSync(job.companion) : undefined;
      handle =
        job.op === "unpack"
          ? wasm.unpack_file(input, companion)
          : wasm.unpack_file_force_exe(input, companion);
      const bytes = handle.bytes;
      return {
        ok: true,
        kind: handle.kind,
        bytes: bytes.length,
        sha256: sha256(bytes),
        suspect: handle.suspect,
        issues: handle.issues,
        companion: handle.companion,
      };
    }
    if (job.op === "metadata") {
      const data = readFileSync(job.input);
      handle = wasm.deobfuscate_metadata(data);
      const bytes = handle.bytes;
      return {
        ok: true,
        bytes: bytes.length,
        sha256: sha256(bytes),
        version: handle.version,
        methods: handle.methods,
        remapped: handle.remapped,
        modules: handle.modules,
      };
    }
    return { ok: false, error: `unknown op ${job.op}` };
  } finally {
    // The worker is terminated immediately after this, so this is belt and
    // braces: release the Rust-side allocation without waiting for GC.
    if (handle && typeof handle.free === "function") {
      try {
        handle.free();
      } catch {
        // A poisoned instance after a trap can refuse; the worker dies anyway.
      }
    }
  }
}

function runWorker(pkgDir, job) {
  return new Promise((resolve) => {
    let settled = false;
    const timeoutMs = Number(process.env.SENBEI_WASM_PARITY_TIMEOUT_MS ?? 120000);
    const worker = new Worker(fileURLToPath(import.meta.url), {
      workerData: { pkgDir, job },
    });
    let timer;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      // Terminate before reporting: a trapped instance must never be reused.
      worker.terminate().finally(() => resolve(result));
    };
    worker.once("message", (message) => finish(message));
    worker.once("error", (error) =>
      finish({ ok: false, error: `worker error: ${error && error.message ? error.message : error}` })
    );
    worker.once("exit", (code) => {
      if (!settled) finish({ ok: false, error: `worker exited without a result (code ${code})` });
    });
    if (timeoutMs > 0) {
      timer = setTimeout(
        () => finish({ ok: false, error: `worker timed out after ${timeoutMs} ms` }),
        timeoutMs
      );
      timer.unref();
    }
  });
}

async function main(pkgDir) {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    let job;
    try {
      job = JSON.parse(line);
    } catch (error) {
      process.stdout.write(JSON.stringify({ ok: false, error: `bad job: ${error}` }) + "\n");
      continue;
    }
    const result = await runWorker(pkgDir, job);
    process.stdout.write(JSON.stringify(result) + "\n");
  }
}

if (isMainThread) {
  const pkgDir = process.argv[2];
  if (!pkgDir) {
    console.error("usage: wasm_parity_driver.mjs <wasm-pkg-dir>");
    process.exit(2);
  }
  main(pkgDir).catch((error) => {
    console.error(String(error && error.stack ? error.stack : error));
    process.exit(1);
  });
} else {
  let result;
  try {
    result = runJob(workerData.pkgDir, workerData.job);
  } catch (error) {
    result = { ok: false, error: String(error && error.message ? error.message : error) };
  }
  parentPort.postMessage(result);
}
