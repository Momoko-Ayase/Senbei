// Native/WASM parity driver. Reads a JSON job list on stdin and prints one
// JSON result per job on stdout. The Rust test starts `node` with this file.
//
// Job:   { "op": "detect" | "unpack" | "unpack_force_exe" | "metadata" | "library",
//          "input": "<path>", "companion": "<path>|null" }
// Result: { "ok": true, ... } with the fields of the job's kind (see `runJob`),
//      or { "ok": false, "error": "...", "profile": {...} }
//
// The wasm package directory is argv[2] (wasm-pack --target nodejs output).
//
// The driver calls the binding the way `web/worker.js` does: the input is
// appended to an `InputBuffer` in slices, the recovered bytes are read through
// the views the outcome hands out, and the digests the binding computes are
// checked against digests of those bytes.
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
import { closeSync, fstatSync, openSync, readFileSync, readSync } from "node:fs";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

const SLICE = 8 * 1024 * 1024;

// Fill an `InputBuffer` from a file in slices, as the page does from a Blob.
function load(wasm, file) {
  const fd = openSync(file, "r");
  try {
    const size = fstatSync(fd).size;
    const buffer = new wasm.InputBuffer(size);
    const slice = Buffer.allocUnsafe(Math.min(SLICE, Math.max(size, 1)));
    for (;;) {
      const read = readSync(fd, slice, 0, slice.length, null);
      if (read === 0) break;
      buffer.append(slice.subarray(0, read));
    }
    if (buffer.length !== size) throw new Error("short read");
    return buffer;
  } finally {
    closeSync(fd);
  }
}

// The digest of a view, which must agree with the digest the binding reports.
// The view is hashed first: it is valid only until the next call into the
// module, and `report` is such a call.
function digestOf(view, report) {
  if (!view || view.length === 0) return null;
  const digest = sha256(view);
  const reported = report();
  if (reported !== digest) throw new Error(`binding digest ${reported} is not the bytes' ${digest}`);
  return digest;
}

// Runs in a worker: one job, one freshly instantiated module.
function runJob(pkgDir, job) {
  const require = createRequire(import.meta.url);
  const wasm = require(path.join(pkgDir, "senbei_wasm.js"));
  if (job.op === "detect") {
    return { ok: true, kind: wasm.detect(readFileSync(job.input)) ?? null };
  }

  const input = load(wasm, job.input);
  let outcome;
  try {
    if (job.op === "unpack" || job.op === "unpack_force_exe") {
      // `unpack_pe` takes the companion buffer over.
      const companion = job.companion ? load(wasm, job.companion) : undefined;
      outcome = wasm.unpack_pe(input, companion, job.op === "unpack_force_exe", "en", undefined);
    } else if (job.op === "metadata") {
      outcome = wasm.restore_metadata(input, undefined, 0, "en");
    } else if (job.op === "library") {
      outcome = wasm.restore_library(input, "en", undefined);
    } else {
      return { ok: false, error: `unknown op ${job.op}` };
    }
    const info = JSON.parse(outcome.info);
    const profile = info.profile;
    if (info.status === "failed") return { ok: false, error: info.error?.text ?? null, profile };

    // Each view is used before the next call into the module.
    const image = outcome.image();
    const bytes = image.length;
    const digest = digestOf(image, () => outcome.image_sha256());
    if (job.op === "metadata") {
      return {
        ok: true,
        status: info.status,
        bytes,
        sha256: digest,
        version: info.metadata?.version ?? null,
        methods: info.metadata?.methods ?? null,
        remapped: info.metadata?.remapped ?? null,
        modules: info.metadata?.modules ?? null,
        layout: info.metadata?.layout ?? null,
        profile,
      };
    }
    if (job.op === "library") {
      const embedded = digestOf(outcome.embedded_metadata(), () => outcome.embedded_metadata_sha256());
      const module = outcome.take_module();
      return {
        ok: true,
        status: info.status,
        bytes,
        sha256: digest,
        embedded,
        module: module ? sha256(module) : null,
        elf: info.elf,
        profile,
      };
    }
    return {
      ok: true,
      kind: info.kind,
      bytes,
      sha256: digest,
      suspect: info.suspect,
      issues: info.findings.map((finding) => finding.message),
      companion: info.companion,
      profile,
    };
  } finally {
    // The worker is terminated immediately after this, so this is belt and
    // braces: release the Rust-side allocations without waiting for GC.
    for (const handle of [outcome, input]) {
      try {
        handle?.free();
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
