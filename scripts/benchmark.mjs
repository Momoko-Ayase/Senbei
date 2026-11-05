// End-to-end timing and output-identity checks. Inputs and reports stay local.
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export function summarize(samples) {
  if (samples.length === 0 || samples.some(n => !Number.isFinite(n) || n < 0)) {
    throw new Error('timings must contain finite, non-negative samples');
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return {
    minimum_ms: sorted[0],
    median_ms: sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2,
    p95_ms: sorted[Math.ceil(sorted.length * 0.95) - 1],
  };
}

export async function fingerprintOutputs(root) {
  const files = [];
  async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) throw new Error('benchmark outputs must not contain links');
      if (entry.isDirectory()) {
        await walk(path);
      } else if (entry.isFile()) {
        const hash = createHash('sha256');
        for await (const chunk of createReadStream(path)) hash.update(chunk);
        files.push({ path: relative(root, path).replaceAll('\\', '/'), sha256: hash.digest('hex') });
      } else {
        throw new Error('benchmark outputs must be regular files');
      }
    }
  }
  await walk(root);
  return files;
}

function positive(value, label) {
  if (!/^[0-9]+$/.test(value)) throw new Error(`${label} must be a positive integer`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) throw new Error(`${label} must be a positive integer`);
  return number;
}

export async function benchmark(cli, input, iterations, caps) {
  if (!Number.isSafeInteger(iterations) || iterations < 1 || caps.length === 0 ||
      caps.some(n => !Number.isSafeInteger(n) || n < 1)) {
    throw new Error('benchmark needs positive iterations and at least one positive thread cap');
  }
  const results = [];
  let reference;
  for (const threads of caps) {
    const timings = [];
    // The first run for each cap is a warm-up, but its bytes are still checked.
    for (let iteration = 0; iteration <= iterations; iteration++) {
      const output = await mkdtemp(join(tmpdir(), 'senbei-bench-'));
      try {
        const start = performance.now();
        const child = spawnSync(cli, [input, '--threads', String(threads), '--out', output,
          '--no-log', '--no-pause', '--strict-integrity', '-q', '-q'],
        { timeout: 600_000, maxBuffer: 1024 * 1024, encoding: 'utf8' });
        const elapsed = performance.now() - start;
        if (child.error) throw child.error;
        if (child.status !== 0) {
          throw new Error(`restore failed for ${threads} thread(s), exit=${child.status}, signal=${child.signal}`);
        }
        const outputs = await fingerprintOutputs(output);
        if (outputs.length === 0) throw new Error('restore produced no outputs; refusing an empty benchmark');
        const identity = JSON.stringify(outputs);
        if (reference === undefined) reference = identity;
        if (identity !== reference) throw new Error('restored bytes differ across benchmark runs');
        if (iteration > 0) timings.push(elapsed);
      } finally {
        // Only the new temporary output tree is removed, never the input tree.
        await rm(output, { recursive: true, force: true });
      }
    }
    results.push({ threads, samples_ms: timings, ...summarize(timings) });
  }
  return { format_version: 1, input, measurement: 'end_to_end_process_ms',
    warmup_runs_per_cap: 1, iterations, outputs: JSON.parse(reference), results };
}

async function main(args) {
  if (args.length < 2 || args.length > 4) {
    throw new Error('usage: node scripts/benchmark.mjs CLI INPUT [ITERATIONS=3] [THREADS=1,2,4]');
  }
  const [cli, input, repeat = '3', threadList = '1,2,4'] = args;
  const iterations = positive(repeat, 'iterations');
  const caps = [...new Set(threadList.split(',').map(value => positive(value, 'thread count')))];
  const report = await benchmark(resolve(cli), resolve(input), iterations, caps);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
