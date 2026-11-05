import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { benchmark, fingerprintOutputs, summarize } from './benchmark.mjs';

test('timings summarize sorted copies with even and odd medians', () => {
  const values = [4, 1, 3, 2];
  assert.deepEqual(summarize(values), { minimum_ms: 1, median_ms: 2.5, p95_ms: 4 });
  assert.deepEqual(values, [4, 1, 3, 2]);
  assert.deepEqual(summarize([3, 1, 2]), { minimum_ms: 1, median_ms: 2, p95_ms: 3 });
});

test('timings reject empty, negative, and non-finite samples', () => {
  for (const values of [[], [-1], [NaN], [Infinity]]) {
    assert.throws(() => summarize(values));
  }
});

test('benchmark rejects empty work before starting a process', async () => {
  for (const [iterations, caps] of [[0, [1]], [1, []], [1, [0]]]) {
    await assert.rejects(benchmark('unused', 'unused', iterations, caps));
  }
});

test('output fingerprints include sorted relative paths and file bytes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'senbei-bench-test-'));
  try {
    await mkdir(join(root, 'nested'));
    await writeFile(join(root, 'z.bin'), 'z');
    await writeFile(join(root, 'nested', 'a.bin'), 'a');
    const hash = value => createHash('sha256').update(value).digest('hex');
    assert.deepEqual(await fingerprintOutputs(root), [
      { path: 'nested/a.bin', sha256: hash('a') },
      { path: 'z.bin', sha256: hash('z') },
    ]);
    await writeFile(join(root, 'nested', 'a.bin'), 'changed');
    const changed = await fingerprintOutputs(root);
    assert.equal(changed[0].sha256, hash('changed'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
