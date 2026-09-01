# senbei/samples

Drop-in corpus for the `samples` integration test (`tests/samples.rs`).

This folder is **git-ignored** (only this `README.md` is tracked), so it holds
whatever Crackproof binaries happen to be on your machine. Nothing here is
committed.

## What to put here

Place protected inputs directly in this folder:

- `*.exe` — Crackproof-protected executables (PE32 or PE32+)
- `*.dll` — Crackproof-protected DLLs (native or managed)
- `*.dat` — il2cpp `global-metadata.dat` blobs (method-token de-obfuscation)

For an **external-companion** module, copy the `<name>._` payload in as well,
keeping the exact `._` suffix on the full file name. The test splices it the
same way the CLI does; without it the loader stub alone is meaningless and the
splice / export-overlay / TLS-restore code is never exercised.

Optionally, place a **golden** next to each input — the known-good unpacked
output, named `<base>.golden.<ext>`:

```
samples/
  app.exe                   <- input
  app.golden.exe            <- golden (optional)
  managed.dll               <- input
  managed.golden.dll        <- golden (optional)
  stub.dll                  <- input  (external-companion layout)
  stub.dll._                <- its encrypted payload  (NOT an input itself)
  stub.golden.dll           <- golden
  global-metadata.dat       <- input
  global-metadata.golden.dat<- golden
  mystery.exe               <- input, no golden
```

The type (EXE vs native/managed DLL vs metadata) is auto-detected from the file
contents, not the extension, so you don't need to classify anything by hand.

Since the corpus is the only regression gate on byte-identical output, keep it
broad: each build family, each layout (marker-based and marker-less), and at
least one external-companion pair. A family with no sample here is a family no
test protects.

## How the test treats each input

Run with:

```
cargo test --release --test samples
```

For every input file, the test runs the same routing the CLI uses
(`job::unpack_bytes`, so companions splice and the stub overlays run) — or
`metadata::deobfuscate` for an il2cpp blob — and then:

| Situation                                   | Result                          |
| ------------------------------------------- | ------------------------------- |
| Golden present, bytes **identical**         | **pass**                        |
| Golden present, bytes **differ**            | **fail** (test fails)           |
| **No golden** found                         | **warning** (needs manual check)|
| Unpack errored / file unreadable            | **fail**                        |

Warnings are printed but do not fail the test — they flag outputs you should
eyeball or promote to a golden once verified. Failures fail the test. An empty
or absent folder is a no-op pass.

To see the per-file warning/pass/fail summary, run with output shown:

```
cargo test --release --test samples -- --nocapture
```

## Naming rules

- An **input** is any `*.exe` / `*.dll` / `*.dat` whose name does **not**
  contain the `.golden.` segment.
- A **golden** is `<base>.golden.<ext>` sitting next to its input. Files with
  `.golden.` in the name are never treated as inputs.
- A **companion** is `<input file name>._` (e.g. `stub.dll._` for `stub.dll`).
  Its extension is `_`, so it is never picked up as an input of its own; it is
  read only when its base module is processed.

## Android corpus (`samples/android/`)

The `android/` subfolder holds Android samples, one **extracted app tree** per
subdirectory (the layout an APK unpacks to: `lib/<abi>/*.so`,
`assets/.../global-metadata.dat`, ...). The test
(`tests/android_samples.rs`) finds protected AArch64 libraries by content and
restores them through the real pipeline. `SENBEI_ANDROID_SAMPLES` overrides
the corpus location.

Sidecar conventions (all next to the protected `.so` input):

| File | Meaning |
| ---- | ------- |
| `<base>.golden.so.sha256` | Expected SHA-256 of the restored library |
| `<base>.golden.metadata.sha256` | Expected SHA-256 of the unwrapped embedded metadata blob (when the library carries one) |
| `<base>.restore-fails` | Empty marker: this input's restore is a known gap and *must* fail (a future fix fails the test, prompting marker removal) |

A missing sidecar is a warning (with the computed digest printed, ready to
promote), never a failure. App packages (`.apk`/`.apks`/`.xapk`) dropped into
a tree are exercised by folder mode as containers.
