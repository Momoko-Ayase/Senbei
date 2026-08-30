# Design

Senbei is a fully static unpacker: it replays the unpacking algorithm on the
file bytes in memory and writes the recovered PE image. No code from the
protected binary is ever executed, no process is launched or attached to, and
no driver or proxy DLL is involved.

## Crate layout

Senbei is a Cargo workspace split into a pure core and thin shells around it:

- **`senbei-pe/`** — the core. Pure functions over byte slices: no file I/O,
  no environment access (beyond a few debugging overrides, see
  [development.md](development.md)), panic-free at the public boundary (all
  internal panics are trapped and converted to `UnpackError::Corrupt`). This
  is what the WebAssembly build embeds.
- **`senbei-crypto/`** — cryptographic, checksum, compression, and bytecode
  primitives the core is built from. Same purity rules as `senbei-pe`.
- **`senbei-metadata/`** — il2cpp `global-metadata.dat` method-token
  de-obfuscation (format version 31; other versions are left untouched).
- **`senbei-io/`** — filesystem and orchestration: recursive folder scanning,
  per-run log file, progress bar, Explorer-friendly exit pause, and the
  single-file/folder orchestration in `job.rs` (incl. the wasm-safe in-memory
  byte API used by the web frontend).
- **`senbei-cli/`** — the `senbei` binary: argument parsing + dispatch. The
  integration test suite (incl. the golden corpus test) lives in
  `senbei-cli/tests/`.

```
senbei-cli/
└── src/main.rs            argument parsing + dispatch
senbei-io/src/
├── job.rs                 single-file + folder orchestration, out-naming,
│                          companion splice, stub overlay/TLS restore,
│                          pipeline routing (incl. the wasm-safe byte API)
├── scan.rs                recursive Crackproof + metadata discovery
├── logfile.rs             per-run timestamped log
├── ui.rs                  progress bar + status lines
└── pause.rs               Explorer-friendly exit pause
senbei-metadata/src/
└── metadata.rs            il2cpp global-metadata.dat de-obfuscation
senbei-crypto/src/
├── primitives.rs          decrypt_data* steps, key derivation
├── bytecode.rs            bytecode VM
├── tables.rs              constant tables
└── crc32.rs               checksum
senbei-pe/src/engine/      pure, panic-free, no-I/O core
├── mod.rs                 detection + unpack_auto dispatch
├── error.rs               structured error taxonomy
├── integrity.rs           static post-unpack sanity check
├── parallel.rs            deterministic block-parallel fan-out
├── layout/                layout discovery + validation
│   ├── dd8.rs             .text dd8 key-formula + shift selection
│   ├── discovery.rs       layout candidate discovery (trial-and-validate)
│   └── image.rs           PE image reconstruction helpers
├── exe/
│   ├── pipeline.rs        EXE pipeline (PE32+ and PE32 orchestration)
│   └── pipeline/pe32.rs   PE32-specific EXE restore
└── dll/
    └── pipeline.rs        native + managed DLL pipeline
```

## Detection and routing

Detection is content-based (`unpacker::detect`), never extension-based: the
key table is derived from the file header and checked against the format
magic, then the PE characteristics classify the input as EXE or DLL and the
CLR data directory splits each into native vs managed (`NativeExe` /
`ManagedExe` / `NativeDll` / `ManagedDll`).

`unpack_auto` then dispatches:

- `NativeExe` / `ManagedExe` → the EXE pipeline (handles both PE32+ and
  PE32). Managed EXEs take the same path: their import-string table is null
  (imports are the CLR bootstrap stub), the entry point comes from the
  protected header (the config block stores 0 for managed images), and the
  COR20 header, BSJB metadata stream, and CLR resources are restored verbatim
  from the protected file, mirroring the managed-DLL restore.
- `NativeDll` / `ManagedDll` → the DLL pipeline first; on failure, the EXE
  pipeline as a fallback. Two DLL layouts exist in the wild: an older layout
  the DLL pipeline parses, and a newer one that protects DLLs with the
  EXE-style shell layout instead. The DLL-first order keeps old-layout outputs
  byte-identical (the EXE pipeline also "succeeds" on old-layout DLLs but
  produces different bytes); the fallback handles the new layout (including
  the managed-DLL .NET metadata restore).

One routing shortcut bypasses `unpack_auto`: inputs spliced from an external
companion (`job.rs`, both the CLI and the wasm byte API) go **straight to the
EXE pipeline**. The companion layout is definitionally the EXE-style shell,
so the DLL probe can never be right for it — and the probe's rejection of
EXE-shell DLLs relies on a caught panic, which is a fatal trap on targets
without unwinding (WebAssembly). Output bytes are identical to the
probe-then-fallback route.

## External-companion inputs

Some builds split a protected module into an on-disk loader stub plus an
encrypted `._` companion. When a `<name>._` sibling matches the stub's header
region, `job.rs` splices the two before unpacking and afterwards overlays the
export table and TLS directory from the stub — pieces the encrypted companion
does not carry. All overlay steps are best-effort no-ops when their inputs
can't be mapped, so a malformed stub can never corrupt an otherwise-good
unpack.

## Pipelines

Both pipelines are **heuristic with trial-and-validate**: where a layout
leaves ambiguity (e.g. which block is the real file decryptor, or a page-XOR
shift), the pipeline tries candidates and validates the result structurally
(an entry-stub oracle, checksum stamps, cluster stamps) instead of trusting
the first match. A validation failure falls through to the next candidate
rather than producing silently wrong output.

Several protected stages are themselves little bytecode programs. The core
includes a small VM (`bytecode.rs`) that generates and interprets those
programs rather than hardcoding each variant's constants.

## Integrity check

Every produced image passes through `integrity::check` — a static, execution-
free sanity check that only flags defects impossible in a correctly unpacked
image (malformed headers, unmapped/non-executable/all-zero/all-int3 entry
point, a native DLL with no base-relocation directory, any import descriptor
whose DLL name is still ciphertext, a managed image whose COR20 header or BSJB
metadata did not survive). See [usage.md](usage.md#integrity-check).
A clean report is not a proof of correctness; a non-clean report is a reliable
"broken" signal.

## Parallelism

Section decrypt/decompress blocks write disjoint output spans and read only
immutable input plus snapshotted key tables, so `parallel.rs` fans them out
across worker threads with **byte-identical** output regardless of thread
count. There is no `unsafe`: the buffer is carved with safe `split_at_mut`
chains so the borrow checker proves spans never alias. Overlapping spans (only
possible on corrupt input) degrade to the sequential whole-buffer pass,
preserving the deterministic last-writer-wins behavior of the serial
pipeline. `SENBEI_THREADS=1` forces the sequential path; on targets without
threads (WebAssembly) the sequential path is used automatically.

## Error model

The public API never panics: every pipeline runs under a `catch_unwind`
wrapper (`catch_unpack`) that converts a trapped panic to
`UnpackError::Corrupt`, with the default panic hook transiently suppressed.
Size requests are bounds-checked against a 1 GiB `MAX_IMAGE_SIZE` before
allocation so a crafted header cannot abort the process with a huge
allocation. In folder mode each file is isolated: one file's failure is logged
and counted, never fatal to the run.

**WebAssembly caveat:** the prebuilt wasm std cannot unwind, so a caught
panic becomes a fatal `unreachable` trap there. The DLL-routing probe relies
on this mechanism to reject EXE-shell-layout DLLs, so the web build routes
around it instead of through it: spliced companion inputs skip the probe
entirely (see "Detection and routing"), and the web app isolates every unpack
in a disposable Web Worker — a trapped DLL is retried once in a fresh worker
with the forced-EXE pipeline (`job::unpack_bytes_force_exe`), reproducing the
probe-then-fallback outcome without a catchable panic. A trap on any other
input is reported as a clean error rather than freezing the page.
