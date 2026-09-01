# Development

## Building

Requires a Rust toolchain (MSVC backend is the default on Windows;
`rustup-init.exe` from <https://rustup.rs> installs it). The pinned toolchain
and targets are in `rust-toolchain.toml`.

```cmd
cargo build --release
```

Output: `target\release\senbei.exe`. The binary is self-contained — no driver,
no proxy DLL, no external assets.

The library and CLI also build for Linux/macOS (`cfg`-gated platform code
only) and for `wasm32-unknown-unknown` (see the [web version](../web/README.md)).

## Testing

```cmd
cargo test --release
```

The suite covers CLI behavior, detection, the folder driver, the run log, and
byte-exact golden tests over `samples/` — a user-managed corpus (git-ignored,
see `samples/README.md`) of real Crackproof inputs plus `<base>.golden.<ext>`
reference outputs. Every input goes through `job::unpack_bytes` — the same
routing the CLI uses, so an `<input>._` companion in the corpus is spliced and
the stub export/TLS overlays run — and is gated on **two** checks: the static
integrity check (catches runtime-broken outputs even when a stale golden would
still byte-match) and, when a golden exists, a bit-for-bit comparison. il2cpp
`*.dat` inputs are routed through `metadata::deobfuscate` instead. An empty or
absent corpus is a no-op pass; set `SENBEI_REQUIRE_SAMPLES` to make it fail
instead (useful on a private CI that has the corpus — public CI never does,
since binaries are not committed).

> **Note:** goldens encode expected *bytes*, not runtime behavior. A golden
> produced before a pipeline fix may byte-match while still being wrong — the
> integrity check is the second gate for exactly this reason. Re-verify
> goldens against real runs when touching the affected pipeline stages.
>
> **The corpus only protects what it contains.** Wire the test to the routing
> the CLI actually takes (it is), and keep a sample for every layout family —
> marker-based, marker-less, external-companion, PE32, PE32+, native, managed,
> metadata. An unrepresented family has no regression gate at all, which is
> how a "re-run the golden corpus" rule can pass while silently covering
> nothing.

## Debugging levers (environment variables)

- `DD8_SHIFT` — override the `decrypt_data8` page-XOR shift (`99` skips dd8
  entirely).
- `SEL_DIAG` — print the dd8 selector's scores: the per-shift `0xCC` counts and
  the plaintext baseline they are compared against (PE32+), and the per-formula
  counts, baseline and net gain (PE32).
- `SENBEI_THREADS` — cap the block-parallel fan-out (`1` forces the fully
  sequential path).
- `SENBEI_SCAN_ALL` — same as `--scan-all` (probe every file in a folder).
- `SENBEI_ANDROID_SAMPLES` — override the Android corpus location (default
  `samples/android/`; see `samples/README.md`). The Android corpus test pins
  restored outputs with SHA-256 sidecar files next to each protected input
  and documents known restore gaps with empty `<base>.restore-fails` markers.

## Conventions

- The `senbei-pe/` core (and its `senbei-crypto/` base) is pure: no file I/O,
  no panics across the public boundary, no `unsafe`. Keep it that way — it is
  what the WebAssembly build embeds.
- Layout heuristics must **trial-and-validate**: never pick a candidate offset
  on shape alone and trust it; validate by decryption/checksum and fall
  through to the next candidate on failure. A silent wrong offset produces a
  silently broken output, which is worse than an error.
- Output must remain byte-identical against the golden corpus for every
  supported layout. When fixing one build family, re-run the full golden
  corpus to prove no other family regressed.
- Folder scanning uses a size floor plus an extension **deny**-list, never an
  allow-list: targets are recognised by content, not extension, and can carry
  arbitrary names, so only known bulk-asset extensions are excluded. The
  pre-filter exists because folder-scan cost is per-file I/O latency, not the
  walk — probe fewer files, don't parallelize the probe loop.
- `cargo fmt` and `cargo clippy` must stay clean (CI enforces both).

## Repository layout

```
senbei/
├── Cargo.toml                 workspace root (members: the senbei-* crates)
├── rust-toolchain.toml        pinned toolchain + targets
├── senbei-cli/                senbei binary (default member)
│   └── tests/                 CLI, detection, golden, and folder tests
├── senbei-pe/                 pure unpacker core (see docs/design.md)
├── senbei-crypto/             crypto/compression primitives
├── senbei-metadata/           il2cpp metadata de-obfuscation
├── senbei-io/                 filesystem, scanning, CLI orchestration
├── senbei-wasm/               WebAssembly bindings crate (own Cargo.lock,
│                              outside the workspace; builds into web/pkg/)
├── samples/                   local-only test corpus (git-ignored)
├── web/                       static browser frontend assets (+ built pkg/)
├── docs/                      usage, design, and development documentation
└── .github/                   CI workflows and issue templates
```

## Web build

See [web/README.md](../web/README.md). In short:

```cmd
cd senbei-wasm
wasm-pack build --target web --release --out-dir ../web/pkg
```

then serve `web/` statically and open `index.html`. Everything runs
client-side; no file leaves the browser.

## Contributing

Issues and pull requests are welcome. A few ground rules:

- **Never commit binaries** (protected or decrypted) to the repository —
  the only corpus is the local git-ignored `samples/`. Attaching a protected
  input file to an issue is welcome if it helps diagnose the problem; only
  attach files you are authorized to share.
- Run `cargo test --release`, `cargo clippy`, and `cargo fmt` before
  submitting.
- Keep the unpacker core free of I/O, `unsafe`, and platform-specific code.
