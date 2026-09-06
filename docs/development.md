# Development

## Building

The pinned Rust toolchain is defined in `rust-toolchain.toml`. Build the CLI with `cargo build --release`; the binary is written to `target/release/senbei.exe` on Windows.

The workspace crates are portable where their APIs are pure. The browser binding is outside the workspace and is checked with `cargo check --manifest-path senbei-wasm/Cargo.toml` or built with `wasm-pack`.

## Testing

```cmd
cargo test --release --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The tracked test suite is safe without protected samples. The optional local `samples/` corpus is user-managed and the ignored `test/` folder can be used for real Windows and Android runs.

For an Android package, use one command at a time because a protected `.so` can be hundreds of megabytes. APK, APKS, and XAPK tests read the ZIP manifest first and extract only `.so` and `global-metadata.dat` entries.

## Environment Variables

- `DD8_SHIFT` overrides the PE page-XOR shift; `99` skips that stage.
- `SEL_DIAG` prints PE layout-selector diagnostics.
- `SENBEI_THREADS` caps deterministic block fan-out; `1` forces the sequential reference path.
- `SENBEI_SCAN_ALL` enables the explicit scan-all mode for selected target names.
- `SENBEI_ANDROID_SAMPLES` overrides the Android sample corpus location.

## Conventions

Format crates stay free of filesystem I/O and protection-specific logic. Windows engine code lives below `senbei-engine/src/windows/`, Android engine code below `senbei-engine/src/android/`, and shared code stays directly under each crate's `src/`.

Layout heuristics must trial and validate every candidate. A failed validation is an error or a fall-through, never a silently accepted offset.

Outputs must remain byte-identical against the available golden corpus. Run the full workspace tests after changing a pipeline or a metadata layout.

Folder scanning uses explicit target names to avoid opening bulk assets. External `.exe._` and `.dll._` files are auxiliary data for their sibling stubs and are not independent scan targets.

## Repository Layout

```text
senbei-cli/       command-line binary and integration tests
senbei-crypto/    shared crypto and Android crypto primitives
senbei-elf/       basic ELF parsing
senbei-engine/    Windows and Android unpacking engines
senbei-io/        filesystem, package, scanning, and CLI orchestration
senbei-metadata/  Windows and Android metadata restoration
senbei-pe/        basic PE parsing
senbei-wasm/      browser bindings and its own lockfile
web/              static browser frontend
samples/          optional local corpus
```

## Web Build

```cmd
cd senbei-wasm
wasm-pack build --target web --release --out-dir ../web/pkg
```

Serve `web/` with a static HTTP server after the build. The browser never uploads input files.
