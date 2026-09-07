# AGENTS.md

Guidance for contributors working in this repository.

## Project

Senbei is a static unpacker for protected PE files and Android AArch64 shared libraries. The workspace contains `senbei-cli`, `senbei-crypto`, `senbei-elf`, `senbei-engine`, `senbei-io`, `senbei-metadata`, and `senbei-pe`; `senbei-wasm` is a separate crate for the browser frontend.

Read `docs/design.md` before changing architecture or pipeline boundaries.

## Commands

```cmd
cargo build --release
cargo test --release --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cd senbei-wasm && wasm-pack build --target web --release --out-dir ../web/pkg
```

The optional `samples/` corpus is user-managed and ignored by Git. The Android corpus is under `samples/android/` when present. Do not delete sample directories as part of routine cleanup.

## Crate Boundaries

`senbei-pe` and `senbei-elf` contain format parsing, address mapping, and ELF dynamic-table helpers only. `senbei-engine/src/windows/` contains the PE unpacking pipeline; `senbei-engine/src/android/` contains Android extraction and ELF restoration. `senbei-crypto/src/windows/` and `senbei-crypto/src/android/` contain platform-specific primitives; seeded Android metadata code is under `senbei-metadata/src/android/`, while the structural metadata transform is shared at the metadata crate root. Shared source stays directly under `src/`.

The format crates and PE engine remain free of filesystem I/O. Native Android extraction and restoration may memory-map inputs and write temporary workspaces. The browser binding must continue to compile for `wasm32-unknown-unknown`.

## Hard Rules

- Outputs must be byte-identical to the available golden corpus.
- Layout heuristics must trial and validate every candidate before accepting it.
- Deterministic parallel and sequential paths must produce identical bytes.
- Folder scanning must not open bulk assets. Windows candidates are `.exe`, `.dll`, and `global-metadata.dat`; Android candidates are `.so` and `global-metadata.dat`. Matching `.exe._` and `.dll._` files are auxiliary payloads and are not counted as skipped targets.
- APK, APKS, and XAPK processing must inspect manifests first and extract only `.so` and `global-metadata.dat` entries.
- Do not commit protected or restored binaries. Use generic fixture names and do not add product-specific names or external tool references to public code, docs, tests, or commit messages.

## Documentation

Use one line for each normal Markdown paragraph. Keep code blocks, table rows, and list items structurally separate. Update `docs/usage.md` when CLI behavior changes.
