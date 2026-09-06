# Senbei

A static unpacker for Crackproof-protected 64-bit and 32-bit PE files and protected Android AArch64 shared libraries. Point it at a file, an app package, or a folder and it writes decrypted copies without launching the protected program.

Senbei reads protected input bytes and replays the unpacking algorithm statically. The command-line tool adds filesystem scanning, progress reporting, and logs; `senbei-wasm` provides the browser binding.

## Crates

The workspace contains eight crates: `senbei-cli`, `senbei-crypto`, `senbei-io`, `senbei-metadata`, `senbei-pe`, `senbei-elf`, `senbei-engine`, and `senbei-wasm`.

`senbei-pe` and `senbei-elf` contain only basic format parsing and address mapping. Protection-specific code is in `senbei-engine/src/windows/` and `senbei-engine/src/android/`. Platform-specific crypto and metadata code is grouped under `senbei-crypto/src/android/`, `senbei-metadata/src/windows/`, and `senbei-metadata/src/android/`.

## Supported Inputs

- Protected Windows `.exe` and `.dll` files, including external `<name>.exe._` and `<name>.dll._` payloads.
- `global-metadata.dat` files with supported method-token layouts.
- Protected Android `.so` files and Android `.apk`, `.apks`, and `.xapk` packages.

Windows scanning probes only `.exe`, `.dll`, and `global-metadata.dat`; companion payloads are consumed through their matching stub and are not counted as skipped files. Android scanning probes only `.so` and `global-metadata.dat`. Android packages are inspected from their ZIP manifests and only matching `.so` and metadata entries are extracted.

## Quick Start

```cmd
cargo build --release
senbei protected.exe
senbei game.apk
senbei "C:\Games\MyGame"
```

Outputs are written below an `unpack` directory unless `--out` is supplied. Every restored PE or ELF image passes a structural validation step before it is reported as successful.

## Tests

```cmd
cargo test --release --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The local `test/` corpus can be passed to the CLI for real sample verification. The tracked `samples/` corpus is optional and remains user-managed.

## Web Build

```cmd
cd senbei-wasm
wasm-pack build --target web --release --out-dir ../web/pkg
```

The generated package is written to the ignored `web/pkg/` directory and can be served with any static HTTP server.

## Legal Notice

Use Senbei only for software you own or are authorized to analyze. The project is intended for lawful reverse engineering, security research, preservation, and interoperability.

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
