# Design

Senbei is a fully static unpacker. It reads protected bytes, replays the protection algorithm, validates the result, and writes a recovered image without launching or attaching to the protected program.

## Crate Layout

The workspace is organized into eight crates. `senbei-cli` is the command-line entry point, `senbei-io` owns filesystem orchestration, `senbei-wasm` provides browser bindings, `senbei-pe` and `senbei-elf` provide basic format parsing, `senbei-crypto` provides shared primitives, `senbei-metadata` restores metadata, and `senbei-engine` owns protection-specific pipelines.

Single-platform source stays directly under `src/`. Multi-platform crates keep platform code below `src/windows/` and `src/android/`, with shared code directly below `src/`.

```text
senbei-cli/src/main.rs
senbei-crypto/src/
senbei-crypto/src/android/
senbei-crypto/src/windows/
senbei-elf/src/
senbei-engine/src/windows/
senbei-engine/src/android/
senbei-io/src/
senbei-io/src/android/
senbei-io/src/windows/
senbei-metadata/src/
senbei-metadata/src/windows/
senbei-metadata/src/android/
senbei-pe/src/
senbei-wasm/src/
```

`senbei-pe` and `senbei-elf` own validated format models, address mapping, and ELF dynamic hash helpers. They do not depend on the unpacking engines, filesystem code, or platform protection logic.

## Windows Engine

`senbei-engine/src/windows/` contains PE detection, layout discovery, EXE and DLL restoration, deterministic block parallelism, and structural integrity checks. Candidate layouts are trial-decrypted and validated before an output is accepted.

External companion inputs are reconstructed as `stub[..4096]` followed by the matching `._` payload. The stub's export, TLS, and declared CLR regions are overlaid after unpacking because those regions are not present in the encrypted companion. Managed restoration follows the COR20 directory and referenced metadata, resources, and vtable fixups through each file's RVA mapping, preserving the decrypted method bodies.

## Android Engine

`senbei-engine/src/android/extract/` decrypts the stage-1 header and stage-2 record streams and writes a temporary module workspace. `senbei-engine/src/android/restore/` applies decoded image and fixup containers to the hollowed ELF and rebuilds dynamic-linker tables. Both phases validate bounds and table placement before writing output.

Windows protection primitives are in `senbei-crypto/src/windows/`, while Android protection primitives are in `senbei-crypto/src/android/`. Android seeded metadata restoration is in `senbei-metadata/src/android/`; the structural MethodDef transform is shared at the metadata crate root because both platform paths use it.

Android ELF dynamic tables are located from the input section table and its actual file ranges. When the original gap is too small, restoration adds a validated read-only `PT_LOAD` after the existing load image and updates the dynamic tags; it never overwrites an adjacent section or emits a partial image.

## Scanning and Packages

Folder scanning uses platform target names to avoid opening bulk assets: Windows candidates are `.exe`, `.dll`, and `global-metadata.dat`; Android candidates are `.so` and `global-metadata.dat`. The shared walker is in `senbei-io/src/scan.rs`; platform name filters and PE companion byte adaptation are in `senbei-io/src/windows/`, and Android package adaptation is in `senbei-io/src/android/`. A Windows `.exe._` or `.dll._` companion is auxiliary input for its sibling stub and is excluded from the skipped count.

APK, APKS, and XAPK files are containers. Senbei reads their ZIP manifests first, follows nested APK entries when necessary, and extracts only `.so` and exact `global-metadata.dat` entries. Extraction streams directly to temporary files, so compressed and decompressed copies are not held in memory together.

## Validation

Every heuristic layout uses trial-and-validate. A candidate that fails structural checks, checksums, or table bounds is rejected and the next candidate is tried. A failed restore is reported as an error rather than emitting a silently damaged binary.

The PE integrity check verifies headers, section ranges, entry-point mapping, import names, relocation requirements, and managed metadata signatures. Android restoration validates ELF ranges, decoded container sizes, fixup bounds, and rebuilt dynamic tables.

## WebAssembly

The browser binding depends on `senbei-engine` through the I/O byte API. Native filesystem and Android package orchestration remain outside the browser workflow. Each browser unpack runs in a disposable worker because WebAssembly cannot recover from a caught panic in the same way as native code.
