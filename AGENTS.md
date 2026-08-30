# AGENTS.md

Guidance for AI coding agents (and human contributors) working in this repo.

## Project

Senbei is a static unpacker for Crackproof-protected PE files: a Cargo
workspace with a pure, panic-free, no-I/O unpacker core (`senbei-pe/`, built
on `senbei-crypto/`), an il2cpp metadata de-obfuscator (`senbei-metadata/`),
filesystem/CLI orchestration (`senbei-io/`), the `senbei` binary
(`senbei-cli/`), and a WebAssembly browser frontend (`web/`, outside the
workspace). Read `docs/design.md` first.

## Commands

```cmd
cargo build --release            :: CLI (default member: senbei-cli)
cargo test --release --workspace :: full suite (golden corpus: samples/, git-ignored)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cd web && wasm-pack build --target web --release   :: browser build
```

The `samples/` corpus is user-managed and absent on CI; without it the
samples test is a no-op pass. `SENBEI_REQUIRE_SAMPLES=1` makes an absent
corpus fail (use this on a private CI that *does* have the corpus). Do not
delete `samples/` with `rm -rf` — it may be a junction; use git
worktree-aware cleanup.

## Hard rules

- **The unpacker core stays pure**: no file I/O, no `unsafe`, no panics across
  the public boundary, no platform-specific code. It must keep compiling to
  `wasm32-unknown-unknown` (`cargo check --target wasm32-unknown-unknown`).
- **`catch_unwind` does not work on wasm** (the prebuilt std can't unwind; a
  caught panic becomes a fatal `unreachable` trap). Native code may rely on
  `catch_unpack`, but any routing decision must also work without a catchable
  panic: spliced companion inputs route straight to the EXE pipeline, and the
  web app isolates every unpack in a disposable Web Worker, retrying trapped
  DLLs with `job::unpack_bytes_force_exe`. Never make correctness on wasm
  depend on catching a panic.
- **Byte-identical output is the contract.** Any pipeline change must re-run
  the full golden corpus; a byte mismatch on any golden is a regression.
- **Trial-and-validate, never trust a heuristic.** A silently wrong offset
  produces a silently broken binary — worse than an error. Every layout
  candidate must be validated (checksum / structural oracle) with fall-through
  to the next candidate.
- **Determinism under parallelism.** Block fan-out must stay byte-identical
  regardless of thread count (`SENBEI_THREADS=1` is the sequential reference).
- **Folder scanning: deny-list, never allow-list.** Targets are recognised by
  content, not extension, and can carry arbitrary names — there is no closed
  set of target extensions an allow-list could enumerate. Only known
  bulk-asset formats are excluded.
- **No binaries in the repo** — not as fixtures, not in commits. The only
  corpus is the local git-ignored `samples/`. (Issue attachments of
  protected inputs are fine when the user is authorized to share them, but
  never commit them.)

## Public-repo hygiene (important)

This is a public research repository. In code comments, docs, tests, and
commit messages:

- **Never name specific games, publishers, or product codenames.** Refer to
  build families generically ("older EXE-64 builds", "the marker-less
  layout", "external-companion builds"). Keep offsets/numbers — drop names.
- **Never name specific protected filenames** from real distributions. Test
  fixtures use generic names (`app.exe`, `managed.dll`, `daemon.exe`).
  Exceptions (platform-standard technology names, allowed): `il2cpp`,
  `Unity`, `global-metadata.dat`, the Crackproof magic `KONN`.
- **Never reference other tools, projects, implementations, or paths outside
  this repo.** Describe behavior and layout directly; do not mention prior
  art, porting, or where any algorithm came from.

## Conventions

- Comments explain *why* (layout rationale, observed variants, failure modes),
  not *what*.
- Rust 2024 edition; clippy-clean at `-D warnings`; rustfmt default style.
- CLI behavior (flags, exit codes, output naming) is documented in
  `docs/usage.md` — update the doc when changing behavior.
