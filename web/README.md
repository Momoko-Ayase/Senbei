# Senbei web

Senbei running in the browser: the unpacker core compiled to WebAssembly,
wrapped in a small static page. Everything is client-side — files are read
into the page, unpacked locally, and offered back as downloads. Nothing is
uploaded; there is no server component.

## Features

- A legal notice is shown as a blocking dialog on page open; the tool is
  unusable until it is acknowledged.
- Dropped files land in a file list, not unpacked immediately: review the
  batch, remove mistakes, then press **Unpack**. A module and its `._`
  companion can be dropped in any order (or in separate drops) — companions
  auto-pair by name (`Foo.dll._` → `Foo.dll`) and show as a badge on the
  module's row; removing a module removes its companion too.
- Rows show state at a glance: black while staged, an animated blue bar
  while unpacking, green on success (with a download button) and red on
  failure.
- Drop one or more protected `.exe` / `.dll` modules → get `<name>.unpack.*`
  downloads.
- Drop an il2cpp `global-metadata.dat` → de-obfuscated
  `global-metadata.unpack.dat` (only when tokens actually change).
- Each output passes the same static integrity check as the CLI; suspect
  outputs are flagged with the specific defects found.

## Architecture notes

- Every unpack runs in a **disposable Web Worker** (fresh wasm instance per
  file): the UI stays responsive on 100 MB+ modules, and a wasm trap is
  isolated to that worker.
- **Why workers matter for correctness:** the DLL-first routing probe relies
  on `catch_unwind` to reject EXE-shell-layout DLLs, and panics cannot be
  caught in WebAssembly — the probe traps the whole call. When a DLL unpack
  traps, the app retries once in a new worker with the forced-EXE pipeline
  (`unpack_file_force_exe`), reproducing the CLI's dll-first/exe-fallback
  outcome. Spliced companion inputs skip the probe entirely (they are always
  EXE-shell layout), exactly like the CLI.
- Rust panic messages are forwarded to the browser console
  (`console_error_panic_hook`) — check devtools when reporting an issue.

## Building

Requires a Rust toolchain (`rust-toolchain.toml` in the repo root pins one,
including the `wasm32-unknown-unknown` target) and
[wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```cmd
cd web
wasm-pack build --target web --release
```

This produces `web/pkg/` (git-ignored). Then serve the `web/` directory with
any static file server and open `index.html`:

```cmd
python -m http.server -d web 8000
:: -> http://localhost:8000
```

(Opening `index.html` via `file://` won't work — ES modules require HTTP.)

## Layout

```
web/
├── Cargo.toml     senbei-web cdylib crate (depends on the senbei lib)
├── src/lib.rs     #[wasm_bindgen] bindings: detect / unpack_file /
│                  unpack_file_force_exe / deobfuscate_metadata
├── index.html     the page
├── app.js         dropzone, file list, worker orchestration, downloads
├── worker.js      one-shot unpack worker (fresh wasm instance per file)
├── style.css
└── pkg/           wasm-pack output (git-ignored)
```
