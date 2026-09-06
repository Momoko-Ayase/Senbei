# Senbei Web

Senbei runs in the browser through the `senbei-wasm` crate. Files are read locally, unpacked in a worker, and offered back as downloads; no server receives input bytes.

## Features

- Protected `.exe` and `.dll` files produce `<name>.unpack.*` downloads.
- External `.exe._` and `.dll._` companions are paired by filename.
- `global-metadata.dat` produces `global-metadata.unpack.dat` when tokens change.
- Each output receives the same static integrity check as the CLI.

Every unpack uses a disposable Web Worker so a WebAssembly trap cannot freeze the page. A trapped DLL can be retried through the forced-EXE path, matching native routing.

## Build

```cmd
cd senbei-wasm
wasm-pack build --target web --release --out-dir ../web/pkg
```

Serve `web/` with a static HTTP server, for example `python -m http.server -d web 8000`. Opening `index.html` with `file://` does not work because browser modules require HTTP.

## Layout

`senbei-wasm/src/lib.rs` contains the bindings. `web/app.js` manages the dropzone and downloads, `web/worker.js` runs one unpack job per worker, and `web/pkg/` contains ignored wasm-pack output.
