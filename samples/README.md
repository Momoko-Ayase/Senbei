# Samples

This ignored directory is the optional local corpus used by the samples integration test. Protected binaries and restored outputs must never be committed.

Place protected `.exe` and `.dll` files, exact `global-metadata.dat` files, and matching `.exe._` or `.dll._` companion payloads here. A golden output may sit beside an input as `<base>.golden.<ext>`.

```text
samples/
  app.exe
  app.golden.exe
  managed.dll
  stub.dll
  stub.dll._
  stub.golden.dll
  global-metadata.dat
  global-metadata.golden.dat
```

Run `cargo test --release --test samples -- --nocapture`. A missing golden prints a warning; a mismatched golden or failed restore fails the test. An empty corpus is a no-op pass.

## Android Corpus

`samples/android/` may contain one extracted app tree per subdirectory. Protected libraries are restored through the real pipeline and can carry SHA-256 sidecars named `<base>.golden.so.sha256` and `<base>.golden.metadata.sha256`. An empty `<base>.restore-fails` marker documents a known restore gap.
