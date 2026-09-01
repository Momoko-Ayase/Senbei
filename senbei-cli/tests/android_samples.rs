//! Corpus test over the user-managed Android samples.
//!
//! Each immediate subdirectory of `samples/android/` that contains a `lib/`
//! tree is one app-package sample (an extracted APK layout). For every
//! protected AArch64 `.so` found by content probe, the test runs the real
//! restore pipeline and checks the result:
//!
//! - `<name>.golden.so.sha256` next to the input pins the restored bytes
//!   (byte-identity through the digest; absent sidecar -> WARNING).
//! - `<name>.restore-fails` (empty marker) documents an input whose restore
//!   is known to fail; the test then *requires* failure, so a future fix
//!   surfaces as a test failure too. Without the marker a failed restore is
//!   a test failure.
//! - A restored library carrying an unwrappable embedded metadata blob must
//!   produce one, pinned by `<name>.golden.metadata.sha256`.
//!
//! The folder-mode driver is then run over each app dir to exercise the
//! scan/restore/write path end to end; its error count must equal the number
//! of marked known-failures.
//!
//! The corpus is git-ignored and absent on CI (no binaries in the repo);
//! `SENBEI_REQUIRE_SAMPLES=1` turns an absent corpus into a failure, and
//! `SENBEI_ANDROID_SAMPLES` overrides the corpus location.

mod common;

use std::path::{Path, PathBuf};

use senbei_io::{android, job};

fn corpus_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("SENBEI_ANDROID_SAMPLES") {
        return PathBuf::from(dir);
    }
    common::samples_dir().join("android")
}

/// Immediate subdirectories of `root` that hold an app tree (a `lib/`
/// folder) — research notes, dumps, and other non-app material in the corpus
/// never match.
fn app_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("read {}: {e}", root.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir() && path.join("lib").is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// Every regular `.so` below `dir`, skipping previous output trees.
fn collect_so_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| !name.eq_ignore_ascii_case("unpack"))
            {
                collect_so_files(&path, out);
            }
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
        {
            out.push(path);
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(data);
    format!("{:x}", digest.finalize())
}

/// `<stem>.golden.so.sha256` next to `input`.
fn golden_sidecar(input: &Path, artifact: &str) -> PathBuf {
    let file = input.file_name().unwrap().to_string_lossy();
    let stem = file.strip_suffix(".so").unwrap_or(&file);
    input.with_file_name(format!("{stem}.golden.{artifact}.sha256"))
}

fn read_sidecar(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_ascii_lowercase())
}

#[test]
fn android_samples_restore_against_goldens() {
    let root = corpus_dir();
    // Same opt-in gate as the PE corpus test: an absent corpus is a no-op
    // pass unless CI explicitly requires it.
    let require = std::env::var_os("SENBEI_REQUIRE_SAMPLES").is_some();
    if !root.is_dir() {
        assert!(
            !require,
            "android samples: {} does not exist — corpus required (CI)",
            root.display()
        );
        eprintln!(
            "android samples: {} does not exist, nothing to test",
            root.display()
        );
        return;
    }
    let apps = app_dirs(&root);
    if apps.is_empty() {
        assert!(
            !require,
            "android samples: no app trees under {} — corpus required (CI)",
            root.display()
        );
        eprintln!("android samples: no app trees under {}", root.display());
        return;
    }

    let mut passed = 0usize;
    let mut warnings: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for app in &apps {
        let mut so_files = Vec::new();
        collect_so_files(app, &mut so_files);
        let protected: Vec<PathBuf> = so_files
            .into_iter()
            .filter(|path| android::is_protected_so_file(path))
            .collect();
        let mut known_failures = 0usize;

        for input in &protected {
            let name = input.file_name().unwrap().to_string_lossy().to_string();
            let known_fails = input.with_file_name(format!(
                "{}.restore-fails",
                name.strip_suffix(".so").unwrap_or(&name)
            ));
            let temp = tempfile::tempdir().expect("tempdir");
            let dest = temp.path().join("restored.so");
            match android::restore_so_file(input, &dest, false) {
                Ok(embedded) => {
                    if known_fails.is_file() {
                        failures.push(format!(
                            "{name}: restore succeeded but a restore-fails marker exists \
                             (delete the marker — the gap is fixed)"
                        ));
                        continue;
                    }
                    let bytes = std::fs::read(&dest).expect("read restored output");
                    match read_sidecar(&golden_sidecar(input, "so")) {
                        Some(expected) if expected == sha256_hex(&bytes) => passed += 1,
                        Some(expected) => failures.push(format!(
                            "{name}: restored bytes differ from golden\n  expected sha256 {expected}\n  actual   sha256 {}",
                            sha256_hex(&bytes)
                        )),
                        None => warnings.push(format!(
                            "{name}: no golden sidecar — restored sha256 {}",
                            sha256_hex(&bytes)
                        )),
                    }
                    if let Some(blob) = embedded {
                        match read_sidecar(&golden_sidecar(input, "metadata")) {
                            Some(expected) if expected == sha256_hex(&blob) => {}
                            Some(expected) => failures.push(format!(
                                "{name}: embedded metadata differs from golden\n  expected sha256 {expected}\n  actual   sha256 {}",
                                sha256_hex(&blob)
                            )),
                            None => warnings.push(format!(
                                "{name}: no embedded-metadata sidecar — sha256 {}",
                                sha256_hex(&blob)
                            )),
                        }
                    }
                }
                Err(error) => {
                    if known_fails.is_file() {
                        known_failures += 1;
                    } else {
                        failures.push(format!("{name}: restore failed: {error:#}"));
                    }
                }
            }
        }

        // Folder-mode smoke run: the scan must route every protected library,
        // and only the marked known-failures may error.
        let out_temp = tempfile::tempdir().expect("tempdir");
        match job::run_folder_opts(app, Some(out_temp.path()), 2, false, true, false) {
            Ok(summary) => {
                if summary.errors != known_failures {
                    failures.push(format!(
                        "{}: folder run errors {} != known-failure markers {known_failures}",
                        app.display(),
                        summary.errors
                    ));
                }
                if summary.unpacked < protected.len().saturating_sub(known_failures) {
                    failures.push(format!(
                        "{}: folder run restored {} libraries, per-file pass found {} ({} known-failing)",
                        app.display(),
                        summary.unpacked,
                        protected.len(),
                        known_failures
                    ));
                }
            }
            Err(error) => failures.push(format!("{}: folder run failed: {error:#}", app.display())),
        }
    }

    for warning in &warnings {
        eprintln!("WARNING: {warning}");
    }
    eprintln!(
        "android samples: {} app tree(s) — {passed} pass, {} warning(s), {} failure(s)",
        apps.len(),
        warnings.len(),
        failures.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
