//! Native/WASM parity over the same byte API.
//!
//! The browser binding calls `senbei_io::job::unpack_bytes`,
//! `..._force_exe`, `senbei_metadata::deobfuscate`, and
//! `senbei_engine::detect`. This test feeds the *same* fixtures to the native
//! functions and to a `wasm-pack --target nodejs` build of `senbei-wasm`, and
//! compares kind, byte length, SHA-256, remap counts, and suspect state.
//!
//! What this does NOT prove: it uses synthetic, hand-built fixtures only. It
//! says nothing about real protected PE recovery, real Android restoration, or
//! arbitrary third-party binaries — those need fixtures in the corpus and are
//! deliberately out of scope here.
//!
//! The test is opt-in because it needs a wasm build:
//!
//! ```text
//! cd senbei-wasm
//! wasm-pack build --target nodejs --release --out-dir ../target/wasm-parity/pkg
//! cd ..
//! SENBEI_WASM_PARITY=1 cargo test --release -p senbei-cli --test wasm_parity
//! ```
//!
//! `SENBEI_WASM_PKG` overrides the package directory; `SENBEI_NODE` overrides
//! the node binary. Private-corpus parity can be requested by setting
//! `SENBEI_WASM_PARITY_CORPUS=<manifest.json>`: every `pe`/`metadata` case in
//! that harness manifest is also compared, still without writing any output.

#[path = "support/fixtures.rs"]
mod fixtures;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn enabled() -> bool {
    match std::env::var("SENBEI_WASM_PARITY") {
        Ok(value) => !matches!(value.trim(), "" | "0"),
        Err(_) => false,
    }
}

fn wasm_pkg_dir() -> PathBuf {
    std::env::var_os("SENBEI_WASM_PKG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/wasm-parity/pkg")
        })
}

fn node_binary() -> String {
    std::env::var("SENBEI_NODE").unwrap_or_else(|_| "node".to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct WasmJob {
    op: &'static str,
    input: PathBuf,
    companion: Option<PathBuf>,
}

/// Run every job in one Node process and return the parsed result lines.
fn run_wasm(jobs: &[WasmJob]) -> Vec<Value> {
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasm_parity_driver.mjs");
    let mut child = Command::new(node_binary())
        .arg(&driver)
        .arg(wasm_pkg_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("start node: {error}"));
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for job in jobs {
            let line = json!({
                "op": job.op,
                "input": job.input.to_string_lossy(),
                "companion": job.companion.as_ref().map(|path| path.to_string_lossy().to_string()),
            });
            writeln!(stdin, "{line}").expect("write job");
        }
    }
    let output = child.wait_with_output().expect("wait for node");
    assert!(
        output.status.success(),
        "node driver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let results: Vec<Value> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("bad result {e}: {line}")))
        .collect();
    assert_eq!(results.len(), jobs.len(), "one result per job");
    results
}

fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn wasm_parity_is_opt_in_and_reports_why() {
    if !enabled() {
        eprintln!(
            "wasm parity skipped: set SENBEI_WASM_PARITY=1 and build senbei-wasm \
             with wasm-pack --target nodejs into target/wasm-parity/pkg"
        );
        return;
    }
    let pkg = wasm_pkg_dir();
    assert!(
        pkg.join("senbei_wasm.js").is_file(),
        "wasm package not found at {}; build it with wasm-pack",
        pkg.display()
    );
}

#[test]
fn synthetic_byte_transforms_match_wasm() {
    if !enabled() {
        eprintln!("wasm parity skipped (SENBEI_WASM_PARITY not set)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut jobs = Vec::new();
    let mut native = Vec::new();

    // Detection: every variant plus a non-target.
    for (name, dll, managed) in [
        ("native-exe.bin", false, false),
        ("native-dll.bin", true, false),
        ("managed-exe.bin", false, true),
        ("managed-dll.bin", true, true),
    ] {
        let bytes = fixtures::synthetic_crackproof_pe(dll, managed);
        let path = write_fixture(dir.path(), name, &bytes);
        jobs.push(WasmJob {
            op: "detect",
            input: path,
            companion: None,
        });
        native.push(native_detect(&bytes));
    }
    let plain = write_fixture(dir.path(), "plain.bin", &fixtures::synthetic_plain_pe());
    jobs.push(WasmJob {
        op: "detect",
        input: plain,
        companion: None,
    });
    native.push(json!({ "ok": true, "kind": null }));

    // Metadata: clean (idempotent) and obfuscated (5 rewrites).
    let mut metadata_native = Vec::new();
    for (name, bytes) in [
        ("clean.dat", fixtures::clean_metadata()),
        ("obfuscated.dat", fixtures::obfuscated_metadata()),
    ] {
        let path = write_fixture(dir.path(), name, &bytes);
        jobs.push(WasmJob {
            op: "metadata",
            input: path,
            companion: None,
        });
        let (out, report) = senbei_metadata::deobfuscate(&bytes).unwrap();
        metadata_native.push(json!({
            "ok": true,
            "bytes": out.len(),
            "sha256": sha256_hex(&out),
            "version": report.version,
            "methods": report.methods,
            "remapped": report.remapped,
            "modules": report.modules,
        }));
    }

    // Metadata probes: both sides must reject with the same error text.
    let mut probe_native = Vec::new();
    for (name, bytes) in fixtures::malformed_metadata_probes() {
        let path = write_fixture(dir.path(), &format!("probe-{name}.dat"), &bytes);
        jobs.push(WasmJob {
            op: "metadata",
            input: path,
            companion: None,
        });
        probe_native.push(match senbei_metadata::deobfuscate(&bytes) {
            Ok(_) => json!({ "ok": false, "error": "unexpected success" }),
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        });
    }

    // Native unpack for every detection fixture: both sides must agree on the
    // error wording for these non-protected/header-only inputs.
    let mut unpack_native = Vec::new();
    for (name, dll, managed) in [
        ("u-native-exe.bin", false, false),
        ("u-native-dll.bin", true, false),
        ("u-managed-exe.bin", false, true),
        ("u-managed-dll.bin", true, true),
    ] {
        let bytes = fixtures::synthetic_crackproof_pe(dll, managed);
        let path = write_fixture(dir.path(), name, &bytes);
        jobs.push(WasmJob {
            op: "unpack",
            input: path.clone(),
            companion: None,
        });
        unpack_native.push(match senbei_io::job::unpack_bytes(&bytes, None) {
            Ok(image) => json!({
                "ok": true,
                "kind": kind_name(image.kind),
                "bytes": image.bytes.len(),
                "sha256": sha256_hex(&image.bytes),
                "suspect": !image.integrity.ok(),
                "issues": image.integrity.issues,
                "companion": image.companion,
            }),
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        });
        // Force-exe is the browser's recovery path; it must agree too.
        let path2 = write_fixture(dir.path(), &format!("{name}.force"), &bytes);
        jobs.push(WasmJob {
            op: "unpack_force_exe",
            input: path2,
            companion: None,
        });
        unpack_native.push(match senbei_io::job::unpack_bytes_force_exe(&bytes, None) {
            Ok(image) => json!({
                "ok": true,
                "kind": kind_name(image.kind),
                "bytes": image.bytes.len(),
                "sha256": sha256_hex(&image.bytes),
                "suspect": !image.integrity.ok(),
                "issues": image.integrity.issues,
                "companion": image.companion,
            }),
            Err(error) => json!({ "ok": false, "error": error.to_string() }),
        });
    }

    let results = run_wasm(&jobs);
    // Negative control: the driver must have produced a real SHA-256 for the
    // clean metadata. If the WASM call silently no-op'd, this would not match
    // the native digest and the control would fail before the loop below.
    let clean_index = jobs
        .iter()
        .position(|job| job.op == "metadata")
        .expect("metadata jobs exist");
    let native_clean = &metadata_native[0];
    assert_eq!(
        results[clean_index]["sha256"], native_clean["sha256"],
        "negative control: wasm metadata digest must match native"
    );
    let all_native: Vec<Value> = native
        .into_iter()
        .chain(metadata_native)
        .chain(probe_native)
        .chain(unpack_native)
        .collect();
    for (index, (want, got)) in all_native.iter().zip(&results).enumerate() {
        assert_eq!(
            want,
            got,
            "parity mismatch at job {index} ({}):\nnative {want}\nwasm   {got}",
            jobs.get(index).map(|job| job.op).unwrap_or("?")
        );
    }
}

fn native_detect(bytes: &[u8]) -> Value {
    match senbei_engine::detect(bytes) {
        Some(detected) => json!({ "ok": true, "kind": kind_name(detected.kind) }),
        None => json!({ "ok": true, "kind": null }),
    }
}

fn kind_name(kind: senbei_engine::Kind) -> &'static str {
    match kind {
        senbei_engine::Kind::NativeExe => "native-exe",
        senbei_engine::Kind::ManagedExe => "managed-exe",
        senbei_engine::Kind::NativeDll => "native-dll",
        senbei_engine::Kind::ManagedDll => "managed-dll",
    }
}

/// Optional: compare private corpus cases as well, when a harness manifest and
/// the gate are both provided. Restored bytes still go nowhere.
#[test]
fn optional_private_corpus_parity() {
    if !enabled() {
        return;
    }
    let Some(manifest) = std::env::var_os("SENBEI_WASM_PARITY_CORPUS") else {
        return;
    };
    let manifest = PathBuf::from(manifest);
    let report = harness_run(&manifest);
    let base = PathBuf::from(report["manifest"]["base_dir"].as_str().unwrap_or("."));
    let mut jobs = Vec::new();
    let mut native = Vec::new();
    for case in report["cases"].as_array().cloned().unwrap_or_default() {
        let kind = case["kind"].as_str().unwrap_or("");
        let status = case["status"].as_str().unwrap_or("");
        if status != "pass" {
            continue;
        }
        let input = base.join(case["input"].as_str().unwrap_or(""));
        let companion = case["companion"].as_str().map(|path| base.join(path));
        match kind {
            "pe" => {
                let bytes = std::fs::read(&input).expect("read corpus input");
                let comp = companion
                    .as_ref()
                    .map(|path| std::fs::read(path).expect("read companion"));
                jobs.push(WasmJob {
                    op: "unpack",
                    input: input.clone(),
                    companion: companion.clone(),
                });
                native.push(
                    match senbei_io::job::unpack_bytes(&bytes, comp.as_deref()) {
                        Ok(image) => json!({
                            "ok": true,
                            "kind": kind_name(image.kind),
                            "bytes": image.bytes.len(),
                            "sha256": sha256_hex(&image.bytes),
                            "suspect": !image.integrity.ok(),
                            "issues": image.integrity.issues,
                            "companion": image.companion,
                        }),
                        Err(error) => json!({ "ok": false, "error": error.to_string() }),
                    },
                );
            }
            "metadata" => {
                let bytes = std::fs::read(&input).expect("read corpus metadata");
                jobs.push(WasmJob {
                    op: "metadata",
                    input,
                    companion: None,
                });
                native.push(match senbei_metadata::deobfuscate(&bytes) {
                    Ok((out, detail)) => json!({
                        "ok": true,
                        "bytes": out.len(),
                        "sha256": sha256_hex(&out),
                        "version": detail.version,
                        "methods": detail.methods,
                        "remapped": detail.remapped,
                        "modules": detail.modules,
                    }),
                    Err(error) => json!({ "ok": false, "error": error.to_string() }),
                });
            }
            _ => {}
        }
    }
    if jobs.is_empty() {
        eprintln!("private corpus parity: no eligible passing cases");
        return;
    }
    let results = run_wasm(&jobs);
    for (want, got) in native.iter().zip(&results) {
        assert_eq!(want, got, "private corpus parity mismatch");
    }
}

/// Minimal in-process harness invocation shared with the example's module.
fn harness_run(manifest: &Path) -> Value {
    #[path = "support/harness.rs"]
    mod harness;
    let report = harness::run(
        manifest,
        &harness::RunOptions {
            commit: None,
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        },
    );
    serde_json::to_value(report).expect("report to JSON")
}
