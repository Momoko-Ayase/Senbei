//! Native/WASM parity over the same byte API.
//!
//! The browser binding calls `senbei_io::job::unpack_bytes_profiled`,
//! `..._force_exe_profiled`, `senbei_io::android::restore_library_bytes`,
//! `senbei_io::android::restore_metadata_bytes_profiled`, and
//! `senbei_engine::detect`. This test feeds the *same* fixtures to the native
//! functions and to a `wasm-pack --target nodejs` build of `senbei-wasm`, and
//! compares the recovery profile, kind, byte length, SHA-256, remap counts,
//! and suspect state.
//!
//! What the default run does NOT prove: it uses synthetic, hand-built fixtures
//! only. It says nothing about real protected PE recovery, real Android
//! restoration, or arbitrary third-party binaries. Those are compared only
//! when a private corpus is named (see below).
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
//! With `SENBEI_ANDROID_SAMPLES=<dir>` set, every `.so` of every app tree in
//! that directory is restored on both sides and compared as well.

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

/// The ceilings the browser binding restores under. They must stay the ones
/// in `senbei-wasm/src/lib.rs`, or the two sides stop at different points.
const BROWSER_LIMITS: senbei_engine::android::ResourceLimits =
    senbei_engine::android::ResourceLimits {
        max_entry_bytes: 1 << 30,
        max_total_bytes: 4 << 30,
        max_entries: 100_000,
        max_depth: 32,
    };

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

/// What the binding's `unpack_pe` reports, computed natively.
fn native_unpack(bytes: &[u8], companion: Option<&[u8]>, force_exe: bool) -> Value {
    let (profile, result) = if force_exe {
        senbei_io::job::unpack_bytes_force_exe_profiled(bytes, companion)
    } else {
        senbei_io::job::unpack_bytes_profiled(bytes, companion)
    };
    match result {
        Ok(image) => json!({
            "ok": true,
            "kind": kind_name(image.kind),
            "bytes": image.bytes.len(),
            "sha256": sha256_hex(&image.bytes),
            "suspect": !image.integrity.ok(),
            "issues": image.integrity.issues.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "companion": image.companion,
            "profile": profile,
        }),
        Err(error) => json!({
            "ok": false,
            "error": error.message().text(),
            "profile": profile,
        }),
    }
}

/// What the binding's `restore_metadata` reports, computed natively.
fn native_metadata(bytes: &[u8]) -> Value {
    use senbei_io::android::{MetadataOutcome, ModuleBinding, restore_metadata_bytes_profiled};
    let (profile, outcome) = restore_metadata_bytes_profiled(bytes, ModuleBinding::None);
    let reported = |status: &str,
                    out: Option<&[u8]>,
                    report: &senbei_metadata::Report,
                    layout: &senbei_engine::LayoutKind| {
        json!({
            "ok": true,
            "status": status,
            "bytes": out.map_or(0, <[u8]>::len),
            "sha256": out.map(sha256_hex),
            "version": report.version,
            "methods": report.methods,
            "remapped": report.remapped,
            "modules": report.modules,
            "layout": layout,
            "profile": &profile,
        })
    };
    match &outcome {
        MetadataOutcome::Restored {
            bytes,
            report,
            layout,
        } => reported("recovered", Some(bytes), report, layout),
        MetadataOutcome::Unchanged { report, layout } => {
            reported("unchanged", None, report, layout)
        }
        MetadataOutcome::Unsupported { .. } => json!({
            "ok": true,
            "status": "unsupported",
            "bytes": 0,
            "sha256": null,
            "version": profile.observed.metadata_version,
            "methods": null,
            "remapped": null,
            "modules": null,
            "layout": null,
            "profile": &profile,
        }),
        MetadataOutcome::Failed(error) => json!({
            "ok": false,
            "error": error.text(),
            "profile": &profile,
        }),
    }
}

/// What the binding's `restore_library` reports, computed natively.
fn native_library(bytes: &[u8]) -> Value {
    use senbei_io::android::{LibraryOutcome, restore_library_bytes};
    let (profile, outcome) = restore_library_bytes(bytes, false, &BROWSER_LIMITS);
    match outcome {
        LibraryOutcome::Restored(restored) => json!({
            "ok": true,
            "status": "recovered",
            "bytes": restored.image.len(),
            "sha256": sha256_hex(&restored.image),
            "embedded": restored.embedded_metadata.as_deref().map(sha256_hex),
            "module": restored.method_index_module.as_deref().map(sha256_hex),
            "elf": restored.elf,
            "profile": profile,
        }),
        LibraryOutcome::NotProtected => json!({
            "ok": true,
            "status": "not_protected",
            "bytes": 0,
            "sha256": null,
            "embedded": null,
            "module": null,
            "elf": null,
            "profile": profile,
        }),
        LibraryOutcome::Failed(error) => json!({
            "ok": false,
            "error": error.text(),
            "profile": profile,
        }),
    }
}

fn assert_parity(jobs: &[WasmJob], native: &[Value], results: &[Value]) {
    assert_eq!(native.len(), results.len(), "one native result per job");
    for (index, (want, got)) in native.iter().zip(results).enumerate() {
        assert_eq!(
            want,
            got,
            "parity mismatch at job {index} ({} {}):\nnative {want}\nwasm   {got}",
            jobs[index].op,
            jobs[index].input.display()
        );
    }
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
    let mut job = |op: &'static str, name: &str, bytes: &[u8]| {
        jobs.push(WasmJob {
            op,
            input: write_fixture(dir.path(), name, bytes),
            companion: None,
        });
    };
    let variants = [
        ("native-exe.bin", false, false),
        ("native-dll.bin", true, false),
        ("managed-exe.bin", false, true),
        ("managed-dll.bin", true, true),
    ];

    // Detection: every variant plus a non-target.
    for (name, dll, managed) in variants {
        let bytes = fixtures::synthetic_crackproof_pe(dll, managed);
        job("detect", name, &bytes);
        native.push(native_detect(&bytes));
    }
    let plain = fixtures::synthetic_plain_pe();
    job("detect", "plain.bin", &plain);
    native.push(json!({ "ok": true, "kind": null }));

    // Metadata: clean (validated, nothing to rewrite) and obfuscated (5
    // rewrites), then blobs both sides must refuse in the same words.
    let metadata_start = native.len();
    for (name, bytes) in [
        ("clean.dat", fixtures::clean_metadata()),
        ("obfuscated.dat", fixtures::obfuscated_metadata()),
    ] {
        job("metadata", name, &bytes);
        native.push(native_metadata(&bytes));
    }
    for (name, bytes) in fixtures::malformed_metadata_probes() {
        job("metadata", &format!("probe-{name}.dat"), &bytes);
        native.push(native_metadata(&bytes));
    }

    // Unpack for every detection fixture, by both routes: the two sides must
    // agree on the profile and the error wording for these header-only inputs.
    // The EXE-only route is the page's retry after a trap.
    for (name, dll, managed) in variants {
        let bytes = fixtures::synthetic_crackproof_pe(dll, managed);
        job("unpack", &format!("u-{name}"), &bytes);
        native.push(native_unpack(&bytes, None, false));
        job("unpack_force_exe", &format!("f-{name}"), &bytes);
        native.push(native_unpack(&bytes, None, true));
    }

    // Library: inputs that are not protected AArch64 libraries.
    for (name, bytes) in [
        ("plain.so", plain.clone()),
        ("stub.so", b"\x7fELF\x02\x01\x01".to_vec()),
        ("empty.so", Vec::new()),
    ] {
        job("library", name, &bytes);
        native.push(native_library(&bytes));
    }

    let results = run_wasm(&jobs);
    // Negative control: the driver must have rewritten the obfuscated blob and
    // hashed real bytes. If the WASM call silently did nothing, the status and
    // digest would not be these.
    assert_eq!(
        results[metadata_start]["status"], "unchanged",
        "clean metadata needs no rewrite"
    );
    let rewritten = &results[metadata_start + 1];
    assert_eq!(rewritten["status"], "recovered", "{rewritten}");
    assert_eq!(rewritten["remapped"], 5, "{rewritten}");
    assert!(rewritten["sha256"].is_string());
    assert_eq!(
        rewritten["sha256"],
        native[metadata_start + 1]["sha256"],
        "negative control: wasm metadata digest must match native"
    );
    assert_parity(&jobs, &native, &results);
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
                native.push(native_unpack(&bytes, comp.as_deref(), false));
                jobs.push(WasmJob {
                    op: "unpack",
                    input,
                    companion,
                });
            }
            "metadata" => {
                let bytes = std::fs::read(&input).expect("read corpus metadata");
                native.push(native_metadata(&bytes));
                jobs.push(WasmJob {
                    op: "metadata",
                    input,
                    companion: None,
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
    assert_parity(&jobs, &native, &results);
}

/// Every `.so` below `dir`, skipping previous output trees.
fn collect_libraries(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| !name.eq_ignore_ascii_case("unpack"))
            {
                collect_libraries(&path, out);
            }
        } else if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("so"))
        {
            out.push(path);
        }
    }
}

/// Optional: restore every library of the private Android corpus on both
/// sides. Each app tree is an immediate subdirectory with a `lib/` folder.
#[test]
fn optional_android_corpus_parity() {
    if !enabled() {
        return;
    }
    let Some(root) = std::env::var_os("SENBEI_ANDROID_SAMPLES").map(PathBuf::from) else {
        return;
    };
    let mut apps: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.join("lib").is_dir())
        .collect();
    apps.sort();
    let mut libraries = Vec::new();
    for app in apps {
        collect_libraries(&app.join("lib"), &mut libraries);
    }
    if libraries.is_empty() {
        eprintln!(
            "android corpus parity: no libraries under {}",
            root.display()
        );
        return;
    }
    let mut jobs = Vec::new();
    let mut native = Vec::new();
    for input in libraries {
        let bytes = std::fs::read(&input).expect("read corpus library");
        native.push(native_library(&bytes));
        jobs.push(WasmJob {
            op: "library",
            input,
            companion: None,
        });
    }
    let restored = native
        .iter()
        .filter(|result| result["status"] == "recovered")
        .count();
    eprintln!(
        "android corpus parity: {} libraries, {restored} restored natively",
        jobs.len()
    );
    let results = run_wasm(&jobs);
    assert_parity(&jobs, &native, &results);
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
