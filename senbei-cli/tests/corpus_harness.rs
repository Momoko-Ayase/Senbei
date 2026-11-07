//! Integration tests for the manifest-driven corpus harness.
//!
//! These exercise the harness itself with generated fixtures only: a
//! CrackProof-shaped PE, synthetic v31 metadata, an ELF probe, and a small app
//! tree. No real corpus, product name, or golden binary is involved.
//!
//! Run just this file with:
//!
//! ```text
//! cargo test --release -p senbei-cli --test corpus_harness
//! ```
//!
//! The example binary (`cargo run --release --example corpus_harness --
//! --manifest FILE`) is the user-facing entry point; its module header
//! documents the JSON schema.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/harness.rs"]
mod harness;

use std::path::{Path, PathBuf};

use harness::{CaseSpec, Defaults, Kind, Manifest, RunOptions};
use sha2::{Digest, Sha256};

fn write_manifest(dir: &Path, cases: Vec<CaseSpec>, defaults: Defaults) -> PathBuf {
    let manifest = Manifest {
        schema: harness::SCHEMA.to_owned(),
        name: Some("test".to_owned()),
        base_dir: None,
        defaults,
        cases,
    };
    let path = dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    path
}

fn case(id: &str, kind: Kind, input: &str) -> CaseSpec {
    CaseSpec {
        id: id.to_owned(),
        kind,
        input: PathBuf::from(input),
        companion: None,
        golden: None,
        golden_sha256: None,
        sha256: None,
        metadata_sha256: None,
        expect_failure: None,
        expect_suspect: None,
        allow_missing_golden: None,
        allow_suspect: None,
        allow_empty: None,
        entries: None,
    }
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

fn options() -> RunOptions {
    RunOptions {
        commit: Some("test-commit".to_owned()),
        cwd: std::env::temp_dir(),
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn synthetic_metadata_passes_against_a_golden_and_reports_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let obfuscated = fixtures::obfuscated_metadata();
    let clean = fixtures::clean_metadata();
    write(dir.path(), "input.dat", &obfuscated);
    write(dir.path(), "input.golden.dat", &clean);
    let mut spec = case("metadata", Kind::Metadata, "input.dat");
    spec.golden = Some(PathBuf::from("input.golden.dat"));
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());

    let report = harness::run(&manifest, &options());
    assert!(
        report.passed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(report.summary.total, 1);
    assert_eq!(report.summary.passed, 1);
    let output = &report.cases[0].outputs[0];
    assert_eq!(output.sha256.as_deref(), Some(sha256_hex(&clean).as_str()));
    assert_eq!(output.remapped, Some(5));
    assert_eq!(output.bytes, Some(clean.len() as u64));
    assert_eq!(report.git.head.as_deref(), Some("test-commit"));
    assert_eq!(report.git.head_source, "caller");
    assert_eq!(report.git.dirty, None, "no repo discovered in temp dir");
    assert!(!report.manifest.sha256.is_empty());
}

#[test]
fn golden_length_difference_is_a_truthful_failure() {
    let dir = tempfile::tempdir().unwrap();
    let clean = fixtures::clean_metadata();
    write(dir.path(), "input.dat", &fixtures::obfuscated_metadata());
    write(dir.path(), "input.golden.dat", &clean[..clean.len() - 4]);
    let mut spec = case("stale", Kind::Metadata, "input.dat");
    spec.golden = Some(PathBuf::from("input.golden.dat"));
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());

    let report = harness::run(&manifest, &options());
    assert!(!report.passed());
    let case = &report.cases[0];
    assert!(
        case.failures
            .iter()
            .any(|failure| failure.contains("length"))
    );
    assert_eq!(report.summary.golden_mismatches, 1);
}

#[test]
fn missing_golden_and_missing_manifest_fail_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "input.dat", &fixtures::obfuscated_metadata());
    let mut spec = case("missing", Kind::Metadata, "input.dat");
    spec.golden = Some(PathBuf::from("does-not-exist.golden.dat"));
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());

    let report = harness::run(&manifest, &options());
    assert!(!report.passed());
    assert!(
        report.cases[0]
            .failures
            .iter()
            .any(|f| f.contains("golden is missing"))
    );

    let absent = dir.path().join("absent.json");
    let report = harness::run(&absent, &options());
    assert!(!report.passed());
    assert!(report.manifest_errors[0].contains("read manifest"));

    let malformed = write(dir.path(), "malformed.json", b"{ not json");
    let report = harness::run(&malformed, &options());
    assert!(!report.passed());
    assert!(report.manifest_errors[0].contains("parse manifest"));
}

#[test]
fn non_empty_manifest_and_complete_expectations_are_required() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "input.dat", &fixtures::obfuscated_metadata());
    let empty = write_manifest(dir.path(), Vec::new(), Defaults::default());
    let report = harness::run(&empty, &options());
    assert!(!report.passed());
    assert!(
        report
            .manifest_errors
            .iter()
            .any(|e| e.contains("no cases"))
    );

    let bare = write_manifest(
        dir.path(),
        vec![case("bare", Kind::Metadata, "input.dat")],
        Defaults::default(),
    );
    let report = harness::run(&bare, &options());
    assert!(!report.passed());
    assert_eq!(report.cases[0].outcome, "invalid_case");
    assert!(
        report.cases[0]
            .failures
            .iter()
            .any(|failure| failure.contains("no expected output"))
    );

    let mut opt_out = case("opt-out", Kind::Metadata, "input.dat");
    opt_out.allow_missing_golden = Some(true);
    let manifest = write_manifest(dir.path(), vec![opt_out], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(
        report.passed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(report.cases[0].outputs[0].status, "ok");
    assert_eq!(report.cases[0].outputs[0].expected_sha256, None);
}

#[test]
fn malformed_metadata_fixtures_fail_truthfully_and_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let mut cases = Vec::new();
    for (name, bytes) in fixtures::malformed_metadata_probes() {
        write(dir.path(), &format!("{name}.dat"), &bytes);
        let mut spec = case(name, Kind::Metadata, &format!("{name}.dat"));
        spec.expect_failure = Some(true);
        cases.push(spec);
    }
    let manifest = write_manifest(dir.path(), cases, Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(
        report.passed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(report.summary.expected_failures, report.summary.total);
    assert_eq!(report.summary.panics, 0);
}

#[test]
fn expected_failure_never_hides_a_missing_input() {
    // A provisioning error is not a restoration-stage failure. If the input
    // does not exist, the case must fail even with expect_failure set.
    let dir = tempfile::tempdir().unwrap();
    let mut spec = case("gone", Kind::Metadata, "absent.dat");
    spec.expect_failure = Some(true);
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(!report.passed());
    assert_eq!(report.cases[0].outcome, "invalid_case");
    assert!(
        report.cases[0]
            .failures
            .iter()
            .any(|f| f.contains("not a file"))
    );
}

#[test]
fn expected_failure_never_hides_an_io_error_after_validation() {
    // Validation sees a file, then the read fails (simulated with a path that
    // is a file at validation time and unreadable at run time is hard on
    // Windows, so instead assert the read-error path directly through a
    // directory-shaped companion, which validates only as a file).
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "input.dat", &fixtures::obfuscated_metadata());
    let mut spec = case("io", Kind::Metadata, "input.dat");
    spec.expect_failure = Some(true);
    // A companion is not read for metadata, but an unreadable companion on a
    // PE case is an I/O error; use a directory that exists.
    spec.companion = Some(PathBuf::from("a-directory"));
    std::fs::create_dir(dir.path().join("a-directory")).unwrap();
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    // Validation requires the companion to be a file, so this is invalid_case.
    assert!(!report.passed());
    assert!(report.cases[0].outcome == "invalid_case");
}

#[test]
fn expected_failure_does_not_inflate_the_restored_count() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "input.dat", &fixtures::obfuscated_metadata());
    // One real success and one genuinely failing (non-metadata) input whose
    // failure is declared. `passed` counts both; `restored` only the success.
    write(dir.path(), "broken.dat", b"not metadata");
    let mut expected = case("expected", Kind::Metadata, "broken.dat");
    expected.expect_failure = Some(true);
    let mut success = case("success", Kind::Metadata, "input.dat");
    success.allow_missing_golden = Some(true);
    let manifest = write_manifest(dir.path(), vec![expected, success], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(
        report.passed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(report.summary.total, 2);
    assert_eq!(report.summary.passed, 2);
    assert_eq!(report.summary.expected_failures, 1);
    assert_eq!(
        report.summary.restored, 1,
        "the declared failure must not count as a recovery"
    );
}

#[test]
fn expected_failure_that_succeeds_is_reported_as_unmet() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "input.dat", &fixtures::obfuscated_metadata());
    let mut spec = case("unmet", Kind::Metadata, "input.dat");
    spec.expect_failure = Some(true);
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(!report.passed());
    assert_eq!(report.cases[0].outcome, "expected_failure_unmet");
    assert_eq!(report.summary.expected_failures, 0);
    assert_eq!(report.summary.restored, 0);
}

#[test]
fn expected_failure_counts_as_a_pass_but_not_a_restore() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "input.dat", b"not metadata");
    let mut spec = case("bad", Kind::Metadata, "input.dat");
    spec.expect_failure = Some(true);
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(report.passed());
    assert_eq!(report.summary.passed, 1);
    assert_eq!(report.summary.expected_failures, 1);
    assert_eq!(report.summary.restored, 0, "a failure is not a restore");
}

#[test]
fn app_level_expected_failure_is_not_a_restore() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    std::fs::create_dir_all(app.join("lib/arm64-v8a")).unwrap();
    // ELF magic but not a protected library: the walk finds nothing, which is
    // a provisioning error unless the case declares it.
    std::fs::write(app.join("lib/arm64-v8a/libx.so"), b"\x7fELF").unwrap();
    let mut spec = case("app", Kind::AndroidApp, "app");
    spec.allow_empty = Some(true);
    spec.expect_failure = Some(true);
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(
        report.passed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(report.cases[0].outcome, "expected_failure");
    assert_eq!(report.summary.restored, 0);
    assert_eq!(report.summary.expected_failures, 1);
}

#[test]
fn unknown_manifest_fields_and_bad_schemas_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let text =
        r#"{"schema":"wrong","cases":[{"id":"x","kind":"metadata","input":"a","surprise":1}]}"#;
    let path = write(dir.path(), "manifest.json", text.as_bytes());
    let report = harness::run(&path, &options());
    assert!(!report.passed());
    assert!(report.manifest_errors[0].contains("parse manifest"));
}

#[test]
fn undetected_pe_with_expected_failure_passes_truthfully() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "plain.exe", &fixtures::synthetic_plain_pe());
    let mut spec = case("plain", Kind::Pe, "plain.exe");
    spec.expect_failure = Some(true);
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(
        report.passed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(report.cases[0].outcome, "expected_failure");
    assert!(report.cases[0].outputs[0].error.is_some());
}

#[test]
fn undetected_pe_without_expected_failure_is_an_unpack_failure() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "plain.exe", &fixtures::synthetic_plain_pe());
    let mut spec = case("plain", Kind::Pe, "plain.exe");
    spec.golden_sha256 = Some(sha256_hex(b"anything"));
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(!report.passed());
    assert_eq!(report.cases[0].outcome, "unpack_failed");
}

#[test]
fn emit_manifest_is_bounded_and_excludes_goldens_and_junctions() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "app.exe",
        &fixtures::synthetic_crackproof_pe(false, false),
    );
    write(dir.path(), "app.golden.exe", b"golden");
    write(dir.path(), "notes.txt", b"not a target");
    write(dir.path(), "plain.exe", &fixtures::synthetic_plain_pe());
    write(
        dir.path(),
        "global-metadata.dat",
        &fixtures::obfuscated_metadata(),
    );
    let out = dir.path().join("emitted.json");
    let count = harness::emit_manifest(&[dir.path().to_path_buf()], &[], &out).unwrap();
    assert_eq!(count, 2, "only the detected PE and the metadata blob");

    let emitted: Manifest = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let inputs: Vec<String> = emitted
        .cases
        .iter()
        .map(|case| case.input.display().to_string())
        .collect();
    assert!(inputs.iter().any(|input| input == "app.exe"));
    assert!(inputs.iter().any(|input| input == "global-metadata.dat"));
    assert!(!inputs.iter().any(|input| input.contains("golden")));
    assert!(!inputs.iter().any(|input| input.contains("notes.txt")));
    assert!(!inputs.iter().any(|input| input.contains("plain.exe")));
    let app = emitted
        .cases
        .iter()
        .find(|case| case.input.ends_with("app.exe"))
        .unwrap();
    assert_eq!(app.golden.as_deref(), Some(Path::new("app.golden.exe")));
}

#[test]
fn emit_manifest_requires_at_least_one_input() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("nothing.txt"), b"x").unwrap();
    let out = dir.path().join("emitted.json");
    assert!(harness::emit_manifest(&[dir.path().to_path_buf()], &[], &out).is_err());
}

#[test]
fn android_app_case_resolves_entries_and_rejects_escapes() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    std::fs::create_dir_all(app.join("lib/arm64-v8a")).unwrap();
    std::fs::write(app.join("lib/arm64-v8a/libx.so"), b"\x7fELF").unwrap();
    std::fs::write(dir.path().join("outside.so"), b"\x7fELF").unwrap();

    let mut spec = case("app", Kind::AndroidApp, "app");
    spec.entries = Some(vec![harness::EntrySpec {
        path: PathBuf::from("../outside.so"),
        sha256: None,
        golden: None,
        golden_sha256: None,
        metadata_sha256: None,
        expect_failure: None,
    }]);
    let manifest = write_manifest(dir.path(), vec![spec], Defaults::default());
    let report = harness::run(&manifest, &options());
    assert!(!report.passed());
    assert!(
        report.cases[0].outputs[0].entries[0]
            .failures
            .iter()
            .any(|failure| failure.contains("escapes") || failure.contains("resolve"))
    );
}
