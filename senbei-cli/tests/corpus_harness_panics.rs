//! Focused tests for how the harness classifies surfaced engine panics.
//!
//! The engine converts a caught panic into `UnpackError::InternalPanic`; the
//! harness's outer `catch_unwind_quiet` therefore sees an ordinary `Err`. A
//! declared `expect_failure` must not swallow that: a panic is a defect.
//!
//! These tests use typed synthetic errors, so they need no protected input.
//! They pin the classifier and the report wiring, not the engine itself.

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/harness.rs"]
mod harness;

use std::path::{Path, PathBuf};

use harness::{CaseSpec, Defaults, Kind, Manifest, RunOptions};

fn internal_panic() -> senbei_engine::UnpackError {
    senbei_engine::UnpackError::InternalPanic {
        message: "synthetic".to_owned(),
        file: "synthetic.rs".to_owned(),
        line: 1,
        column: 1,
    }
}

fn stage5_not_found() -> senbei_engine::UnpackError {
    senbei_engine::UnpackError::Stage5MarkerNotFound
}

#[test]
fn classifier_detects_direct_and_nested_internal_panics() {
    assert!(harness::surfaced_internal_panic(&internal_panic()));

    let nested = senbei_engine::UnpackError::PipelineFallbackFailed {
        dll: Box::new(stage5_not_found()),
        exe: Box::new(internal_panic()),
    };
    assert!(harness::surfaced_internal_panic(&nested));

    let nested_dll = senbei_engine::UnpackError::PipelineFallbackFailed {
        dll: Box::new(internal_panic()),
        exe: Box::new(stage5_not_found()),
    };
    assert!(harness::surfaced_internal_panic(&nested_dll));

    let deep = senbei_engine::UnpackError::PipelineFallbackFailed {
        dll: Box::new(nested),
        exe: Box::new(stage5_not_found()),
    };
    assert!(harness::surfaced_internal_panic(&deep));
}

#[test]
fn classifier_leaves_ordinary_restore_errors_alone() {
    assert!(!harness::surfaced_internal_panic(&stage5_not_found()));
    let ordinary_fallback = senbei_engine::UnpackError::PipelineFallbackFailed {
        dll: Box::new(senbei_engine::UnpackError::NotCrackProof),
        exe: Box::new(stage5_not_found()),
    };
    assert!(!harness::surfaced_internal_panic(&ordinary_fallback));
}

#[test]
fn classifier_sees_a_panic_wrapped_in_anyhow_context() {
    let wrapped = anyhow::Error::new(internal_panic()).context("restore protected library");
    assert!(harness::surfaced_internal_panic_in(&wrapped));
    let ordinary = anyhow::Error::new(stage5_not_found()).context("restore protected library");
    assert!(!harness::surfaced_internal_panic_in(&ordinary));
}

fn write_manifest(dir: &Path, cases: Vec<CaseSpec>) -> PathBuf {
    let manifest = Manifest {
        schema: harness::SCHEMA.to_owned(),
        name: Some("panic-classification".to_owned()),
        base_dir: None,
        defaults: Defaults::default(),
        cases,
    };
    let path = dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    path
}

fn case(id: &str, input: &str) -> CaseSpec {
    CaseSpec {
        id: id.to_owned(),
        kind: Kind::Pe,
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

fn options() -> RunOptions {
    RunOptions {
        commit: Some("test-commit".to_owned()),
        cwd: std::env::temp_dir(),
    }
}

/// The exact branch `run_pe` uses: a surfaced panic always yields outcome
/// `panic` and a failing case. A declared `expect_failure` must not change it.
#[test]
fn classify_keeps_a_surfaced_panic_failing_even_when_expected() {
    for error in [
        internal_panic(),
        senbei_engine::UnpackError::PipelineFallbackFailed {
            dll: Box::new(stage5_not_found()),
            exe: Box::new(internal_panic()),
        },
    ] {
        let mut output = harness::OutputReport::new("case");
        let mut report = harness::CaseReport::new_for_test("case");
        harness::classify_unpack_error(&mut output, &mut report, &error, true);
        assert_eq!(output.status, "failed");
        assert_eq!(report.outcome, "panic");
        assert_eq!(report.status, "fail");
        assert!(
            report.failures[0].contains("engine-internal panic surfaced"),
            "{:?}",
            report.failures
        );
    }
}

/// Ordinary restore-stage errors keep the existing policy.
#[test]
fn classify_keeps_normal_errors_declarable() {
    let mut output = harness::OutputReport::new("case");
    let mut report = harness::CaseReport::new_for_test("case");
    harness::classify_unpack_error(&mut output, &mut report, &stage5_not_found(), true);
    assert_eq!(report.outcome, "expected_failure");
    assert_eq!(report.status, "pass");

    let mut output = harness::OutputReport::new("case");
    let mut report = harness::CaseReport::new_for_test("case");
    harness::classify_unpack_error(&mut output, &mut report, &stage5_not_found(), false);
    assert_eq!(report.outcome, "unpack_failed");
    assert_eq!(report.status, "fail");
}

/// Report-level invariant: `summary.panics` counts exactly the cases whose
/// outcome is `panic`, and such a case can never make the run pass.
#[test]
fn report_panic_count_matches_panic_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("input.exe"),
        fixtures::synthetic_crackproof_pe(false, false),
    )
    .unwrap();
    let mut spec = case("crackproof-header-only", "input.exe");
    spec.expect_failure = Some(true);
    let manifest = write_manifest(dir.path(), vec![spec]);

    let report = harness::run(&manifest, &options());
    let panics = report
        .cases
        .iter()
        .filter(|case| case.outcome == "panic")
        .count();
    assert_eq!(
        report.summary.panics, panics,
        "summary.panics must count exactly the cases reported as panic"
    );
    if panics > 0 {
        assert!(!report.passed(), "a surfaced panic must fail the run");
    }
}
