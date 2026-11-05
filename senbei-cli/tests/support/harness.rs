//! Local, manifest-driven corpus harness.
//!
//! This module is compiled into `senbei-cli` integration tests and into the
//! `corpus_harness` example. It never walks a corpus on its own, never follows
//! junctions, never writes next to an input, and never uploads anything.
//!
//! # Manifest
//!
//! ```json
//! {
//!   "schema": "senbei-corpus-harness/1",
//!   "name": "local-corpus",
//!   "base_dir": ".",
//!   "defaults": {
//!     "expect_failure": false,
//!     "allow_missing_golden": false,
//!     "allow_suspect": false,
//!     "allow_empty": false
//!   },
//!   "cases": [
//!     {
//!       "id": "native-pe-1",
//!       "kind": "pe",
//!       "input": "app.exe",
//!       "companion": "app.exe._",
//!       "golden": "app.golden.exe"
//!     },
//!     {
//!       "id": "metadata-1",
//!       "kind": "metadata",
//!       "input": "global-metadata.dat",
//!       "golden_sha256": "0123..."
//!     },
//!     {
//!       "id": "android-app-1",
//!       "kind": "android-app",
//!       "input": "app-tree"
//!     }
//!   ]
//! }
//! ```
//!
//! `kind` is one of `pe`, `metadata`, `android-so`, or `android-app`. Inputs,
//! companions, goldens, and `base_dir` are resolved relative to the manifest's
//! directory unless absolute. Every non-`expect_failure` case must pin its
//! output with `golden`, `golden_sha256`, or `sha256`, or explicitly opt out
//! with `allow_missing_golden: true`. A missing golden, a mismatch, a length
//! difference, or a stale sidecar is reported as a failure; nothing is
//! regenerated.
//!
//! `android-so` and `android-app` cases also read the sidecars used by the
//! existing Android corpus (`<name>.golden.so.sha256`,
//! `<name>.golden.metadata.sha256`, `<name>.restore-fails`) when no explicit
//! expectation is given. `android-app` with no `entries` performs a bounded
//! walk *inside the supplied app folder only* (no junctions, no `unpack`
//! directories) and checks every protected library it finds. Supplying
//! `entries` restricts the case to those relative files.
//!
//! # Report
//!
//! The report records the git commit used (caller-supplied or queried
//! locally), whether the worktree is dirty, the manifest SHA-256, per-case
//! byte counts/SHA-256 values, integrity findings, timings, and pass/fail
//! status. Restored bytes live in a temporary directory and are dropped.

#![allow(dead_code)] // one module, several targets; each uses a subset

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "senbei-corpus-harness/1";
pub const REPORT_SCHEMA: &str = "senbei-corpus-report/1";
const MANIFEST_SCHEMA: &str = "senbei-corpus-manifest/1";
const MAX_APP_DEPTH: usize = 32;
const MAX_APP_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Pe,
    Metadata,
    AndroidSo,
    AndroidApp,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pe => "pe",
            Self::Metadata => "metadata",
            Self::AndroidSo => "android-so",
            Self::AndroidApp => "android-app",
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Defaults {
    pub expect_failure: bool,
    pub allow_missing_golden: bool,
    pub allow_suspect: bool,
    pub allow_empty: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub base_dir: Option<PathBuf>,
    #[serde(default)]
    pub defaults: Defaults,
    pub cases: Vec<CaseSpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSpec {
    pub id: String,
    pub kind: Kind,
    pub input: PathBuf,
    #[serde(default)]
    pub companion: Option<PathBuf>,
    #[serde(default)]
    pub golden: Option<PathBuf>,
    #[serde(default)]
    pub golden_sha256: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub metadata_sha256: Option<String>,
    #[serde(default)]
    pub expect_failure: Option<bool>,
    #[serde(default)]
    pub expect_suspect: Option<bool>,
    #[serde(default)]
    pub allow_missing_golden: Option<bool>,
    #[serde(default)]
    pub allow_suspect: Option<bool>,
    #[serde(default)]
    pub allow_empty: Option<bool>,
    #[serde(default)]
    pub entries: Option<Vec<EntrySpec>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntrySpec {
    pub path: PathBuf,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub golden: Option<PathBuf>,
    #[serde(default)]
    pub golden_sha256: Option<String>,
    #[serde(default)]
    pub metadata_sha256: Option<String>,
    #[serde(default)]
    pub expect_failure: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Caller-supplied commit. A local query result is still recorded, and a
    /// dirty worktree is never hidden.
    pub commit: Option<String>,
    /// Directory used for `git` discovery when the manifest is outside a repo.
    pub cwd: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub generated_unix_ms: u64,
    pub harness_version: String,
    pub git: GitInfo,
    pub manifest: ManifestInfo,
    pub options: OptionsInfo,
    pub cases: Vec<CaseReport>,
    pub manifest_errors: Vec<String>,
    pub summary: Summary,
    pub timings: Timings,
    pub status: String,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.status == "pass"
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GitInfo {
    pub is_repo: bool,
    pub worktree: Option<String>,
    pub head: Option<String>,
    pub head_source: String,
    pub caller_commit: Option<String>,
    pub local_head: Option<String>,
    pub dirty: Option<bool>,
    pub modified: usize,
    pub untracked: usize,
    pub status_count: usize,
    pub status_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ManifestInfo {
    pub path: String,
    pub sha256: String,
    pub name: Option<String>,
    pub declared_schema: String,
    pub base_dir: String,
    pub case_count: usize,
}

#[derive(Debug, Serialize)]
pub struct OptionsInfo {
    pub caller_commit: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub panics: usize,
    /// Declared failures that failed as expected. These are reported as
    /// `passed` by the exit-status rule, but they are **not** recovery
    /// successes, so they are counted separately from `restored`.
    pub expected_failures: usize,
    /// Cases whose operation actually produced output (or, for an Android app,
    /// whose protected libraries all restored). This is the only recovery
    /// count; expected failures never inflate it.
    pub restored: usize,
    pub integrity_failures: usize,
    pub golden_mismatches: usize,
    pub missing_goldens: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Timings {
    pub total_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct CaseReport {
    pub id: String,
    pub kind: String,
    pub input: String,
    pub status: String,
    pub outcome: String,
    pub expect_failure: bool,
    pub allow_missing_golden: bool,
    pub duration_ms: u64,
    pub outputs: Vec<OutputReport>,
    pub failures: Vec<String>,
    pub notes: Vec<String>,
    pub error: Option<String>,
}

impl CaseReport {
    fn new(case: &CaseSpec, base: &Path) -> Self {
        Self {
            id: case.id.clone(),
            kind: case.kind.as_str().to_owned(),
            input: resolved_display(base, &case.input),
            status: "fail".to_owned(),
            outcome: "not_run".to_owned(),
            expect_failure: false,
            allow_missing_golden: false,
            duration_ms: 0,
            outputs: Vec::new(),
            failures: Vec::new(),
            notes: Vec::new(),
            error: None,
        }
    }

    /// Bare shell for focused classification tests (no manifest needed).
    pub fn new_for_test(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            kind: "pe".to_owned(),
            input: id.to_owned(),
            status: "fail".to_owned(),
            outcome: "not_run".to_owned(),
            expect_failure: false,
            allow_missing_golden: false,
            duration_ms: 0,
            outputs: Vec::new(),
            failures: Vec::new(),
            notes: Vec::new(),
            error: None,
        }
    }

    fn fail(&mut self, outcome: &str, message: impl Into<String>) {
        self.status = "fail".to_owned();
        self.outcome = outcome.to_owned();
        self.failures.push(message.into());
    }

    fn pass(&mut self, outcome: &str) {
        self.status = "pass".to_owned();
        self.outcome = outcome.to_owned();
    }
}

#[derive(Debug, Serialize)]
pub struct OutputReport {
    pub label: String,
    pub status: String,
    pub detected_kind: Option<String>,
    pub bytes: Option<u64>,
    pub sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub expected_source: Option<String>,
    pub golden: Option<String>,
    pub golden_bytes: Option<u64>,
    pub remapped: Option<u64>,
    pub integrity: Option<IntegrityInfo>,
    pub entries: Vec<EntryReport>,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub notes: Vec<String>,
    pub failures: Vec<String>,
}

impl OutputReport {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: "failed".to_owned(),
            detected_kind: None,
            bytes: None,
            sha256: None,
            expected_sha256: None,
            expected_source: None,
            golden: None,
            golden_bytes: None,
            remapped: None,
            integrity: None,
            entries: Vec::new(),
            duration_ms: 0,
            error: None,
            notes: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        self.status = "failed".to_owned();
        self.failures.push(message.into());
    }
}

#[derive(Debug, Serialize)]
pub struct IntegrityInfo {
    pub ok: bool,
    pub fatal: bool,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EntryReport {
    pub input: String,
    pub status: String,
    pub expected_failure: bool,
    pub bytes: Option<u64>,
    pub sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub expected_source: Option<String>,
    pub embedded_sha256: Option<String>,
    pub embedded_expected_sha256: Option<String>,
    pub golden: Option<String>,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub notes: Vec<String>,
    pub failures: Vec<String>,
}

impl EntryReport {
    fn new(input: impl Into<String>) -> Self {
        Self {
            input: input.into(),
            status: "failed".to_owned(),
            expected_failure: false,
            bytes: None,
            sha256: None,
            expected_sha256: None,
            expected_source: None,
            embedded_sha256: None,
            embedded_expected_sha256: None,
            golden: None,
            duration_ms: 0,
            error: None,
            notes: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        self.status = "failed".to_owned();
        self.failures.push(message.into());
    }

    fn pass(&mut self) {
        self.status = "pass".to_owned();
    }
}

/// Run a manifest and return the report. Manifest parse/IO failures are
/// represented in the report, never panicked.
pub fn run(manifest_path: &Path, options: &RunOptions) -> Report {
    let started = Instant::now();
    let absolute = absolute_path(manifest_path);
    let base = absolute
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let (raw, manifest_sha256) = match std::fs::read(&absolute) {
        Ok(raw) => {
            let digest = sha256_hex(&raw);
            (Some(raw), digest)
        }
        Err(error) => {
            return fatal_report(
                &absolute,
                &base,
                options,
                "",
                Vec::new(),
                format!("read manifest: {error}"),
                started,
            );
        }
    };
    let raw = raw.unwrap_or_default();
    let manifest: Manifest = match serde_json::from_slice(&raw) {
        Ok(manifest) => manifest,
        Err(error) => {
            return fatal_report(
                &absolute,
                &base,
                options,
                &manifest_sha256,
                Vec::new(),
                format!("parse manifest: {error}"),
                started,
            );
        }
    };
    let mut manifest_errors = Vec::new();
    if manifest.schema != SCHEMA {
        manifest_errors.push(format!(
            "schema mismatch: manifest declares {:?}, expected {SCHEMA:?}",
            manifest.schema
        ));
    }
    if manifest.cases.is_empty() {
        manifest_errors.push("manifest contains no cases".to_owned());
    }
    let base_dir = manifest
        .base_dir
        .as_ref()
        .map(|path| absolute_from(&base, path))
        .unwrap_or_else(|| base.clone());
    let base_dir = absolute_path(&base_dir);

    let mut seen = BTreeSet::new();
    let duplicate: BTreeSet<String> = manifest
        .cases
        .iter()
        .filter_map(|case| {
            if seen.insert(case.id.clone()) {
                None
            } else {
                Some(case.id.clone())
            }
        })
        .collect();
    for id in &duplicate {
        manifest_errors.push(format!("duplicate case id {id:?}"));
    }

    let mut cases = Vec::with_capacity(manifest.cases.len());
    for spec in &manifest.cases {
        let effective_expect_failure = spec
            .expect_failure
            .unwrap_or(manifest.defaults.expect_failure);
        let effective_allow_missing = spec
            .allow_missing_golden
            .unwrap_or(manifest.defaults.allow_missing_golden);
        let effective_allow_suspect = spec
            .allow_suspect
            .unwrap_or(manifest.defaults.allow_suspect);
        let effective_allow_empty = spec.allow_empty.unwrap_or(manifest.defaults.allow_empty);
        let mut report = CaseReport::new(spec, &base_dir);
        report.expect_failure = effective_expect_failure;
        report.allow_missing_golden = effective_allow_missing;
        if duplicate.contains(&spec.id) {
            report.fail("invalid_case", format!("duplicate case id {:?}", spec.id));
            cases.push(report);
            continue;
        }
        let validation = validate_case(
            spec,
            &base_dir,
            effective_expect_failure,
            effective_allow_missing,
            effective_allow_empty,
        );
        if !validation.is_empty() {
            report.outcome = "invalid_case".to_owned();
            report.failures.extend(validation);
            cases.push(report);
            continue;
        }
        let start = Instant::now();
        let outcome = senbei_engine::catch_unwind_quiet(|| {
            run_case(
                spec,
                &base_dir,
                effective_expect_failure,
                effective_allow_missing,
                effective_allow_suspect,
                effective_allow_empty,
            )
        });
        report.duration_ms = elapsed_ms(start);
        match outcome {
            Ok(result) => cases.push(result),
            Err(payload) => {
                report.fail("panic", format!("panic: {}", panic_message(&payload)));
                report.error = Some(report.failures.join("; "));
                cases.push(report);
            }
        }
    }

    let summary = summarize(&cases, &manifest_errors);
    let status = if summary.failed == 0 && manifest_errors.is_empty() {
        "pass"
    } else {
        "fail"
    };
    let git = git_info(options, &base);
    Report {
        schema: REPORT_SCHEMA,
        generated_unix_ms: now_ms(),
        harness_version: env!("CARGO_PKG_VERSION").to_owned(),
        git,
        manifest: ManifestInfo {
            path: absolute.display().to_string(),
            sha256: manifest_sha256,
            name: manifest.name.clone(),
            declared_schema: manifest.schema.clone(),
            base_dir: base_dir.display().to_string(),
            case_count: manifest.cases.len(),
        },
        options: OptionsInfo {
            caller_commit: options.commit.clone(),
        },
        cases,
        manifest_errors,
        summary,
        timings: Timings {
            total_ms: elapsed_ms(started),
        },
        status: status.to_owned(),
    }
}

fn fatal_report(
    manifest_path: &Path,
    base: &Path,
    options: &RunOptions,
    manifest_sha256: &str,
    cases: Vec<CaseReport>,
    error: String,
    started: Instant,
) -> Report {
    Report {
        schema: REPORT_SCHEMA,
        generated_unix_ms: now_ms(),
        harness_version: env!("CARGO_PKG_VERSION").to_owned(),
        git: git_info(options, base),
        manifest: ManifestInfo {
            path: manifest_path.display().to_string(),
            sha256: manifest_sha256.to_owned(),
            name: None,
            declared_schema: String::new(),
            base_dir: base.display().to_string(),
            case_count: 0,
        },
        options: OptionsInfo {
            caller_commit: options.commit.clone(),
        },
        cases,
        manifest_errors: vec![error],
        summary: Summary::default(),
        timings: Timings {
            total_ms: elapsed_ms(started),
        },
        status: "fail".to_owned(),
    }
}

fn summarize(cases: &[CaseReport], manifest_errors: &[String]) -> Summary {
    let mut summary = Summary {
        total: cases.len(),
        ..Summary::default()
    };
    for case in cases {
        if case.status == "pass" {
            summary.passed += 1;
        } else {
            summary.failed += 1;
        }
        if case.outcome == "panic" {
            summary.panics += 1;
        }
        if case.outcome == "expected_failure" {
            summary.expected_failures += 1;
        }
        if case.status == "pass" && case.outcome != "expected_failure" {
            summary.restored += 1;
        }
        if case
            .failures
            .iter()
            .any(|failure| failure.contains("integrity") || failure.contains("suspect"))
        {
            summary.integrity_failures += 1;
        }
        if case.outcome == "golden_mismatch" {
            summary.golden_mismatches += 1;
        }
        if case.outcome == "golden_missing" {
            summary.missing_goldens += 1;
        }
    }
    if !manifest_errors.is_empty() && summary.failed == 0 {
        summary.failed = 1;
    }
    summary
}

fn validate_case(
    spec: &CaseSpec,
    base: &Path,
    expect_failure: bool,
    allow_missing: bool,
    allow_empty: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    if spec.id.trim().is_empty() {
        errors.push("case id is empty".to_owned());
    }
    let input = absolute_from(base, &spec.input);
    match spec.kind {
        Kind::Pe | Kind::Metadata | Kind::AndroidSo => {
            if !input.is_file() {
                errors.push(format!("input is not a file: {}", input.display()));
            }
        }
        Kind::AndroidApp => {
            if !input.is_dir() {
                errors.push(format!("input is not a directory: {}", input.display()));
            }
        }
    }
    if let Some(companion) = &spec.companion {
        let companion = absolute_from(base, companion);
        if !companion.is_file() {
            errors.push(format!("companion is not a file: {}", companion.display()));
        }
    }
    if let Some(golden) = &spec.golden {
        let golden = absolute_from(base, golden);
        if !golden.is_file() {
            errors.push(format!("golden is missing: {}", golden.display()));
        }
    }
    for (name, value) in [
        ("golden_sha256", spec.golden_sha256.as_deref()),
        ("sha256", spec.sha256.as_deref()),
        ("metadata_sha256", spec.metadata_sha256.as_deref()),
    ] {
        if let Some(value) = value
            && !is_sha256(value)
        {
            errors.push(format!("{name} is not a 64-hex SHA-256: {value:?}"));
        }
    }
    if spec.entries.is_some() && spec.kind != Kind::AndroidApp {
        errors.push("entries are only valid for kind android-app".to_owned());
    }
    for entry in spec.entries.iter().flatten() {
        for (name, value) in [
            ("sha256", entry.sha256.as_deref()),
            ("golden_sha256", entry.golden_sha256.as_deref()),
            ("metadata_sha256", entry.metadata_sha256.as_deref()),
        ] {
            if let Some(value) = value
                && !is_sha256(value)
            {
                errors.push(format!(
                    "entry {:?} {name} is not a 64-hex SHA-256: {value:?}",
                    entry.path
                ));
            }
        }
        if entry.path.is_absolute() {
            errors.push(format!(
                "entry path must be relative: {}",
                entry.path.display()
            ));
        }
    }
    if !expect_failure && spec.kind != Kind::AndroidApp {
        let declared =
            spec.golden.is_some() || spec.golden_sha256.is_some() || spec.sha256.is_some();
        if !declared && !allow_missing {
            errors.push(
                "no expected output declared: add golden, golden_sha256, or sha256, \
                 or set allow_missing_golden"
                    .to_owned(),
            );
        }
    }
    if spec.kind == Kind::AndroidApp
        && spec.entries.as_ref().is_some_and(Vec::is_empty)
        && !allow_empty
    {
        errors.push("android-app case declares an empty entries list".to_owned());
    }
    errors
}

fn run_case(
    spec: &CaseSpec,
    base: &Path,
    expect_failure: bool,
    allow_missing: bool,
    allow_suspect: bool,
    allow_empty: bool,
) -> CaseReport {
    let mut report = CaseReport::new(spec, base);
    report.expect_failure = expect_failure;
    report.allow_missing_golden = allow_missing;
    match spec.kind {
        Kind::Pe => run_pe(
            spec,
            base,
            &mut report,
            expect_failure,
            allow_missing,
            allow_suspect,
        ),
        Kind::Metadata => run_metadata(spec, base, &mut report, expect_failure, allow_missing),
        Kind::AndroidSo => run_android_so(spec, base, &mut report, expect_failure, allow_missing),
        Kind::AndroidApp => run_android_app(
            spec,
            base,
            &mut report,
            expect_failure,
            allow_missing,
            allow_empty,
        ),
    }
    report
}

fn run_pe(
    spec: &CaseSpec,
    base: &Path,
    report: &mut CaseReport,
    expect_failure: bool,
    allow_missing: bool,
    allow_suspect: bool,
) {
    let start = Instant::now();
    let mut output = OutputReport::new(spec.id.clone());
    let input = absolute_from(base, &spec.input);
    let input_bytes = match std::fs::read(&input) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.fail("read_error", format!("read input: {error}"));
            report.outputs.push(output);
            return;
        }
    };
    let companion = match &spec.companion {
        Some(path) => {
            let path = absolute_from(base, path);
            match std::fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    report.fail("read_error", format!("read companion: {error}"));
                    report.outputs.push(output);
                    return;
                }
            }
        }
        None => None,
    };
    // An expected failure needs no output expectation: the failure itself is
    // the assertion. Only a successful run is compared.
    let expectation = if expect_failure {
        None
    } else {
        match expectation(spec, base, allow_missing) {
            Ok(expectation) => expectation,
            Err(error) => {
                report.fail("golden_missing", error);
                report.outputs.push(output);
                return;
            }
        }
    };
    let expected = expectation.as_ref();
    match senbei_io::job::unpack_bytes(&input_bytes, companion.as_deref()) {
        Ok(image) => {
            output.detected_kind = Some(kind_name(image.kind).to_owned());
            output.bytes = Some(image.bytes.len() as u64);
            output.sha256 = Some(sha256_hex(&image.bytes));
            output.integrity = Some(IntegrityInfo {
                ok: image.integrity.ok(),
                fatal: image.integrity.has_fatal(),
                issues: image.integrity.issues.clone(),
            });
            if expect_failure {
                output.fail("expected failure, but the input unpacked");
                report.fail(
                    "expected_failure_unmet",
                    "expected failure, but the input unpacked",
                );
            } else {
                compare_output(
                    &mut output,
                    &image.bytes,
                    expected,
                    allow_suspect,
                    &image.integrity.issues,
                );
                finish_case(report, &mut output, "unpacked");
            }
        }
        Err(error) => {
            output.error = Some(error.to_string());
            classify_unpack_error(&mut output, report, &error, expect_failure);
        }
    }
    output.duration_ms = elapsed_ms(start);
    report.outputs.push(output);
}

fn run_metadata(
    spec: &CaseSpec,
    base: &Path,
    report: &mut CaseReport,
    expect_failure: bool,
    allow_missing: bool,
) {
    let start = Instant::now();
    let mut output = OutputReport::new(spec.id.clone());
    let input = absolute_from(base, &spec.input);
    let bytes = match std::fs::read(&input) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.fail("read_error", format!("read input: {error}"));
            report.outputs.push(output);
            return;
        }
    };
    let expectation = if expect_failure {
        None
    } else {
        match expectation(spec, base, allow_missing) {
            Ok(expectation) => expectation,
            Err(error) => {
                report.fail("golden_missing", error);
                report.outputs.push(output);
                return;
            }
        }
    };
    let expected = expectation.as_ref();
    match senbei_metadata::deobfuscate(&bytes) {
        Ok((out, result)) => {
            output.bytes = Some(out.len() as u64);
            output.remapped = Some(result.remapped as u64);
            output.sha256 = Some(sha256_hex(&out));
            if expect_failure {
                output.fail("expected failure, but the metadata transformed");
                report.fail(
                    "expected_failure_unmet",
                    "expected failure, but the metadata transformed",
                );
            } else {
                compare_output(&mut output, &out, expected, true, &[]);
                finish_case(report, &mut output, "transformed");
            }
        }
        Err(error) => {
            output.error = Some(error.to_string());
            if expect_failure {
                output.status = "pass".to_owned();
                output.notes.push("expected failure observed".to_owned());
                report.pass("expected_failure");
            } else {
                output.fail(format!("metadata transform failed: {error}"));
                report.fail(
                    "metadata_failed",
                    format!("metadata transform failed: {error}"),
                );
            }
        }
    }
    output.duration_ms = elapsed_ms(start);
    report.outputs.push(output);
}

fn run_android_so(
    spec: &CaseSpec,
    base: &Path,
    report: &mut CaseReport,
    expect_failure: bool,
    allow_missing: bool,
) {
    let start = Instant::now();
    let mut output = OutputReport::new(spec.id.clone());
    let input = absolute_from(base, &spec.input);
    let temporary = match tempfile::tempdir() {
        Ok(temporary) => temporary,
        Err(error) => {
            report.fail(
                "workspace_error",
                format!("create temporary workspace: {error}"),
            );
            report.outputs.push(output);
            return;
        }
    };
    let dest = temporary.path().join("restored.so");
    let effective_expect_failure = spec
        .expect_failure
        .unwrap_or(expect_failure || known_failure_marker(&input));
    let (expectation, embedded_expectation) = if effective_expect_failure {
        (None, None)
    } else {
        let expectation = match android_expectation(spec, base, &input, allow_missing, None) {
            Ok(expectation) => expectation,
            Err(error) => {
                report.fail("golden_missing", error);
                report.outputs.push(output);
                return;
            }
        };
        let embedded_expectation = match android_embedded_expectation(spec, base, &input, None) {
            Ok(expectation) => expectation,
            Err(error) => {
                report.fail("golden_missing", error);
                report.outputs.push(output);
                return;
            }
        };
        (expectation, embedded_expectation)
    };
    let mut entry = EntryReport::new(resolved_display(base, &spec.input));
    entry.expected_failure = effective_expect_failure;
    match senbei_io::android::restore_so_file(&input, &dest, false) {
        Ok(embedded) => {
            let restored = match std::fs::read(&dest) {
                Ok(bytes) => bytes,
                Err(error) => {
                    entry.fail(format!("read restored output: {error}"));
                    output.entries.push(entry);
                    report.fail("output_error", "read restored output");
                    report.outputs.push(output);
                    return;
                }
            };
            entry.bytes = Some(restored.len() as u64);
            entry.sha256 = Some(sha256_hex(&restored));
            if effective_expect_failure {
                entry.fail("expected failure, but the library restored");
                report.fail(
                    "expected_failure_unmet",
                    "expected failure, but the library restored",
                );
            } else {
                apply_android_expectation(&mut entry, expectation.as_ref());
                if let Some(expected) = &embedded_expectation {
                    match &embedded {
                        Some(blob) => {
                            let actual = sha256_hex(blob);
                            entry.embedded_sha256 = Some(actual.clone());
                            compare_hash(
                                &mut entry,
                                Some(actual.as_str()),
                                Some(expected),
                                "embedded metadata",
                            );
                        }
                        None => entry.fail(
                            "restored library has no embedded metadata, but an expected hash was declared",
                        ),
                    }
                } else if let Some(blob) = &embedded {
                    entry.embedded_sha256 = Some(sha256_hex(blob));
                }
                if entry.failures.is_empty() {
                    entry.pass();
                    report.pass("restored");
                } else {
                    report.fail("golden_mismatch", entry.failures.join("; "));
                }
            }
        }
        Err(error) => {
            entry.error = Some(error.to_string());
            if surfaced_internal_panic_in(&error) {
                entry.fail(format!("engine-internal panic surfaced: {error}"));
                report.fail("panic", format!("engine-internal panic surfaced: {error}"));
            } else if effective_expect_failure {
                entry.status = "pass".to_owned();
                entry.notes.push("expected failure observed".to_owned());
                report.pass("expected_failure");
            } else {
                entry.fail(format!("restore failed: {error}"));
                report.fail("restore_failed", format!("restore failed: {error}"));
            }
        }
    }
    output.entries.push(entry);
    output.duration_ms = elapsed_ms(start);
    report.outputs.push(output);
}

fn run_android_app(
    spec: &CaseSpec,
    base: &Path,
    report: &mut CaseReport,
    expect_failure: bool,
    allow_missing: bool,
    allow_empty: bool,
) {
    let start = Instant::now();
    let mut output = OutputReport::new(spec.id.clone());
    let app = absolute_from(base, &spec.input);
    let app_canonical = match app.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            report.fail("read_error", format!("canonicalize app folder: {error}"));
            report.outputs.push(output);
            return;
        }
    };
    let mut targets = Vec::new();
    match &spec.entries {
        Some(entries) => {
            for entry in entries {
                match resolve_entry(&app_canonical, &entry.path) {
                    Ok(path) => targets.push((path, Some(entry))),
                    Err(error) => {
                        let mut result = EntryReport::new(entry.path.display().to_string());
                        result.fail(error);
                        output.entries.push(result);
                    }
                }
            }
        }
        None => match collect_protected_so(&app_canonical) {
            Ok(found) => {
                targets.extend(found.into_iter().map(|path| (path, None)));
            }
            Err(error) => {
                report.fail("walk_error", error);
                report.outputs.push(output);
                return;
            }
        },
    }
    if targets.is_empty() && output.entries.is_empty() && !allow_empty {
        report.fail(
            "no_entries",
            "android-app case found no protected libraries",
        );
        report.outputs.push(output);
        return;
    }
    let temporary = match tempfile::tempdir() {
        Ok(temporary) => temporary,
        Err(error) => {
            report.fail(
                "workspace_error",
                format!("create temporary workspace: {error}"),
            );
            report.outputs.push(output);
            return;
        }
    };
    for (index, (input, entry_spec)) in targets.iter().enumerate() {
        let entry_start = Instant::now();
        let relative = input
            .strip_prefix(&app_canonical)
            .unwrap_or(input)
            .display()
            .to_string();
        let mut result = EntryReport::new(relative);
        let dest = temporary.path().join(format!("entry-{index}.so"));
        let effective_expect_failure = entry_spec
            .and_then(|entry| entry.expect_failure)
            .unwrap_or(expect_failure || known_failure_marker(input));
        result.expected_failure = effective_expect_failure;
        // A known-failure marker is the assertion. Demanding an output hash for
        // an input that is expected to fail would turn a documented gap into a
        // golden-missing error.
        let (expectation, embedded_expectation) = if effective_expect_failure {
            (None, None)
        } else {
            let expectation =
                match android_expectation(spec, base, input, allow_missing, *entry_spec) {
                    Ok(expectation) => expectation,
                    Err(error) => {
                        result.fail(error);
                        result.duration_ms = elapsed_ms(entry_start);
                        output.entries.push(result);
                        continue;
                    }
                };
            let embedded_expectation =
                match android_embedded_expectation(spec, base, input, *entry_spec) {
                    Ok(expectation) => expectation,
                    Err(error) => {
                        result.fail(error);
                        result.duration_ms = elapsed_ms(entry_start);
                        output.entries.push(result);
                        continue;
                    }
                };
            (expectation, embedded_expectation)
        };
        match senbei_io::android::restore_so_file(input, &dest, false) {
            Ok(embedded) => {
                let restored = match std::fs::read(&dest) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        result.fail(format!("read restored output: {error}"));
                        result.duration_ms = elapsed_ms(entry_start);
                        output.entries.push(result);
                        continue;
                    }
                };
                result.bytes = Some(restored.len() as u64);
                result.sha256 = Some(sha256_hex(&restored));
                if effective_expect_failure {
                    result.fail("expected failure, but the library restored");
                } else {
                    apply_android_expectation(&mut result, expectation.as_ref());
                    if let Some(expected) = &embedded_expectation {
                        match &embedded {
                            Some(blob) => {
                                let actual = sha256_hex(blob);
                                result.embedded_sha256 = Some(actual.clone());
                                compare_hash(
                                    &mut result,
                                    Some(actual.as_str()),
                                    Some(expected),
                                    "embedded metadata",
                                );
                            }
                            None => result.fail(
                                "restored library has no embedded metadata, but an expected hash was declared",
                            ),
                        }
                    } else if let Some(blob) = &embedded {
                        result.embedded_sha256 = Some(sha256_hex(blob));
                    }
                    if result.failures.is_empty() {
                        result.pass();
                    }
                }
            }
            Err(error) => {
                result.error = Some(error.to_string());
                if surfaced_internal_panic_in(&error) {
                    result.fail(format!("engine-internal panic surfaced: {error}"));
                    result
                        .notes
                        .push("surfaced panic is not a known failure".to_owned());
                } else if effective_expect_failure {
                    result.status = "pass".to_owned();
                    result.notes.push("known failure observed".to_owned());
                } else {
                    result.fail(format!("restore failed: {error}"));
                }
            }
        }
        result.duration_ms = elapsed_ms(entry_start);
        output.entries.push(result);
    }
    let failed = output.entries.iter().any(|entry| entry.status != "pass");
    let surfaced_panic = output.entries.iter().any(|entry| {
        entry
            .failures
            .iter()
            .any(|failure| failure.contains("engine-internal panic surfaced"))
    });
    output.duration_ms = elapsed_ms(start);
    if failed {
        let messages: Vec<String> = output
            .entries
            .iter()
            .flat_map(|entry| {
                entry
                    .failures
                    .iter()
                    .map(|failure| format!("{}: {failure}", entry.input))
            })
            .collect();
        // A surfaced panic must be visible in `summary.panics`, not folded
        // into an ordinary per-entry failure.
        let outcome = if surfaced_panic {
            "panic"
        } else {
            "entry_failed"
        };
        report.fail(outcome, messages.join("; "));
    } else if expect_failure {
        // Every entry failed as declared: the case passes, but it is an
        // expected failure, not a recovery.
        report.pass("expected_failure");
    } else {
        report.pass("restored");
    }
    report.outputs.push(output);
}

fn finish_case(report: &mut CaseReport, output: &mut OutputReport, success: &str) {
    if output.failures.is_empty() {
        output.status = "ok".to_owned();
        report.pass(success);
    } else {
        let outcome = if output.failures.iter().any(|f| f.contains("golden")) {
            "golden_mismatch"
        } else if output.failures.iter().any(|f| f.contains("integrity")) {
            "integrity_failed"
        } else {
            "failed"
        };
        report.fail(outcome, output.failures.join("; "));
    }
}

fn compare_output(
    output: &mut OutputReport,
    actual: &[u8],
    expected: Option<&Expectation>,
    allow_suspect: bool,
    integrity_issues: &[String],
) {
    if let Some(expected) = expected {
        output.expected_sha256 = Some(expected.sha256.clone());
        output.expected_source = Some(expected.source.clone());
        output.golden = expected
            .golden
            .as_ref()
            .map(|path| path.display().to_string());
        output.golden_bytes = expected.golden_bytes;
        if let Some(bytes) = expected.golden_bytes
            && bytes != actual.len() as u64
        {
            output.fail(format!(
                "golden length differs: got {} want {bytes}",
                actual.len()
            ));
        } else {
            let actual_sha = sha256_hex(actual);
            if actual_sha != expected.sha256 {
                output.fail(format!(
                    "golden digest differs: got {actual_sha} want {}",
                    expected.sha256
                ));
            }
        }
    }
    if !integrity_issues.is_empty() && !allow_suspect {
        output.fail(format!(
            "integrity check failed: {}",
            integrity_issues.join("; ")
        ));
    } else if !integrity_issues.is_empty() {
        output
            .notes
            .push("integrity warnings accepted by allow_suspect".to_owned());
    }
}

fn apply_android_expectation(entry: &mut EntryReport, expected: Option<&Expectation>) {
    let Some(expected) = expected else {
        return;
    };
    entry.expected_sha256 = Some(expected.sha256.clone());
    entry.expected_source = Some(expected.source.clone());
    entry.golden = expected
        .golden
        .as_ref()
        .map(|path| path.display().to_string());
    let actual = entry.sha256.clone();
    compare_hash(entry, actual.as_deref(), Some(expected), "restored library");
}

fn compare_hash(
    entry: &mut EntryReport,
    actual: Option<&str>,
    expected: Option<&Expectation>,
    label: &str,
) {
    let (Some(actual), Some(expected)) = (actual, expected) else {
        return;
    };
    if actual != expected.sha256 {
        entry.fail(format!(
            "{label} digest differs: got {actual} want {}",
            expected.sha256
        ));
    }
}

struct Expectation {
    sha256: String,
    source: String,
    golden: Option<PathBuf>,
    golden_bytes: Option<u64>,
}

fn expectation(
    spec: &CaseSpec,
    base: &Path,
    allow_missing: bool,
) -> Result<Option<Expectation>, String> {
    let declared = declared_hashes(spec.golden_sha256.as_deref(), spec.sha256.as_deref())?;
    if let Some(golden) = &spec.golden {
        let golden = absolute_from(base, golden);
        let bytes = std::fs::read(&golden)
            .map_err(|error| format!("read golden {}: {error}", golden.display()))?;
        let actual = sha256_hex(&bytes);
        if let Some(declared) = &declared
            && declared != &actual
        {
            return Err(format!(
                "manifest inconsistency: golden {} hashes to {actual}, but the manifest declares {declared}",
                golden.display()
            ));
        }
        return Ok(Some(Expectation {
            sha256: actual,
            source: "golden".to_owned(),
            golden: Some(golden),
            golden_bytes: Some(bytes.len() as u64),
        }));
    }
    if let Some(declared) = declared {
        return Ok(Some(Expectation {
            sha256: declared,
            source: "manifest".to_owned(),
            golden: None,
            golden_bytes: None,
        }));
    }
    if allow_missing {
        Ok(None)
    } else {
        Err("no expected output declared and allow_missing_golden is false".to_owned())
    }
}

fn declared_hashes(a: Option<&str>, b: Option<&str>) -> Result<Option<String>, String> {
    match (a, b) {
        (Some(a), Some(b)) if a != b => Err(format!(
            "conflicting expected hashes: golden_sha256 {a:?} vs sha256 {b:?}"
        )),
        (Some(a), _) => Ok(Some(a.to_owned())),
        (None, Some(b)) => Ok(Some(b.to_owned())),
        (None, None) => Ok(None),
    }
}

fn android_expectation(
    spec: &CaseSpec,
    base: &Path,
    input: &Path,
    allow_missing: bool,
    entry: Option<&EntrySpec>,
) -> Result<Option<Expectation>, String> {
    if let Some(entry) = entry {
        if let Some(golden) = &entry.golden {
            return golden_expectation(base, golden, entry.golden_sha256.as_deref());
        }
        if let Some(sha) = entry.golden_sha256.as_deref().or(entry.sha256.as_deref()) {
            return Ok(Some(manifest_expectation(sha)));
        }
    }
    if let Some(golden) = &spec.golden {
        return golden_expectation(base, golden, spec.golden_sha256.as_deref());
    }
    if let Some(declared) = declared_hashes(spec.golden_sha256.as_deref(), spec.sha256.as_deref())?
    {
        return Ok(Some(manifest_expectation(&declared)));
    }
    if let Some(sidecar) = read_sidecar(&android_sidecar(input, "so"))? {
        return Ok(Some(Expectation {
            sha256: sidecar,
            source: "sidecar".to_owned(),
            golden: None,
            golden_bytes: None,
        }));
    }
    if allow_missing {
        Ok(None)
    } else {
        Err(format!(
            "no expected restored hash and no sidecar at {}",
            android_sidecar(input, "so").display()
        ))
    }
}

fn android_embedded_expectation(
    spec: &CaseSpec,
    base: &Path,
    input: &Path,
    entry: Option<&EntrySpec>,
) -> Result<Option<Expectation>, String> {
    if let Some(entry) = entry {
        if let Some(golden) = &entry.golden {
            let golden = absolute_from(base, golden);
            let bytes = std::fs::read(&golden)
                .map_err(|error| format!("read golden {}: {error}", golden.display()))?;
            let actual = sha256_hex(&bytes);
            if let Some(declared) = entry.metadata_sha256.as_deref()
                && declared != actual
            {
                return Err(format!(
                    "manifest inconsistency: golden {} hashes to {actual}, but the manifest declares {declared}",
                    golden.display()
                ));
            }
            return Ok(Some(Expectation {
                sha256: actual,
                source: "golden".to_owned(),
                golden: Some(golden),
                golden_bytes: Some(bytes.len() as u64),
            }));
        }
        if let Some(declared) = &entry.metadata_sha256 {
            return Ok(Some(manifest_expectation(declared)));
        }
    }
    if entry.is_none()
        && let Some(declared) = &spec.metadata_sha256
    {
        return Ok(Some(manifest_expectation(declared)));
    }
    if let Some(sidecar) = read_sidecar(&android_sidecar(input, "metadata"))? {
        return Ok(Some(Expectation {
            sha256: sidecar,
            source: "sidecar".to_owned(),
            golden: None,
            golden_bytes: None,
        }));
    }
    Ok(None)
}

fn manifest_expectation(sha256: &str) -> Expectation {
    Expectation {
        sha256: sha256.to_owned(),
        source: "manifest".to_owned(),
        golden: None,
        golden_bytes: None,
    }
}

fn golden_expectation(
    base: &Path,
    golden: &Path,
    declared: Option<&str>,
) -> Result<Option<Expectation>, String> {
    let golden = absolute_from(base, golden);
    let bytes = std::fs::read(&golden)
        .map_err(|error| format!("read golden {}: {error}", golden.display()))?;
    let actual = sha256_hex(&bytes);
    if let Some(declared) = declared
        && declared != actual
    {
        return Err(format!(
            "manifest inconsistency: golden {} hashes to {actual}, but the manifest declares {declared}",
            golden.display()
        ));
    }
    Ok(Some(Expectation {
        sha256: actual,
        source: "golden".to_owned(),
        golden: Some(golden),
        golden_bytes: Some(bytes.len() as u64),
    }))
}

fn android_sidecar(input: &Path, artifact: &str) -> PathBuf {
    let name = input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name
        .strip_suffix(".so")
        .or_else(|| name.strip_suffix(".SO"))
        .unwrap_or(&name);
    input.with_file_name(format!("{stem}.golden.{artifact}.sha256"))
}

fn known_failure_marker(input: &Path) -> bool {
    let name = input
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = name
        .strip_suffix(".so")
        .or_else(|| name.strip_suffix(".SO"))
        .unwrap_or(&name);
    input
        .with_file_name(format!("{stem}.restore-fails"))
        .is_file()
}

fn read_sidecar(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = text.trim().to_ascii_lowercase();
            if !is_sha256(&text) {
                return Err(format!(
                    "sidecar {} is not a 64-hex SHA-256",
                    path.display()
                ));
            }
            Ok(Some(text))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read sidecar {}: {error}", path.display())),
    }
}

fn resolve_entry(app: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.is_absolute() {
        return Err(format!(
            "entry path must be relative: {}",
            relative.display()
        ));
    }
    let candidate = app.join(relative);
    let canonical = candidate
        .canonicalize()
        .map_err(|error| format!("resolve entry {}: {error}", candidate.display()))?;
    if !canonical.starts_with(app) {
        return Err(format!(
            "entry escapes the app folder: {}",
            relative.display()
        ));
    }
    if !canonical.is_file() {
        return Err(format!("entry is not a file: {}", relative.display()));
    }
    if has_reparse_component(app, &canonical) {
        return Err(format!(
            "entry path crosses a reparse point: {}",
            relative.display()
        ));
    }
    Ok(canonical)
}

fn has_reparse_component(app: &Path, file: &Path) -> bool {
    let mut current = app.to_path_buf();
    let Ok(relative) = file.strip_prefix(app) else {
        return true;
    };
    for component in relative.components() {
        current.push(component);
        if is_reparse_point(&current) {
            return true;
        }
    }
    false
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_reparse_point(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn collect_protected_so(app: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut visited = 0usize;
    walk_so(app, 0, &mut found, &mut visited)?;
    found.sort();
    found.retain(|path| senbei_io::android::is_protected_so_file(path));
    Ok(found)
}

fn walk_so(
    directory: &Path,
    depth: usize,
    found: &mut Vec<PathBuf>,
    visited: &mut usize,
) -> Result<(), String> {
    if depth > MAX_APP_DEPTH {
        return Err(format!(
            "app folder exceeds the {MAX_APP_DEPTH}-level nesting ceiling"
        ));
    }
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
        *visited += 1;
        if *visited > MAX_APP_ENTRIES {
            return Err(format!(
                "app folder exceeds the {MAX_APP_ENTRIES}-entry ceiling"
            ));
        }
        let path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(|error| format!("read metadata for {}: {error}", path.display()))?;
        if metadata.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case("unpack"))
            {
                continue;
            }
            if is_reparse_point(&path) {
                continue;
            }
            walk_so(&path, depth + 1, found, visited)?;
        } else if metadata.is_file()
            && !is_reparse_point(&path)
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))
        {
            found.push(path);
        }
    }
    Ok(())
}

/// Emit a manifest for explicit inputs. `roots` are scanned at their top
/// level only (no recursion); `android_apps` become `android-app` cases whose
/// walk happens later, inside the supplied folder only.
pub fn emit_manifest(
    roots: &[PathBuf],
    android_apps: &[PathBuf],
    out: &Path,
) -> Result<usize, String> {
    let base = roots
        .first()
        .map(|root| absolute_path(root))
        .unwrap_or_else(|| PathBuf::from("."));
    let mut cases = Vec::new();
    let mut seen = BTreeSet::new();
    for root in roots {
        let root = absolute_path(root);
        let entries = std::fs::read_dir(&root)
            .map_err(|error| format!("read {}: {error}", root.display()))?;
        let mut files: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| is_regular_non_reparse_file(path))
            .collect();
        files.sort();
        for path in files {
            if !is_emittable_input(&path) {
                continue;
            }
            let name = match path.file_name().and_then(|name| name.to_str()) {
                Some(name) => name.to_owned(),
                None => continue,
            };
            let id = name.clone();
            if !seen.insert(id.clone()) {
                continue;
            }
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default();
            let golden = path.with_file_name(format!("{stem}.golden.{extension}"));
            let companion = {
                let mut companion_name = path
                    .file_name()
                    .map(|name| name.to_os_string())
                    .unwrap_or_default();
                companion_name.push("._");
                let companion = path.with_file_name(companion_name);
                companion.is_file().then_some(companion)
            };
            let relative = path.strip_prefix(&base).unwrap_or(&path).to_path_buf();
            let kind = if extension == "dat" {
                Kind::Metadata
            } else {
                Kind::Pe
            };
            let mut case = CaseSpec {
                id,
                kind,
                input: relative,
                companion: companion
                    .map(|path| path.strip_prefix(&base).unwrap_or(&path).to_path_buf()),
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
            };
            if golden.is_file() {
                case.golden = Some(golden.strip_prefix(&base).unwrap_or(&golden).to_path_buf());
            }
            cases.push(case);
        }
    }
    for app in android_apps {
        let app = absolute_path(app);
        let name = app
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "android-app".to_owned());
        let mut id = format!("android-app:{name}");
        let mut suffix = 1usize;
        while !seen.insert(id.clone()) {
            suffix += 1;
            id = format!("android-app:{name}:{suffix}");
        }
        cases.push(CaseSpec {
            id,
            kind: Kind::AndroidApp,
            input: app,
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
        });
    }
    if cases.is_empty() {
        return Err("no inputs found for the emitted manifest".to_owned());
    }
    let manifest = Manifest {
        schema: SCHEMA.to_owned(),
        name: Some(MANIFEST_SCHEMA.to_owned()),
        base_dir: Some(base.clone()),
        defaults: Defaults::default(),
        cases,
    };
    let text = serde_json::to_string_pretty(&manifest)
        .map_err(|error| format!("serialize manifest: {error}"))?;
    write_atomic(out, text.as_bytes()).map_err(|error| format!("write manifest: {error}"))?;
    Ok(manifest.cases.len())
}

fn is_regular_non_reparse_file(path: &Path) -> bool {
    path.is_file() && !is_reparse_point(path)
}

fn is_emittable_input(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name.contains(".golden.") || name.ends_with("._") {
        return false;
    }
    let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
        return false;
    };
    let extension = extension.to_ascii_lowercase();
    if extension != "exe" && extension != "dll" && extension != "dat" {
        return false;
    }
    if extension == "dat" {
        let Ok(mut file) = std::fs::File::open(path) else {
            return false;
        };
        let mut magic = [0u8; 4];
        use std::io::Read;
        if file.read_exact(&mut magic).is_err() {
            return false;
        }
        return u32::from_le_bytes(magic) == 0xFAB1_1BAF;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut prefix = vec![0u8; 8 * 1024];
    use std::io::Read;
    let read = file.read(&mut prefix).unwrap_or(0);
    prefix.truncate(read);
    senbei_engine::detect(&prefix).is_some()
}

/// Write a report atomically: a uniquely named temporary in the destination
/// directory, flushed and synced, then persisted over the destination.
pub fn write_atomic(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = dest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".senbei-harness-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(dest)
        .map(|_| ())
        .map_err(|error| error.error)
}

fn git_info(options: &RunOptions, manifest_base: &Path) -> GitInfo {
    let mut info = GitInfo {
        is_repo: false,
        worktree: None,
        head: options.commit.clone(),
        head_source: if options.commit.is_some() {
            "caller".to_owned()
        } else {
            "none".to_owned()
        },
        caller_commit: options.commit.clone(),
        local_head: None,
        dirty: None,
        modified: 0,
        untracked: 0,
        status_count: 0,
        status_error: None,
    };
    let Some(root) = find_git_root(manifest_base).or_else(|| find_git_root(&options.cwd)) else {
        info.status_error = Some("not a git worktree (or git is unavailable)".to_owned());
        return info;
    };
    info.is_repo = true;
    info.worktree = Some(root.display().to_string());
    match git_capture(&root, &["rev-parse", "HEAD"]) {
        Ok(head) if !head.is_empty() => {
            info.local_head = Some(head.clone());
            if options.commit.is_none() {
                info.head = Some(head);
                info.head_source = "local".to_owned();
            }
        }
        Ok(_) => {
            info.status_error = Some("git rev-parse HEAD returned nothing".to_owned());
        }
        Err(error) => {
            info.status_error = Some(error);
        }
    }
    match git_capture(&root, &["status", "--porcelain"]) {
        Ok(status) => {
            let lines: Vec<&str> = status.lines().filter(|line| !line.is_empty()).collect();
            info.status_count = lines.len();
            info.dirty = Some(!lines.is_empty());
            info.untracked = lines.iter().filter(|line| line.starts_with("??")).count();
            info.modified = info.status_count - info.untracked;
        }
        Err(error) => {
            info.status_error = Some(match info.status_error {
                Some(existing) => format!("{existing}; {error}"),
                None => error,
            });
        }
    }
    info
}

fn find_git_root(dir: &Path) -> Option<PathBuf> {
    let dir = absolute_path(dir);
    let output = Command::new("git")
        .arg("-C")
        .arg(&dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!text.is_empty()).then(|| PathBuf::from(text))
}

fn git_capture(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("run git {:?}: {error}", args))?;
    if !output.status.success() {
        return Err(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn kind_name(kind: senbei_engine::Kind) -> &'static str {
    match kind {
        senbei_engine::Kind::NativeExe => "native-exe",
        senbei_engine::Kind::ManagedExe => "managed-exe",
        senbei_engine::Kind::NativeDll => "native-dll",
        senbei_engine::Kind::ManagedDll => "managed-dll",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.finalize() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn resolved_display(base: &Path, path: &Path) -> String {
    absolute_from(base, path).display().to_string()
}

fn absolute_from(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// True when `error` **surfaces** an engine-internal panic.
///
/// The engine converts a caught panic into `UnpackError::InternalPanic`; the
/// outer `catch_unwind_quiet` therefore sees an ordinary `Err`, not a panic.
/// A DLL-first run that falls back to the EXE pipeline wraps both candidate
/// errors in `PipelineFallbackFailed`, so the internal panic can be nested.
/// Walk the wrapper recursively so a panic cannot masquerade as an ordinary
/// restore-stage failure (in particular under `expect_failure`).
///
/// Scope: this detects panics the engine converted and returned. It says
/// nothing about a worker-thread panic that was swallowed by a successful
/// fallback — that state is not observable from the returned `Result`.
/// Apply the PE error policy to `error`.
///
/// Kept separate so the panic-vs-expected-failure decision can be tested with
/// typed errors that no synthetic input reliably produces:
///
/// * a surfaced engine panic is always outcome `panic` and always fails the
///   case, regardless of `expect_failure`;
/// * any other error is a declared `expected_failure` when requested;
/// * otherwise it is an ordinary `unpack_failed`.
pub fn classify_unpack_error(
    output: &mut OutputReport,
    report: &mut CaseReport,
    error: &senbei_engine::UnpackError,
    expect_failure: bool,
) {
    if surfaced_internal_panic(error) {
        // An engine panic is a defect, never a declared outcome — even when the
        // case declared expect_failure. The outer catch never sees it because
        // the engine converts it to an Err.
        output.fail(format!("engine-internal panic surfaced: {error}"));
        report.fail("panic", format!("engine-internal panic surfaced: {error}"));
    } else if expect_failure {
        output.status = "pass".to_owned();
        output.notes.push("expected failure observed".to_owned());
        report.pass("expected_failure");
    } else {
        output.fail(format!("unpack failed: {error}"));
        report.fail("unpack_failed", format!("unpack failed: {error}"));
    }
}

/// Like [`surfaced_internal_panic`], for the `anyhow` errors the Android
/// orchestration returns. Android engines do not currently convert panics into
/// a typed error (a panic reaches the outer `catch_unwind_quiet`), but if one
/// is ever wrapped in a context chain the harness must still not accept it as
/// an expected failure.
pub fn surfaced_internal_panic_in(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<senbei_engine::UnpackError>()
            .is_some_and(surfaced_internal_panic)
    })
}

pub fn surfaced_internal_panic(error: &senbei_engine::UnpackError) -> bool {
    match error {
        senbei_engine::UnpackError::InternalPanic { .. } => true,
        senbei_engine::UnpackError::PipelineFallbackFailed { dll, exe } => {
            surfaced_internal_panic(dll) || surfaced_internal_panic(exe)
        }
        _ => false,
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "<non-string panic payload>".to_owned()
    }
}
