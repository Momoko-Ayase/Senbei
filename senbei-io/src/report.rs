//! Versioned, machine-readable run report.
//!
//! One [`Report`] describes one CLI invocation: which inputs were examined,
//! what each of them turned out to be, which routes were tried and selected,
//! what was written, and which defects were found. It is the only structure the
//! `--json` output serializes, so its shape is the contract reported by
//! [`REPORT_FORMAT_VERSION`].
//!
//! Two rules shape the fields:
//!
//! * Every value is something that was actually observed. Timings are recorded
//!   only where a stage was measured (`None` otherwise); hashes are taken from
//!   the bytes that were actually produced; a route is only marked selected if
//!   a pipeline accepted it.
//! * Inspection never claims recovery. An [`Mode::Inspect`] run reports
//!   recognition and the planned routes, never `selected`, `recovered`, or a
//!   static-validation verdict.
//!
//! A container (`.apk`/`.apks`/`.xapk`) is reported as one input with
//! [`Role::Container`]: its manifest inventory is listed separately from the
//! entries that were actually probed and restored, so a manifest list is never
//! mistaken for inspected protected content.

use std::path::Path;
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use senbei_engine::{
    AttemptOutcome, LayoutKind, ProtectionEvidence, ProtectionProfile, RecognitionStatus,
    RecoveryStatus, ValidationStatus,
};

/// Version of the serialized [`Report`] schema.
pub const REPORT_FORMAT_VERSION: u32 = 1;

/// What the invocation was asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Detection only: no recovery, no output, no log.
    Inspect,
    /// Restore and write outputs.
    Unpack,
    /// Run the real recovery, keep nothing (no ordinary output, no log).
    DryRun,
}

/// Whether the input is a protected file or a container of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A single protected file, metadata blob, or unrecognized file.
    Content,
    /// An app package whose entries are handled one by one.
    Container,
}

/// Outcome of one input, from the caller's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputStatus {
    /// Produced output.
    Ok,
    /// Produced output that fails the static integrity check.
    Suspect,
    /// Inspection recognized a protected target. Nothing was recovered, so
    /// this is never counted as an output.
    Recognized,
    /// Not a target, already handled, or a layout this build does not know.
    Skipped,
    /// A target that failed.
    Error,
}

/// Outcome of one container entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    /// Restored or de-obfuscated and written.
    Restored,
    /// Byte-identical content was already restored from another source.
    Duplicate,
    /// Probed and not a protected target.
    NotTarget,
    /// A metadata blob whose protected fields were already canonical.
    Unchanged,
    /// Listed in a container inventory. Not probed, so not a target claim.
    Inventoried,
    /// Recognized as a target but the restore failed.
    Error,
}

/// What a container entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    SharedLibrary,
    Metadata,
}

/// One measured or declared stage of an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Detection,
    ManifestInventory,
    EntryProbe,
    Recovery,
    StaticValidation,
    OutputWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Ok,
    Skipped,
    Failed,
    Blocked,
}

/// State of the `<input>._` companion relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionState {
    /// No sibling `._` file.
    Absent,
    /// A `._` payload was found and is the input's payload.
    Spliced,
    /// A sibling `._` exists but does not pair with this stub.
    Unmatched,
    /// A sibling `._` exists but could not be read.
    Unreadable,
}

/// Size and SHA-256 of bytes that were actually produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Digest {
    pub size: u64,
    pub sha256: String,
}

impl Digest {
    /// Digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self {
            size: bytes.len() as u64,
            sha256: senbei_crypto::hex_digest(&hasher.finalize()),
        }
    }
}

/// One output file that was left on disk.
///
/// `sha256` is present only when the producing step had the bytes in hand. An
/// engine that streams straight to its output file reports size alone rather
/// than re-reading the file just to hash it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutputFile {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
}

impl OutputFile {
    /// Output whose bytes are known.
    pub fn from_bytes(path: &Path, bytes: &[u8]) -> Self {
        Self {
            path: path.display().to_string(),
            size: bytes.len() as u64,
            sha256: Some(Digest::of(bytes).sha256),
        }
    }

    /// Output that an engine streamed to disk.
    ///
    /// Size is observed from the file; no hash is reported because hashing
    /// would mean reading a potentially huge output back solely for the
    /// report. `sha256` is `Some` only where the producing step already held
    /// the bytes.
    pub fn from_path(path: &Path) -> Self {
        Self {
            path: path.display().to_string(),
            size: std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0),
            sha256: None,
        }
    }
}

/// Non-target tallies from a folder scan, kept apart from input results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    /// Named candidates that were probed and matched no detector.
    pub non_target_skipped: usize,
    /// Directory entries the walk could not read.
    pub walk_errors: usize,
    /// Selected files whose content probe failed.
    pub probe_errors: usize,
}

/// The companion relationship recorded for one Windows input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompanionReport {
    pub state: CompanionState,
    pub path: Option<String>,
    pub detail: Option<String>,
}

/// One manifest parsed from a container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestReport {
    /// Where the manifest was read from: the package, or `package::entry`.
    pub source: String,
    pub package: Option<String>,
    pub version: Option<String>,
    /// True only when the manifest named both a package and a version.
    pub named: bool,
}

/// Container inventory: membership facts, not inspected content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerReport {
    /// `apk`, `apks`, or `xapk`.
    pub kind: String,
    pub manifests: Vec<ManifestReport>,
    /// Central-directory entry count of the top-level package.
    pub entry_count: usize,
    /// Entry names that would be probed during a restore.
    pub candidate_entries: Vec<String>,
    /// Nested packages discovered at the top level of a bundle.
    pub nested_packages: Vec<String>,
}

/// One stage of an input, with its measured duration when it was timed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StageReport {
    pub stage: Stage,
    pub status: StageStatus,
    pub detail: Option<String>,
    pub duration_ms: Option<u64>,
}

impl StageReport {
    pub fn new(stage: Stage, status: StageStatus) -> Self {
        Self {
            stage,
            status,
            detail: None,
            duration_ms: None,
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn timed(mut self, elapsed_ms: u64) -> Self {
        self.duration_ms = Some(elapsed_ms);
        self
    }
}

/// One entry of a container, or one artifact produced for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryReport {
    /// Source label, e.g. `base.apk::lib/arm64-v8a/libil2cpp.so`.
    pub name: String,
    pub status: EntryStatus,
    pub kind: Option<EntryKind>,
    /// Route selected for this entry, when one was.
    pub layout: Option<LayoutKind>,
    pub metadata_version: Option<u32>,
    pub remapped: Option<usize>,
    /// Libraries whose decoded module was paired with this metadata entry.
    pub provenance: Vec<String>,
    /// Where the restored bytes were written (absent in dry-run/inspect).
    pub output: Option<OutputFile>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl EntryReport {
    pub fn new(name: impl Into<String>, status: EntryStatus) -> Self {
        Self {
            name: name.into(),
            status,
            kind: None,
            layout: None,
            metadata_version: None,
            remapped: None,
            provenance: Vec::new(),
            output: None,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

/// Everything observed for one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InputReport {
    pub path: String,
    pub role: Role,
    pub status: InputStatus,
    /// Engine profile: recognition evidence, candidate routes, and — only when
    /// recovery actually ran — the selected route and static-validation verdict.
    pub profile: Option<ProtectionProfile>,
    pub companion: Option<CompanionReport>,
    pub container: Option<ContainerReport>,
    pub entries: Vec<EntryReport>,
    /// Output files left on disk. Empty for inspect and dry-run.
    pub outputs: Vec<OutputFile>,
    /// Digest of the recovered image, when recovery produced one.
    pub recovered: Option<Digest>,
    /// Metadata header identity, when the input was an il2cpp metadata blob.
    pub metadata: Option<senbei_metadata::MetadataIdentity>,
    /// Raw il2cpp metadata version, duplicated for flat consumers.
    pub metadata_version: Option<u32>,
    /// Libraries whose decoded module was paired with this metadata input.
    pub provenance: Vec<String>,
    pub stages: Vec<StageReport>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

impl InputReport {
    pub fn new(path: &Path, role: Role) -> Self {
        Self {
            path: path.display().to_string(),
            role,
            status: InputStatus::Skipped,
            profile: None,
            companion: None,
            container: None,
            entries: Vec::new(),
            outputs: Vec::new(),
            recovered: None,
            metadata: None,
            metadata_version: None,
            provenance: Vec::new(),
            stages: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            duration_ms: 0,
        }
    }

    pub fn warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    pub fn error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }
}

/// Counts over the whole invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SummaryReport {
    /// Inputs examined.
    pub inputs: usize,
    /// Inputs that produced output.
    pub recovered: usize,
    /// Inputs whose protection was recognized. Only an `inspect` run fills
    /// this: it is detection evidence, never a recovery claim.
    pub recognized: usize,
    /// Inputs that were not targets or were left untouched.
    pub skipped: usize,
    /// Inputs whose output fails the static integrity check.
    pub suspect: usize,
    /// Inputs that failed.
    pub errors: usize,
    /// il2cpp metadata blobs de-obfuscated, including embedded ones.
    pub metadata: usize,
    /// App packages opened.
    pub packages: usize,
}

/// Identity of the tool that produced the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

/// One invocation's report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub format_version: u32,
    pub tool: Tool,
    pub mode: Mode,
    /// Folder scan tallies. `None` for a single-file run.
    pub scan: Option<ScanReport>,
    pub inputs: Vec<InputReport>,
    pub summary: SummaryReport,
    /// Run-level failures that are not attributable to one input.
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

impl Report {
    /// Serialize as one JSON document.
    pub fn to_json(&self) -> String {
        // The report contains only owned, serializable values.
        serde_json::to_string(self).unwrap_or_else(|error| {
            format!(
                "{{\"format_version\":{REPORT_FORMAT_VERSION},\"error\":\"report serialization failed: {error}\"}}"
            )
        })
    }

    /// One-line summary in the same shape as [`crate::job::Summary::line`].
    pub fn summary_line(&self) -> String {
        let s = &self.summary;
        let mut line = format!(
            "{} unpacked · {} skipped · {} errors · {} suspect · {} metadata",
            s.recovered, s.skipped, s.errors, s.suspect, s.metadata
        );
        if s.packages > 0 {
            line.push_str(&format!(" · {} packages", s.packages));
        }
        line
    }

    /// Human-readable rendering, one block per input, for non-`--json` runs.
    pub fn render_text(&self) -> String {
        let mut text = String::new();
        for input in &self.inputs {
            text.push_str(&render_input(input));
        }
        if !self.errors.is_empty() {
            for error in &self.errors {
                text.push_str(&format!("error: {error}\n"));
            }
        }
        text
    }
}

fn render_input(input: &InputReport) -> String {
    let mut text = format!("{}\n", input.path);
    text.push_str(&format!("  role: {:?}\n", input.role));
    if let Some(profile) = &input.profile {
        text.push_str(&format!("  recognition: {:?}\n", profile.recognition));
        if !profile.evidence.is_empty() {
            text.push_str(&format!("  evidence: {:?}\n", profile.evidence));
        }
        for candidate in &profile.candidates {
            let mut line = format!(
                "  route {}: {:?}",
                layout_name(candidate.layout),
                candidate.outcome
            );
            if !candidate.errors.is_empty() {
                line.push_str(&format!(" ({})", candidate.errors.join("; ")));
            }
            text.push_str(&line);
            text.push('\n');
        }
        if let Some(selected) = profile.selected {
            text.push_str(&format!("  selected: {:?}\n", layout_name(selected)));
        }
        text.push_str(&format!("  recovery: {:?}\n", profile.recovery));
        text.push_str(&format!(
            "  static validation: {:?}\n",
            profile.static_validation
        ));
    }
    if let Some(metadata) = &input.metadata {
        text.push_str(&format!(
            "  metadata: version {} ({:?}, capabilities {:?})\n",
            metadata.raw_version, metadata.layout, metadata.capabilities
        ));
    }
    if let Some(container) = &input.container {
        text.push_str(&format!(
            "  container: {} · {} entries · {} manifests\n",
            container.kind,
            container.entry_count,
            container.manifests.len()
        ));
        for manifest in &container.manifests {
            text.push_str(&format!(
                "    manifest {} → {} {}\n",
                manifest.source,
                manifest.package.as_deref().unwrap_or("<unnamed>"),
                manifest.version.as_deref().unwrap_or("")
            ));
        }
        for entry in &container.candidate_entries {
            text.push_str(&format!("    candidate {entry}\n"));
        }
    }
    for entry in &input.entries {
        text.push_str(&format!(
            "  entry {}: {:?}{}\n",
            entry.name,
            entry.status,
            entry
                .output
                .as_ref()
                .map(|output| format!(" -> {}", output.path))
                .unwrap_or_default()
        ));
    }
    if let Some(recovered) = &input.recovered {
        text.push_str(&format!(
            "  recovered: {} bytes · {}\n",
            recovered.size, recovered.sha256
        ));
    }
    text.push_str(&format!("  status: {:?}\n", input.status));
    text
}

fn layout_name(layout: LayoutKind) -> &'static str {
    match layout {
        LayoutKind::Dll => "dll",
        LayoutKind::ExeStyle => "exe_style",
        LayoutKind::AndroidStaged => "android_staged",
        LayoutKind::MetadataStructural => "metadata_structural",
        LayoutKind::MetadataSeeded => "metadata_seeded",
        LayoutKind::MetadataMethodIndices => "metadata_method_indices",
    }
}

/// Accumulates inputs during one invocation.
pub struct Collector {
    mode: Mode,
    started: Instant,
    scan: Option<ScanReport>,
    inputs: Vec<InputReport>,
    summary: SummaryReport,
    errors: Vec<String>,
}

impl Collector {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            started: Instant::now(),
            scan: None,
            inputs: Vec::new(),
            summary: SummaryReport::default(),
            errors: Vec::new(),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Record the folder scan tallies for a folder run.
    pub fn set_scan(&mut self, scan: ScanReport) {
        self.scan = Some(scan);
    }

    /// Record one finished input and fold its status into the summary.
    pub fn push(&mut self, mut input: InputReport) {
        if self.mode == Mode::DryRun {
            // Nothing produced by a dry run is retained, so no output file may
            // be reported. The attempt itself keeps its real outcome.
            if !input.outputs.is_empty() {
                // The produced byte count is a real result of the attempt even
                // though the file itself is not kept. A hash is only carried
                // over when the producing step actually computed one.
                if input.recovered.is_none()
                    && let Some(first) = input.outputs.first()
                    && let Some(sha256) = &first.sha256
                {
                    input.recovered = Some(Digest {
                        size: first.size,
                        sha256: sha256.clone(),
                    });
                }
                for stage in &mut input.stages {
                    if stage.stage == Stage::OutputWrite {
                        stage.status = StageStatus::Skipped;
                        stage.detail =
                            Some("dry run: the produced output was discarded".to_owned());
                    }
                }
                if !input
                    .stages
                    .iter()
                    .any(|stage| stage.stage == Stage::OutputWrite)
                {
                    input.stages.push(
                        StageReport::new(Stage::OutputWrite, StageStatus::Skipped)
                            .detail("dry run: the produced output was discarded"),
                    );
                }
                input.outputs.clear();
            }
            for entry in &mut input.entries {
                entry.output = None;
            }
        }
        self.summary.inputs += 1;
        match input.status {
            InputStatus::Ok => self.summary.recovered += 1,
            InputStatus::Suspect => {
                self.summary.recovered += 1;
                self.summary.suspect += 1;
            }
            InputStatus::Recognized => self.summary.recognized += 1,
            InputStatus::Skipped => self.summary.skipped += 1,
            InputStatus::Error => self.summary.errors += 1,
        }
        self.inputs.push(input);
    }

    pub fn summary_mut(&mut self) -> &mut SummaryReport {
        &mut self.summary
    }

    /// Record a run-level failure that is not attributable to one input.
    pub fn push_error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }

    pub fn finish(self) -> Report {
        Report {
            format_version: REPORT_FORMAT_VERSION,
            tool: Tool {
                name: "senbei".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            mode: self.mode,
            scan: self.scan,
            inputs: self.inputs,
            summary: self.summary,
            errors: self.errors,
            duration_ms: self.started.elapsed().as_millis() as u64,
        }
    }
}

pub(crate) fn now_ms(since: Instant) -> u64 {
    since.elapsed().as_millis() as u64
}

// ---------------------------------------------------------------------------
// Profile helpers shared by the platform adapters
// ---------------------------------------------------------------------------

/// Profile for a protected Android library whose restore actually succeeded.
///
/// The staged route is recorded as attempted and selected because the restore
/// wrote an image; no probe is repeated here.
pub(crate) fn android_recovered_profile() -> ProtectionProfile {
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::android(Some(
        senbei_engine::TargetFormat::Elf64Aarch64,
    )));
    profile.recognition = RecognitionStatus::Recognized;
    profile.evidence = vec![
        ProtectionEvidence::PrivateSection,
        ProtectionEvidence::AesSchedule,
    ];
    profile.candidates = vec![senbei_engine::LayoutAttempt {
        layout: LayoutKind::AndroidStaged,
        outcome: AttemptOutcome::Succeeded,
        warnings: Vec::new(),
        errors: Vec::new(),
    }];
    profile.selected = Some(LayoutKind::AndroidStaged);
    profile.recovery = RecoveryStatus::Succeeded;
    profile
}

/// Profile for a library the scan selected but whose restore failed.
///
/// Recognition is inherited from the scan probe that selected the file; the
/// route is recorded as failed with the error that stopped it.
pub(crate) fn android_failed_profile(error: &str) -> ProtectionProfile {
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::android(None));
    profile.recognition = RecognitionStatus::Recognized;
    profile.candidates = vec![senbei_engine::LayoutAttempt {
        layout: LayoutKind::AndroidStaged,
        outcome: AttemptOutcome::Failed,
        warnings: Vec::new(),
        errors: vec![error.to_owned()],
    }];
    profile.recovery = RecoveryStatus::Failed;
    profile.push_error(error.to_owned());
    profile
}

/// Profile for a metadata blob whose transform changed protected fields.
///
/// A metadata magic match alone is not protection evidence, so this is only
/// used after the transform returned `remapped > 0` and validated.
pub(crate) fn metadata_recovered_profile(
    identity: Option<senbei_metadata::MetadataIdentity>,
    route: LayoutKind,
) -> ProtectionProfile {
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::metadata(
        identity.map(|identity| identity.raw_version),
    ));
    profile.recognition = RecognitionStatus::Recognized;
    profile.evidence = vec![ProtectionEvidence::ValidatedMetadataTransform];
    profile.candidates = vec![senbei_engine::LayoutAttempt {
        layout: route,
        outcome: AttemptOutcome::Succeeded,
        warnings: Vec::new(),
        errors: Vec::new(),
    }];
    profile.selected = Some(route);
    profile.recovery = RecoveryStatus::Succeeded;
    // Not a PE image: the PE static check does not apply to metadata output.
    profile.static_validation = ValidationStatus::NotRun;
    profile
}

/// Profile for a metadata blob that was identified but needed no change.
///
/// Nothing was transformed, so no protection evidence is claimed.
pub(crate) fn metadata_unchanged_profile(
    identity: Option<senbei_metadata::MetadataIdentity>,
) -> ProtectionProfile {
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::metadata(
        identity.map(|identity| identity.raw_version),
    ));
    profile.recognition = RecognitionStatus::NotRecognized;
    profile.static_validation = ValidationStatus::NotRun;
    profile
}

/// Profile for a metadata blob whose transform failed.
pub(crate) fn metadata_failed_profile(
    identity: Option<senbei_metadata::MetadataIdentity>,
    route: LayoutKind,
    error: &str,
) -> ProtectionProfile {
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::metadata(
        identity.map(|identity| identity.raw_version),
    ));
    // An attempted transform that did not validate establishes no protection
    // verdict, even when the metadata header identifies a known version.
    profile.recognition = RecognitionStatus::Blocked;
    profile.candidates = vec![senbei_engine::LayoutAttempt {
        layout: route,
        outcome: AttemptOutcome::Failed,
        warnings: Vec::new(),
        errors: vec![error.to_owned()],
    }];
    profile.recovery = RecoveryStatus::Failed;
    profile.push_error(error.to_owned());
    profile.static_validation = ValidationStatus::NotRun;
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input(status: InputStatus) -> InputReport {
        let mut input = InputReport::new(Path::new("a.exe"), Role::Content);
        input.status = status;
        input.recovered = Some(Digest::of(b"bytes"));
        input
    }

    #[test]
    fn a_failed_metadata_transform_cannot_claim_protection() {
        for version in [31u32, 999] {
            let mut header = 0xFAB1_1BAFu32.to_le_bytes().to_vec();
            header.extend_from_slice(&version.to_le_bytes());
            let profile = metadata_failed_profile(
                senbei_metadata::identify(&header),
                LayoutKind::MetadataStructural,
                "transform did not validate",
            );
            assert_eq!(profile.observed.metadata_version, Some(version));
            assert_eq!(profile.recognition, RecognitionStatus::Blocked);
            assert!(profile.evidence.is_empty());
            assert_eq!(profile.recovery, RecoveryStatus::Failed);
            assert_eq!(profile.static_validation, ValidationStatus::NotRun);
            assert!(profile.selected.is_none());
        }
    }

    #[test]
    fn report_round_trips_through_json_with_a_version_field() {
        let mut collector = Collector::new(Mode::DryRun);
        collector.push(sample_input(InputStatus::Ok));
        collector.push(sample_input(InputStatus::Suspect));
        let report = collector.finish();
        assert_eq!(report.format_version, REPORT_FORMAT_VERSION);
        let json = report.to_json();
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["format_version"], REPORT_FORMAT_VERSION);
        assert_eq!(value["mode"], "dry_run");
        assert_eq!(value["summary"]["inputs"], 2);
        assert_eq!(value["summary"]["suspect"], 1);
        assert_eq!(value["summary"]["errors"], 0);
        assert_eq!(value["tool"]["name"], "senbei");
        assert!(value["inputs"][0]["recovered"]["sha256"].is_string());
    }

    #[test]
    fn error_status_counts_and_surfaces_in_the_summary() {
        let mut collector = Collector::new(Mode::Unpack);
        collector.push(sample_input(InputStatus::Error));
        collector.push(sample_input(InputStatus::Skipped));
        let report = collector.finish();
        assert_eq!(report.summary.errors, 1);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.summary.recovered, 0);
    }

    #[test]
    fn digest_matches_a_known_sha256() {
        let digest = Digest::of(b"abc");
        assert_eq!(digest.size, 3);
        assert_eq!(
            digest.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn inspect_profile_helpers_never_claim_recovery() {
        let unchanged = metadata_unchanged_profile(None);
        assert_eq!(unchanged.recovery, RecoveryStatus::NotAttempted);
        assert!(unchanged.selected.is_none());
        assert!(unchanged.evidence.is_empty());
        assert_eq!(unchanged.static_validation, ValidationStatus::NotRun);

        let recovered = metadata_recovered_profile(None, LayoutKind::MetadataSeeded);
        assert_eq!(recovered.selected, Some(LayoutKind::MetadataSeeded));
        assert_eq!(
            recovered.evidence,
            vec![ProtectionEvidence::ValidatedMetadataTransform]
        );
        assert_eq!(recovered.static_validation, ValidationStatus::NotRun);
    }
}
