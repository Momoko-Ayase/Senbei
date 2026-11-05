//! Versioned, machine-readable protection profile.
//!
//! A profile separates four questions that the unpack pipelines answer at
//! different stages:
//!
//! 1. Is this a supported protected target? ([`RecognitionStatus`])
//! 2. Which layout route was tried, and what happened? ([`LayoutAttempt`])
//! 3. Did recovery produce an image? ([`RecoveryStatus`])
//! 4. Does that image pass the static checks? ([`ValidationStatus`])
//!
//! The profile records only what was observed in the input and what the
//! pipelines reported. It deliberately carries no inferred protection build,
//! vendor version, or runtime-behaviour claim. A caller can serialize it as-is;
//! the schema is versioned by [`PROFILE_FORMAT_VERSION`].

use serde::Serialize;

use crate::windows::{IntegrityReport, IntegritySeverity, Kind};

/// Version of the serialized [`ProtectionProfile`] schema.
pub const PROFILE_FORMAT_VERSION: u32 = 1;

/// Host format family of the observed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    WindowsPe,
    AndroidElf,
    Il2cppMetadata,
}

/// Container format recognized from the input header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetFormat {
    Pe32,
    Pe32Plus,
    Elf64Aarch64,
    Il2cppMetadata,
}

/// One observed signal that supports (or rejects) protective handling.
///
/// These are evidence of *what was found*, not an identification of a product
/// build. `HeaderMagic` means the input's header key table carries the supported
/// magic; `ExternalCompanionDeclaration` means the loader never reads past its
/// own file without a companion suffix; `CompanionSpliced` means a matching
/// `._` payload was actually used; `PrivateSection` means Android's private
/// loader section exists; `AesSchedule` means the seeded AES schedule parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionEvidence {
    HeaderMagic,
    ExternalCompanionDeclaration,
    CompanionSpliced,
    PrivateSection,
    AesSchedule,
    /// An obfuscated metadata blob was structurally transformed and the result
    /// validated. The IO metadata adapter records this only after the transform
    /// actually succeeds; a mere metadata magic match is not evidence.
    ValidatedMetadataTransform,
}

/// What recognition concluded, independent of recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionStatus {
    NotAttempted,
    Recognized,
    NotRecognized,
    /// Recognition could not run because an input ceiling was exceeded. This
    /// is not the same as "not protected"; the caller read a limit error.
    Blocked,
}

/// What recovery concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    NotAttempted,
    Succeeded,
    Failed,
    /// Recovery was not attempted because a prerequisite (a companion payload,
    /// or a resource ceiling) was missing or exceeded.
    Blocked,
}

/// Result of the static validation over the final image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    NotRun,
    Clean,
    Warnings,
    Failed,
}

/// Recovery route considered for an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutKind {
    /// The legacy DLL layout.
    Dll,
    /// The EXE-style shell layout (also the external-companion route).
    ExeStyle,
    /// Android staged extraction + ELF restoration. A matched probe may list
    /// this as `NotAttempted`; that is not a recovery claim.
    AndroidStaged,
    /// Structural IL2CPP metadata transform.
    MetadataStructural,
    /// Seeded IL2CPP metadata restoration.
    MetadataSeeded,
    /// IL2CPP method-index recovery.
    MetadataMethodIndices,
}

/// Outcome of one layout attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// The route was planned but not run because a prior route was accepted.
    NotAttempted,
    Succeeded,
    /// The route produced an image, but a fatal static check rejected it.
    Rejected,
    /// The route returned an error.
    Failed,
}

/// The observed input, before any recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedTarget {
    pub platform: Platform,
    pub format: Option<TargetFormat>,
    pub kind: Option<Kind>,
    /// IL2CPP metadata format version, when the adapter parsed one.
    pub metadata_version: Option<u32>,
    /// True only when the recovered image came from an external `._` companion
    /// that was actually spliced into the input.
    pub external_companion: bool,
}

impl ObservedTarget {
    #[must_use]
    pub fn windows(format: Option<TargetFormat>, kind: Option<Kind>) -> Self {
        Self {
            platform: Platform::WindowsPe,
            format,
            kind,
            metadata_version: None,
            external_companion: false,
        }
    }

    #[must_use]
    pub fn android(format: Option<TargetFormat>) -> Self {
        Self {
            platform: Platform::AndroidElf,
            format,
            kind: None,
            metadata_version: None,
            external_companion: false,
        }
    }

    #[must_use]
    pub fn metadata(version: Option<u32>) -> Self {
        Self {
            platform: Platform::Il2cppMetadata,
            format: Some(TargetFormat::Il2cppMetadata),
            kind: None,
            metadata_version: version,
            external_companion: false,
        }
    }
}

/// One attempted route, kept even when a later route succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayoutAttempt {
    pub layout: LayoutKind,
    pub outcome: AttemptOutcome,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl LayoutAttempt {
    #[must_use]
    pub fn not_attempted(layout: LayoutKind) -> Self {
        Self {
            layout,
            outcome: AttemptOutcome::NotAttempted,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }
}

/// Versioned result of inspecting and (optionally) recovering one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectionProfile {
    pub format_version: u32,
    pub observed: ObservedTarget,
    pub evidence: Vec<ProtectionEvidence>,
    pub recognition: RecognitionStatus,
    pub recovery: RecoveryStatus,
    pub static_validation: ValidationStatus,
    /// Candidate routes in evaluation order. An accepted route keeps the
    /// failures that preceded it.
    pub candidates: Vec<LayoutAttempt>,
    /// The route whose output was accepted, when recovery succeeded.
    pub selected: Option<LayoutKind>,
    /// Defects still present after the final validation. Empty when clean.
    pub warnings: Vec<String>,
    /// Unresolved failures: rejected/failed candidates when no route was
    /// accepted, or fatal findings on an accepted image. Empty when none.
    pub errors: Vec<String>,
}

impl ProtectionProfile {
    #[must_use]
    pub fn new(observed: ObservedTarget) -> Self {
        Self {
            format_version: PROFILE_FORMAT_VERSION,
            observed,
            evidence: Vec::new(),
            recognition: RecognitionStatus::NotAttempted,
            recovery: RecoveryStatus::NotAttempted,
            static_validation: ValidationStatus::NotRun,
            candidates: Vec::new(),
            selected: None,
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn push_warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    pub fn push_error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
    }

    /// Record that an external `._` companion was spliced into the input.
    ///
    /// The I/O layer calls this only after the splice actually happened. The
    /// observed target then reports the external-companion layout and the EXE
    /// route as the only candidate, without changing any pipeline result.
    pub fn record_companion_spliced(&mut self) {
        self.observed.external_companion = true;
        push_unique(&mut self.evidence, ProtectionEvidence::CompanionSpliced);
        if self.candidates.is_empty() {
            self.candidates
                .push(LayoutAttempt::not_attempted(LayoutKind::ExeStyle));
        }
    }

    /// The attempt for `layout`, if it was planned or run.
    pub fn attempt_mut(&mut self, layout: LayoutKind) -> Option<&mut LayoutAttempt> {
        self.candidates
            .iter_mut()
            .find(|attempt| attempt.layout == layout)
    }

    /// Record an attempt, adding a planned `NotAttempted` entry first when this
    /// layout has not been seen yet. Returns the updated attempt.
    pub(crate) fn record_attempt(
        &mut self,
        layout: LayoutKind,
        outcome: AttemptOutcome,
        warnings: Vec<String>,
        errors: Vec<String>,
    ) -> &mut LayoutAttempt {
        if self.attempt_mut(layout).is_none() {
            self.candidates.push(LayoutAttempt::not_attempted(layout));
        }
        let attempt = self
            .attempt_mut(layout)
            .expect("attempt was just inserted or already existed");
        attempt.outcome = outcome;
        attempt.warnings = warnings;
        attempt.errors = errors;
        attempt
    }

    /// Replace the validation fields with the final image's report.
    ///
    /// The I/O layer calls this after companion overlays so the profile
    /// describes the bytes that are actually returned, not the pre-overlay
    /// image.
    pub fn record_static_validation(&mut self, report: &IntegrityReport) {
        self.static_validation = validation_status(report);
        self.warnings = messages(report, IntegritySeverity::Warning);
        self.errors = messages(report, IntegritySeverity::Fatal);
    }
}

fn push_unique(evidence: &mut Vec<ProtectionEvidence>, value: ProtectionEvidence) {
    if !evidence.contains(&value) {
        evidence.push(value);
    }
}

fn validation_status(report: &IntegrityReport) -> ValidationStatus {
    if report.ok() {
        ValidationStatus::Clean
    } else if report.has_fatal() {
        ValidationStatus::Failed
    } else {
        ValidationStatus::Warnings
    }
}

fn messages(report: &IntegrityReport, severity: IntegritySeverity) -> Vec<String> {
    report
        .findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .map(|finding| finding.message.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::{IntegrityFinding, IntegrityReport};

    fn report(findings: &[(IntegritySeverity, &str)]) -> IntegrityReport {
        IntegrityReport {
            issues: findings
                .iter()
                .map(|(_, issue)| (*issue).to_owned())
                .collect(),
            findings: findings
                .iter()
                .map(|(severity, message)| IntegrityFinding {
                    severity: *severity,
                    message: (*message).to_owned(),
                })
                .collect(),
        }
    }

    #[test]
    fn new_profile_is_versioned_and_unattempted() {
        let profile = ProtectionProfile::new(ObservedTarget::windows(
            Some(TargetFormat::Pe32Plus),
            Some(Kind::NativeDll),
        ));
        assert_eq!(profile.format_version, PROFILE_FORMAT_VERSION);
        assert_eq!(profile.recognition, RecognitionStatus::NotAttempted);
        assert_eq!(profile.recovery, RecoveryStatus::NotAttempted);
        assert_eq!(profile.static_validation, ValidationStatus::NotRun);
        assert!(profile.candidates.is_empty());
        assert!(profile.selected.is_none());
    }

    #[test]
    fn validation_status_separates_warnings_from_fatal_findings() {
        let clean = ProtectionProfile::new(ObservedTarget::android(None));
        let mut clean = clean;
        clean.record_static_validation(&report(&[]));
        assert_eq!(clean.static_validation, ValidationStatus::Clean);
        assert!(clean.warnings.is_empty() && clean.errors.is_empty());

        let mut warned = ProtectionProfile::new(ObservedTarget::android(None));
        warned.record_static_validation(&report(&[(IntegritySeverity::Warning, "w")]));
        assert_eq!(warned.static_validation, ValidationStatus::Warnings);
        assert_eq!(warned.warnings, ["w"]);
        assert!(warned.errors.is_empty());

        let mut failed = ProtectionProfile::new(ObservedTarget::android(None));
        failed.record_static_validation(&report(&[
            (IntegritySeverity::Warning, "w"),
            (IntegritySeverity::Fatal, "f"),
        ]));
        assert_eq!(failed.static_validation, ValidationStatus::Failed);
        assert_eq!(failed.warnings, ["w"]);
        assert_eq!(failed.errors, ["f"]);
    }

    #[test]
    fn attempts_keep_order_and_are_updated_in_place() {
        let mut profile = ProtectionProfile::new(ObservedTarget::windows(None, None));
        profile
            .candidates
            .push(LayoutAttempt::not_attempted(LayoutKind::Dll));
        profile
            .candidates
            .push(LayoutAttempt::not_attempted(LayoutKind::ExeStyle));
        profile.record_attempt(
            LayoutKind::Dll,
            AttemptOutcome::Rejected,
            Vec::new(),
            vec!["bad".to_owned()],
        );
        profile.record_attempt(
            LayoutKind::ExeStyle,
            AttemptOutcome::Succeeded,
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(profile.candidates.len(), 2);
        assert_eq!(profile.candidates[0].layout, LayoutKind::Dll);
        assert_eq!(profile.candidates[0].outcome, AttemptOutcome::Rejected);
        assert_eq!(profile.candidates[1].outcome, AttemptOutcome::Succeeded);
    }

    #[test]
    fn serialized_profile_uses_versioned_snake_case_schema() {
        let mut profile = ProtectionProfile::new(ObservedTarget::windows(
            Some(TargetFormat::Pe32Plus),
            Some(Kind::NativeDll),
        ));
        profile.evidence.push(ProtectionEvidence::HeaderMagic);
        profile.record_attempt(
            LayoutKind::ExeStyle,
            AttemptOutcome::Succeeded,
            Vec::new(),
            Vec::new(),
        );
        let value = serde_json::to_value(&profile).expect("profile serializes");
        assert_eq!(value["format_version"], 1);
        assert_eq!(value["observed"]["platform"], "windows_pe");
        assert_eq!(value["observed"]["format"], "pe32_plus");
        assert_eq!(value["observed"]["kind"], "native_dll");
        assert_eq!(value["evidence"][0], "header_magic");
        assert_eq!(value["candidates"][0]["layout"], "exe_style");
        assert_eq!(value["candidates"][0]["outcome"], "succeeded");
    }
}
