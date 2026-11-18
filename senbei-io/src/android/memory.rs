//! Android recovery over bytes, for a front end that has no filesystem.
//!
//! The browser binding calls these. They run the same engines as the
//! path-based drivers in the parent module and describe the result through the
//! same profile helpers, so a library or a metadata blob is reported the same
//! way whichever front end handled it.
//!
//! Application context stays with the caller. A metadata blob is paired with a
//! module `0x0C` only when the caller passes one, and the caller is the one
//! that knows which library belongs to the same application.

use anyhow::Context;
use senbei_engine::android::{
    ResourceLimits, extract_stage2_in_memory, probe_libil2cpp_profiled_with_limits,
    restore_libil2cpp_in_memory,
};
use senbei_engine::{LayoutKind, ProtectionProfile, ValidationStatus};
use senbei_i18n::{Message, Msg};

use super::ValidationDiagnostics;
use crate::message::of_error;

/// A protected library restored in memory.
#[derive(Debug)]
pub struct LibraryBytes {
    /// The restored ELF image.
    pub image: Vec<u8>,
    /// The unwrapped metadata blob, when the restored image embeds one.
    pub embedded_metadata: Option<Vec<u8>>,
    /// Decoded module `0x0C`. It belongs to this library's application and is
    /// what a v24 metadata blob of that application needs.
    pub method_index_module: Option<Vec<u8>>,
    /// Structural diagnostics for `image`. Advisory: the restore accepted it.
    pub validation: ValidationDiagnostics,
    /// Table counts of `image`, as the restore's own validation read them.
    pub elf: ElfSummary,
}

/// Table counts of a restored ELF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ElfSummary {
    pub sections: usize,
    pub segments: usize,
    pub dynamic_symbols: usize,
    pub dynamic_relocations: usize,
    pub pltgot_relocations: usize,
}

/// What [`restore_library_bytes`] did with one input.
#[derive(Debug)]
pub enum LibraryOutcome {
    Restored(LibraryBytes),
    /// The probe did not match. The input is not a supported target.
    NotProtected,
    /// The probe was blocked by a ceiling, or the restore failed.
    Failed(Message),
}

/// Probe and restore one AArch64 library held in memory.
///
/// The profile is returned in every case. A probe that does not match leaves
/// it `not_recognized` and nothing else runs.
pub fn restore_library_bytes(
    input: &[u8],
    verbose: bool,
    limits: &ResourceLimits,
) -> (ProtectionProfile, LibraryOutcome) {
    let (probe, matched) = probe_libil2cpp_profiled_with_limits(input, limits);
    match matched {
        Ok(true) => {}
        Ok(false) => return (probe, LibraryOutcome::NotProtected),
        Err(error) => {
            let detail = of_error(&anyhow::Error::new(error));
            return (probe, LibraryOutcome::Failed(detail));
        }
    }
    match restore_matched_library(input, verbose, limits) {
        Ok(restored) => {
            let mut profile = crate::report::android_recovered_profile();
            profile.static_validation = if restored.validation.is_clean() {
                ValidationStatus::Clean
            } else {
                ValidationStatus::Warnings
            };
            profile.warnings.extend(
                restored
                    .validation
                    .messages
                    .iter()
                    .cloned()
                    .map(Message::from),
            );
            (profile, LibraryOutcome::Restored(restored))
        }
        Err(error) => {
            let detail = of_error(&error);
            let mut profile = crate::report::android_failed_profile(&detail);
            // The probe read this input, so its format and evidence are known.
            profile.observed = probe.observed;
            profile.evidence = probe.evidence;
            (profile, LibraryOutcome::Failed(detail))
        }
    }
}

fn restore_matched_library(
    input: &[u8],
    verbose: bool,
    limits: &ResourceLimits,
) -> anyhow::Result<LibraryBytes> {
    let extraction =
        extract_stage2_in_memory(input, limits).context("extract stage-1/stage-2 payload")?;
    let restored = restore_libil2cpp_in_memory(input, &extraction, verbose, limits)
        .context("restore protected library")?;
    Ok(LibraryBytes {
        embedded_metadata: senbei_metadata::android::extract_embedded_metadata(&restored.bytes),
        method_index_module: extraction.module(0x0c).map(<[u8]>::to_vec),
        elf: ElfSummary {
            sections: restored.validation.sections,
            segments: restored.validation.segments,
            dynamic_symbols: restored.validation.dynamic_symbols,
            dynamic_relocations: restored.validation.dynamic_relocations,
            pltgot_relocations: restored.validation.pltgot_relocations,
        },
        validation: ValidationDiagnostics {
            messages: restored.validation.diagnostics,
        },
        image: restored.bytes,
    })
}

/// What [`restore_metadata_bytes_profiled`] did with one blob.
///
/// `layout` is the transform that ran. A blob that needed no change keeps it
/// here only: its profile claims no route, as an ordinary run's does.
#[derive(Debug)]
pub enum MetadataOutcome {
    /// Protected fields were rewritten; `bytes` is the restored blob.
    Restored {
        bytes: Vec<u8>,
        report: senbei_metadata::Report,
        layout: LayoutKind,
    },
    /// The transform ran and validated, and the blob needed no change.
    Unchanged {
        report: senbei_metadata::Report,
        layout: LayoutKind,
    },
    /// A format version this build leaves untouched by design.
    Unsupported {
        version: u32,
    },
    Failed(Message),
}

/// The module `0x0C` images the caller collected for a blob's application.
#[derive(Debug, Clone, Copy)]
pub enum ModuleBinding<'a> {
    /// No library of the application yielded a module.
    None,
    /// Every library that yielded a module yielded this one.
    One(&'a [u8]),
    /// The libraries yielded this many different modules.
    Conflicting { profiles: usize },
}

/// Restore one il2cpp metadata blob held in memory.
///
/// Only a v24 blob consumes module `0x0C`, so only a v24 blob fails on a
/// missing or conflicting binding. The later layouts ignore it.
pub fn restore_metadata_bytes_profiled(
    data: &[u8],
    binding: ModuleBinding<'_>,
) -> (ProtectionProfile, MetadataOutcome) {
    let identity = senbei_metadata::identify(data);
    let method_index_module = match binding {
        ModuleBinding::One(module) => Some(module),
        ModuleBinding::None => None,
        ModuleBinding::Conflicting { profiles } => {
            if identity.is_some_and(|identity| identity.raw_version == 24) {
                let detail = Message::with_text(
                    Msg::AmbiguousModule0c,
                    format!("ambiguous module 0x0C binding ({profiles} distinct profiles)"),
                );
                let profile = crate::report::metadata_failed_profile(
                    identity,
                    LayoutKind::MetadataMethodIndices,
                    &detail,
                );
                return (profile, MetadataOutcome::Failed(detail));
            }
            None
        }
    };
    match super::restore_metadata_bytes_with_module(data, method_index_module) {
        Ok((bytes, report, layout)) if report.remapped > 0 => (
            crate::report::metadata_recovered_profile(identity, layout),
            MetadataOutcome::Restored {
                bytes,
                report,
                layout,
            },
        ),
        Ok((_, report, layout)) => (
            crate::report::metadata_unchanged_profile(identity),
            MetadataOutcome::Unchanged { report, layout },
        ),
        Err(error) => match unsupported_version(&error) {
            Some(version) => {
                let mut profile = crate::report::metadata_unchanged_profile(identity);
                profile.push_warning(Msg::MetadataLeftUntouched { version });
                (profile, MetadataOutcome::Unsupported { version })
            }
            None => {
                let detail = of_error(&error);
                let profile = crate::report::metadata_failed_profile(
                    identity,
                    LayoutKind::MetadataStructural,
                    &detail,
                );
                (profile, MetadataOutcome::Failed(detail))
            }
        },
    }
}

/// The version in a [`senbei_metadata::Error::UnsupportedVersion`] anywhere in
/// `error`'s chain.
fn unsupported_version(error: &anyhow::Error) -> Option<u32> {
    error.chain().find_map(|cause| match cause.downcast_ref() {
        Some(senbei_metadata::Error::UnsupportedVersion(version)) => Some(*version),
        _ => None,
    })
}

/// Application identity from a package's root `AndroidManifest.xml`: the
/// `package` name and its version.
///
/// `bytes` is the manifest entry, plain or compiled. `truncated` says the
/// caller's bounded read stopped before the end of the entry, in which case no
/// identity is returned.
pub fn manifest_identity(bytes: &[u8], truncated: bool) -> Option<(String, String)> {
    super::manifest::identity(bytes, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use senbei_engine::{RecognitionStatus, RecoveryStatus};

    fn metadata_header(version: u32) -> Vec<u8> {
        let mut blob = 0xFAB1_1BAF_u32.to_le_bytes().to_vec();
        blob.extend_from_slice(&version.to_le_bytes());
        blob
    }

    #[test]
    fn an_ordinary_library_is_not_protected_and_nothing_runs() {
        let (profile, outcome) = restore_library_bytes(
            b"\x7fELF not a real image",
            false,
            &ResourceLimits::default(),
        );
        assert!(matches!(outcome, LibraryOutcome::NotProtected));
        assert_eq!(profile.recognition, RecognitionStatus::NotRecognized);
        assert!(profile.candidates.is_empty());
        assert_eq!(profile.recovery, RecoveryStatus::NotAttempted);
    }

    #[test]
    fn v24_metadata_without_its_module_fails_instead_of_skipping() {
        let (profile, outcome) =
            restore_metadata_bytes_profiled(&metadata_header(24), ModuleBinding::None);
        let MetadataOutcome::Failed(detail) = outcome else {
            panic!("a v24 blob with no module must fail: {outcome:?}");
        };
        assert_eq!(detail.msg(), Some(&Msg::NoModule0c));
        assert_eq!(profile.recognition, RecognitionStatus::Blocked);
        assert_eq!(profile.recovery, RecoveryStatus::Failed);
        assert_eq!(profile.static_validation, ValidationStatus::NotRun);
    }

    #[test]
    fn an_unsupported_version_is_left_untouched() {
        let (profile, outcome) =
            restore_metadata_bytes_profiled(&metadata_header(999), ModuleBinding::None);
        assert!(matches!(
            outcome,
            MetadataOutcome::Unsupported { version: 999 }
        ));
        assert_eq!(profile.recognition, RecognitionStatus::NotRecognized);
        assert_eq!(profile.recovery, RecoveryStatus::NotAttempted);
        assert!(profile.errors.is_empty());
        assert_eq!(profile.warnings.len(), 1);
    }

    #[test]
    fn a_malformed_blob_fails_without_a_protection_verdict() {
        let (profile, outcome) =
            restore_metadata_bytes_profiled(&metadata_header(31), ModuleBinding::None);
        assert!(matches!(outcome, MetadataOutcome::Failed(_)));
        assert_eq!(profile.recognition, RecognitionStatus::Blocked);
        assert!(profile.evidence.is_empty());
        assert!(profile.selected.is_none());
    }

    #[test]
    fn conflicting_modules_stop_only_the_layout_that_needs_one() {
        let conflicting = ModuleBinding::Conflicting { profiles: 2 };
        let (profile, outcome) = restore_metadata_bytes_profiled(&metadata_header(24), conflicting);
        let MetadataOutcome::Failed(detail) = outcome else {
            panic!("a v24 blob cannot choose between two modules: {outcome:?}");
        };
        assert_eq!(detail.msg(), Some(&Msg::AmbiguousModule0c));
        assert_eq!(profile.recovery, RecoveryStatus::Failed);

        // A layout that takes no module is decided by its own transform.
        let (_, outcome) = restore_metadata_bytes_profiled(&metadata_header(31), conflicting);
        let MetadataOutcome::Failed(detail) = outcome else {
            panic!("a header-only blob is malformed: {outcome:?}");
        };
        assert_ne!(detail.msg(), Some(&Msg::AmbiguousModule0c));
    }

    #[test]
    fn a_truncated_manifest_names_no_application() {
        let manifest = br#"<manifest package="com.example.app" android:versionCode="7">"#;
        assert_eq!(
            manifest_identity(manifest, false),
            Some(("com.example.app".to_owned(), "7".to_owned()))
        );
        assert_eq!(manifest_identity(manifest, true), None);
    }
}
