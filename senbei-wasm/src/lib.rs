//! WebAssembly bindings for the senbei unpacker core.
//!
//! Everything here is I/O-free: the browser hands in file bytes and gets
//! unpacked file bytes back. No network, no filesystem, no uploads.

use senbei_engine::{IntegrityReport, IntegritySeverity, ProtectionProfile, UnpackError};
use wasm_bindgen::prelude::*;

/// Install a panic hook that forwards Rust panic messages to the browser
/// console (and to the JS error), instead of a bare `unreachable` trap.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Serialize a profile for the JS layer.
///
/// `ProtectionProfile` has a derived serializer and no fallible field, but a
/// serialization failure must never panic inside wasm, so the fallback is the
/// JSON literal `null`.
fn profile_json(profile: &ProtectionProfile) -> String {
    serde_json::to_string(profile).unwrap_or_else(|_| "null".to_string())
}

/// `"fatal"` / `"warning"`, matching the labels the JSON report uses.
fn severity_label(severity: IntegritySeverity) -> &'static str {
    match severity {
        IntegritySeverity::Fatal => "fatal",
        IntegritySeverity::Warning => "warning",
    }
}

/// Result of unpacking one protected module.
#[wasm_bindgen]
pub struct UnpackResult {
    kind: String,
    bytes: Vec<u8>,
    suspect: bool,
    issues: Vec<String>,
    companion: bool,
    severities: Vec<String>,
    fatal: bool,
    profile_json: Option<String>,
}

#[wasm_bindgen]
impl UnpackResult {
    /// Detected module kind: `"native-exe"`, `"managed-exe"`, `"native-dll"`,
    /// or `"managed-dll"`.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The unpacked image bytes.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// True when the static integrity check flagged the output as likely
    /// broken at runtime. The bytes are still the best available.
    #[wasm_bindgen(getter)]
    pub fn suspect(&self) -> bool {
        self.suspect
    }

    /// Human-readable integrity defects (empty when the check is clean).
    #[wasm_bindgen(getter)]
    pub fn issues(&self) -> Vec<String> {
        self.issues.clone()
    }

    /// True when the input was spliced from an external-companion (`._`)
    /// payload.
    #[wasm_bindgen(getter)]
    pub fn companion(&self) -> bool {
        self.companion
    }

    /// Severity of each entry in [`Self::issues`] at the same index:
    /// `"fatal"` or `"warning"`. A fatal finding means the loader or CLR
    /// rejects the image; a warning means a recoverable region looks
    /// unrestored.
    #[wasm_bindgen(getter)]
    pub fn severities(&self) -> Vec<String> {
        self.severities.clone()
    }

    /// True when at least one finding is fatal.
    #[wasm_bindgen(getter)]
    pub fn fatal(&self) -> bool {
        self.fatal
    }

    /// The recovery profile as JSON, or `undefined` when the call did not
    /// collect one. See [`unpack_file_reported`] for the variant that always
    /// carries the profile, including on failure.
    #[wasm_bindgen(getter)]
    pub fn profile_json(&self) -> Option<String> {
        self.profile_json.clone()
    }
}

/// Result of de-obfuscating an il2cpp `global-metadata.dat`.
#[wasm_bindgen]
pub struct MetadataResult {
    bytes: Vec<u8>,
    version: u32,
    methods: usize,
    remapped: usize,
    modules: usize,
}

#[wasm_bindgen]
impl MetadataResult {
    /// The (possibly rewritten) metadata bytes.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Total method-definition entries in the metadata.
    #[wasm_bindgen(getter)]
    pub fn methods(&self) -> usize {
        self.methods
    }

    /// Method tokens actually rewritten (0 means the input was already
    /// de-obfuscated and the bytes are unchanged).
    #[wasm_bindgen(getter)]
    pub fn remapped(&self) -> usize {
        self.remapped
    }

    /// Modules (images) owning at least one method.
    #[wasm_bindgen(getter)]
    pub fn modules(&self) -> usize {
        self.modules
    }
}

fn kind_str(kind: senbei_engine::Kind) -> &'static str {
    match kind {
        senbei_engine::Kind::NativeExe => "native-exe",
        senbei_engine::Kind::ManagedExe => "managed-exe",
        senbei_engine::Kind::NativeDll => "native-dll",
        senbei_engine::Kind::ManagedDll => "managed-dll",
    }
}

/// Copy an integrity report's findings into the parallel arrays the JS layer
/// reads (`issues[i]` and `severities[i]` describe the same defect).
fn split_findings(report: &IntegrityReport) -> (Vec<String>, Vec<String>, bool) {
    let issues: Vec<String> = report
        .issues
        .iter()
        .map(|issue| issue.to_string())
        .collect();
    let mut severities = Vec::with_capacity(report.findings.len());
    let mut fatal = false;
    for finding in &report.findings {
        let label = severity_label(finding.severity);
        if finding.severity == IntegritySeverity::Fatal {
            fatal = true;
        }
        severities.push(label.to_string());
    }
    // `issues` and `findings` are documented to have the same order and
    // length; if a future change breaks that, the UI must still line up.
    if severities.len() != issues.len() {
        severities = issues.iter().map(|_| "warning".to_string()).collect();
        fatal = false;
    }
    (issues, severities, fatal)
}

/// Classify a file's bytes without unpacking.
///
/// Returns `"native-exe"`, `"managed-exe"`, `"native-dll"`, `"managed-dll"`,
/// `"metadata"` (an il2cpp `global-metadata.dat`), or `undefined` for
/// anything unrecognized.
#[wasm_bindgen]
pub fn detect(input: &[u8]) -> Option<String> {
    if senbei_metadata::is_metadata(input) {
        return Some("metadata".to_string());
    }
    senbei_engine::detect(input).map(|d| kind_str(d.kind).to_string())
}

/// Return the pre-recovery profile for an input as JSON.
///
/// This never runs a recovery, so every candidate stays `not_attempted` and
/// `selected` is `null`. Two things are deliberately kept separate in the
/// returned document:
///
/// * a PE input reports `recognition: "recognized"` only when the header key
///   table carries the supported magic;
/// * an il2cpp metadata input reports the observed format version with
///   `recognition: "not_attempted"`, because a metadata magic/version match
///   identifies a format, not a protection.
///
/// Always returns a JSON object (never `null`); an unrecognized input gets a
/// profile with `recognition: "not_recognized"`.
#[wasm_bindgen]
pub fn inspect_profile_json(input: &[u8]) -> String {
    if let Some(identity) = senbei_metadata::identify(input) {
        let version = identity.version.raw();
        let mut profile =
            ProtectionProfile::new(senbei_engine::ObservedTarget::metadata(Some(version)));
        profile.push_warning(
            "the il2cpp metadata magic and version identify a file format; \
             they do not establish that the file is protected",
        );
        return profile_json(&profile);
    }
    profile_json(&senbei_engine::inspect_profile(input))
}

/// Unpack a protected module.
///
/// `input` is the protected `.exe`/`.dll`; `companion` is the optional
/// `<input>._` external-companion payload (pass `null`/`undefined` when there
/// is none). Throws a string error when the input is not a supported
/// CrackProof file or is corrupt.
#[wasm_bindgen]
pub fn unpack_file(input: &[u8], companion: Option<Vec<u8>>) -> Result<UnpackResult, JsError> {
    let r = senbei_io::job::unpack_bytes(input, companion.as_deref())
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(UnpackResult::from_image(r))
}

/// De-obfuscate the method tokens of an il2cpp `global-metadata.dat`.
///
/// The transform is idempotent: an already-clean metadata comes back
/// byte-identical with `remapped == 0`. Throws a string error for non-metadata
/// input, an unsupported format version, or a malformed layout.
#[wasm_bindgen]
pub fn deobfuscate_metadata(data: &[u8]) -> Result<MetadataResult, JsError> {
    let (bytes, report) =
        senbei_metadata::deobfuscate(data).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(MetadataResult {
        bytes,
        version: report.version,
        methods: report.methods,
        remapped: report.remapped,
        modules: report.modules,
    })
}

/// De-obfuscate metadata and return the transform profile alongside it.
///
/// [`deobfuscate_metadata`] throws; this variant never does, so the web worker
/// can report why an input was rejected and still export a profile for it.
///
/// The profile records `ValidatedMetadataTransform` evidence only after the
/// transform actually rewrote tokens. A metadata that is already clean is
/// reported as `recognition: "not_recognized"` with a warning: its header
/// identifies the format, not a protection.
#[wasm_bindgen]
pub fn deobfuscate_metadata_reported(data: &[u8]) -> MetadataReport {
    let (version, profile, result) = metadata_outcome(data);
    MetadataReport::from_outcome(version, profile, result)
}

type MetadataTransform = Result<(Vec<u8>, senbei_metadata::Report), senbei_metadata::Error>;

/// Build the metadata profile the same way the I/O report does, so the browser
/// export and the CLI JSON report describe one transform identically.
///
/// * a successful rewrite is the only case that claims
///   `ValidatedMetadataTransform` evidence;
/// * an already-clean blob is `not_recognized` — the header matched, but
///   nothing was transformed, so there is no protection evidence;
/// * the PE static check does not apply to metadata output, so
///   `static_validation` stays `not_run` in every case.
fn metadata_outcome(data: &[u8]) -> (Option<u32>, ProtectionProfile, MetadataTransform) {
    use senbei_engine::{
        AttemptOutcome, LayoutAttempt, LayoutKind, ObservedTarget, ProtectionEvidence,
        RecognitionStatus, RecoveryStatus, ValidationStatus,
    };

    let identity = senbei_metadata::identify(data);
    let version = identity.map(|identity| identity.raw_version);
    let mut profile = ProtectionProfile::new(ObservedTarget::metadata(version));
    if identity.is_none() {
        profile.recognition = RecognitionStatus::NotRecognized;
        profile.push_error("not an il2cpp global-metadata.dat");
        return (version, profile, Err(senbei_metadata::Error::NotMetadata));
    }
    // The structural transform is the route this binding runs. A version that
    // identifies but has no structural layout still gets this candidate, and
    // the transform's own error explains the refusal.
    let route = LayoutKind::MetadataStructural;
    let result = senbei_metadata::deobfuscate(data);
    match &result {
        Ok((_, report)) if report.remapped > 0 => {
            profile.recognition = RecognitionStatus::Recognized;
            profile.evidence = vec![ProtectionEvidence::ValidatedMetadataTransform];
            profile.candidates = vec![LayoutAttempt {
                layout: route,
                outcome: AttemptOutcome::Succeeded,
                warnings: Vec::new(),
                errors: Vec::new(),
            }];
            profile.selected = Some(route);
            profile.recovery = RecoveryStatus::Succeeded;
        }
        Ok(_) => {
            profile.recognition = RecognitionStatus::NotRecognized;
            profile.candidates = vec![LayoutAttempt {
                layout: route,
                outcome: AttemptOutcome::Succeeded,
                warnings: Vec::new(),
                errors: Vec::new(),
            }];
            profile.push_warning("metadata is already de-obfuscated; no tokens were rewritten");
        }
        Err(error) => {
            // A version/magic match plus a failed transform cannot establish
            // that protected method fields were present in this input.
            profile.recognition = RecognitionStatus::Blocked;
            profile.candidates = vec![LayoutAttempt {
                layout: route,
                outcome: AttemptOutcome::Failed,
                warnings: Vec::new(),
                errors: vec![error.to_string().into()],
            }];
            profile.recovery = RecoveryStatus::Failed;
            profile.push_error(error.to_string());
        }
    }
    profile.static_validation = ValidationStatus::NotRun;
    (version, profile, result)
}

#[cfg(test)]
mod metadata_profile_tests {
    use super::*;
    use senbei_engine::{RecognitionStatus, RecoveryStatus, ValidationStatus};

    #[test]
    fn failed_metadata_transform_has_no_protection_verdict() {
        for version in [31u32, 999] {
            let mut input = 0xFAB1_1BAFu32.to_le_bytes().to_vec();
            input.extend_from_slice(&version.to_le_bytes());
            let (observed, profile, result) = metadata_outcome(&input);
            assert!(result.is_err());
            assert_eq!(observed, Some(version));
            assert_eq!(profile.recognition, RecognitionStatus::Blocked);
            assert!(profile.evidence.is_empty());
            assert_eq!(profile.recovery, RecoveryStatus::Failed);
            assert_eq!(profile.static_validation, ValidationStatus::NotRun);
            assert!(profile.selected.is_none());
        }
    }
}

/// Outcome of [`deobfuscate_metadata_reported`].
#[wasm_bindgen]
pub struct MetadataReport {
    ok: bool,
    bytes: Vec<u8>,
    version: u32,
    methods: usize,
    remapped: usize,
    modules: usize,
    error: Option<String>,
    profile_json: String,
}

#[wasm_bindgen]
impl MetadataReport {
    /// True when the transform succeeded. A successful run may still have
    /// rewritten nothing — check [`Self::remapped`].
    #[wasm_bindgen(getter)]
    pub fn ok(&self) -> bool {
        self.ok
    }

    /// The (possibly rewritten) metadata bytes; empty when [`Self::ok`] is false.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Raw header version, or 0 when the input was not metadata.
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Total method-definition entries (0 on failure).
    #[wasm_bindgen(getter)]
    pub fn methods(&self) -> usize {
        self.methods
    }

    /// Method tokens actually rewritten.
    #[wasm_bindgen(getter)]
    pub fn remapped(&self) -> usize {
        self.remapped
    }

    /// Modules (images) owning at least one method.
    #[wasm_bindgen(getter)]
    pub fn modules(&self) -> usize {
        self.modules
    }

    /// The error message when [`Self::ok`] is false.
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }

    /// The transform profile as JSON, in every case.
    #[wasm_bindgen(getter)]
    pub fn profile_json(&self) -> String {
        self.profile_json.clone()
    }
}

impl MetadataReport {
    fn from_outcome(
        version: Option<u32>,
        profile: ProtectionProfile,
        result: Result<(Vec<u8>, senbei_metadata::Report), senbei_metadata::Error>,
    ) -> Self {
        let profile_json = profile_json(&profile);
        match result {
            Ok((bytes, report)) => Self {
                ok: true,
                bytes,
                version: report.version,
                methods: report.methods,
                remapped: report.remapped,
                modules: report.modules,
                error: None,
                profile_json,
            },
            Err(error) => Self {
                ok: false,
                bytes: Vec::new(),
                version: version.unwrap_or(0),
                methods: 0,
                remapped: 0,
                modules: 0,
                error: Some(error.to_string()),
                profile_json,
            },
        }
    }
}

/// Unpack a protected module, forcing the EXE pipeline (no DLL-pipeline
/// probe). See [`senbei_io::job::unpack_bytes_force_exe`] for why the web app
/// needs this recovery path.
#[wasm_bindgen]
pub fn unpack_file_force_exe(
    input: &[u8],
    companion: Option<Vec<u8>>,
) -> Result<UnpackResult, JsError> {
    let r = senbei_io::job::unpack_bytes_force_exe(input, companion.as_deref())
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(UnpackResult::from_image(r))
}

impl UnpackResult {
    fn from_image(r: senbei_io::job::UnpackedImage) -> Self {
        let (issues, severities, fatal) = split_findings(&r.integrity);
        Self {
            kind: kind_str(r.kind).to_string(),
            bytes: r.bytes,
            suspect: !r.integrity.ok(),
            issues,
            companion: r.companion,
            severities,
            fatal,
            profile_json: None,
        }
    }
}

/// Outcome of [`unpack_file_reported`]: success data or the error message,
/// plus the recovery profile in both cases.
///
/// Unlike [`UnpackResult`], this never throws for an unpack failure. The web
/// worker needs the failed routes (which pipeline ran, why it was rejected) to
/// show why a file did not recover; a thrown string would lose them.
#[wasm_bindgen]
pub struct UnpackReport {
    ok: bool,
    kind: String,
    bytes: Vec<u8>,
    suspect: bool,
    issues: Vec<String>,
    severities: Vec<String>,
    fatal: bool,
    companion: bool,
    error: Option<String>,
    profile_json: String,
}

#[wasm_bindgen]
impl UnpackReport {
    /// True when recovery produced an image.
    #[wasm_bindgen(getter)]
    pub fn ok(&self) -> bool {
        self.ok
    }

    /// Detected module kind (same labels as [`UnpackResult::kind`]); empty when
    /// the input was not recognized as a supported target.
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The unpacked image bytes (empty when [`Self::ok`] is false).
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// True when the static integrity check flagged the image as likely broken.
    #[wasm_bindgen(getter)]
    pub fn suspect(&self) -> bool {
        self.suspect
    }

    /// Integrity defects, in the checker's order.
    #[wasm_bindgen(getter)]
    pub fn issues(&self) -> Vec<String> {
        self.issues.clone()
    }

    /// Severity of each [`Self::issues`] entry: `"fatal"` or `"warning"`.
    #[wasm_bindgen(getter)]
    pub fn severities(&self) -> Vec<String> {
        self.severities.clone()
    }

    /// True when at least one finding is fatal.
    #[wasm_bindgen(getter)]
    pub fn fatal(&self) -> bool {
        self.fatal
    }

    /// True when the input was reconstructed from an external `._` companion.
    #[wasm_bindgen(getter)]
    pub fn companion(&self) -> bool {
        self.companion
    }

    /// The error message when [`Self::ok`] is false.
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }

    /// The recovery profile as JSON, in every case — including failures and
    /// inputs that were never recognized.
    #[wasm_bindgen(getter)]
    pub fn profile_json(&self) -> String {
        self.profile_json.clone()
    }
}

/// Unpack with the full profile, without throwing on an unpack failure.
///
/// `force_exe` selects the EXE-only route (the web app's retry path for a DLL
/// whose DLL-first probe trapped). See [`unpack_file`] for the arguments.
#[wasm_bindgen]
pub fn unpack_file_reported(
    input: &[u8],
    companion: Option<Vec<u8>>,
    force_exe: bool,
) -> UnpackReport {
    let (profile, result) = if force_exe {
        senbei_io::job::unpack_bytes_force_exe_profiled(input, companion.as_deref())
    } else {
        senbei_io::job::unpack_bytes_profiled(input, companion.as_deref())
    };
    UnpackReport::from_outcome(profile, result)
}

impl UnpackReport {
    fn from_outcome(
        profile: ProtectionProfile,
        result: Result<senbei_io::job::UnpackedImage, UnpackError>,
    ) -> Self {
        let profile_json = profile_json(&profile);
        let kind = profile
            .observed
            .kind
            .map(|kind| kind_str(kind).to_string())
            .unwrap_or_default();
        match result {
            Ok(r) => {
                let (issues, severities, fatal) = split_findings(&r.integrity);
                Self {
                    ok: true,
                    kind: kind_str(r.kind).to_string(),
                    bytes: r.bytes,
                    suspect: !r.integrity.ok(),
                    issues,
                    severities,
                    fatal,
                    companion: r.companion,
                    error: None,
                    profile_json,
                }
            }
            Err(error) => Self {
                ok: false,
                kind,
                bytes: Vec::new(),
                suspect: false,
                issues: Vec::new(),
                severities: Vec::new(),
                fatal: false,
                companion: profile.observed.external_companion,
                error: Some(error.to_string()),
                profile_json,
            },
        }
    }
}
