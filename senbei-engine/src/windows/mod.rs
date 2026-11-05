//! PE detection, unpacking, and structural validation.

pub mod dll;
mod error;
pub mod exe;
pub mod integrity;
mod layout;
pub(crate) mod parallel;

use senbei_crypto::primitives;
use serde::Serialize;

use crate::profile::{
    AttemptOutcome, LayoutAttempt, LayoutKind, ObservedTarget, ProtectionEvidence,
    ProtectionProfile, RecognitionStatus, RecoveryStatus, TargetFormat,
};
use integrity::IntegritySeverity as ProfileSeverity;

pub(crate) use crate::panic_capture::{PanicCapture, current_panic_capture, with_panic_capture};

pub use crate::thread_cap;
pub use dll::{unpack_dll, unpack_dll_v};
pub use error::*;
pub use exe::{unpack as unpack_exe, unpack_v as unpack_exe_v};
pub use integrity::{
    IntegrityFinding, IntegrityReport, IntegritySeverity, check as check_integrity,
};

/// Maximum plausible PE `SizeOfImage` we are willing to allocate a zero buffer
/// for. Guards against a corrupt/crafted header requesting a multi-gigabyte
/// (or, as a sign-extended negative `i32`, multi-exabyte) allocation, which
/// would abort the process — an abort that `catch_unpack` below cannot trap.
/// Real protected binaries are far below this.
pub(crate) const MAX_IMAGE_SIZE: u64 = senbei_crypto::MAX_IMAGE_SIZE;

/// Run an unpack pipeline, converting any internal panic into a clean
/// [`UnpackError::InternalPanic`] so the public API stays panic-free on any input
/// (truncated/garbled files chase offsets out of bounds). The panic location and
/// payload are captured for diagnostics without printing a backtrace to stderr.
///
/// Note: allocation *failures* abort the process and are NOT caught here; size
/// requests are bounds-checked against [`MAX_IMAGE_SIZE`] before allocating.
pub(crate) fn catch_unpack<F>(f: F) -> Result<Vec<u8>, UnpackError>
where
    F: FnOnce() -> Result<Vec<u8>, UnpackError>,
{
    crate::panic_capture::install_hook();
    let capture = PanicCapture::new();
    let r = with_panic_capture(Some(capture.clone()), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
    });
    match r {
        Ok(result) => result,
        Err(payload) => {
            let details = capture.details(payload.as_ref());
            Err(UnpackError::InternalPanic {
                message: details.message,
                file: details.file,
                line: details.line,
                column: details.column,
            })
        }
    }
}

/// Crackproof header magic stored in `keys[1]`/`info[1]`.
pub(crate) const MAGIC_KONN: u32 = 0x4E4E4F4B; // b"KONN" little-endian (= 1313754955)

/// True if `magic` is the Crackproof magic this unpacker supports.
pub(crate) fn is_supported_magic(magic: u32) -> bool {
    magic == MAGIC_KONN
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    NativeExe,
    ManagedExe,
    NativeDll,
    ManagedDll,
}

#[derive(Debug, Clone, Copy)]
pub struct Detected {
    pub kind: Kind,
    pub magic: u32,
}

// ---------------------------------------------------------------------------
// Content-based detection
// ---------------------------------------------------------------------------

/// Derive the 8-element Crackproof key table from the header at offset 4096.
/// Returns `None` if the input is too short or doesn't have a valid PE signature.
fn key_table(input: &[u8]) -> Option<[u32; 8]> {
    // Need at least 4128 bytes: the key-table loop below reads dwords up to
    // offset 4124 (bytes 4124..4127). Guarding only `< 4096` would let a
    // 4096..4127-byte PE (e.g. a 4 KiB stub) panic in `get_u32`.
    if input.len() < 4128 {
        return None;
    }
    // Validate the PE signature with checked arithmetic so a crafted offset
    // cannot wrap the bounds check on a narrower target.
    let e_lfanew = primitives::get_u32(input, 0x3C);
    let pe_start = e_lfanew as usize;
    if pe_start.checked_add(4).is_none_or(|end| end > input.len()) {
        return None;
    }
    if &input[pe_start..pe_start + 4] != b"PE\0\0" {
        return None;
    }
    // Derive 8 keys per the Crackproof header-key formula.
    let mut keys = [0u32; 8];
    keys[0] = primitives::get_u32(input, 4096);
    let mut k = keys[0];
    for i in 0u32..7 {
        let cell = primitives::get_u32(input, 4100u32.wrapping_add(i.wrapping_mul(4)));
        keys[(i + 1) as usize] = k ^ cell;
        k = i.wrapping_mul(i) ^ (k.wrapping_add(cell).wrapping_sub(i));
    }
    Some(keys)
}

/// Detect whether `input` is a Crackproof-protected binary and classify it.
/// Returns `None` if the magic doesn't match.
///
/// Routing: `keys[1]` must be the Crackproof magic (`KONN`).
/// The PE IMAGE_FILE_DLL characteristic distinguishes EXE vs DLL;
/// the CLR data-directory RVA distinguishes managed from native for both.
pub fn detect(input: &[u8]) -> Option<Detected> {
    let keys = key_table(input)?;
    let magic = keys[1];
    // Anything whose magic doesn't match is left untouched rather than
    // detected-then-errored, honoring the "anything that doesn't match is
    // left untouched" contract.
    if !is_supported_magic(magic) {
        return None;
    }
    // Use the PE DLL characteristic to distinguish EXE from DLL.
    // IMAGE_FILE_HEADER.Characteristics is at peOff+4+18; bit 0x2000 = IMAGE_FILE_DLL.
    let pe_off = primitives::get_u32(input, 0x3C);
    let chars_offset = pe_off.wrapping_add(4).wrapping_add(18);
    if (chars_offset as usize)
        .checked_add(2)
        .is_none_or(|end| end > input.len())
    {
        return None;
    }
    let chars =
        (input[chars_offset as usize] as u16) | ((input[chars_offset as usize + 1] as u16) << 8);
    let is_dll = (chars & 0x2000) != 0;
    // Managed vs native via the CLR data-directory RVA.
    // peOff + 24 = start of optional header. The data directories start at a
    // magic-dependent offset within it: PE32 (0x10B) at +96, PE32+ (0x20B) at
    // +112. Using the PE32+ offset on a PE32 image reads the wrong dword and
    // can mis-flag a native image as managed.
    //
    // `get_u16`/`get_u32` index unchecked, so every read past the already-
    // checked Characteristics word must be bounds-checked first: a truncated
    // file (e.g. `e_lfanew` pointing at len-24) would otherwise panic here,
    // and this detector runs on the folder scan threads where a panic aborts
    // the whole run.
    let opt_magic_off = pe_off.wrapping_add(24) as usize;
    let b = input.get(opt_magic_off..opt_magic_off.checked_add(2)?)?;
    let opt_magic = u16::from_le_bytes([b[0], b[1]]);
    let dd_off: u32 = if opt_magic == 0x20B { 112 } else { 96 };
    // + 14*8 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    let clr_rva_offset = pe_off
        .wrapping_add(24)
        .wrapping_add(dd_off)
        .wrapping_add(14u32.wrapping_mul(8));
    if (clr_rva_offset as usize)
        .checked_add(4)
        .is_none_or(|end| end > input.len())
    {
        return None;
    }
    let clr_rva = primitives::get_u32(input, clr_rva_offset);
    let kind = match (is_dll, clr_rva != 0) {
        (false, false) => Kind::NativeExe,
        (false, true) => Kind::ManagedExe,
        (true, false) => Kind::NativeDll,
        (true, true) => Kind::ManagedDll,
    };
    Some(Detected { kind, magic })
}

/// Detect the file type and dispatch to the matching pipeline.
/// Returns the detected `Kind` together with the unpacked image bytes.
pub fn unpack_auto(input: &[u8]) -> Result<(Kind, Vec<u8>), UnpackError> {
    unpack_auto_v(input, false)
}

/// Like [`unpack_auto`], but prints detailed `[N/9]` unpack-step progress to
/// stdout when `verbose` is true. Output bytes are identical regardless.
pub fn unpack_auto_v(input: &[u8], verbose: bool) -> Result<(Kind, Vec<u8>), UnpackError> {
    let detected = detect(input).ok_or(UnpackError::NotCrackproof)?;
    let out = match detected.kind {
        Kind::NativeExe | Kind::ManagedExe => unpack_exe_v(input, verbose)?,
        Kind::NativeDll | Kind::ManagedDll => select_dll_layout(
            || dll::unpack_dll_v(input, verbose),
            || exe::unpack_v(input, verbose),
        )?,
    };
    Ok((detected.kind, out))
}

/// Inspect a Windows input without recovering it.
///
/// Recognizes the supported header magic, records the PE format/kind, and lists
/// the routes a recovery would attempt. No candidate is run, so
/// [`ProtectionProfile::selected`](crate::profile::ProtectionProfile::selected)
/// stays `None` and every candidate is `NotAttempted`. Companion splicing is
/// the I/O layer's job: pass the spliced bytes and mark the profile with
/// [`ProtectionProfile::record_companion_spliced`](crate::profile::ProtectionProfile::record_companion_spliced).
#[must_use]
pub fn inspect_profile(input: &[u8]) -> ProtectionProfile {
    let detected = detect(input);
    inspect_detected(input, detected)
}

fn inspect_detected(input: &[u8], detected: Option<Detected>) -> ProtectionProfile {
    let mut profile = ProtectionProfile::new(ObservedTarget::windows(
        pe_target_format(input),
        detected.map(|detected| detected.kind),
    ));
    let Some(detected) = detected else {
        profile.recognition = RecognitionStatus::NotRecognized;
        return profile;
    };
    profile.recognition = RecognitionStatus::Recognized;
    profile.evidence.push(ProtectionEvidence::HeaderMagic);
    profile.candidates = planned_routes(detected.kind);
    profile
}

fn planned_routes(kind: Kind) -> Vec<LayoutAttempt> {
    match kind {
        Kind::NativeExe | Kind::ManagedExe => {
            vec![LayoutAttempt::not_attempted(LayoutKind::ExeStyle)]
        }
        Kind::NativeDll | Kind::ManagedDll => vec![
            LayoutAttempt::not_attempted(LayoutKind::Dll),
            LayoutAttempt::not_attempted(LayoutKind::ExeStyle),
        ],
    }
}

fn pe_target_format(input: &[u8]) -> Option<TargetFormat> {
    let headers = senbei_pe::parse(input).ok()?;
    Some(if headers.is_pe32_plus {
        TargetFormat::Pe32Plus
    } else {
        TargetFormat::Pe32
    })
}

/// Detect, recover, and return the profile that records the route taken.
///
/// This is [`unpack_auto`] with its evidence preserved: the profile is returned
/// on success and on [`Err`], so a failed attempt still says which routes ran
/// and why they were rejected.
pub fn unpack_auto_profiled(
    input: &[u8],
) -> (ProtectionProfile, Result<(Kind, Vec<u8>), UnpackError>) {
    unpack_auto_profiled_v(input, false)
}

/// Verbose counterpart of [`unpack_auto_profiled`].
pub fn unpack_auto_profiled_v(
    input: &[u8],
    verbose: bool,
) -> (ProtectionProfile, Result<(Kind, Vec<u8>), UnpackError>) {
    let detected = detect(input);
    let mut profile = inspect_detected(input, detected);
    let Some(detected) = detected else {
        let error = UnpackError::NotCrackproof;
        profile.push_error(error.to_string());
        return (profile, Err(error));
    };
    let result = match detected.kind {
        Kind::NativeExe | Kind::ManagedExe => {
            run_exe_attempt(&mut profile, input, verbose).map(|out| (detected.kind, out))
        }
        Kind::NativeDll | Kind::ManagedDll => select_dll_layout_profiled(
            &mut profile,
            || dll::unpack_dll_v(input, verbose),
            || exe::unpack_v(input, verbose),
        )
        .map(|out| (detected.kind, out)),
    };
    (profile, result)
}

/// Run only the EXE-style route and return its profile.
///
/// The external-companion I/O path uses this after splicing, because that
/// layout is definitionally the EXE-style shell.
pub fn unpack_exe_profiled(input: &[u8]) -> (ProtectionProfile, Result<Vec<u8>, UnpackError>) {
    unpack_exe_profiled_v(input, false)
}

/// Verbose counterpart of [`unpack_exe_profiled`].
pub fn unpack_exe_profiled_v(
    input: &[u8],
    verbose: bool,
) -> (ProtectionProfile, Result<Vec<u8>, UnpackError>) {
    let detected = detect(input);
    let mut profile = inspect_detected(input, detected);
    if detected.is_none() {
        let error = UnpackError::NotCrackproof;
        profile.push_error(error.to_string());
        return (profile, Err(error));
    }
    // This entry point will never run the DLL route, so a DLL-kind detection's
    // planned DLL candidate must not appear as an untried option.
    profile
        .candidates
        .retain(|attempt| attempt.layout == LayoutKind::ExeStyle);
    let result = run_exe_attempt(&mut profile, input, verbose);
    (profile, result)
}

fn run_exe_attempt(
    profile: &mut ProtectionProfile,
    input: &[u8],
    verbose: bool,
) -> Result<Vec<u8>, UnpackError> {
    match exe::unpack_v(input, verbose) {
        Ok(out) => {
            let report = integrity::check(&out);
            let warnings = profile_messages(&report, ProfileSeverity::Warning);
            profile.record_attempt(
                LayoutKind::ExeStyle,
                AttemptOutcome::Succeeded,
                warnings,
                Vec::new(),
            );
            profile.selected = Some(LayoutKind::ExeStyle);
            profile.recovery = RecoveryStatus::Succeeded;
            profile.record_static_validation(&report);
            Ok(out)
        }
        Err(error) => {
            profile.record_attempt(
                LayoutKind::ExeStyle,
                AttemptOutcome::Failed,
                Vec::new(),
                vec![error.to_string()],
            );
            profile.recovery = RecoveryStatus::Failed;
            profile.push_error(error.to_string());
            Err(error)
        }
    }
}

/// `select_dll_layout`, additionally recording each candidate in `profile`.
///
/// Routing and gates are exactly those of [`select_dll_layout`]: the DLL layout
/// is accepted whenever it has no fatal finding, warnings included; the EXE
/// layout runs only after the DLL layout errors or is structurally invalid.
fn select_dll_layout_profiled<D, E>(
    profile: &mut ProtectionProfile,
    dll_layout: D,
    exe_layout: E,
) -> Result<Vec<u8>, UnpackError>
where
    D: FnOnce() -> Result<Vec<u8>, UnpackError>,
    E: FnOnce() -> Result<Vec<u8>, UnpackError>,
{
    match accept_dll_layout(dll_layout()) {
        Ok((output, report)) => {
            record_accepted(profile, LayoutKind::Dll, report);
            Ok(output)
        }
        Err(dll) => {
            record_rejected(profile, LayoutKind::Dll, &dll);
            match accept_dll_layout(exe_layout()) {
                Ok((output, report)) => {
                    record_accepted(profile, LayoutKind::ExeStyle, report);
                    Ok(output)
                }
                Err(exe) => {
                    record_rejected(profile, LayoutKind::ExeStyle, &exe);
                    profile.recovery = RecoveryStatus::Failed;
                    let error = UnpackError::PipelineFallbackFailed {
                        dll: Box::new(dll.error),
                        exe: Box::new(exe.error),
                    };
                    profile.push_error(error.to_string());
                    Err(error)
                }
            }
        }
    }
}

fn record_accepted(profile: &mut ProtectionProfile, layout: LayoutKind, report: IntegrityReport) {
    let warnings = profile_messages(&report, ProfileSeverity::Warning);
    profile.record_attempt(layout, AttemptOutcome::Succeeded, warnings, Vec::new());
    profile.selected = Some(layout);
    profile.recovery = RecoveryStatus::Succeeded;
    profile.record_static_validation(&report);
}

fn record_rejected(profile: &mut ProtectionProfile, layout: LayoutKind, failure: &LayoutFailure) {
    let (warnings, errors) = match &failure.report {
        Some(report) => (
            profile_messages(report, ProfileSeverity::Warning),
            profile_messages(report, ProfileSeverity::Fatal),
        ),
        None => (Vec::new(), vec![failure.error.to_string()]),
    };
    let outcome = if failure.report.is_some() {
        AttemptOutcome::Rejected
    } else {
        AttemptOutcome::Failed
    };
    profile.record_attempt(layout, outcome, warnings, errors);
}

fn profile_messages(report: &IntegrityReport, severity: ProfileSeverity) -> Vec<String> {
    report
        .findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .map(|finding| finding.message.clone())
        .collect()
}

/// One rejected layout attempt and the report that rejected it, if the
/// pipeline produced an image at all.
struct LayoutFailure {
    error: UnpackError,
    report: Option<IntegrityReport>,
}

impl std::fmt::Debug for LayoutFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayoutFailure")
            .field("error", &self.error)
            .field("rejected_by_integrity", &self.report.is_some())
            .finish()
    }
}

/// Pick between the older DLL layout and the EXE-style shell layout.
///
/// `Ok` from a pipeline is not proof it chose the right layout: a wrong layout
/// can emit a PE-shaped image the loader would reject. Each successful image is
/// judged with [`dll_layout_invalid`]. The older DLL layout is kept whenever it
/// is structurally acceptable, including when its only defects are ordinary
/// warnings (a missing base-relocation directory is one of those). The EXE-style
/// layout runs only when the DLL layout errors or is structurally invalid.
///
/// The two closures exist so tests can inject synthetic images without running
/// either real pipeline. Production passes `dll::unpack_dll_v` and `exe::unpack_v`.
fn select_dll_layout<D, E>(dll_layout: D, exe_layout: E) -> Result<Vec<u8>, UnpackError>
where
    D: FnOnce() -> Result<Vec<u8>, UnpackError>,
    E: FnOnce() -> Result<Vec<u8>, UnpackError>,
{
    match validate_dll_layout(dll_layout()) {
        Ok(output) => Ok(output),
        Err(dll) => {
            validate_dll_layout(exe_layout()).map_err(|exe| UnpackError::PipelineFallbackFailed {
                dll: Box::new(dll),
                exe: Box::new(exe),
            })
        }
    }
}

fn validate_dll_layout(output: Result<Vec<u8>, UnpackError>) -> Result<Vec<u8>, UnpackError> {
    accept_dll_layout(output)
        .map(|(output, _)| output)
        .map_err(|failure| failure.error)
}

/// Run one pipeline and apply the layout gate with a single integrity check.
fn accept_dll_layout(
    output: Result<Vec<u8>, UnpackError>,
) -> Result<(Vec<u8>, IntegrityReport), LayoutFailure> {
    let output = output.map_err(|error| LayoutFailure {
        error,
        report: None,
    })?;
    let report = integrity::check(&output);
    if !report.has_fatal() {
        return Ok((output, report));
    }
    let issues = profile_messages(&report, ProfileSeverity::Fatal);
    Err(LayoutFailure {
        error: UnpackError::InvalidLayoutCandidate { issues },
        report: Some(report),
    })
}

/// Structural defects that mean a DLL layout candidate must not be accepted.
///
/// Returns `None` when [`integrity::check`] reports nothing fatal. Warning
/// findings stay on the image: a native DLL with no base-relocation directory,
/// a zeroed or `int3` entry stub, or an import name that is mapped but not
/// printable ASCII. Those are the existing suspect conditions. A fatal finding
/// is one the loader or CLR rejects before that — the image is not a PE, a
/// claimed directory or entry point does not map, a section's raw range runs
/// past the file, or managed metadata has no COR20/BSJB signature.
///
/// Severity comes from [`IntegrityReport::has_fatal`], which the checker sets
/// when it records each finding. This does not re-read issue text.
#[cfg(test)]
fn dll_layout_invalid(image: &[u8]) -> Option<IntegrityReport> {
    let report = integrity::check(image);
    report.has_fatal().then_some(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caught_panic_reports_location_and_message() {
        let error = catch_unpack(|| -> Result<Vec<u8>, UnpackError> {
            panic!("test panic");
        })
        .expect_err("panic must become an error");
        let UnpackError::InternalPanic {
            message,
            file,
            line,
            column,
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(message, "test panic");
        assert!(
            file.ends_with("senbei-engine/src/windows/mod.rs")
                || file.ends_with("senbei-engine\\src\\windows\\mod.rs")
        );
        assert!(line > 0);
        assert!(column > 0);
    }

    #[test]
    fn worker_panic_keeps_the_worker_source_location() {
        let error = catch_unpack(|| -> Result<Vec<u8>, UnpackError> {
            let capture = current_panic_capture();
            let result = std::thread::spawn(move || {
                with_panic_capture(capture, || panic!("worker panic"));
            })
            .join();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
            Ok(Vec::new())
        })
        .expect_err("worker panic must become an error");
        let UnpackError::InternalPanic {
            message,
            file,
            line,
            column,
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(message, "worker panic");
        assert!(
            file.ends_with("senbei-engine/src/windows/mod.rs")
                || file.ends_with("senbei-engine\\src\\windows\\mod.rs")
        );
        assert!(line > 0);
        assert!(column > 0);
    }
}

#[cfg(test)]
mod dll_layout_selection {
    use super::*;
    use crate::profile::{Platform, ValidationStatus};

    fn pipeline_err(stage: &'static str) -> UnpackError {
        UnpackError::InputTooShort {
            actual: stage.len(),
            required: 1,
        }
    }

    /// Minimal PE32+ image large enough for `integrity::check` to walk headers,
    /// one section, and (when asked) an import name or a COR20 header.
    struct SyntheticPe {
        dll: bool,
        size_of_image: u32,
        entry_rva: u32,
        entry_bytes: Vec<u8>,
        executable: bool,
        reloc: bool,
        import_name: Option<&'static str>,
        import_unmapped: bool,
        managed: bool,
        cor20_cb: u32,
        metadata_sig: &'static [u8],
        section_count: u16,
        raw_past_eof: bool,
    }

    impl Default for SyntheticPe {
        fn default() -> Self {
            Self {
                dll: true,
                size_of_image: 0x2000,
                entry_rva: 0x1000,
                entry_bytes: vec![0xC3],
                executable: true,
                reloc: true,
                import_name: None,
                import_unmapped: false,
                managed: false,
                cor20_cb: 0x48,
                metadata_sig: b"BSJB",
                section_count: 1,
                raw_past_eof: false,
            }
        }
    }

    impl SyntheticPe {
        fn build(&self) -> Vec<u8> {
            let optional_size: u16 = 0xF0;
            let pe = 0x80usize;
            let section = pe + 24 + optional_size as usize;
            let file_size = if self.raw_past_eof { 0x200 } else { 0x500 };
            let mut data = vec![0u8; file_size];
            data[..2].copy_from_slice(b"MZ");
            data[0x3C..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
            data[pe..pe + 4].copy_from_slice(b"PE\0\0");
            data[pe + 6..pe + 8].copy_from_slice(&self.section_count.to_le_bytes());
            let chars: u16 = if self.dll { 0x2000 } else { 0 };
            data[pe + 22..pe + 24].copy_from_slice(&chars.to_le_bytes());
            data[pe + 20..pe + 22].copy_from_slice(&optional_size.to_le_bytes());
            data[pe + 24..pe + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
            data[pe + 24 + 16..pe + 24 + 20].copy_from_slice(&self.entry_rva.to_le_bytes());
            data[pe + 24 + 56..pe + 24 + 60].copy_from_slice(&self.size_of_image.to_le_bytes());
            // NumberOfRvaAndSizes must cover the directories we publish.
            data[pe + 24 + 108..pe + 24 + 112].copy_from_slice(&16u32.to_le_bytes());
            let dd = pe + 24 + 112;
            if self.reloc && !self.managed {
                // A relocation directory has to be *backed by the file*: one
                // block (page RVA 0x1000, 8-byte header + one HIGHLOW entry)
                // at RVA 0x1020 -> file 0x220, inside the section's raw range.
                data[dd + 5 * 8..dd + 5 * 8 + 4].copy_from_slice(&0x1020u32.to_le_bytes());
                data[dd + 5 * 8 + 4..dd + 5 * 8 + 8].copy_from_slice(&12u32.to_le_bytes());
                if data.len() >= 0x220 + 12 {
                    data[0x220..0x224].copy_from_slice(&0x1000u32.to_le_bytes());
                    data[0x224..0x228].copy_from_slice(&12u32.to_le_bytes());
                    data[0x228..0x22a].copy_from_slice(&0x3000u16.to_le_bytes());
                }
            }
            if self.import_name.is_some() || self.import_unmapped {
                data[dd + 8..dd + 12].copy_from_slice(&0x1100u32.to_le_bytes());
                data[dd + 12..dd + 16].copy_from_slice(&40u32.to_le_bytes());
            }
            if self.managed {
                data[dd + 14 * 8..dd + 14 * 8 + 4].copy_from_slice(&0x1400u32.to_le_bytes());
                data[dd + 14 * 8 + 4..dd + 14 * 8 + 8].copy_from_slice(&0x48u32.to_le_bytes());
            }
            if self.section_count > 0 && section + 40 <= data.len() {
                let characteristics: u32 = if self.executable {
                    0x6000_0020
                } else {
                    0x4000_0040
                };
                let raw_size: u32 = if self.raw_past_eof { 0x1000 } else { 0x300 };
                for (offset, value) in [
                    (8usize, 0x1000u32),
                    (12, 0x1000),
                    (16, raw_size),
                    (20, 0x200),
                    (36, characteristics),
                ] {
                    data[section + offset..section + offset + 4]
                        .copy_from_slice(&value.to_le_bytes());
                }
            }
            if self.entry_rva != 0 && !self.entry_bytes.is_empty() {
                let at = 0x200 + (self.entry_rva.saturating_sub(0x1000)) as usize;
                if let Some(slot) = data.get_mut(at..at + self.entry_bytes.len()) {
                    slot.copy_from_slice(&self.entry_bytes);
                }
            }
            if self.import_name.is_some() || self.import_unmapped {
                // Descriptor at RVA 0x1100 -> file 0x300. The name has to sit
                // *before* that descriptor: bytes after it are the next
                // descriptor, and a name like "kernel32.dll" would be walked
                // as one. Mapped name RVA 0x1010 -> file 0x210, which is past
                // the 16-byte entry stub and still inside the section.
                let name_rva: u32 = if self.import_unmapped { 0x9000 } else { 0x1010 };
                if data.len() >= 0x300 + 20 {
                    data[0x30C..0x310].copy_from_slice(&name_rva.to_le_bytes());
                }
                if let Some(name) = self.import_name.filter(|_| !self.import_unmapped) {
                    let name_at = 0x210;
                    let bytes = name.as_bytes();
                    if let Some(slot) = data.get_mut(name_at..name_at + bytes.len()) {
                        slot.copy_from_slice(bytes);
                    }
                }
            }
            if self.managed {
                let cor = 0x200 + (0x1400 - 0x1000);
                if data.len() >= cor + 0x48 {
                    data[cor..cor + 4].copy_from_slice(&self.cor20_cb.to_le_bytes());
                    let md_rva = 0x1500u32;
                    data[cor + 8..cor + 12].copy_from_slice(&md_rva.to_le_bytes());
                    data[cor + 12..cor + 16].copy_from_slice(&4u32.to_le_bytes());
                    let md = 0x200 + (0x1500 - 0x1000);
                    let sig = self.metadata_sig;
                    if let Some(slot) = data.get_mut(md..md + sig.len()) {
                        slot.copy_from_slice(sig);
                    }
                }
            }
            data
        }
    }

    fn valid_native_dll() -> Vec<u8> {
        SyntheticPe::default().build()
    }

    #[test]
    fn invalid_dll_layout_falls_back_to_valid_exe_layout() {
        let dll_image = SyntheticPe {
            entry_rva: 0x9000,
            ..SyntheticPe::default()
        }
        .build();
        let exe_image = valid_native_dll();
        let selected = select_dll_layout(|| Ok(dll_image.clone()), || Ok(exe_image.clone()))
            .expect("valid EXE-layout image must be accepted");
        assert_eq!(selected, exe_image);
        assert!(dll_layout_invalid(&dll_image).is_some());
        assert!(dll_layout_invalid(&exe_image).is_none());
    }

    #[test]
    fn structurally_valid_dll_layout_is_kept_without_calling_exe() {
        let dll_image = valid_native_dll();
        let selected = select_dll_layout(
            || Ok(dll_image.clone()),
            || panic!("EXE layout must not run when the DLL layout is valid"),
        )
        .expect("DLL layout");
        assert_eq!(selected, dll_image);
    }

    #[test]
    fn dll_warning_is_not_fatal_and_blocks_exe_fallback() {
        let warned = SyntheticPe {
            reloc: false,
            ..SyntheticPe::default()
        }
        .build();
        let report = integrity::check(&warned);
        assert!(!report.ok(), "fixture must actually warn, got {report:?}");
        assert!(
            dll_layout_invalid(&warned).is_none(),
            "a missing relocation directory is a warning, not a rejected layout"
        );
        let selected = select_dll_layout(
            || Ok(warned.clone()),
            || panic!("warnings must not trigger the EXE layout"),
        )
        .expect("warned DLL layout");
        assert_eq!(selected, warned);
    }

    #[test]
    fn zeroed_entry_stub_is_a_warning_not_a_rejected_layout() {
        let warned = SyntheticPe {
            entry_bytes: vec![0; 16],
            ..SyntheticPe::default()
        }
        .build();
        let report = integrity::check(&warned);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("all zeros"))
        );
        assert!(dll_layout_invalid(&warned).is_none());
    }

    #[test]
    fn both_layouts_structurally_invalid_reports_both_candidates() {
        let invalid = SyntheticPe {
            entry_rva: 0x9000,
            ..SyntheticPe::default()
        }
        .build();
        let error = select_dll_layout(|| Ok(invalid.clone()), || Ok(invalid.clone()))
            .expect_err("neither layout is acceptable");
        match error {
            UnpackError::PipelineFallbackFailed { dll, exe } => {
                let dll = dll.to_string();
                let exe = exe.to_string();
                assert!(dll.contains("structurally invalid"), "{dll}");
                assert!(exe.contains("structurally invalid"), "{exe}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn dll_error_then_exe_error_keeps_pipeline_diagnostics() {
        let error = select_dll_layout(
            || Err(pipeline_err("dll")),
            || Err(pipeline_err("exe-layout")),
        )
        .expect_err("both pipelines failed");
        match error {
            UnpackError::PipelineFallbackFailed { dll, exe } => {
                let dll = dll.to_string();
                let exe = exe.to_string();
                assert!(dll.contains("got 3"), "{dll}");
                assert!(exe.contains("got 10"), "{exe}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn dll_error_then_invalid_exe_image_names_both_failures() {
        let invalid = SyntheticPe {
            raw_past_eof: true,
            ..SyntheticPe::default()
        }
        .build();
        assert!(dll_layout_invalid(&invalid).is_some());
        let error = select_dll_layout(|| Err(pipeline_err("dll")), || Ok(invalid))
            .expect_err("EXE image is not a usable fallback");
        match error {
            UnpackError::PipelineFallbackFailed { dll, exe } => {
                let dll = dll.to_string();
                let exe = exe.to_string();
                assert!(dll.contains("need at least 1"), "{dll}");
                assert!(exe.contains("structurally invalid"), "{exe}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn unmapped_import_and_bad_metadata_are_fatal() {
        let imports = SyntheticPe {
            import_unmapped: true,
            import_name: Some("unused"),
            ..SyntheticPe::default()
        }
        .build();
        assert!(dll_layout_invalid(&imports).is_some());

        let metadata = SyntheticPe {
            managed: true,
            reloc: false,
            metadata_sig: b"XXXX",
            ..SyntheticPe::default()
        }
        .build();
        assert!(dll_layout_invalid(&metadata).is_some());

        let readable = SyntheticPe {
            import_name: Some("kernel32.dll"),
            ..SyntheticPe::default()
        }
        .build();
        assert!(
            dll_layout_invalid(&readable).is_none(),
            "{:?}",
            integrity::check(&readable).issues
        );
    }

    // -----------------------------------------------------------------------
    // Profiled routing: same gates, evidence preserved.
    // -----------------------------------------------------------------------

    fn profiled<D, E>(
        dll_layout: D,
        exe_layout: E,
    ) -> (ProtectionProfile, Result<Vec<u8>, UnpackError>)
    where
        D: FnOnce() -> Result<Vec<u8>, UnpackError>,
        E: FnOnce() -> Result<Vec<u8>, UnpackError>,
    {
        let mut profile = ProtectionProfile::new(ObservedTarget::windows(
            Some(TargetFormat::Pe32Plus),
            Some(Kind::NativeDll),
        ));
        profile.recognition = RecognitionStatus::Recognized;
        profile.candidates = planned_routes(Kind::NativeDll);
        let result = select_dll_layout_profiled(&mut profile, dll_layout, exe_layout);
        (profile, result)
    }

    #[test]
    fn profiled_keeps_accepting_dll_route_and_leaves_exe_unattempted() {
        let dll_image = valid_native_dll();
        let (profile, result) = profiled(
            || Ok(dll_image.clone()),
            || panic!("EXE layout must not run when the DLL layout is valid"),
        );
        assert_eq!(result.unwrap(), dll_image);
        assert_eq!(profile.selected, Some(LayoutKind::Dll));
        assert_eq!(profile.recovery, RecoveryStatus::Succeeded);
        assert_eq!(profile.static_validation, ValidationStatus::Clean);
        assert_eq!(profile.candidates.len(), 2);
        assert_eq!(profile.candidates[0].layout, LayoutKind::Dll);
        assert_eq!(profile.candidates[0].outcome, AttemptOutcome::Succeeded);
        assert_eq!(profile.candidates[1].layout, LayoutKind::ExeStyle);
        assert_eq!(profile.candidates[1].outcome, AttemptOutcome::NotAttempted);
        assert!(profile.errors.is_empty());
    }

    #[test]
    fn profiled_fallback_retains_the_rejected_dll_attempt_first() {
        let dll_image = SyntheticPe {
            entry_rva: 0x9000,
            ..SyntheticPe::default()
        }
        .build();
        let exe_image = valid_native_dll();
        let (profile, result) = profiled(|| Ok(dll_image.clone()), || Ok(exe_image.clone()));
        assert_eq!(result.unwrap(), exe_image);
        assert_eq!(profile.selected, Some(LayoutKind::ExeStyle));
        let dll = &profile.candidates[0];
        assert_eq!(dll.layout, LayoutKind::Dll);
        assert_eq!(dll.outcome, AttemptOutcome::Rejected);
        assert!(
            dll.errors
                .iter()
                .any(|error| error.contains("entry point RVA")),
            "{:?}",
            dll.errors
        );
        let exe = &profile.candidates[1];
        assert_eq!(exe.outcome, AttemptOutcome::Succeeded);
        // The accepted image is clean, so the rejected candidate's fatal
        // findings stay on its own attempt rather than the profile top level.
        assert!(profile.errors.is_empty());
    }

    #[test]
    fn profiled_failure_reports_every_route_and_no_selection() {
        let invalid = SyntheticPe {
            entry_rva: 0x9000,
            ..SyntheticPe::default()
        }
        .build();
        let (profile, result) = profiled(|| Ok(invalid.clone()), || Ok(invalid.clone()));
        assert!(result.is_err());
        assert_eq!(profile.selected, None);
        assert_eq!(profile.recovery, RecoveryStatus::Failed);
        assert!(!profile.errors.is_empty());
        assert_eq!(profile.candidates.len(), 2);
        assert_eq!(profile.candidates[0].outcome, AttemptOutcome::Rejected);
        assert_eq!(profile.candidates[1].outcome, AttemptOutcome::Rejected);
    }

    #[test]
    fn profiled_pipeline_errors_are_recorded_per_route() {
        let (profile, result) = profiled(
            || Err(pipeline_err("dll")),
            || Err(pipeline_err("exe-layout")),
        );
        assert!(matches!(
            result,
            Err(UnpackError::PipelineFallbackFailed { .. })
        ));
        assert_eq!(profile.candidates[0].outcome, AttemptOutcome::Failed);
        assert_eq!(profile.candidates[1].outcome, AttemptOutcome::Failed);
        assert!(profile.candidates[0].errors[0].contains("got 3"));
        assert!(profile.candidates[1].errors[0].contains("got 10"));
    }

    #[test]
    fn profiled_dll_warning_keeps_the_route_and_records_the_warning() {
        let warned = SyntheticPe {
            reloc: false,
            ..SyntheticPe::default()
        }
        .build();
        let (profile, result) = profiled(
            || Ok(warned.clone()),
            || panic!("warnings must not trigger the EXE layout"),
        );
        assert_eq!(result.unwrap(), warned);
        assert_eq!(profile.selected, Some(LayoutKind::Dll));
        assert_eq!(profile.static_validation, ValidationStatus::Warnings);
        assert!(!profile.warnings.is_empty());
        assert_eq!(profile.candidates[0].outcome, AttemptOutcome::Succeeded);
        assert!(!profile.candidates[0].warnings.is_empty());
    }

    /// A minimal protected-shaped input `detect` accepts: enough bytes for the
    /// header key table, a valid PE signature, the DLL characteristic, and a
    /// PE32+ optional header. Generates header words at offset 4096 so that
    /// `keys[1]` is the supported magic.
    fn detected_dll_input() -> Vec<u8> {
        let mut data = SyntheticPe::default().build();
        data.resize(0x1100, 0);
        let pe = 0x80usize;
        let chars = 0x2000u16 | 0x0002;
        data[pe + 22..pe + 24].copy_from_slice(&chars.to_le_bytes());
        // Header key derivation: keys[0] = word(4096);
        // keys[1] = keys[0] ^ word(4100). Choose keys[0] = 1 so the stored
        // cell yields the magic.
        let key0 = 1u32;
        let cell = key0 ^ MAGIC_KONN;
        data[4096..4100].copy_from_slice(&key0.to_le_bytes());
        data[4100..4104].copy_from_slice(&cell.to_le_bytes());
        data
    }

    #[test]
    fn inspect_profile_reports_recognition_without_running_a_route() {
        let profile = inspect_profile(&detected_dll_input());
        assert_eq!(profile.recognition, RecognitionStatus::Recognized);
        assert_eq!(profile.observed.platform, Platform::WindowsPe);
        assert_eq!(profile.observed.format, Some(TargetFormat::Pe32Plus));
        assert_eq!(profile.observed.kind, Some(Kind::NativeDll));
        assert!(profile.evidence.contains(&ProtectionEvidence::HeaderMagic));
        assert_eq!(profile.selected, None);
        assert_eq!(profile.recovery, RecoveryStatus::NotAttempted);
        assert_eq!(profile.static_validation, ValidationStatus::NotRun);
        assert_eq!(profile.candidates.len(), 2);
        assert!(
            profile
                .candidates
                .iter()
                .all(|attempt| attempt.outcome == AttemptOutcome::NotAttempted)
        );
    }

    #[test]
    fn profiled_entrypoints_reject_unknown_input_with_evidence() {
        let sample = vec![0_u8; 64];
        let (profile, result) = unpack_auto_profiled(&sample);
        assert!(matches!(result, Err(UnpackError::NotCrackproof)));
        assert_eq!(profile.recognition, RecognitionStatus::NotRecognized);
        assert!(profile.candidates.is_empty());
        assert!(!profile.errors.is_empty());

        let (profile, result) = unpack_exe_profiled(&sample);
        assert!(matches!(result, Err(UnpackError::NotCrackproof)));
        assert_eq!(profile.recognition, RecognitionStatus::NotRecognized);
        assert!(!profile.errors.is_empty());
    }

    #[test]
    fn companion_splice_evidence_is_explicit() {
        let mut profile = inspect_profile(&detected_dll_input());
        assert!(!profile.observed.external_companion);
        profile.record_companion_spliced();
        assert!(profile.observed.external_companion);
        assert!(
            profile
                .evidence
                .contains(&ProtectionEvidence::CompanionSpliced)
        );
        // Pairing proves a splice, not that the loader declares an external
        // suffix. That declaration requires separate entry-record evidence.
        assert!(
            !profile
                .evidence
                .contains(&ProtectionEvidence::ExternalCompanionDeclaration)
        );
        // Idempotent, and it never claims recovery.
        profile.record_companion_spliced();
        assert_eq!(
            profile
                .evidence
                .iter()
                .filter(|evidence| **evidence == ProtectionEvidence::CompanionSpliced)
                .count(),
            1
        );
        assert_eq!(profile.recovery, RecoveryStatus::NotAttempted);
    }
}
