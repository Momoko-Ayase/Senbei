use std::path::Path;

use senbei_crypto::android::Module9bConfig;
use senbei_elf::AARCH64_MACHINE;

use super::error::Error;
use super::stage1::{self, DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE};
use crate::android::ResourceLimits;
use crate::profile::{
    AttemptOutcome, LayoutAttempt, LayoutKind, ObservedTarget, ProtectionEvidence,
    ProtectionProfile, RecognitionStatus, TargetFormat,
};

/// Return whether `data` has a supported protected AArch64 IL2CPP layout.
///
/// This uses the default ceilings. A size past those ceilings is reported as
/// not protected, matching a scan that has not opted into a custom limit.
/// [`probe_libil2cpp_with_limits`] returns that limit error instead.
#[must_use]
pub fn is_protected_libil2cpp(data: &[u8]) -> bool {
    probe_libil2cpp_with_limits(data, &ResourceLimits::default()).unwrap_or(false)
}

/// Probe one image under explicit ceilings.
///
/// A parse or configuration mismatch is `Ok(false)`: the image is not a
/// supported target. [`Error::Limit`] is returned as-is, because the declared
/// Stage 1 payload was large enough that classifying it would require the
/// allocation the ceiling exists to prevent. The payload copy is capped by
/// `min(max_entry_bytes, max_total_bytes)` before it is reserved.
pub fn probe_libil2cpp_with_limits(data: &[u8], limits: &ResourceLimits) -> Result<bool, Error> {
    let stage1 = match stage1::inspect(
        data,
        Path::new("<probe>"),
        DEFAULT_OUTER_SIZE,
        DEFAULT_CIPHER_CONSTANT,
        Some(limits.max_entry_bytes.min(limits.max_total_bytes)),
    ) {
        Ok(stage1) => stage1,
        Err(Error::Limit(limit)) => return Err(Error::Limit(limit)),
        Err(_) => return Ok(false),
    };
    Ok(Module9bConfig::parse_embedded(&stage1.plaintext).is_ok())
}

/// [`is_protected_libil2cpp`] with the profile that produced the answer.
///
/// A false answer is `NotRecognized`. A size that exceeds the default ceilings
/// stays a [`Error::Limit`] inside the profile rather than silently becoming
/// "not protected": `RecognitionStatus::Blocked` plus the limit text. The
/// matched case lists the staged route as `NotAttempted`; the probe never
/// claims recovery.
#[must_use]
pub fn is_protected_libil2cpp_profiled(data: &[u8]) -> (ProtectionProfile, bool) {
    let (profile, result) = probe_libil2cpp_profiled_with_limits(data, &ResourceLimits::default());
    let protected = result.unwrap_or(false);
    (profile, protected)
}

/// [`probe_libil2cpp_with_limits`] with its evidence preserved.
///
/// The profile is returned even when the probe returns [`Error::Limit`], and in
/// that case `recognition` is `Blocked`, never `NotRecognized`.
pub fn probe_libil2cpp_profiled_with_limits(
    data: &[u8],
    limits: &ResourceLimits,
) -> (ProtectionProfile, Result<bool, Error>) {
    let mut profile = ProtectionProfile::new(ObservedTarget::android(android_target_format(data)));
    match probe_libil2cpp_with_limits(data, limits) {
        Ok(true) => {
            profile.recognition = RecognitionStatus::Recognized;
            profile.evidence = vec![
                ProtectionEvidence::PrivateSection,
                ProtectionEvidence::AesSchedule,
            ];
            profile
                .candidates
                .push(LayoutAttempt::not_attempted(LayoutKind::AndroidStaged));
            (profile, Ok(true))
        }
        Ok(false) => {
            profile.recognition = RecognitionStatus::NotRecognized;
            (profile, Ok(false))
        }
        Err(error) => {
            profile.recognition = RecognitionStatus::Blocked;
            profile.push_error(error.to_string());
            if let Error::Limit(_) = error {
                profile
                    .candidates
                    .push(LayoutAttempt::not_attempted(LayoutKind::AndroidStaged));
            }
            (profile, Err(error))
        }
    }
}

fn android_target_format(data: &[u8]) -> Option<TargetFormat> {
    let elf = senbei_elf::parse(data).ok()?;
    (elf.header.e_machine == AARCH64_MACHINE).then_some(TargetFormat::Elf64Aarch64)
}

/// Mark a matched Android profile as recovered after a successful restore.
///
/// The I/O adapter calls this after the staged restore actually writes an
/// image; the probe alone must not claim recovery.
pub fn record_android_recovered(profile: &mut ProtectionProfile) {
    if profile.recognition == RecognitionStatus::Recognized {
        profile.candidates = vec![LayoutAttempt {
            layout: LayoutKind::AndroidStaged,
            outcome: AttemptOutcome::Succeeded,
            warnings: Vec::new(),
            errors: Vec::new(),
        }];
        profile.selected = Some(LayoutKind::AndroidStaged);
        profile.recovery = crate::profile::RecoveryStatus::Succeeded;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::RecoveryStatus;

    /// Stage 1 header words, encrypted with the default cipher constant.
    fn encrypt_header(words: [u32; 8]) -> [u8; 0x20] {
        let key = words[0];
        let mut raw = [0_u8; 0x20];
        raw[..4].copy_from_slice(&key.to_le_bytes());
        for (index, value) in words.into_iter().enumerate().skip(1) {
            let index = index as u32;
            let word = (value ^ DEFAULT_CIPHER_CONSTANT.wrapping_mul(index + 1))
                .wrapping_sub((index + 3).wrapping_mul(key));
            raw[index as usize * 4..index as usize * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        raw
    }

    fn put(data: &mut [u8], offset: usize, bytes: &[u8]) {
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// A minimal AArch64 ELF whose SHT_LOUSER payload declares `payload_size`.
    ///
    /// The declared payload is not present in the file. Inspection rejects that
    /// size before copying it when the ceiling is smaller.
    fn elf_with_payload_size(payload_size: u32) -> Vec<u8> {
        let outer = DEFAULT_OUTER_SIZE;
        let section_file_size = outer + 0x1000;
        let section_offset = 64_usize;
        let shoff = section_offset + section_file_size;
        // Offsets into `names`: dynsym 1, dynstr 9, gnu.version 17,
        // gnu.version_r 30, hash 44, private 50, shstrtab 59.
        let names =
            b"\0.dynsym\0.dynstr\0.gnu.version\0.gnu.version_r\0.hash\0.private\0.shstrtab\0";
        let strtab = shoff + 64 * 8;
        let mut data = vec![0_u8; strtab + names.len()];
        put(&mut data, 0, b"\x7fELF\x02\x01\x01");
        put(&mut data, 16, &3_u16.to_le_bytes());
        put(&mut data, 18, &183_u16.to_le_bytes());
        put(&mut data, 20, &1_u32.to_le_bytes());
        put(&mut data, 40, &(shoff as u64).to_le_bytes());
        put(&mut data, 52, &64_u16.to_le_bytes());
        put(&mut data, 58, &64_u16.to_le_bytes());
        put(&mut data, 60, &8_u16.to_le_bytes());
        put(&mut data, 62, &7_u16.to_le_bytes());
        let header = encrypt_header([1, 0, 0x20, payload_size, 0, 0, payload_size, payload_size]);
        put(&mut data, section_offset + outer, &header);
        put(&mut data, strtab, names);
        let sections: [(u32, u32, u64, u64); 8] = [
            (0, 0, 0, 0),
            (1, 11, 0, 0),
            (9, 3, 0, 0),
            (17, 0x6fff_fff0, 0, 0),
            (30, 0x6fff_fffe, 0, 0),
            (45, 5, 0, 0),
            (
                51,
                0x8000_0000,
                section_offset as u64,
                (outer + 0x1000 + payload_size as usize) as u64,
            ),
            (60, 3, strtab as u64, names.len() as u64),
        ];
        for (index, (name, kind, offset, size)) in sections.into_iter().enumerate() {
            let at = shoff + index * 64;
            put(&mut data, at, &name.to_le_bytes());
            put(&mut data, at + 4, &kind.to_le_bytes());
            put(&mut data, at + 24, &offset.to_le_bytes());
            put(&mut data, at + 32, &size.to_le_bytes());
        }
        data
    }

    #[test]
    fn oversized_stage1_payload_is_a_limit_error_not_a_clean_miss() {
        let image = elf_with_payload_size(8);
        let limits = ResourceLimits {
            max_entry_bytes: 4,
            max_total_bytes: 4,
            ..ResourceLimits::default()
        };
        let error = probe_libil2cpp_with_limits(&image, &limits);
        assert!(
            matches!(error, Err(Error::Limit(_))),
            "unexpected probe result: {error:?}"
        );
        assert!(
            !probe_libil2cpp_with_limits(&[], &limits).expect("an empty image is not protected")
        );
        assert!(!is_protected_libil2cpp(&[]));
    }

    #[test]
    fn profiled_limit_is_blocked_with_the_error_retained() {
        let image = elf_with_payload_size(8);
        let limits = ResourceLimits {
            max_entry_bytes: 4,
            max_total_bytes: 4,
            ..ResourceLimits::default()
        };
        let (profile, result) = probe_libil2cpp_profiled_with_limits(&image, &limits);
        assert!(matches!(result, Err(Error::Limit(_))));
        assert_eq!(profile.recognition, RecognitionStatus::Blocked);
        assert_ne!(profile.recognition, RecognitionStatus::NotRecognized);
        assert!(!profile.errors.is_empty());
        assert!(
            profile
                .errors
                .iter()
                .any(|error| error.contains("resource limit")),
            "{:?}",
            profile.errors
        );
        assert_eq!(profile.selected, None);
        assert_eq!(profile.candidates[0].outcome, AttemptOutcome::NotAttempted);
    }

    #[test]
    fn profiled_not_protected_image_is_recognized_as_absent() {
        let (profile, result) =
            probe_libil2cpp_profiled_with_limits(&[], &ResourceLimits::default());
        assert!(result.is_ok_and(|protected| !protected));
        assert_eq!(profile.recognition, RecognitionStatus::NotRecognized);
        assert!(profile.candidates.is_empty());
        assert_eq!(
            profile.observed.platform,
            crate::profile::Platform::AndroidElf
        );
    }

    #[test]
    fn profiled_matched_image_lists_staged_route_without_claiming_recovery() {
        // A complete, parseable Stage 1 + module 0x0C would require a full
        // protected image; this fixture only reaches the pre-probe format
        // branch, so verify the route contract on a profile built from it.
        let mut profile =
            ProtectionProfile::new(ObservedTarget::android(Some(TargetFormat::Elf64Aarch64)));
        profile.recognition = RecognitionStatus::Recognized;
        profile
            .candidates
            .push(LayoutAttempt::not_attempted(LayoutKind::AndroidStaged));
        assert_eq!(profile.recovery, RecoveryStatus::NotAttempted);
        assert_eq!(profile.selected, None);
        record_android_recovered(&mut profile);
        assert_eq!(profile.recovery, RecoveryStatus::Succeeded);
        assert_eq!(profile.selected, Some(LayoutKind::AndroidStaged));
        assert_eq!(profile.candidates[0].outcome, AttemptOutcome::Succeeded);
    }
}
