//! Conservative recognition of the loader's external-file declaration.

use super::{HEADER_OFF, splice_companion};
use senbei_engine::UnpackError;

/// Recognize the observed PE32+ loader entry record, rather than guessing from
/// file size, hollow sections, or an unpack failure (all occur in single-file
/// builds too). Its last complemented immediate is a suffix appended to the
/// module path before CreateFileW; zero means reopen the module itself.
fn expects_companion(input: &[u8]) -> Option<()> {
    senbei_engine::detect(input)?;
    let pe = senbei_pe::parse(input).ok()?;
    if !pe.is_pe32_plus
        || u16::from_le_bytes(
            input
                .get(pe.pe_offset + 4..pe.pe_offset + 6)?
                .try_into()
                .ok()?,
        ) != 0x8664
        || pe.sections == 0
        || pe.size_of_image == 0
        || pe.sections_offset < pe.pe_offset + 24 + 0xf0
    {
        return None;
    }
    let headers_end = pe
        .sections_offset
        .checked_add(usize::from(pe.sections) * 40)?;
    let header_size = u32::from_le_bytes(
        input
            .get(pe.pe_offset + 84..pe.pe_offset + 88)?
            .try_into()
            .ok()?,
    ) as usize;
    if header_size < headers_end || header_size > input.len() {
        return None;
    }
    // A truncated section table/raw section is evidence of a broken stub, not
    // sufficient evidence to diagnose a missing companion.
    for section in senbei_pe::sections(input, pe).ok()? {
        if section.raw_size != 0 {
            let end = section.raw_offset.checked_add(section.raw_size)? as usize;
            input.get(section.raw_offset as usize..end)?;
        }
        if section
            .virtual_address
            .checked_add(section.virtual_size.max(section.raw_size))?
            > pe.size_of_image
        {
            return None;
        }
    }
    let range = senbei_pe::rva_range(input, pe, pe.entry_rva, 63).ok()?;
    let entry = &input[range];
    let dword = |offset: usize| u32::from_le_bytes(entry[offset..offset + 4].try_into().unwrap());
    // Four call/ret entry thunks must all reach the same, file-backed loader.
    if entry[0] != 0xe8 || entry[5] != 0xc3 {
        return None;
    }
    let target = i64::from(pe.entry_rva) + 5 + i64::from(dword(1) as i32);
    let target = u32::try_from(target).ok()?;
    senbei_pe::rva_range(input, pe, target, 1).ok()?;
    for (offset, argument) in [(6, 0), (14, 1), (22, 2)] {
        if entry[offset..offset + 3] != [0x6a, argument, 0xe8]
            || entry[offset + 7] != 0xc3
            || i64::from(pe.entry_rva) + offset as i64 + 7 + i64::from(dword(offset + 3) as i32)
                != i64::from(target)
        {
            return None;
        }
    }
    if entry[30..32] != [0x6a, 3]
        || [32, 37, 42, 47, 52, 57]
            .iter()
            .any(|&offset| entry[offset] != 0x68)
        || entry[62] != 0xc3
        || dword(48).wrapping_add(pe.entry_rva).wrapping_add(1) != 0
        || !dword(53) != HEADER_OFF as u32
        || !dword(58) != u32::from_le_bytes(*b"._\0\0")
    {
        return None;
    }
    Some(())
}

pub(super) fn prepare_companion(
    input: &[u8],
    companion: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, UnpackError> {
    let spliced = companion.and_then(|payload| splice_companion(input, payload));
    if spliced.is_none() && expects_companion(input).is_some() {
        return Err(if companion.is_some() {
            UnpackError::CompanionMismatch
        } else {
            UnpackError::CompanionMissing
        });
    }
    Ok(spliced)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Generated PE and entry record; no protected binary bytes are embedded.
    pub(crate) fn stub() -> Vec<u8> {
        let mut bytes = vec![0; 0x3000];
        bytes[..2].copy_from_slice(b"MZ");
        put32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        put32(&mut bytes, 0xa8, 0x1100);
        put32(&mut bytes, 0xd0, 0x4000);
        put32(&mut bytes, 0xd4, 0x1000);
        bytes[0x188..0x18d].copy_from_slice(b".text");
        for (offset, value) in [
            (0x190, 0x2000),
            (0x194, 0x1000),
            (0x198, 0x1000),
            (0x19c, 0x2000),
        ] {
            put32(&mut bytes, offset, value);
        }
        put32(&mut bytes, HEADER_OFF, 0x12345678);
        put32(&mut bytes, HEADER_OFF + 4, 0x12345678 ^ 0x4e4e4f4b);
        let entry = &mut bytes[0x2100..0x213f];
        entry[0] = 0xe8;
        put32(entry, 1, (-0x105i32) as u32);
        entry[5] = 0xc3;
        for (offset, argument) in [(6, 0), (14, 1), (22, 2)] {
            entry[offset..offset + 3].copy_from_slice(&[0x6a, argument, 0xe8]);
            put32(entry, offset + 3, (-(0x100 + offset as i32 + 7)) as u32);
            entry[offset + 7] = 0xc3;
        }
        entry[30..32].copy_from_slice(&[0x6a, 3]);
        for offset in [32, 37, 42, 47, 52, 57] {
            entry[offset] = 0x68;
        }
        put32(entry, 48, !0x1100);
        put32(entry, 53, !(HEADER_OFF as u32));
        put32(entry, 58, !u32::from_le_bytes(*b"._\0\0"));
        entry[62] = 0xc3;
        bytes
    }

    #[test]
    fn missing_companion_reaches_both_byte_entry_points() {
        let input = stub();
        for force in [false, true] {
            let error = super::super::unpack_bytes_impl(&input, None, force)
                .err()
                .unwrap();
            assert_eq!(error, UnpackError::CompanionMissing);
            assert!(error.to_string().contains("Companion missing?"));
        }
    }

    #[test]
    fn provided_companion_is_not_reported_missing() {
        let input = stub();
        for payload in [&[][..], &[0; 32][..]] {
            assert_eq!(
                prepare_companion(&input, Some(payload)),
                Err(UnpackError::CompanionMismatch)
            );
        }
        let payload = &input[HEADER_OFF..];
        assert_eq!(
            prepare_companion(&input, Some(payload)).unwrap().unwrap(),
            input
        );
        // A matching but damaged payload keeps its original pipeline error.
        let error = super::super::unpack_bytes(&input, Some(payload))
            .err()
            .unwrap();
        assert!(!matches!(
            error,
            UnpackError::CompanionMissing | UnpackError::CompanionMismatch
        ));
    }

    #[test]
    fn single_file_and_damaged_or_unknown_stubs_are_not_diagnosed_as_missing() {
        let input = stub();
        let mut single = input.clone();
        put32(&mut single, 0x213a, !0);
        assert!(expects_companion(&single).is_none());
        assert!(
            prepare_companion(&single, Some(&[0; 32]))
                .unwrap()
                .is_none()
        );
        for (offset, value) in [
            (0, 0),
            (0x84, 0),
            (0x98, 0),
            (0x1004, 0),
            (0x2101, 0),
            (0x2109, 0),
            (0x2130, 0),
            (0x2135, 0),
            (0x2139, 0),
        ] {
            let mut damaged = input.clone();
            damaged[offset] = value;
            assert!(expects_companion(&damaged).is_none(), "offset {offset:x}");
        }
        for length in [0, 0x1000, 0x101f, 0x2100, input.len() - 1] {
            assert!(expects_companion(&input[..length]).is_none());
        }
        let mut unbacked = input.clone();
        put32(&mut unbacked, 0x198, 0x100);
        assert!(expects_companion(&unbacked).is_none());
    }

    #[test]
    fn filesystem_reports_expected_path_and_preserves_read_errors() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("module.dll");
        let payload = dir.path().join("module.dll._");
        let bytes = stub();
        std::fs::write(&input, &bytes).unwrap();
        let error = super::super::read_unpacker_input(&input).err().unwrap();
        assert!(matches!(
            error.downcast_ref(),
            Some(UnpackError::CompanionMissing)
        ));
        assert!(format!("{error:#}").contains("module.dll._"));
        std::fs::write(&payload, [0; 32]).unwrap();
        let error = super::super::read_unpacker_input(&input).err().unwrap();
        assert!(matches!(
            error.downcast_ref(),
            Some(UnpackError::CompanionMismatch)
        ));
        std::fs::write(&payload, &bytes[HEADER_OFF..]).unwrap();
        let paired = super::super::read_unpacker_input(&input).unwrap();
        assert_eq!(paired.bytes, bytes);
        assert_eq!(paired.stub.as_deref(), Some(bytes.as_slice()));
        std::fs::remove_file(&payload).unwrap();
        std::fs::create_dir(&payload).unwrap();
        let error = super::super::read_unpacker_input(&input).err().unwrap();
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(error.downcast_ref::<UnpackError>().is_none());
    }

    #[test]
    fn file_and_folder_jobs_count_missing_companion_as_error_and_log_hint() {
        for folder in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("module.exe");
            let out = dir.path().join("unpack");
            std::fs::write(&input, stub()).unwrap();
            let summary = if folder {
                crate::job::run_folder_v(dir.path(), Some(&out), 2, false, false)
            } else {
                crate::job::run_file_v(&input, Some(&out), 2, false, false)
            }
            .unwrap();
            assert_eq!(summary.errors, 1);
            assert_eq!(summary.unpacked, 0);
            assert!(!out.join("module.unpack.exe").exists());
            let log = std::fs::read_dir(&out)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let log = std::fs::read_to_string(log).unwrap();
            assert!(log.contains("Companion missing?"), "{log}");
            assert!(log.contains("module.exe._"), "{log}");
        }
    }

    /// Inspection must describe a companion-declaring stub, not reproduce the
    /// recovery entry point's refusal.
    ///
    /// [`stub`] is a generated PE32+ loader whose entry record declares the
    /// `._` suffix, so `read_unpacker_input` errors on it when the payload is
    /// missing or does not pair. Inspection is detection only and must keep
    /// the stub's recognition while reporting the pairing as inventory.
    fn inspect_report(path: &std::path::Path) -> serde_json::Value {
        let report = crate::job::inspect_path(
            path,
            false,
            &senbei_engine::android::ResourceLimits::default(),
        )
        .expect("inspection must not fail for a readable stub");
        serde_json::from_str(&report.to_json()).expect("valid report")
    }

    fn assert_no_recovery_claim(input: &serde_json::Value) {
        assert_eq!(input["status"], "recognized", "the stub is recognized");
        let profile = &input["profile"];
        assert_eq!(profile["recognition"], "recognized");
        assert!(
            profile["selected"].is_null(),
            "inspection selects no route: {profile}"
        );
        assert_eq!(profile["recovery"], "not_attempted");
        assert_eq!(profile["static_validation"], "not_run");
        assert!(
            input["outputs"].as_array().unwrap().is_empty(),
            "inspection writes nothing"
        );
        assert!(input["recovered"].is_null());
        for candidate in profile["candidates"].as_array().unwrap() {
            assert_eq!(
                candidate["outcome"], "not_attempted",
                "inspection runs no route: {candidate}"
            );
        }
        assert!(
            input["errors"].as_array().unwrap().is_empty(),
            "a companion relationship is inventory, not an error: {input}"
        );
    }

    #[test]
    fn inspect_of_a_companion_stub_without_its_payload_stays_detection() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("module.exe");
        std::fs::write(&input, stub()).unwrap();

        // The recovery entry point refuses this input.
        assert!(super::super::read_unpacker_input(&input).is_err());

        let value = inspect_report(&input);
        let reported = &value["inputs"][0];
        assert_no_recovery_claim(reported);
        assert_eq!(reported["companion"]["state"], "absent");
        assert!(reported["companion"]["path"].is_null());
        assert_eq!(
            reported["profile"]["observed"]["external_companion"], false,
            "nothing was spliced, so no external-companion claim"
        );
    }

    #[test]
    fn inspect_of_a_companion_stub_with_a_non_matching_payload_reports_it() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("module.exe");
        std::fs::write(&input, stub()).unwrap();
        std::fs::write(dir.path().join("module.exe._"), [0u8; 32]).unwrap();

        assert!(super::super::read_unpacker_input(&input).is_err());

        let value = inspect_report(&input);
        let reported = &value["inputs"][0];
        assert_no_recovery_claim(reported);
        assert_eq!(reported["companion"]["state"], "unmatched");
        assert!(reported["companion"]["path"].is_string());
        assert!(reported["companion"]["detail"].is_string());
        assert_eq!(reported["profile"]["observed"]["external_companion"], false);
    }

    #[test]
    fn inspect_of_a_companion_stub_with_its_payload_reports_the_pairing() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("module.exe");
        let bytes = stub();
        std::fs::write(&input, &bytes).unwrap();
        // The companion is byte-for-byte the stub's payload from the header.
        std::fs::write(dir.path().join("module.exe._"), &bytes[HEADER_OFF..]).unwrap();
        assert!(super::super::read_unpacker_input(&input).is_ok());

        let value = inspect_report(&input);
        let reported = &value["inputs"][0];
        assert_eq!(reported["status"], "recognized");
        assert_eq!(reported["companion"]["state"], "spliced");
        assert_eq!(reported["profile"]["observed"]["external_companion"], true);
        // A real pairing is evidence; recovery still did not run.
        assert_eq!(reported["profile"]["recovery"], "not_attempted");
        assert!(reported["profile"]["selected"].is_null());
        assert_eq!(reported["profile"]["static_validation"], "not_run");
    }

    #[test]
    fn folder_inspect_of_companion_stubs_stays_detection() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.exe");
        let unmatched = dir.path().join("unmatched.dll");
        std::fs::write(&missing, stub()).unwrap();
        std::fs::write(&unmatched, stub()).unwrap();
        std::fs::write(dir.path().join("unmatched.dll._"), [0u8; 32]).unwrap();

        let report = crate::job::inspect_path(
            dir.path(),
            false,
            &senbei_engine::android::ResourceLimits::default(),
        )
        .expect("folder inspection must not fail");
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        let inputs = value["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), 2, "both stubs are inspected: {value}");
        let states: Vec<&str> = inputs
            .iter()
            .map(|input| input["companion"]["state"].as_str().unwrap())
            .collect();
        assert!(states.contains(&"absent"), "{states:?}");
        assert!(states.contains(&"unmatched"), "{states:?}");
        for input in inputs {
            assert_no_recovery_claim(input);
        }
        assert_eq!(value["summary"]["errors"], 0);
    }

    /// A genuine read error still fails the input, but never fabricates a
    /// recovery attempt that inspection did not make.
    #[test]
    fn inspect_read_error_does_not_invent_a_failed_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gone.exe");
        let report = crate::job::inspect_path(
            &path,
            false,
            &senbei_engine::android::ResourceLimits::default(),
        )
        .expect("inspection returns a report even when the input cannot be read");
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        let input = &value["inputs"][0];
        assert_eq!(input["status"], "error");
        assert!(!input["errors"].as_array().unwrap().is_empty());
        let profile = &input["profile"];
        assert_eq!(profile["recovery"], "not_attempted");
        assert!(profile["selected"].is_null());
        assert_eq!(profile["static_validation"], "not_run");
        assert!(profile["candidates"].as_array().unwrap().is_empty());
    }
}
