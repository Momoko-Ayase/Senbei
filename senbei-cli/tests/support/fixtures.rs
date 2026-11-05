//! Synthetic byte fixtures shared by the local corpus harness tests and the
//! native/WASM parity test.
#![allow(dead_code)] // shared by several test targets; each uses a subset
//!
//! Everything here is generated from public format rules. No protected
//! binaries, product names, or real corpus paths appear in this file.

/// il2cpp metadata sanity magic (`0xFAB11BAF`).
pub const METADATA_MAGIC: u32 = 0xFAB1_1BAF;
/// Structural transform version these fixtures describe.
pub const METADATA_VERSION: u32 = 31;

const HDR_METHODS: usize = 0x30;
const HDR_TYPES: usize = 0xA0;
const HDR_IMAGES: usize = 0xA8;
const METHOD_STRIDE: usize = 0x24;
const METHOD_TOKEN_OFF: usize = 0x18;
const TYPE_STRIDE: usize = 0x58;
const TYPE_METHOD_START_OFF: usize = 0x24;
const TYPE_METHOD_COUNT_OFF: usize = 0x40;
const IMAGE_STRIDE: usize = 0x28;
const IMAGE_TYPE_START_OFF: usize = 0x08;
const IMAGE_TYPE_COUNT_OFF: usize = 0x0C;

/// Build a structurally valid version-31 metadata image with two modules.
///
/// Module 0 owns methods 0..2 and module 1 owns methods 2..5. Tokens are
/// written verbatim, so the caller chooses obfuscated (sparse) or canonical
/// (per-module contiguous) values.
pub fn synthetic_metadata(tokens: [u32; 5]) -> Vec<u8> {
    let header = 0x100usize;
    let images = header;
    let image_count = 2usize;
    let types = images + image_count * IMAGE_STRIDE;
    let type_count = 2usize;
    let methods = types + type_count * TYPE_STRIDE;
    let method_count = tokens.len();
    let total = methods + method_count * METHOD_STRIDE;
    let mut data = vec![0u8; total];

    let put32 = |data: &mut [u8], offset: usize, value: u32| {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    };
    let put16 = |data: &mut [u8], offset: usize, value: u16| {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    };

    put32(&mut data, 0, METADATA_MAGIC);
    put32(&mut data, 4, METADATA_VERSION);
    put32(&mut data, HDR_METHODS, methods as u32);
    put32(
        &mut data,
        HDR_METHODS + 4,
        (method_count * METHOD_STRIDE) as u32,
    );
    put32(&mut data, HDR_TYPES, types as u32);
    put32(&mut data, HDR_TYPES + 4, (type_count * TYPE_STRIDE) as u32);
    put32(&mut data, HDR_IMAGES, images as u32);
    put32(
        &mut data,
        HDR_IMAGES + 4,
        (image_count * IMAGE_STRIDE) as u32,
    );

    put32(&mut data, images + IMAGE_TYPE_START_OFF, 0);
    put32(&mut data, images + IMAGE_TYPE_COUNT_OFF, 1);
    put32(&mut data, images + IMAGE_STRIDE + IMAGE_TYPE_START_OFF, 1);
    put32(&mut data, images + IMAGE_STRIDE + IMAGE_TYPE_COUNT_OFF, 1);

    put32(&mut data, types + TYPE_METHOD_START_OFF, 0);
    put16(&mut data, types + TYPE_METHOD_COUNT_OFF, 2);
    put32(&mut data, types + TYPE_STRIDE + TYPE_METHOD_START_OFF, 2);
    put16(&mut data, types + TYPE_STRIDE + TYPE_METHOD_COUNT_OFF, 3);

    for (index, token) in tokens.iter().enumerate() {
        put32(
            &mut data,
            methods + index * METHOD_STRIDE + METHOD_TOKEN_OFF,
            *token,
        );
    }
    data
}

/// Canonical metadata: per-module tokens are already `1..=count`.
pub fn clean_metadata() -> Vec<u8> {
    synthetic_metadata([
        0x0600_0001,
        0x0600_0002,
        0x0600_0001,
        0x0600_0002,
        0x0600_0003,
    ])
}

/// Obfuscated metadata: sparse tokens that the structural transform rewrites.
pub fn obfuscated_metadata() -> Vec<u8> {
    synthetic_metadata([
        0x0600_D49F,
        0x0600_FFFF,
        0x0600_1234,
        0x0600_ABCD,
        0x0600_5555,
    ])
}

/// Named malformed metadata probes. Each must be rejected without a panic.
pub fn malformed_metadata_probes() -> Vec<(&'static str, Vec<u8>)> {
    let base = obfuscated_metadata();
    let mut wrong_magic = base.clone();
    wrong_magic[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let mut unsupported = base.clone();
    unsupported[4..8].copy_from_slice(&30u32.to_le_bytes());
    let mut misaligned = base.clone();
    misaligned[HDR_METHODS + 4..HDR_METHODS + 8].copy_from_slice(&7u32.to_le_bytes());
    let mut out_of_range = base.clone();
    out_of_range[HDR_METHODS..HDR_METHODS + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut unowned = base.clone();
    unowned[types_offset() + TYPE_STRIDE + TYPE_METHOD_COUNT_OFF
        ..types_offset() + TYPE_STRIDE + TYPE_METHOD_COUNT_OFF + 2]
        .copy_from_slice(&2u16.to_le_bytes());
    let mut double_owned = base.clone();
    double_owned[types_offset() + TYPE_STRIDE + TYPE_METHOD_START_OFF
        ..types_offset() + TYPE_STRIDE + TYPE_METHOD_START_OFF + 4]
        .copy_from_slice(&1u32.to_le_bytes());
    vec![
        ("empty", Vec::new()),
        ("prefix", b"MZ".to_vec()),
        ("wrong_magic", wrong_magic),
        ("unsupported_version", unsupported),
        ("truncated_header", base[..0x20].to_vec()),
        ("misaligned_methods", misaligned),
        ("out_of_range_table", out_of_range),
        ("unowned_method", unowned),
        ("double_owned_method", double_owned),
    ]
}

fn types_offset() -> usize {
    0x100 + 2 * IMAGE_STRIDE
}

/// Build a PE that the Crackproof detector classifies.
///
/// Only the fields the detector reads are populated: the DOS/PE headers, the
/// COFF characteristics word, the optional-header magic, the CLR directory,
/// and the 8-dword key table at file offset 4096.
pub fn synthetic_crackproof_pe(dll: bool, managed: bool) -> Vec<u8> {
    const PE_OFFSET: usize = 0x80;
    const KEY_OFFSET: usize = 4096;
    const KONN: u32 = 0x4E4E_4F4B;

    let mut data = vec![0u8; KEY_OFFSET + 32];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3C..0x40].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes());
    data[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
    let characteristics: u16 = if dll { 0x2000 } else { 0 };
    data[PE_OFFSET + 4 + 18..PE_OFFSET + 4 + 20].copy_from_slice(&characteristics.to_le_bytes());
    data[PE_OFFSET + 20..PE_OFFSET + 22].copy_from_slice(&0xF0u16.to_le_bytes());
    data[PE_OFFSET + 24..PE_OFFSET + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
    data[PE_OFFSET + 24 + 108..PE_OFFSET + 24 + 112].copy_from_slice(&16u32.to_le_bytes());
    let directories = PE_OFFSET + 24 + 112;
    if managed {
        data[directories + 14 * 8..directories + 14 * 8 + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes());
        data[directories + 14 * 8 + 4..directories + 14 * 8 + 8]
            .copy_from_slice(&0x48u32.to_le_bytes());
    }
    // keys[0] = 0 and keys[1] = keys[0] ^ cell, so cell = KONN makes the
    // derived magic match.
    data[KEY_OFFSET..KEY_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    data[KEY_OFFSET + 4..KEY_OFFSET + 8].copy_from_slice(&KONN.to_le_bytes());
    data
}

/// A PE-shaped input whose derived magic is not the supported one.
pub fn synthetic_plain_pe() -> Vec<u8> {
    let mut data = synthetic_crackproof_pe(false, false);
    data[4096 + 4..4096 + 8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_metadata_round_trips_through_the_parser() {
        let (out, report) = senbei_metadata::deobfuscate(&obfuscated_metadata()).unwrap();
        assert_eq!(report.version, METADATA_VERSION);
        assert_eq!(report.methods, 5);
        assert_eq!(report.modules, 2);
        assert_eq!(report.remapped, 5);
        assert_eq!(out, clean_metadata());
    }

    #[test]
    fn detection_fixture_matches_the_requested_kind() {
        assert_eq!(
            senbei_engine::detect(&synthetic_crackproof_pe(false, false))
                .map(|detected| detected.kind),
            Some(senbei_engine::Kind::NativeExe)
        );
        assert_eq!(
            senbei_engine::detect(&synthetic_crackproof_pe(true, false))
                .map(|detected| detected.kind),
            Some(senbei_engine::Kind::NativeDll)
        );
        assert_eq!(
            senbei_engine::detect(&synthetic_crackproof_pe(false, true))
                .map(|detected| detected.kind),
            Some(senbei_engine::Kind::ManagedExe)
        );
        assert!(senbei_engine::detect(&synthetic_plain_pe()).is_none());
    }
}
