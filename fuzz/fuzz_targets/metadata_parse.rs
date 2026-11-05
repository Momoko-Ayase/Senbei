#![no_main]

//! il2cpp metadata parsing (structural transform and seed discovery).
//!
//! Input is capped at 2 MiB: real metadata is large, but a fuzz corpus of
//! multi-megabyte blobs slows iteration without reaching new code, and the
//! parser's bounds checks are index-driven, not size-driven.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 2 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    let _ = senbei_metadata::is_metadata(data);
    let _ = senbei_metadata::deobfuscate(data);
    let _ = senbei_metadata::android::discover_method_token_seeds(data);
});
