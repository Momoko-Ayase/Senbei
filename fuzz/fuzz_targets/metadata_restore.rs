#![no_main]

//! Metadata restorers that depend on a decoded module.
//!
//! The first byte splits the input into a seed selector and the metadata
//! bytes, so both `restore_method_tokens` and the v24.1 method-index restore
//! get structured-but-arbitrary inputs. Bounded to 2 MiB per iteration.

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 2 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let seed = u32::from(selector);
    let _ = senbei_metadata::android::restore_method_tokens(body, seed);
    // The module bytes are attacker-shaped too: an arbitrary "module 0x0C"
    // must fail validation, never panic.
    let _ = senbei_metadata::android::restore_method_indices_v24_1(body, body);
    let _ = senbei_metadata::android::extract_embedded_metadata(body);
});
