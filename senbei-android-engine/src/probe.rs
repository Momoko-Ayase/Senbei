use std::path::Path;

use senbei_android_crypto::Module9bConfig;

use crate::stage1::{self, DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE};

/// Return whether `data` has a supported protected AArch64 IL2CPP layout.
#[must_use]
pub fn is_protected_libil2cpp(data: &[u8]) -> bool {
    if !stage1::looks_protected(data) {
        return false;
    }
    let Ok(stage1) = stage1::inspect(
        data,
        Path::new("<probe>"),
        DEFAULT_OUTER_SIZE,
        DEFAULT_CIPHER_CONSTANT,
    ) else {
        return false;
    };
    Module9bConfig::parse_embedded(&stage1.plaintext).is_ok()
}
