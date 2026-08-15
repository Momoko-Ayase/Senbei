//! Pure-static Stage 1 decryption and recursive Stage 2 module extraction.

mod error;
mod extract;
mod report;
mod stage1;
mod stream;

pub use error::Error;
pub use extract::{ExtractOptions, extract_stage2};
pub use report::ExtractionReport;
pub use stage1::{DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE};

/// Return whether `data` has the protected AArch64 Stage 1 section layout.
///
/// This is a cheap, read-only probe used by folder mode to distinguish the
/// protected target from ordinary Unity libraries before invoking extraction.
#[must_use]
pub fn is_protected_libil2cpp(data: &[u8]) -> bool {
    if !stage1::looks_protected(data) {
        return false;
    }
    let Ok(stage1) = stage1::inspect(
        data,
        std::path::Path::new("<probe>"),
        DEFAULT_OUTER_SIZE,
        DEFAULT_CIPHER_CONSTANT,
    ) else {
        return false;
    };
    senbei_android_crypto::Module9bConfig::parse_embedded(&stage1.plaintext).is_ok()
}
