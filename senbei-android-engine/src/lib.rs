//! Pure-static Stage 1 decryption and recursive Stage 2 module extraction.

mod error;
mod extract;
mod probe;
mod report;
mod stage1;
mod stream;

pub use error::Error;
pub use extract::{ExtractOptions, extract_stage2};
pub use probe::is_protected_libil2cpp;
pub use report::ExtractionReport;
pub use stage1::{DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE};
