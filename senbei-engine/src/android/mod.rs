//! Android AArch64 extraction and ELF restoration.

mod extract;
mod restore;

pub use extract::{
    DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE, Error as ExtractionError, ExtractOptions,
    ExtractionReport, extract_stage2, is_protected_libil2cpp,
};
pub use restore::{Error as RestoreError, RestoreOptions, RestoreReport, restore_libil2cpp};
