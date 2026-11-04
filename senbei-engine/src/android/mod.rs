//! Android AArch64 extraction and ELF restoration.

mod common;
mod extract;
mod limits;
mod restore;

pub use extract::{
    DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE, Error as ExtractionError, ExtractOptions,
    ExtractionReport, extract_stage2, extract_stage2_with_limits, is_protected_libil2cpp,
    probe_libil2cpp_with_limits,
};
pub use limits::{
    ByteBudget, DEFAULT_MAX_DEPTH, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_ENTRY_BYTES,
    DEFAULT_MAX_TOTAL_BYTES, EntryBudget, LimitExceeded, ResourceLimits,
};
pub use restore::{
    Error as RestoreError, RestoreOptions, RestoreReport, restore_libil2cpp,
    restore_libil2cpp_with_limits,
};
