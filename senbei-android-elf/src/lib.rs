//! Static restoration of the current protected AArch64 `libil2cpp.so`.

mod artifact;
mod error;
mod hash;
mod layout;
mod restore;

pub use error::Error;
pub use restore::{RestoreOptions, RestoreReport, restore_libil2cpp};
