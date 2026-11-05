//! Unity il2cpp metadata restoration.

pub mod android;
mod common;
mod layout;
mod structural;
pub mod windows;

pub use common::is_metadata;
pub use layout::{Capabilities, LayoutStatus, MetadataIdentity, MetadataVersion, identify};
pub use structural::*;
