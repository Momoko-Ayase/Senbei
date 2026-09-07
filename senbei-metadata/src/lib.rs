//! Unity il2cpp metadata restoration.

pub mod android;
mod common;
mod structural;
pub mod windows;

pub use common::is_metadata;
pub use structural::*;
