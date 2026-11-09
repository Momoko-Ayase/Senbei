//! Senbei's desktop front end.
//!
//! The window ([`Workbench`]) talks to the machine only through a
//! [`backend::Backend`]; the native backend runs the same recovery pipeline as
//! the command line, in process.

pub mod backend;
pub mod format;
pub mod labels;
pub mod model;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
pub mod settings;
pub mod text;
pub mod theme;
pub mod ui;

pub use ui::Workbench;
