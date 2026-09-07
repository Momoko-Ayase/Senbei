//! Filesystem and command-line orchestration.

/// File name of an IL2CPP metadata blob shared by both platform scanners.
pub const METADATA_FILE_NAME: &str = "global-metadata.dat";

pub mod android;
mod atomic;
pub mod job;
pub mod logfile;
pub mod pause;
pub mod scan;
pub mod ui;
pub mod windows;
