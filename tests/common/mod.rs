//! Shared test fixtures.
#![allow(dead_code)]

use std::path::PathBuf;

/// Path to `senbei/samples` — the user-managed corpus dropped in by hand.
/// Git-ignored except its README; tests here run against whatever is present.
pub fn samples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples")
}
