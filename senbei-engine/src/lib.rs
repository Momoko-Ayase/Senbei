//! Platform-specific unpacking engines.

pub mod android;
pub mod windows;

pub use windows::{
    Detected, IntegrityReport, Kind, UnpackError, check_integrity, detect, unpack_auto,
    unpack_auto_v, unpack_dll, unpack_dll_v, unpack_exe, unpack_exe_v,
};

/// Deterministic worker-thread cap shared by filesystem scanning and engines.
pub fn thread_cap() -> usize {
    windows::thread_cap()
}
