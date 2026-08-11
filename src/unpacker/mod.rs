//! Pure, panic-free Crackproof unpacker core. No file I/O lives here.

mod bytecode;
mod crc32;
pub mod dll;
pub mod exe;
pub mod integrity;
pub(crate) mod parallel;
pub(crate) mod primitives;
mod tables;

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

pub use dll::{unpack_dll, unpack_dll_v};
pub use exe::{
    BufferOperation, BytecodeStage, DecompressionStage, DescriptorTable, SectionPipeline,
    UnpackError, unpack as unpack_exe, unpack_v as unpack_exe_v,
};
pub use integrity::{IntegrityReport, check as check_integrity};

/// Maximum plausible PE `SizeOfImage` we are willing to allocate a zero buffer
/// for. Guards against a corrupt/crafted header requesting a multi-gigabyte
/// (or, as a sign-extended negative `i32`, multi-exabyte) allocation, which
/// would abort the process — an abort that `catch_unpack` below cannot trap.
/// Real protected binaries are far below this.
pub(crate) const MAX_IMAGE_SIZE: u64 = 1 << 30; // 1 GiB

#[derive(Clone)]
pub(crate) struct PanicCapture(Arc<Mutex<Option<PanicDetails>>>);

#[derive(Clone)]
struct PanicDetails {
    message: String,
    file: String,
    line: u32,
    column: u32,
}

thread_local! {
    static ACTIVE_PANIC_CAPTURE: RefCell<Option<PanicCapture>> = const { RefCell::new(None) };
}

struct PanicCaptureGuard(Option<PanicCapture>);

impl Drop for PanicCaptureGuard {
    fn drop(&mut self) {
        ACTIVE_PANIC_CAPTURE.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}

impl PanicCapture {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn record(&self, info: &std::panic::PanicHookInfo<'_>) {
        let location = info.location();
        let details = PanicDetails {
            message: panic_message(info.payload()),
            file: location
                .map(|value| value.file().to_owned())
                .unwrap_or_else(|| "<unknown>".to_owned()),
            line: location.map_or(0, std::panic::Location::line),
            column: location.map_or(0, std::panic::Location::column),
        };
        let mut captured = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if captured.is_none() {
            *captured = Some(details);
        }
    }

    fn into_error(self, payload: &(dyn std::any::Any + Send)) -> UnpackError {
        let details = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| PanicDetails {
                message: panic_message(payload),
                file: "<unknown>".to_owned(),
                line: 0,
                column: 0,
            });
        UnpackError::InternalPanic {
            message: details.message,
            file: details.file,
            line: details.line,
            column: details.column,
        }
    }

    fn merge_from(&self, other: &Self) {
        let details = other
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(details) = details else { return };
        let mut captured = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if captured.is_none() {
            *captured = Some(details);
        }
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn install_panic_capture_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let capture = ACTIVE_PANIC_CAPTURE
                .try_with(|slot| slot.borrow().clone())
                .ok()
                .flatten();
            if let Some(capture) = capture {
                capture.record(info);
            } else {
                previous(info);
            }
        }));
    });
}

#[cfg(target_arch = "wasm32")]
fn install_panic_capture_hook() {}

pub(crate) fn current_panic_capture() -> Option<PanicCapture> {
    ACTIVE_PANIC_CAPTURE.with(|slot| slot.borrow().clone())
}

pub(crate) fn with_panic_capture<R>(capture: Option<PanicCapture>, f: impl FnOnce() -> R) -> R {
    let previous = ACTIVE_PANIC_CAPTURE.with(|slot| slot.replace(capture));
    let _guard = PanicCaptureGuard(previous);
    f()
}

/// Run an unpack pipeline, converting any internal panic into a clean
/// [`UnpackError::InternalPanic`] so the public API stays panic-free on any input
/// (truncated/garbled files chase offsets out of bounds). The panic location and
/// payload are captured for diagnostics without printing a backtrace to stderr.
///
/// Note: allocation *failures* abort the process and are NOT caught here; size
/// requests are bounds-checked against [`MAX_IMAGE_SIZE`] before allocating.
pub(crate) fn catch_unpack<F>(f: F) -> Result<Vec<u8>, UnpackError>
where
    F: FnOnce() -> Result<Vec<u8>, UnpackError>,
{
    // Hook capture is skipped on wasm: the prebuilt std cannot unwind there,
    // so a panic traps immediately. The Web Worker boundary reports that trap.
    install_panic_capture_hook();
    let capture = PanicCapture::new();
    let r = with_panic_capture(Some(capture.clone()), || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
    });
    match r {
        Ok(result) => result,
        Err(payload) => Err(capture.into_error(payload.as_ref())),
    }
}

/// Crackproof header magic stored in `keys[1]`/`info[1]`.
pub(crate) const MAGIC_KONN: u32 = 0x4E4E4F4B; // b"KONN" little-endian (= 1313754955)

/// True if `magic` is the Crackproof magic this unpacker supports.
pub(crate) fn is_supported_magic(magic: u32) -> bool {
    magic == MAGIC_KONN
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Exe,
    NativeDll,
    ManagedDll,
}

#[derive(Debug, Clone, Copy)]
pub struct Detected {
    pub kind: Kind,
    pub magic: u32,
}

// ---------------------------------------------------------------------------
// Content-based detection
// ---------------------------------------------------------------------------

/// Derive the 8-element Crackproof key table from the header at offset 4096.
/// Returns `None` if the input is too short or doesn't have a valid PE signature.
fn key_table(input: &[u8]) -> Option<[u32; 8]> {
    // Need at least 4128 bytes: the key-table loop below reads dwords up to
    // offset 4124 (bytes 4124..4127). Guarding only `< 4096` would let a
    // 4096..4127-byte PE (e.g. a 4 KiB stub) panic in `get_u32`.
    if input.len() < 4128 {
        return None;
    }
    // Validate PE signature. `checked_add`, not `+`: `usize` is 32-bit on
    // wasm32, where an `e_lfanew` of 0xFFFF_FFFC..=0xFFFF_FFFF wraps the bound
    // check, and the slice below then panics with start > end. `detect` runs on
    // the folder-scan threads and (in the web app) on the main thread outside
    // the disposable-worker isolation, so it must not panic on any input.
    let e_lfanew = primitives::get_u32(input, 0x3C);
    let pe_start = e_lfanew as usize;
    if pe_start.checked_add(4).is_none_or(|end| end > input.len()) {
        return None;
    }
    if &input[pe_start..pe_start + 4] != b"PE\0\0" {
        return None;
    }
    // Derive 8 keys per the Crackproof header-key formula.
    let mut keys = [0u32; 8];
    keys[0] = primitives::get_u32(input, 4096);
    let mut k = keys[0];
    for i in 0u32..7 {
        let cell = primitives::get_u32(input, 4100u32.wrapping_add(i.wrapping_mul(4)));
        keys[(i + 1) as usize] = k ^ cell;
        k = i.wrapping_mul(i) ^ (k.wrapping_add(cell).wrapping_sub(i));
    }
    Some(keys)
}

/// Detect whether `input` is a Crackproof-protected binary and classify it.
/// Returns `None` if the magic doesn't match.
///
/// Routing: `keys[1]` must be the Crackproof magic (`KONN`).
/// The PE IMAGE_FILE_DLL characteristic distinguishes EXE vs DLL;
/// the CLR data-directory RVA further distinguishes ManagedDll from NativeDll.
pub fn detect(input: &[u8]) -> Option<Detected> {
    let keys = key_table(input)?;
    let magic = keys[1];
    // Anything whose magic doesn't match is left untouched rather than
    // detected-then-errored, honoring the "anything that doesn't match is
    // left untouched" contract.
    if !is_supported_magic(magic) {
        return None;
    }
    // Use the PE DLL characteristic to distinguish EXE from DLL.
    // IMAGE_FILE_HEADER.Characteristics is at peOff+4+18; bit 0x2000 = IMAGE_FILE_DLL.
    let pe_off = primitives::get_u32(input, 0x3C);
    let chars_offset = pe_off.wrapping_add(4).wrapping_add(18);
    if (chars_offset as usize)
        .checked_add(2)
        .is_none_or(|end| end > input.len())
    {
        return None;
    }
    let chars =
        (input[chars_offset as usize] as u16) | ((input[chars_offset as usize + 1] as u16) << 8);
    let is_dll = (chars & 0x2000) != 0;
    if !is_dll {
        return Some(Detected {
            kind: Kind::Exe,
            magic,
        });
    }
    // DLL: determine managed vs native via CLR data-directory RVA.
    // peOff + 24 = start of optional header. The data directories start at a
    // magic-dependent offset within it: PE32 (0x10B) at +96, PE32+ (0x20B) at
    // +112. Using the PE32+ offset on a PE32 image reads the wrong dword and
    // can mis-flag a native DLL as managed.
    //
    // `get_u16`/`get_u32` index unchecked, so every read past the already-
    // checked Characteristics word must be bounds-checked first: a truncated
    // DLL (e.g. `e_lfanew` pointing at len-24) would otherwise panic here,
    // and this detector runs on the folder scan threads where a panic aborts
    // the whole run.
    let opt_magic_off = pe_off.wrapping_add(24) as usize;
    let b = input.get(opt_magic_off..opt_magic_off.checked_add(2)?)?;
    let opt_magic = u16::from_le_bytes([b[0], b[1]]);
    let dd_off: u32 = if opt_magic == 0x20B { 112 } else { 96 };
    // + 14*8 = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    let clr_rva_offset = pe_off
        .wrapping_add(24)
        .wrapping_add(dd_off)
        .wrapping_add(14u32.wrapping_mul(8));
    if (clr_rva_offset as usize)
        .checked_add(4)
        .is_none_or(|end| end > input.len())
    {
        return None;
    }
    let clr_rva = primitives::get_u32(input, clr_rva_offset);
    let kind = if clr_rva != 0 {
        Kind::ManagedDll
    } else {
        Kind::NativeDll
    };
    Some(Detected { kind, magic })
}

/// Detect the file type and dispatch to the matching pipeline.
/// Returns the detected `Kind` together with the unpacked image bytes.
pub fn unpack_auto(input: &[u8]) -> Result<(Kind, Vec<u8>), UnpackError> {
    unpack_auto_v(input, false)
}

/// Like [`unpack_auto`], but prints detailed `[N/9]` unpack-step progress to
/// stdout when `verbose` is true. Output bytes are identical regardless.
pub fn unpack_auto_v(input: &[u8], verbose: bool) -> Result<(Kind, Vec<u8>), UnpackError> {
    let detected = detect(input).ok_or(UnpackError::NotCrackproof)?;
    let out = match detected.kind {
        Kind::Exe => unpack_exe_v(input, verbose)?,
        Kind::NativeDll | Kind::ManagedDll => {
            // Two Crackproof DLL layouts exist. The older one (the byte-identical
            // DLL goldens) follows the pipeline in `dll.rs`. Newer builds protect
            // DLLs with the EXE-style shell layout instead — `dll::unpack_dll`
            // cannot parse them and errors. Try the DLL pipeline first; on
            // failure, fall back to the EXE pipeline, which handles the new
            // layout (including managed-DLL CLR metadata restore). The DLL-first
            // order keeps the old-layout goldens byte-identical (the EXE
            // pipeline "succeeds" on them but with different bytes).
            match dll::unpack_dll_v(input, verbose) {
                Ok(out) => out,
                Err(dll_err) => match exe::unpack_v(input, verbose) {
                    Ok(out) => out,
                    // Surface the DLL-pipeline error, not the EXE one: for a
                    // genuinely corrupt DLL the DLL error is the more relevant
                    // diagnostic, and the EXE fallback is best-effort.
                    Err(_) => return Err(dll_err),
                },
            }
        }
    };
    Ok((detected.kind, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn caught_panic_reports_location_and_message() {
        let error = catch_unpack(|| -> Result<Vec<u8>, UnpackError> {
            panic!("test panic");
        })
        .expect_err("panic must become an error");
        let UnpackError::InternalPanic {
            message,
            file,
            line,
            column,
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(message, "test panic");
        assert!(file.ends_with("src/unpacker/mod.rs") || file.ends_with("src\\unpacker\\mod.rs"));
        assert!(line > 0);
        assert!(column > 0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn worker_panic_keeps_the_worker_source_location() {
        let error = catch_unpack(|| -> Result<Vec<u8>, UnpackError> {
            let capture = current_panic_capture();
            let result = std::thread::spawn(move || {
                with_panic_capture(capture, || panic!("worker panic"));
            })
            .join();
            if let Err(payload) = result {
                std::panic::resume_unwind(payload);
            }
            Ok(Vec::new())
        })
        .expect_err("worker panic must become an error");
        let UnpackError::InternalPanic {
            message,
            file,
            line,
            column,
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(message, "worker panic");
        assert!(file.ends_with("src/unpacker/mod.rs") || file.ends_with("src\\unpacker\\mod.rs"));
        assert!(line > 0);
        assert!(column > 0);
    }
}
