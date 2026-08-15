//! Pure, panic-free Crackproof unpacker core. No file I/O lives here.

mod bytecode;
mod crc32;
pub mod dll;
pub mod exe;
pub mod integrity;
pub(crate) mod parallel;
pub(crate) mod primitives;
mod tables;

pub use dll::{unpack_dll, unpack_dll_v};
pub use exe::{UnpackError, unpack as unpack_exe, unpack_v as unpack_exe_v};
pub use integrity::{IntegrityReport, check as check_integrity};

/// Maximum plausible PE `SizeOfImage` we are willing to allocate a zero buffer
/// for. Guards against a corrupt/crafted header requesting a multi-gigabyte
/// (or, as a sign-extended negative `i32`, multi-exabyte) allocation, which
/// would abort the process — an abort that `catch_unpack` below cannot trap.
/// Real protected binaries are far below this.
pub(crate) const MAX_IMAGE_SIZE: u64 = 1 << 30; // 1 GiB

/// Run an unpack pipeline, converting any internal panic into a clean
/// [`UnpackError::Corrupt`] so the public API stays panic-free on any input
/// (truncated/garbled files chase offsets out of bounds). The default panic
/// hook is suppressed transiently so a trapped panic does not spill a
/// backtrace to stderr.
///
/// Note: allocation *failures* abort the process and are NOT caught here; size
/// requests are bounds-checked against [`MAX_IMAGE_SIZE`] before allocating.
pub(crate) fn catch_unpack<F>(f: F) -> Result<Vec<u8>, UnpackError>
where
    F: FnOnce() -> Result<Vec<u8>, UnpackError>,
{
    // Hook suppression is skipped on wasm: the prebuilt std cannot unwind
    // there, so a panic traps immediately — and the suppressed hook would
    // hide the panic message, leaving a bare `unreachable` with no clue.
    #[cfg(not(target_arch = "wasm32"))]
    let prev = std::panic::take_hook();
    #[cfg(not(target_arch = "wasm32"))]
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    #[cfg(not(target_arch = "wasm32"))]
    std::panic::set_hook(prev);
    r.unwrap_or(Err(UnpackError::Corrupt))
}

/// Crackproof header magic stored in `keys[1]`/`info[1]`.
pub(crate) const MAGIC_KONN: u32 = 0x4E4E4F4B; // b"KONN" little-endian (= 1313754955)

/// True if `magic` is the Crackproof magic this unpacker supports.
pub(crate) fn is_supported_magic(magic: u32) -> bool {
    magic == MAGIC_KONN
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    NativeExe,
    ManagedExe,
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
/// the CLR data-directory RVA distinguishes managed from native for both.
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
    // Managed vs native via the CLR data-directory RVA.
    // peOff + 24 = start of optional header. The data directories start at a
    // magic-dependent offset within it: PE32 (0x10B) at +96, PE32+ (0x20B) at
    // +112. Using the PE32+ offset on a PE32 image reads the wrong dword and
    // can mis-flag a native image as managed.
    //
    // `get_u16`/`get_u32` index unchecked, so every read past the already-
    // checked Characteristics word must be bounds-checked first: a truncated
    // file (e.g. `e_lfanew` pointing at len-24) would otherwise panic here,
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
    let kind = match (is_dll, clr_rva != 0) {
        (false, false) => Kind::NativeExe,
        (false, true) => Kind::ManagedExe,
        (true, false) => Kind::NativeDll,
        (true, true) => Kind::ManagedDll,
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
        Kind::NativeExe | Kind::ManagedExe => unpack_exe_v(input, verbose)?,
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
