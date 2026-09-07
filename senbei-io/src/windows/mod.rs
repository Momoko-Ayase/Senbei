//! Windows filesystem adapter for PE companion payloads and byte APIs.

use senbei_engine as unpacker;
use std::path::Path;

use crate::atomic::write_atomic;

pub(crate) fn is_pe_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll"))
}

pub(crate) fn is_companion(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(stub_name) = name.strip_suffix("._") else {
        return false;
    };
    is_pe_extension(Path::new(stub_name))
}

/// Return whether a directory entry is an NTFS reparse point. The scanner keeps
/// this host-specific check in the Windows adapter while the traversal itself
/// remains platform-neutral.
#[cfg(windows)]
pub(crate) fn is_reparse_point(entry: &walkdir::DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    entry
        .metadata()
        .map(|metadata| metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(_entry: &walkdir::DirEntry) -> bool {
    false
}

/// Crackproof header key table lives at this fixed file offset. For the
/// external-companion layout, the companion payload aligns to the stub here.
const HEADER_OFF: usize = 4096;

/// Build the unpacker input for `input`, transparently handling the
/// **external-companion** layout used by some il2cpp games.
///
/// In that layout a protected module is split into a thin on-disk loader stub
/// (`Foo.dll`, whose code sections are stripped to one page) plus an encrypted
/// `Foo.dll._` companion holding the real payload. The companion is byte-for-byte
/// the stub's payload region starting at the Crackproof header (offset 4096), so
/// `stub[..4096] ++ companion` reconstructs the ordinary embedded-payload file
/// the existing pipelines already unpack. The runtime loader does exactly this:
/// it maps `Foo.dll._` and feeds it through the standard Crackproof unpack.
///
/// The splice fires only when a sibling `<input>._` exists *and* its first 32
/// bytes equal the stub's header at offset 4096 — a precise signal that the
/// companion is this stub's payload. Otherwise the file is returned untouched,
/// so normal (embedded-payload) inputs are unaffected.
pub(crate) fn read_unpacker_input(input: &Path) -> std::io::Result<UnpackerInput> {
    let stub = std::fs::read(input)?;

    // Companion path: append "._" to the full file name (Foo.dll -> Foo.dll._).
    let companion = match input.file_name() {
        Some(name) => {
            let mut n = name.to_os_string();
            n.push("._");
            input.with_file_name(n)
        }
        None => {
            return Ok(UnpackerInput {
                bytes: stub,
                stub: None,
            });
        }
    };
    if !companion.is_file() {
        return Ok(UnpackerInput {
            bytes: stub,
            stub: None,
        });
    }
    let comp = std::fs::read(&companion)?;
    match splice_companion(&stub, &comp) {
        // A splice fired: keep the stub so its plaintext export table can be
        // overlaid onto the unpacked image (the companion does not carry it).
        Some(spliced) => Ok(UnpackerInput {
            bytes: spliced,
            stub: Some(stub),
        }),
        None => Ok(UnpackerInput {
            bytes: stub,
            stub: None,
        }),
    }
}

/// The bytes fed to the unpacker, plus the original loader stub when the input
/// was reconstructed from an external companion. The stub is retained because
/// the crackproof loader rebuilds the PE export table at runtime from data kept
/// in the stub — that table is *not* present in the encrypted companion, so the
/// unpacked image needs it overlaid from the stub afterwards
/// (see [`overlay_exports_from_stub`]).
pub(crate) struct UnpackerInput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) stub: Option<Vec<u8>>,
}

/// Overlay the PE export table from the loader `stub` onto the unpacked image
/// `out`, for the external-companion layout.
///
/// In that layout the encrypted companion carries the real `.text`/`il2cpp`
/// payload but **not** a usable export directory: the crackproof loader rebuilds
/// exports at runtime from the plaintext copy retained in the stub's `.rdata`.
/// Statically, the spliced input therefore decrypts to a garbage export
/// directory (`NumberOfFunctions` etc. are ciphertext), which makes downstream
/// tools (IL2CppDumper, IDA) choke when they parse it. The fix does what the
/// loader does: copy the export-directory region byte-for-byte from the stub to
/// the same RVA in the unpacked image.
///
/// No-op (leaves `out` untouched) if there is no export directory, or if the
/// region cannot be mapped in either image — so a malformed stub can never
/// corrupt an otherwise-good unpack.
pub(crate) fn overlay_exports_from_stub(out: &mut [u8], stub: &[u8]) {
    let (export_rva, export_size) = match pe_export_dir(out) {
        Some(v) if v.1 != 0 => v,
        _ => return,
    };
    let dst = match rva_to_file_off(out, export_rva) {
        Some(o) => o,
        None => return,
    };
    let src = match rva_to_file_off(stub, export_rva) {
        Some(o) => o,
        None => return,
    };
    let n = export_size as usize;
    if dst + n <= out.len() && src + n <= stub.len() {
        out[dst..dst + n].copy_from_slice(&stub[src..src + n]);
    }
}

/// Restore the TLS directory from the loader `stub` onto the unpacked image
/// `out`, for the external-companion layout.
///
/// Crackproof strips the whole `IMAGE_TLS_DIRECTORY` from the encrypted payload
/// — the data-directory entry, the directory struct, the raw-data template, and
/// the base relocations for the struct's four 64-bit pointer fields — and
/// re-installs TLS itself from data kept in the stub when it loads the module.
/// A statically-unpacked DLL is loaded by the ordinary Windows loader instead,
/// which needs a valid TLS directory or it never allocates a TLS slot for the
/// module nor writes `_tls_index`. The module's C++ `thread_local` accesses then
/// read a garbage TLS slot — observed as a `0xC0000005` deep in IL2CPP type
/// resolution (a TypeDef token used as a raw `s_TypeInfoTable` index).
///
/// The stub retains the full plaintext `.rdata` (only `.text`/`il2cpp` are
/// stripped to one page), so the directory struct and its raw-data template are
/// copied back byte-for-byte at their RVAs, the data-directory entry is taken
/// from the stub header (the unpacked image's was overwritten with the zeroed
/// saved-header blob), and four DIR64 relocations are appended to `.reloc`.
///
/// No-op if the stub declares no TLS directory or if any required region cannot
/// be mapped/relocated — so it can never corrupt an otherwise-good unpack.
pub(crate) fn restore_tls_from_stub(out: &mut [u8], stub: &[u8]) {
    let pe = match read_u32(out, 0x3C) {
        Some(v) => v as usize,
        None => return,
    };
    if out.get(pe..pe + 4) != Some(&b"PE\0\0"[..]) {
        return;
    }
    // This restore is PE32+-only: it copies a 40-byte IMAGE_TLS_DIRECTORY64,
    // converts fields with a 64-bit image base, and appends DIR64 relocs. A
    // PE32 module needs the 24-byte struct / DIR32 handling (the unpacker core
    // does that itself — see `restore_pe32_tls_from_stub`), so bail rather than
    // read the data directories at the wrong (PE32+) offset and write garbage.
    if read_u16(out, pe + 24) != Some(0x20B) {
        return;
    }
    // TLS is data-directory index 9 (PE32+ directories at optional header +112).
    let tls_dd = match pe.checked_add(24 + 112 + 9 * 8) {
        Some(v) => v,
        None => return,
    };
    // The genuine entry survives in the stub header; the unpacked image's copy
    // was clobbered by the (zeroed-TLS) saved-header blob.
    let (tls_rva, tls_size) = match (read_u32(stub, tls_dd), read_u32(stub, tls_dd + 4)) {
        (Some(r), Some(s)) if r != 0 && s != 0 => (r, s),
        _ => return, // module has no TLS — nothing to restore
    };
    // Image base (PE32+, optional header +24) converts the struct's absolute VAs
    // back to RVAs for the raw-data template overlay.
    let image_base = match read_u64(out, pe + 24 + 24) {
        Some(v) => v,
        None => return,
    };

    // 1) Overlay the IMAGE_TLS_DIRECTORY struct from the stub at its RVA.
    let dst = match rva_to_file_off(out, tls_rva) {
        Some(o) => o,
        None => return,
    };
    let src = match rva_to_file_off(stub, tls_rva) {
        Some(o) => o,
        None => return,
    };
    let n = tls_size as usize;
    if dst.checked_add(n).is_none_or(|e| e > out.len())
        || src.checked_add(n).is_none_or(|e| e > stub.len())
    {
        return;
    }
    out[dst..dst + n].copy_from_slice(&stub[src..src + n]);

    // 2) Restore the data-directory entry so the loader processes TLS at all.
    write_u32_at(out, tls_dd, tls_rva);
    write_u32_at(out, tls_dd + 4, tls_size);

    // 3) Overlay the raw-data template [StartAddressOfRawData, EndAddressOfRawData).
    if let (Some(start_va), Some(end_va)) = (read_u64(out, dst), read_u64(out, dst + 8))
        && end_va > start_va
        && start_va >= image_base
    {
        let tpl_rva = (start_va - image_base) as u32;
        let tpl_len = (end_va - start_va) as usize;
        if let (Some(td), Some(ts)) = (
            rva_to_file_off(out, tpl_rva),
            rva_to_file_off(stub, tpl_rva),
        ) && td.checked_add(tpl_len).is_some_and(|e| e <= out.len())
            && ts.checked_add(tpl_len).is_some_and(|e| e <= stub.len())
        {
            out[td..td + tpl_len].copy_from_slice(&stub[ts..ts + tpl_len]);
        }
    }

    // 4) Append DIR64 relocations for the struct's four 64-bit pointer fields
    //    (Start/End/Index/CallBacks at +0/+8/+0x10/+0x18). Without them the
    //    loader would leave preferred-base VAs in a rebased image.
    add_tls_relocs(out, pe, tls_rva);
}

/// Append a single base-relocation block covering the four 64-bit pointer fields
/// of the TLS directory struct at `tls_rva`. The block is written immediately
/// after the existing relocation table (which must be free space and in bounds)
/// and the BaseReloc directory size is grown to include it. No-op if the table
/// is absent, the fields straddle a relocation page, or the slot is not free.
fn add_tls_relocs(out: &mut [u8], pe: usize, tls_rva: u32) {
    let reloc_dd = pe + 24 + 112 + 5 * 8; // BaseReloc = directory index 5
    let (reloc_rva, reloc_size) = match (read_u32(out, reloc_dd), read_u32(out, reloc_dd + 4)) {
        (Some(r), Some(s)) if r != 0 => (r, s),
        _ => return,
    };
    // All four fields (last at +0x18) must share one 0x1000 relocation page.
    let page = tls_rva & !0xFFF;
    if (tls_rva.wrapping_add(0x18)) & !0xFFF != page {
        return;
    }
    const BLOCK: usize = 8 + 4 * 2; // header + four DIR64 entries
    let at = match rva_to_file_off(out, reloc_rva.wrapping_add(reloc_size)) {
        Some(o) => o,
        None => return,
    };
    if at.checked_add(BLOCK).is_none_or(|e| e > out.len()) {
        return;
    }
    if out[at..at + BLOCK].iter().any(|&b| b != 0) {
        return; // refuse to clobber existing data
    }
    write_u32_at(out, at, page);
    write_u32_at(out, at + 4, BLOCK as u32);
    for (i, off) in [0u32, 8, 0x10, 0x18].iter().enumerate() {
        let entry = (10u16 << 12) | (((tls_rva.wrapping_add(*off)) & 0xFFF) as u16);
        let p = at + 8 + i * 2;
        out[p..p + 2].copy_from_slice(&entry.to_le_bytes());
    }
    write_u32_at(out, reloc_dd + 4, reloc_size.wrapping_add(BLOCK as u32));
}

/// Read the Export data-directory (RVA, size) from a PE image, or `None` if the
/// headers are too short/invalid to parse.
fn pe_export_dir(buf: &[u8]) -> Option<(u32, u32)> {
    let headers = senbei_pe::parse(buf).ok()?;
    senbei_pe::data_directory(buf, headers, 0).ok()
}

/// Map an RVA to a file offset using the PE section table. Returns `None` if no
/// section contains the RVA or the headers cannot be parsed.
fn rva_to_file_off(buf: &[u8], rva: u32) -> Option<usize> {
    let headers = senbei_pe::parse(buf).ok()?;
    senbei_pe::rva_to_offset(buf, headers, rva).ok()
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let b = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

/// Write a little-endian `u32` at `off`, silently doing nothing if out of bounds.
fn write_u32_at(buf: &mut [u8], off: usize, val: u32) {
    if let Some(slot) = buf.get_mut(off..off + 4) {
        slot.copy_from_slice(&val.to_le_bytes());
    }
}

/// Splice a stub and its external-companion payload into the embedded-payload
/// form the pipelines expect, or `None` if `comp` is not this stub's payload.
///
/// The companion is byte-for-byte the stub's payload region from the Crackproof
/// header (offset 4096) onward, so the result is `stub[..4096] ++ comp`. The
/// splice fires only when the first 32 bytes of `comp` equal the stub's header
/// at offset 4096 — a 32-byte match on the key-table/magic region that confirms
/// the pairing and leaves ordinary (non-companion) inputs untouched.
pub(crate) fn splice_companion(stub: &[u8], comp: &[u8]) -> Option<Vec<u8>> {
    let hdr_end = HEADER_OFF + 32;
    if stub.len() >= hdr_end && comp.len() >= 32 && stub[HEADER_OFF..hdr_end] == comp[..32] {
        let mut spliced = Vec::with_capacity(HEADER_OFF + comp.len());
        spliced.extend_from_slice(&stub[..HEADER_OFF]);
        spliced.extend_from_slice(comp);
        return Some(spliced);
    }
    None
}

/// Detect `bytes` and run the right pipeline. Spliced external companions use
/// the EXE pipeline directly because that layout is definitionally EXE-style.
///
/// Routing spliced inputs straight to the EXE pipeline is safe: the
/// companion layout is definitionally the EXE-style shell (the runtime
/// loader maps the companion and runs the standard shell unpack), so the DLL
/// pipeline probe can never be right for it. Output bytes are identical to the
/// DLL-first + EXE-fallback route for every input that route handles.
pub(crate) fn unpack_spliced_or_auto(
    bytes: &[u8],
    spliced: bool,
    force_exe: bool,
    verbose: bool,
) -> Result<(unpacker::Kind, Vec<u8>), unpacker::UnpackError> {
    if spliced || force_exe {
        let detected = unpacker::detect(bytes).ok_or(unpacker::UnpackError::NotCrackproof)?;
        let out = unpacker::unpack_exe_v(bytes, verbose)?;
        return Ok((detected.kind, out));
    }
    unpacker::unpack_auto_v(bytes, verbose)
}

/// Unpack a single file to `dest`. Returns the Kind and integrity report on success.
pub fn unpack_one(
    input: &Path,
    dest: &Path,
) -> anyhow::Result<(unpacker::Kind, unpacker::IntegrityReport)> {
    unpack_one_v(input, dest, false)
}

/// Outcome of a byte-level unpack ([`unpack_bytes`]): the image, its detected
/// kind, and its integrity report. No file I/O is involved.
pub struct UnpackedImage {
    pub kind: unpacker::Kind,
    pub bytes: Vec<u8>,
    pub integrity: unpacker::IntegrityReport,
    /// True when the input was reconstructed from an external companion (the
    /// `._` layout), i.e. the export/TLS overlays ran.
    pub companion: bool,
}

/// Unpack in-memory `input` bytes, optionally paired with an external
/// companion payload `companion` (the `<input>._` file's contents).
///
/// This is the in-memory counterpart of [`unpack_one_v`]: splice a matching
/// companion, unpack, overlay the export table and TLS directory from the stub,
/// then run the static integrity check.
pub fn unpack_bytes(
    input: &[u8],
    companion: Option<&[u8]>,
) -> Result<UnpackedImage, unpacker::UnpackError> {
    unpack_bytes_impl(input, companion, false)
}

/// Like [`unpack_bytes`], but forces the EXE pipeline (no DLL-pipeline
/// probe). This is the web app's recovery path: the DLL-first probe relies
/// on `catch_unwind` to reject EXE-shell-layout DLLs, and panics cannot be
/// caught on wasm — the probe traps the whole call. The web app runs each
/// unpack in a disposable Web Worker and retries trapped DLLs with this
/// entry point, reproducing the CLI's dll-first/exe-fallback routing.
pub fn unpack_bytes_force_exe(
    input: &[u8],
    companion: Option<&[u8]>,
) -> Result<UnpackedImage, unpacker::UnpackError> {
    unpack_bytes_impl(input, companion, true)
}

fn unpack_bytes_impl(
    input: &[u8],
    companion: Option<&[u8]>,
    force_exe: bool,
) -> Result<UnpackedImage, unpacker::UnpackError> {
    let spliced = companion.and_then(|c| splice_companion(input, c));
    let bytes: &[u8] = spliced.as_deref().unwrap_or(input);
    let (kind, mut out) = unpack_spliced_or_auto(bytes, spliced.is_some(), force_exe, false)?;
    if spliced.is_some() {
        overlay_exports_from_stub(&mut out, input);
        restore_tls_from_stub(&mut out, input);
    }
    let integrity = unpacker::check_integrity(&out);
    Ok(UnpackedImage {
        kind,
        bytes: out,
        integrity,
        companion: spliced.is_some(),
    })
}

/// Like [`unpack_one`], but prints detailed `[N/9]` step progress (and a final
/// `Write to <dest>` line) to stdout when `verbose` is true.
pub fn unpack_one_v(
    input: &Path,
    dest: &Path,
    verbose: bool,
) -> anyhow::Result<(unpacker::Kind, unpacker::IntegrityReport)> {
    let UnpackerInput { bytes, stub } = read_unpacker_input(input)?;
    let (kind, mut out) = unpack_spliced_or_auto(&bytes, stub.is_some(), false, verbose)?;
    // External-companion layout: restore the export table from the stub, which
    // the encrypted companion does not carry (the loader rebuilds it at runtime).
    if let Some(stub) = stub {
        overlay_exports_from_stub(&mut out, &stub);
        // ...and the TLS directory, which Crackproof strips from the payload and
        // re-installs at runtime; the ordinary loader needs it or thread_local
        // access crashes (see [`restore_tls_from_stub`]).
        restore_tls_from_stub(&mut out, &stub);
    }
    let report = unpacker::check_integrity(&out);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(dest, &out)?;
    if verbose {
        println!("Write to {}", dest.display());
    }
    Ok((kind, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_OFF: usize = 4096;

    fn stub_with_header(header: &[u8; 32], extra: usize) -> Vec<u8> {
        let mut stub = vec![0_u8; HEADER_OFF];
        stub.extend_from_slice(header);
        stub.extend_from_slice(&vec![0xAA_u8; extra]);
        stub
    }

    #[test]
    fn splices_when_header_matches() {
        let header = [7_u8; 32];
        let stub = stub_with_header(&header, 16);
        let mut companion = header.to_vec();
        companion.extend_from_slice(&[0x42_u8; 1000]);

        let output = splice_companion(&stub, &companion).expect("should splice");
        assert_eq!(output.len(), HEADER_OFF + companion.len());
        assert_eq!(&output[..HEADER_OFF], &stub[..HEADER_OFF]);
        assert_eq!(&output[HEADER_OFF..], &companion[..]);
    }

    #[test]
    fn no_splice_when_header_differs() {
        let stub = stub_with_header(&[7_u8; 32], 16);
        let mut companion = vec![9_u8; 32];
        companion.extend_from_slice(&[0x42_u8; 1000]);
        assert!(splice_companion(&stub, &companion).is_none());
    }

    #[test]
    fn no_splice_when_too_short() {
        let short_stub = vec![0_u8; HEADER_OFF + 8];
        let companion = vec![0_u8; 64];
        assert!(splice_companion(&short_stub, &companion).is_none());

        let stub = stub_with_header(&[1_u8; 32], 0);
        let short_companion = vec![1_u8; 16];
        assert!(splice_companion(&stub, &short_companion).is_none());
    }
}
