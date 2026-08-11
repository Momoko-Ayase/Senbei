//! Static sanity check for unpacked PE images.
//!
//! The unpack pipelines can succeed structurally (no error, no panic) yet emit
//! a binary the OS loader rejects at runtime with `0xC0000005`
//! (STATUS_ACCESS_VIOLATION) — e.g. when the entry-point stub or import strings
//! were left encrypted because a layout heuristic picked the wrong offset. This
//! module inspects the *output* bytes alone (no reference, no execution) and
//! reports defects that are near-certain runtime crashes.
//!
//! It is intentionally conservative: it only flags conditions that cannot occur
//! in a correctly unpacked image, so a clean report is not a guarantee of
//! correctness, but a non-clean report is a reliable "this is broken" signal.
//!
//! All reads are bounds-checked; the check never panics on any input.

/// Result of a static integrity check over an unpacked image.
#[derive(Debug, Clone, Default)]
pub struct IntegrityReport {
    /// Each entry describes one detected defect. Empty means no defect found.
    pub issues: Vec<String>,
}

impl IntegrityReport {
    /// True when no defects were detected.
    pub fn ok(&self) -> bool {
        self.issues.is_empty()
    }
}

// `checked_add`, not `+`: `usize` is 32-bit on wasm32, so a header-derived
// offset near `u32::MAX` would wrap the range and panic (`start > end`) in a
// module documented never to panic on any input.
fn rd_u16(d: &[u8], off: u32) -> Option<u16> {
    let i = off as usize;
    d.get(i..i.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn rd_u32(d: &[u8], off: u32) -> Option<u32> {
    let i = off as usize;
    d.get(i..i.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A parsed section-table entry (only the fields we translate against).
struct Section {
    va: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
    chars: u32,
}

/// Walk the output's own section table and translate an RVA to a file offset.
/// Works for both memory-image output (raw_ptr == va) and compacted disk
/// output (real raw pointers), because it consults whatever the output declares.
/// Returns the offset only if the translated range `[off, off+need)` lies inside
/// the file.
fn rva_to_off(secs: &[Section], file_len: usize, rva: u32, need: u32) -> Option<u32> {
    for s in secs {
        // The mapped span is the larger of virtual and raw size, so an RVA that
        // falls in the virtual tail of a section still resolves.
        let span = s.vsize.max(s.raw_size);
        if span == 0 {
            continue;
        }
        if rva >= s.va && rva < s.va.wrapping_add(span) {
            let delta = rva - s.va;
            let off = s.raw_ptr.checked_add(delta)?;
            let end = off.checked_add(need)?;
            if (end as usize) <= file_len {
                return Some(off);
            }
            return None;
        }
    }
    None
}

/// Inspect an unpacked PE image and report any defect that would make the OS
/// loader fault at runtime. `out` is the bytes the unpacker produced.
pub fn check(out: &[u8]) -> IntegrityReport {
    let mut r = IntegrityReport::default();
    let file_len = out.len();

    // --- DOS + PE headers ---------------------------------------------------
    if rd_u16(out, 0) != Some(0x5A4D) {
        r.issues.push("missing 'MZ' DOS signature".into());
        return r; // nothing else is meaningful
    }
    let pe_off = match rd_u32(out, 0x3C) {
        Some(v) => v,
        None => {
            r.issues.push("truncated DOS header (no e_lfanew)".into());
            return r;
        }
    };
    if rd_u32(out, pe_off) != Some(0x0000_4550) {
        r.issues
            .push(format!("missing 'PE\\0\\0' signature at 0x{pe_off:X}"));
        return r;
    }

    let num_sections = match rd_u16(out, pe_off.wrapping_add(6)) {
        Some(v) => v as u32,
        None => {
            r.issues.push("truncated COFF header".into());
            return r;
        }
    };
    let opt_hdr_size = rd_u16(out, pe_off.wrapping_add(20)).unwrap_or(0) as u32;
    let opt = pe_off.wrapping_add(24);
    let magic = match rd_u16(out, opt) {
        Some(v) => v,
        None => {
            r.issues.push("truncated optional header".into());
            return r;
        }
    };
    let is64 = match magic {
        0x20B => true,
        0x10B => false,
        other => {
            r.issues
                .push(format!("bad optional-header magic 0x{other:X}"));
            return r;
        }
    };

    if num_sections == 0 || num_sections > 96 {
        r.issues
            .push(format!("implausible section count {num_sections}"));
    }

    let size_of_image = rd_u32(out, pe_off.wrapping_add(80)).unwrap_or(0);
    if size_of_image == 0 {
        r.issues.push("SizeOfImage is zero".into());
    }

    // --- Section table ------------------------------------------------------
    let sec_table = opt.wrapping_add(opt_hdr_size);
    let mut secs: Vec<Section> = Vec::new();
    for i in 0..num_sections {
        let base = sec_table.wrapping_add(i * 40);
        // If the table runs past EOF the image is structurally broken.
        let (vsize, va, raw_size, raw_ptr, chars) = match (
            rd_u32(out, base.wrapping_add(8)),
            rd_u32(out, base.wrapping_add(12)),
            rd_u32(out, base.wrapping_add(16)),
            rd_u32(out, base.wrapping_add(20)),
            rd_u32(out, base.wrapping_add(36)),
        ) {
            (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
            _ => {
                r.issues
                    .push("section table extends past end of file".into());
                return r;
            }
        };
        // Raw data must lie within the file for compacted (disk-layout) output.
        if raw_size != 0 {
            let end = raw_ptr.wrapping_add(raw_size) as usize;
            if end > file_len {
                r.issues.push(format!(
                    "section #{i} raw data [0x{raw_ptr:X}..0x{end:X}] exceeds file size 0x{file_len:X}"
                ));
            }
        }
        secs.push(Section {
            va,
            vsize,
            raw_ptr,
            raw_size,
            chars,
        });
    }

    // --- Managed (CLR) detection ------------------------------------------
    // The COR20 (CLR) data directory, when present and non-zero, marks a managed
    // assembly. Such images are dispatched through the CLR (via the COR20 header
    // + BSJB metadata), not the native loader, so the native-loader heuristics
    // below (zeroed EP stub, encrypted first import name) do NOT apply: CrackProof
    // legitimately leaves a managed DLL's native EP and import strings in a state
    // the native loader would reject, and that state is preserved here.
    // Detect it before the EP / import checks so we can scope them to native
    // images only.
    let clr_rva = rd_u32(
        out,
        opt.wrapping_add(if is64 { 112 } else { 96 })
            .wrapping_add(14 * 8),
    )
    .unwrap_or(0);
    let is_managed = clr_rva != 0;

    // --- Native DLL relocatability ------------------------------------------
    // A native DLL is almost always loaded at a non-preferred base, so a
    // missing base-relocation directory (DD[5]) is a guaranteed crash on
    // rebase — exactly the failure mode produced when an unpacker wrongly
    // applies the /FIXED-EXE fixup (zero BaseReloc + DllCharacteristics) to a
    // DLL. Managed assemblies are exempt: the CLR rebases nothing through the
    // native table, and their golden outputs legitimately carry no DD[5].
    let dd_base = opt.wrapping_add(if is64 { 112 } else { 96 });
    let chars_coff = rd_u16(out, pe_off.wrapping_add(22)).unwrap_or(0);
    let is_dll = (chars_coff & 0x2000) != 0;
    if is_dll && !is_managed {
        let reloc_rva = rd_u32(out, dd_base.wrapping_add(5 * 8)).unwrap_or(0);
        if reloc_rva == 0 {
            r.issues.push(
                "native DLL has no base relocation table (DD[5] is zero) — will crash when loaded at a non-preferred base"
                    .into(),
            );
        }
    }

    // --- Entry point --------------------------------------------------------
    // An entry RVA that does not resolve to a section, or whose target bytes are
    // all zero, is a guaranteed access violation the instant the loader jumps to
    // it. A zeroed/encrypted entry stub is the classic broken-unpack symptom.
    let ep = rd_u32(out, pe_off.wrapping_add(40)).unwrap_or(0);
    if ep == 0 {
        // A DLL may legitimately have no entry point; an EXE never does.
        if !is_dll {
            r.issues.push("entry point RVA is zero".into());
        }
    } else if !is_managed {
        match rva_to_off(&secs, file_len, ep, 16) {
            None => {
                r.issues.push(format!(
                    "entry point RVA 0x{ep:X} does not map into any section"
                ));
            }
            Some(off) => {
                let stub = &out[off as usize..off as usize + 16];
                if stub.iter().all(|&b| b == 0) {
                    r.issues.push(format!(
                        "entry point at RVA 0x{ep:X} is all zeros (stub not recovered)"
                    ));
                } else if stub.iter().all(|&b| b == 0xCC) {
                    // 16 bytes of int3 padding where the entry stub should be:
                    // the stub region was never recovered, the loader walks
                    // straight into a debug-break wall.
                    r.issues.push(format!(
                        "entry point at RVA 0x{ep:X} is all int3 padding (stub not recovered)"
                    ));
                }
                // The entry must live in an executable section.
                let exec = secs.iter().any(|s| {
                    let span = s.vsize.max(s.raw_size);
                    ep >= s.va && ep < s.va.wrapping_add(span) && (s.chars & 0x2000_0000) != 0
                });
                if !exec {
                    r.issues.push(format!(
                        "entry point RVA 0x{ep:X} is not in an executable section"
                    ));
                }
            }
        }
    }

    // --- Import table -------------------------------------------------------
    // If an import directory is present, every descriptor's DLL name must be
    // readable printable ASCII. Encrypted/garbage names mean import-string
    // decryption failed, and the loader faults resolving them — checking only
    // the first descriptor misses later ones still left as ciphertext. Skipped
    // for managed assemblies (their import table is a CLR bootstrap stub the
    // native loader doesn't resolve the same way). Note this no longer gates
    // on NumberOfRvaAndSizes: a corrupt optional header shrinking that field
    // must not silence the walk while a bogus import RVA still points at
    // ciphertext.
    if !is_managed {
        let imp_rva = rd_u32(out, dd_base.wrapping_add(8)).unwrap_or(0);
        if imp_rva != 0 {
            match rva_to_off(&secs, file_len, imp_rva, 20) {
                None => r.issues.push(format!(
                    "import directory RVA 0x{imp_rva:X} does not map into any section"
                )),
                Some(desc_off) => {
                    // 256 descriptors is far beyond any real import table; the
                    // cap keeps a corrupt, never-null table from walking on.
                    for i in 0..256u32 {
                        let d_off = desc_off.wrapping_add(i.wrapping_mul(20));
                        let name_rva = rd_u32(out, d_off.wrapping_add(12)).unwrap_or(0);
                        // name_rva == 0 is the terminating null descriptor (or
                        // a read past the table) — done.
                        if name_rva == 0 {
                            break;
                        }
                        match rva_to_off(&secs, file_len, name_rva, 1) {
                            None => r.issues.push(format!(
                                "import descriptor {i} DLL name RVA 0x{name_rva:X} does not map into any section"
                            )),
                            Some(noff) => {
                                if !looks_like_dll_name(out, noff) {
                                    r.issues.push(format!(
                                        "import descriptor {i} DLL name at RVA 0x{name_rva:X} is not readable ASCII (imports left encrypted?)"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // --- Managed (CLR) header + metadata ------------------------------------
    // For a managed assembly the COR20 (CLR) header and the BSJB MetaData stream
    // it points at must survive unpacking intact, or the runtime rejects the
    // image with BadImageFormatException ("Invalid COR20 header signature" /
    // bad metadata) before any code runs. CrackProof copies both regions through
    // verbatim; a unpacker that lets the .text dd8 pass scribble over them (they
    // live inside .text) produces a structurally-valid-looking PE that the CLR
    // still refuses to load. Validate: COR20 cb == 0x48, and the MetaData stream
    // begins with the "BSJB" signature.
    if is_managed {
        match rva_to_off(&secs, file_len, clr_rva, 0x48) {
            None => r.issues.push(format!(
                "CLR (COR20) directory RVA 0x{clr_rva:X} does not map into any section"
            )),
            Some(coff) => {
                let cb = rd_u32(out, coff).unwrap_or(0);
                if cb != 0x48 {
                    r.issues.push(format!(
                        "COR20 header at RVA 0x{clr_rva:X} has cb 0x{cb:X} (expected 0x48) — CLR header corrupt"
                    ));
                } else {
                    // MetaData RVA/size live at COR20 + 0x08 / + 0x0C.
                    let md_rva = rd_u32(out, coff.wrapping_add(8)).unwrap_or(0);
                    if md_rva != 0 {
                        match rva_to_off(&secs, file_len, md_rva, 4) {
                            None => r.issues.push(format!(
                                "CLR MetaData RVA 0x{md_rva:X} does not map into any section"
                            )),
                            Some(moff) => {
                                let sig = out.get(moff as usize..moff as usize + 4);
                                if sig != Some(b"BSJB") {
                                    r.issues.push(format!(
                                        "CLR MetaData at RVA 0x{md_rva:X} lacks 'BSJB' signature (metadata corrupt — managed image will not load)"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    r
}

/// True if the NUL-terminated string starting at `off` looks like a DLL name:
/// at least one byte, all printable ASCII up to the NUL, within a sane length.
fn looks_like_dll_name(d: &[u8], off: u32) -> bool {
    let start = off as usize;
    let mut end = start;
    let limit = (start + 256).min(d.len());
    while end < limit && d[end] != 0 {
        end += 1;
    }
    if end == start || end >= limit {
        return false; // empty, or no NUL within a sane window
    }
    d[start..end].iter().all(|&b| (0x20..0x7F).contains(&b))
}
