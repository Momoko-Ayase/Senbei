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
//! Everything in this module is a *structural* statement about the output
//! bytes. It never executes the image, never resolves an external symbol, and
//! never reads a callback's bytes — a clean report therefore means "the loader
//! would be able to walk these tables", not "this image runs".
//!
//! All reads are bounds-checked; the check never panics on any input.

use senbei_i18n::{Message, Msg};

mod clr;
mod directories;

/// How serious one [`IntegrityReport`] defect is for choosing a DLL layout.
///
/// This does not change what [`check`] puts in [`IntegrityReport::issues`].
/// Callers that surface suspect output still read that list. Layout selection
/// uses [`IntegrityFinding::severity`] so a warning (the image may still be the
/// right layout) is not treated as "try the other pipeline".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegritySeverity {
    /// The loader or runtime rejects the image before executing it, or a
    /// directory the header claims to own does not resolve inside the file.
    /// A DLL layout that reports one of these is the wrong layout.
    Fatal,
    /// The image is a PE, but a recoverable region looks unrestored. Real
    /// outputs can carry these and still be the layout that must be kept
    /// (a native DLL with no base relocations, an entry stub left as zeros
    /// or `int3`).
    Warning,
}

/// One defect from [`check`], with the severity layout selection needs.
///
/// `message` is the same string stored in [`IntegrityReport::issues`]. Severity
/// is decided while the check still knows which rule fired, not by reading the
/// message back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityFinding {
    pub severity: IntegritySeverity,
    pub message: Message,
}

/// Result of a static integrity check over an unpacked image.
#[derive(Debug, Clone, Default)]
pub struct IntegrityReport {
    /// Each entry describes one detected defect. Empty means no defect found.
    /// Order and wording match [`IntegrityReport::findings`].
    pub issues: Vec<Message>,
    /// The same defects as `issues`, each tagged fatal or warning.
    pub findings: Vec<IntegrityFinding>,
}

impl IntegrityReport {
    /// True when no defects were detected.
    pub fn ok(&self) -> bool {
        self.issues.is_empty()
    }

    /// True when every defect is a [`IntegritySeverity::Warning`].
    ///
    /// An empty report is not fatal. Layout selection uses this to keep a DLL
    /// image whose only defects are warnings, and to reject one the loader
    /// cannot map.
    pub fn has_fatal(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == IntegritySeverity::Fatal)
    }

    fn push(&mut self, severity: IntegritySeverity, message: impl Into<Message>) {
        let message = message.into();
        self.issues.push(message.clone());
        self.findings.push(IntegrityFinding { severity, message });
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

/// PE format section data used by the integrity policy.
type Section = senbei_pe::Section;

/// Walk the output's own section table and translate an RVA to a file offset.
/// Works for both memory-image output (raw_ptr == va) and compacted disk
/// output (real raw pointers), because it consults whatever the output declares.
/// Returns the offset only if the translated range `[off, off+need)` lies inside
/// the file.
fn rva_to_off(data: &[u8], headers: senbei_pe::Headers, rva: u32, need: u32) -> Option<u32> {
    let offset = u32::try_from(senbei_pe::rva_to_offset(data, headers, rva).ok()?).ok()?;
    let end = offset.checked_add(need)?;
    (usize::try_from(end).ok()? <= data.len()).then_some(offset)
}

fn is_executable_rva(secs: &[Section], rva: u32) -> bool {
    secs.iter().any(|section| {
        let span = section.virtual_size.max(section.raw_size);
        rva >= section.virtual_address
            && rva < section.virtual_address.wrapping_add(span)
            && (section.characteristics & 0x2000_0000) != 0
    })
}

fn check_common_entry_branches(
    stub: &[u8],
    ep: u32,
    secs: &[Section],
    report: &mut IntegrityReport,
) {
    if stub.len() < 18
        || stub[0..3] != [0x48, 0x83, 0xEC]
        || stub[4] != 0xE8
        || stub[9..12] != [0x48, 0x83, 0xC4]
        || stub[12] != stub[3]
        || stub[13] != 0xE9
    {
        return;
    }
    for (name, rel_off, instruction_len) in [("call", 5usize, 9i64), ("jump", 14usize, 18i64)] {
        let rel = i32::from_le_bytes([
            stub[rel_off],
            stub[rel_off + 1],
            stub[rel_off + 2],
            stub[rel_off + 3],
        ]) as i64;
        let target = i64::from(ep) + instruction_len + rel;
        let valid = u32::try_from(target)
            .ok()
            .is_some_and(|rva| is_executable_rva(secs, rva));
        if !valid {
            report.push(
                IntegritySeverity::Fatal,
                Msg::EntryStubTargetOutsideCode {
                    branch: name,
                    target,
                },
            );
        }
    }
}

/// Inspect an unpacked PE image and report any defect that would make the OS
/// loader fault at runtime. `out` is the bytes the unpacker produced.
pub fn check(out: &[u8]) -> IntegrityReport {
    let mut r = IntegrityReport::default();
    let file_len = out.len();

    // --- DOS + PE headers ---------------------------------------------------
    if rd_u16(out, 0) != Some(0x5A4D) {
        r.push(IntegritySeverity::Fatal, Msg::MissingMz);
        return r; // nothing else is meaningful
    }
    let pe_off = match rd_u32(out, 0x3C) {
        Some(v) => v,
        None => {
            r.push(IntegritySeverity::Fatal, Msg::TruncatedDosHeader);
            return r;
        }
    };
    if rd_u32(out, pe_off) != Some(0x0000_4550) {
        r.push(
            IntegritySeverity::Fatal,
            Msg::MissingPeSignature { offset: pe_off },
        );
        return r;
    }

    let num_sections = match rd_u16(out, pe_off.wrapping_add(6)) {
        Some(v) => v as u32,
        None => {
            r.push(IntegritySeverity::Fatal, Msg::TruncatedCoffHeader);
            return r;
        }
    };
    let opt = pe_off.wrapping_add(24);
    let magic = match rd_u16(out, opt) {
        Some(v) => v,
        None => {
            r.push(IntegritySeverity::Fatal, Msg::TruncatedOptionalHeader);
            return r;
        }
    };
    let is64 = match magic {
        0x20B => true,
        0x10B => false,
        other => {
            r.push(
                IntegritySeverity::Fatal,
                Msg::BadOptionalMagic { magic: other },
            );
            return r;
        }
    };

    if num_sections == 0 || num_sections > 96 {
        r.push(
            IntegritySeverity::Fatal,
            Msg::ImplausibleSectionCount {
                count: num_sections,
            },
        );
    }

    let size_of_image = rd_u32(out, pe_off.wrapping_add(80)).unwrap_or(0);
    if size_of_image == 0 {
        r.push(IntegritySeverity::Fatal, Msg::ZeroSizeOfImage);
    }

    // --- Section table ------------------------------------------------------
    let headers = match senbei_pe::parse(out) {
        Ok(headers) => headers,
        Err(_) => {
            r.push(IntegritySeverity::Fatal, Msg::SectionTablePastEof);
            return r;
        }
    };
    let parsed_sections = match senbei_pe::sections(out, headers) {
        Ok(sections) => sections,
        Err(_) => {
            r.push(IntegritySeverity::Fatal, Msg::SectionTablePastEof);
            return r;
        }
    };
    let secs: Vec<Section> = parsed_sections
        .into_iter()
        .enumerate()
        .map(|(i, section)| {
            if section.raw_size != 0 {
                let end = section.raw_offset.wrapping_add(section.raw_size) as usize;
                if end > file_len {
                    r.push(
                        IntegritySeverity::Fatal,
                        Msg::SectionRawPastEof {
                            index: i,
                            start: section.raw_offset,
                            end,
                            file_len,
                        },
                    );
                }
            }
            section
        })
        .collect();

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
            // Warning, not fatal: a native DLL can ship without base relocations
            // (`IMAGE_FILE_RELOCS_STRIPPED`, or a module that is only ever loaded
            // at its preferred base). Rejecting the layout here would fall back
            // to the other pipeline and change bytes that previously unpacked.
            r.push(IntegritySeverity::Warning, Msg::NoBaseRelocations);
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
            r.push(IntegritySeverity::Fatal, Msg::ZeroEntryPoint);
        }
    } else if !is_managed {
        match rva_to_off(out, headers, ep, 16) {
            None => {
                r.push(IntegritySeverity::Fatal, Msg::EntryUnmapped { rva: ep });
            }
            Some(off) => {
                let stub = &out[off as usize..off as usize + 16];
                if stub.iter().all(|&b| b == 0) {
                    // Warning: the entry maps and is executable, but its bytes
                    // were not recovered. That is the suspect signal for an
                    // already-chosen layout, not proof another layout is the
                    // right one.
                    r.push(IntegritySeverity::Warning, Msg::EntryAllZeros { rva: ep });
                } else if stub.iter().all(|&b| b == 0xCC) {
                    // 16 bytes of int3 padding where the entry stub should be:
                    // the stub region was never recovered, the loader walks
                    // straight into a debug-break wall. Same severity as a
                    // zeroed stub: the image is mapped, the bytes look unrestored.
                    r.push(IntegritySeverity::Warning, Msg::EntryAllInt3 { rva: ep });
                }
                // The entry must live in an executable section.
                let exec = secs.iter().any(|s| {
                    let span = s.virtual_size.max(s.raw_size);
                    ep >= s.virtual_address
                        && ep < s.virtual_address.wrapping_add(span)
                        && (s.characteristics & 0x2000_0000) != 0
                });
                if !exec {
                    r.push(
                        IntegritySeverity::Fatal,
                        Msg::EntryNotExecutable { rva: ep },
                    );
                }
                if let Some(entry_stub) = out.get(off as usize..off as usize + 18) {
                    check_common_entry_branches(entry_stub, ep, &secs, &mut r);
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
            match rva_to_off(out, headers, imp_rva, 20) {
                None => r.push(
                    IntegritySeverity::Fatal,
                    Msg::ImportDirectoryUnmapped { rva: imp_rva },
                ),
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
                        match rva_to_off(out, headers, name_rva, 1) {
                            None => r.push(
                                IntegritySeverity::Fatal,
                                Msg::ImportNameUnmapped {
                                    index: i,
                                    rva: name_rva,
                                },
                            ),
                            Some(noff) => {
                                if !looks_like_dll_name(out, noff) {
                                    // Warning: the name is inside the image, so
                                    // the directory is structurally present.
                                    // Unreadable bytes are the "left encrypted"
                                    // suspect signal, not an unmapped PE.
                                    r.push(
                                        IntegritySeverity::Warning,
                                        Msg::ImportNameUnreadable {
                                            index: i,
                                            rva: name_rva,
                                        },
                                    );
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
        match rva_to_off(out, headers, clr_rva, 0x48) {
            None => r.push(
                IntegritySeverity::Fatal,
                Msg::ClrDirectoryUnmapped { rva: clr_rva },
            ),
            Some(coff) => {
                let cb = rd_u32(out, coff).unwrap_or(0);
                if cb != 0x48 {
                    r.push(
                        IntegritySeverity::Fatal,
                        Msg::ClrHeaderBadSize {
                            rva: clr_rva,
                            size: cb,
                        },
                    );
                } else {
                    // MetaData RVA/size live at COR20 + 0x08 / + 0x0C.
                    let md_rva = rd_u32(out, coff.wrapping_add(8)).unwrap_or(0);
                    if md_rva != 0 {
                        match rva_to_off(out, headers, md_rva, 4) {
                            None => r.push(
                                IntegritySeverity::Fatal,
                                Msg::ClrMetadataUnmapped { rva: md_rva },
                            ),
                            Some(moff) => {
                                let sig = out.get(moff as usize..moff as usize + 4);
                                if sig != Some(b"BSJB") {
                                    r.push(
                                        IntegritySeverity::Fatal,
                                        Msg::ClrMetadataNoBsjb { rva: md_rva },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // --- Structural diagnostics --------------------------------------------
    // Everything below is advisory. These checks walk the directories the
    // loader or the CLR reads in order, and they only report a table that
    // cannot be walked from these bytes at all. They never decide whether a
    // layout candidate is acceptable: an image whose directories are intact
    // still need not run (see the module docs), and one that carries a
    // protected-but-present directory must not be rejected for it. Reporting
    // them as warnings keeps DLL layout selection and the golden outputs
    // exactly where they were.
    let mut diagnostics = Vec::new();
    let image = directories::Image {
        data: out,
        headers,
        sections: &secs,
        is64,
        image_base: headers.image_base,
        size_of_image,
    };
    if is_managed {
        if let Some(metadata) = clr_metadata(out, &image) {
            // The metadata walk formats one message per malformed stream, so
            // it gets a bounded sink like the directory walks.
            let mut findings = crate::findings::Findings::new(&mut diagnostics);
            clr::collect(&metadata, &mut findings);
            findings.finish();
        }
    } else {
        directories::collect(&image, &mut diagnostics);
    }
    for message in diagnostics {
        r.push(IntegritySeverity::Warning, message);
    }

    r
}

/// Locate the BSJB metadata blob of a managed image for the CLR diagnostics.
///
/// Returns `None` when the COR20 header or the blob itself does not resolve;
/// the fatal checks above already report that case, and there is nothing
/// further to enumerate.
fn clr_metadata<'a>(out: &'a [u8], image: &directories::Image<'_>) -> Option<clr::Metadata<'a>> {
    let (clr_rva, _) = senbei_pe::data_directory(out, image.headers, 14).ok()?;
    if clr_rva == 0 {
        return None;
    }
    let cor = image.file_range(clr_rva, 0x10)?;
    let md_rva = rd_u32(out, (cor.start as u32).saturating_add(8))?;
    let md_size = rd_u32(out, (cor.start as u32).saturating_add(12))?;
    if md_rva == 0 {
        return None;
    }
    // The blob's first four bytes must be backed by the file; its declared
    // size may legitimately exceed the file only if the CLR would refuse it,
    // which is exactly what the diagnostics report.
    let start = image.file_range(md_rva, 4)?.start;
    let available = out.len().saturating_sub(start);
    let len = usize::try_from(md_size).unwrap_or(available).min(available);
    Some(clr::Metadata {
        data: out,
        start,
        len,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn executable_text() -> Vec<Section> {
        vec![Section {
            virtual_address: 0x1000,
            virtual_size: 0x4000,
            raw_offset: 0x1000,
            raw_size: 0x4000,
            characteristics: 0x6000_0020,
        }]
    }

    #[test]
    fn common_entry_stub_rejects_out_of_image_branches() {
        let stub = [
            0x48, 0x83, 0xEC, 0x28, 0xE8, 0x5B, 0x02, 0x41, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xE9,
            0x7A, 0xFE, 0x54, 0xFF,
        ];
        let mut report = IntegrityReport::default();
        check_common_entry_branches(&stub, 0x1264, &executable_text(), &mut report);
        assert_eq!(report.issues.len(), 2);
    }

    #[test]
    fn common_entry_stub_accepts_executable_branches() {
        let stub = [
            0x48, 0x83, 0xEC, 0x28, 0xE8, 0x5B, 0x02, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x28, 0xE9,
            0x7A, 0xFE, 0xFF, 0xFF,
        ];
        let mut report = IntegrityReport::default();
        check_common_entry_branches(&stub, 0x1264, &executable_text(), &mut report);
        assert!(report.ok());
    }
}
