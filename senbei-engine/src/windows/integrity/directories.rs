//! Bounded structural diagnostics for PE data directories.
//!
//! Every function here reports *file-structure* problems only: a directory
//! entry that does not resolve inside the image, a table that runs past the
//! end of the file, an entry whose target is outside every mapped section.
//! Such a table cannot be walked by the Windows loader or by a disassembler,
//! which is a defect the output bytes themselves prove.
//!
//! It is **not** a statement about runtime behaviour. A clean report says the
//! tables are internally consistent; it does not say the code they describe
//! will run. Conversely a diagnostics entry means "this region could not be
//! walked from the output", not "the other layout would have been right".
//!
//! Callers must treat these findings as [`IntegritySeverity::Warning`]:
//!
//! * callback bytes are never inspected — a callback address is just a value,
//!   so the most that can be said structurally is "mapped, and executable";
//! * import *symbols* need not resolve to a local definition; the loader binds
//!   them from another module, so only the name RVA is checked;
//! * a delay-import document built with virtual addresses (legacy PE32) is
//!   reported but not treated as corruption.
//!
//! All reads are bounds-checked and every loop has a hard cap, so this module
//! never panics on a crafted image.

use super::Section;
use super::rd_u32;
use crate::findings::Findings;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Maximum import descriptors walked. Far beyond any real import table; the
/// cap only stops a corrupt, never-NUL table from walking on.
const MAX_IMPORT_DESCRIPTORS: u32 = 256;
/// Maximum thunks (IAT/INT entries) walked in one table.
const MAX_THUNKS: u32 = 65_536;
/// Maximum delay-load descriptors walked.
const MAX_DELAY_DESCRIPTORS: u32 = 256;
/// Maximum TLS callback slots walked.
const MAX_TLS_CALLBACKS: u32 = 1_024;
/// Maximum relocation blocks walked.
const MAX_RELOCATION_BLOCKS: u32 = 262_144;
/// Maximum exception directory entries inspected.
const MAX_EXCEPTION_ENTRIES: u32 = 1_000_000;
/// Maximum bound-import descriptors (plus their forwarder references).
const MAX_BOUND_ENTRIES: u32 = 256;
/// Longest import/export name accepted as "plausible".
const MAX_NAME: u32 = 512;
/// One unpacked PE image, resolved through its own headers.
///
/// Both the memory-image outputs (raw pointer == virtual address) and the
/// compacted disk outputs are supported, because the mapping is computed from
/// whatever the output declares.
pub(super) struct Image<'a> {
    pub(super) data: &'a [u8],
    pub(super) headers: senbei_pe::Headers,
    pub(super) sections: &'a [Section],
    pub(super) is64: bool,
    pub(super) image_base: u64,
    pub(super) size_of_image: u32,
}

impl Image<'_> {
    /// File offset backing a complete virtual range, if any. Rejects a
    /// section's zero-filled tail: a table that exists only in memory cannot
    /// be walked from the output file.
    ///
    /// This mirrors [`senbei_pe::rva_range`] exactly — the header region is
    /// used when the whole range is inside `SizeOfHeaders`, otherwise one
    /// section must back every byte — but resolves against the sections this
    /// image already holds. `rva_range` re-parses and allocates the whole
    /// section table per call, which a 65 Ki-entry thunk walk would turn into
    /// quadratic allocation over image size.
    pub(super) fn file_range(&self, rva: u32, size: u32) -> Option<std::ops::Range<usize>> {
        // `SizeOfHeaders` lives in the optional header; recomputing it costs
        // one read and no allocation, so it is not cached on the struct.
        let header_size = self
            .headers
            .pe_offset
            .checked_add(24)
            .and_then(|at| at.checked_add(60))
            .and_then(|at| u32::try_from(at).ok())
            .and_then(|at| rd_u32(self.data, at))
            .unwrap_or(0);
        let offset = if rva < header_size && size <= header_size - rva {
            rva
        } else {
            self.sections.iter().find_map(|section| {
                let delta = rva.checked_sub(section.virtual_address)?;
                // Only file-backed bytes count: `delta >= raw_size` is the
                // zero-filled tail and has no offset in the output.
                if delta >= section.raw_size || size > section.raw_size - delta {
                    return None;
                }
                section.raw_offset.checked_add(delta)
            })?
        };
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(size).ok()?)?;
        (end <= self.data.len()).then_some(start..end)
    }

    /// File offset backing a complete virtual range, if any.
    fn file_offset(&self, rva: u32, size: u32) -> Option<usize> {
        self.file_range(rva, size).map(|range| range.start)
    }

    /// True when `[rva, rva+size)` is inside the loader's virtual image: the
    /// header region, or one section's virtual extent. The bytes need not be
    /// backed by the file — a zero-filled tail is still mapped at runtime.
    pub(super) fn mapped(&self, rva: u32, size: u32) -> bool {
        let Some(end) = rva.checked_add(size) else {
            return false;
        };
        if end > self.size_of_image {
            return false;
        }
        let first_section = self
            .sections
            .iter()
            .map(|section| section.virtual_address)
            .min()
            .unwrap_or(u32::MAX);
        if end <= first_section {
            return true;
        }
        self.sections.iter().any(|section| {
            let span = section.virtual_size.max(section.raw_size);
            rva >= section.virtual_address
                && end
                    <= section
                        .virtual_address
                        .wrapping_add(span)
                        .min(self.size_of_image)
        })
    }

    /// True when the whole range lies in one executable section.
    pub(super) fn executable(&self, rva: u32, size: u32) -> bool {
        let Some(end) = rva.checked_add(size) else {
            return false;
        };
        self.sections.iter().any(|section| {
            let span = section.virtual_size.max(section.raw_size);
            (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
                && rva >= section.virtual_address
                && end <= section.virtual_address.wrapping_add(span)
        })
    }

    fn u16_at(&self, offset: usize) -> Option<u16> {
        let end = offset.checked_add(2)?;
        let bytes: [u8; 2] = self.data.get(offset..end)?.try_into().ok()?;
        Some(u16::from_le_bytes(bytes))
    }

    fn u32_at(&self, offset: usize) -> Option<u32> {
        let end = offset.checked_add(4)?;
        let bytes: [u8; 4] = self.data.get(offset..end)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn pointer_at(&self, offset: usize) -> Option<u64> {
        if self.is64 {
            let end = offset.checked_add(8)?;
            let bytes: [u8; 8] = self.data.get(offset..end)?.try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        } else {
            self.u32_at(offset).map(u64::from)
        }
    }

    fn thunk_size(&self) -> u32 {
        if self.is64 { 8 } else { 4 }
    }

    /// Read one thunk entry at a file offset.
    fn thunk_at(&self, offset: usize) -> Option<u64> {
        self.pointer_at(offset)
    }

    fn is_ordinal(&self, thunk: u64) -> bool {
        if self.is64 {
            thunk & IMAGE_ORDINAL_FLAG64 != 0
        } else {
            thunk & u64::from(IMAGE_ORDINAL_FLAG32) != 0
        }
    }

    /// Classify a named import's hint/name entry.
    ///
    /// `None` means the entry does not resolve to file bytes at all (a real
    /// structural defect); `Some(false)` means it resolves but is not a
    /// printable name — the "imports left encrypted" signal.
    fn import_name(&self, entry_rva: u32) -> Option<bool> {
        // A hint/name entry is a u16 ordinal followed by the name.
        let start = self.file_offset(entry_rva, 2)?.checked_add(2)?;
        self.classify_string(start)
    }

    /// Classify a plain NUL-terminated string at `rva`: same three-way result
    /// as [`Image::import_name`].
    fn printable_c_string(&self, rva: u32) -> Option<bool> {
        let start = self.file_offset(rva, 1)?;
        self.classify_string(start)
    }

    fn classify_string(&self, start: usize) -> Option<bool> {
        let limit = usize::try_from(MAX_NAME).unwrap_or(usize::MAX);
        let window = self
            .data
            .get(start..start.checked_add(limit)?.min(self.data.len()))?;
        let Some(nul) = window.iter().position(|&byte| byte == 0) else {
            return Some(false);
        };
        Some(nul != 0 && window[..nul].iter().all(|&b| (0x20..0x7F).contains(&b)))
    }

    /// Walk one thunk array, checking its framing and (optionally) its names.
    ///
    /// `check_names` must be false for an array that may be *bound*: a bound
    /// IAT holds already-resolved virtual addresses, not hint/name RVAs, so
    /// classifying those as names would report every import as corrupt.
    ///
    /// Returns the number of entries walked, or `None` when the array's first
    /// entry is not backed by the file.
    fn walk_thunks(
        &self,
        table_rva: u32,
        label: &str,
        check_names: bool,
        out: &mut Findings<'_>,
    ) -> Option<u32> {
        let start = self.file_offset(table_rva, self.thunk_size())?;
        let stride = self.thunk_size() as usize;
        let slots = self.data.len().saturating_sub(start) / stride;
        let limit = slots.min(MAX_THUNKS as usize);
        let mut count = 0_usize;
        let mut terminated = false;
        while count < limit {
            let Some(thunk) = self.thunk_at(start + count * stride) else {
                break;
            };
            if thunk == 0 {
                terminated = true;
                break;
            }
            // Once the sink is full, stop doing per-entry work: the findings
            // would be dropped anyway, and formatting them is the allocation
            // cost this walk exists to avoid.
            if check_names && out.wants_more() && !self.is_ordinal(thunk) {
                // Hint/name RVA is the low 31 bits of a by-name thunk.
                let name_rva = (thunk & 0x7FFF_FFFF) as u32;
                match self.import_name(name_rva) {
                    None => out.push(format!(
                        "{label} entry {count} name RVA 0x{name_rva:X} does not map into any file-backed section"
                    )),
                    Some(false) => out.push(format!(
                        "{label} entry {count} name RVA 0x{name_rva:X} is not a printable string (imports left encrypted?)"
                    )),
                    Some(true) => {}
                }
            }
            count += 1;
        }
        // A thunk array runs until its null terminator. Running out of slots
        // means the table reaches the end of the file (truncated); reaching the
        // cap means it is not terminated within any plausible table.
        if !terminated {
            out.push(if limit == MAX_THUNKS as usize {
                format!("{label} has no terminating null within {MAX_THUNKS} entries")
            } else {
                format!("{label} runs to the end of the file without a terminating null")
            });
        }
        Some(count as u32)
    }
}

/// `(rva, size)` of a data directory. Missing header bytes read as `(0, 0)`,
/// which every consumer treats as "directory absent" — matching the loader.
fn directory(image: &Image<'_>, index: u32) -> (u32, u32) {
    let base = image
        .headers
        .pe_offset
        .wrapping_add(24)
        .wrapping_add(if image.is64 { 112 } else { 96 });
    let Ok(base) = u32::try_from(base) else {
        return (0, 0);
    };
    let offset = base.saturating_add(index.saturating_mul(8));
    (
        rd_u32(image.data, offset).unwrap_or(0),
        rd_u32(image.data, offset.saturating_add(4)).unwrap_or(0),
    )
}

/// Collect every data-directory defect of a native image.
///
/// Managed assemblies are excluded by the caller: their import table is a CLR
/// bootstrap stub the native loader does not resolve the same way.
pub(super) fn collect(image: &Image<'_>, out: &mut Vec<String>) {
    // One bounded sink per directory: a corrupt table cannot flood the report,
    // and each directory that overflowed still says so.
    for check in [
        collect_imports as fn(&Image<'_>, &mut Findings<'_>),
        collect_delay_imports,
        collect_bound_imports,
        collect_iat,
        collect_tls,
        collect_relocations,
        collect_exception,
        collect_load_config,
    ] {
        let mut findings = Findings::new(out);
        check(image, &mut findings);
        findings.finish();
    }
}

fn collect_imports(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, _) = directory(image, 1);
    if rva == 0 {
        return;
    }
    // The existing fatal check already reports an unmapped import directory;
    // do not duplicate it here.
    let Some(range) = image.file_range(rva, 20) else {
        return;
    };
    let stride = 20usize;
    for index in 0..MAX_IMPORT_DESCRIPTORS {
        let Some(offset) = (index as usize)
            .checked_mul(stride)
            .and_then(|delta| range.start.checked_add(delta))
        else {
            return;
        };
        // The table is walked until its all-zero terminator; running out of
        // file inside it means the terminator is missing.
        if offset
            .checked_add(stride)
            .is_none_or(|end| end > image.data.len())
        {
            out.push(format!(
                "import directory runs past the end of the file before descriptor {index}"
            ));
            return;
        }
        let original_first_thunk = image.u32_at(offset).unwrap_or(0);
        let name_rva = image.u32_at(offset + 12).unwrap_or(0);
        let first_thunk = image.u32_at(offset + 16).unwrap_or(0);
        if name_rva == 0 {
            return;
        }
        if image.file_range(name_rva, 1).is_none() {
            // The fatal check already reports this per descriptor.
            continue;
        }
        // A bound image may omit OriginalFirstThunk; the loader then walks the
        // IAT itself. Either is a valid description of the imports.
        let table = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        if table == 0 {
            out.push(format!(
                "import descriptor {index} has neither OriginalFirstThunk nor FirstThunk"
            ));
            continue;
        }
        // Only a by-name lookup table carries hint/name RVAs. When the
        // descriptor has no OriginalFirstThunk, `table` is the IAT and the
        // image may be bound, so its entries are addresses, not names.
        let Some(by_name) = image.walk_thunks(
            table,
            &format!("import descriptor {index} lookup table"),
            original_first_thunk != 0,
            out,
        ) else {
            out.push(format!(
                "import descriptor {index} lookup table RVA 0x{table:X} does not map into any file-backed section"
            ));
            continue;
        };
        // When both arrays exist the loader treats them as parallel: it copies
        // the lookup table into the IAT, so a shorter IAT leaves imports
        // unresolved. Only the counts are compared; the contents legitimately
        // differ between an unbound and a bound image. The IAT is counted with
        // name classification off: when the image is bound its entries are
        // resolved addresses, not hint/name RVAs.
        if original_first_thunk != 0 && first_thunk != 0 {
            let mut ignored = out.silenced();
            if let Some(iat) = image.walk_thunks(
                first_thunk,
                &format!("import descriptor {index} IAT"),
                false,
                &mut ignored,
            ) && iat != by_name
            {
                out.push(format!(
                    "import descriptor {index} IAT holds {iat} entries but its lookup table holds {by_name}"
                ));
            }
        }
    }
    out.push(format!(
        "import directory has more than {MAX_IMPORT_DESCRIPTORS} descriptors (missing null terminator)"
    ));
}

fn collect_delay_imports(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, _) = directory(image, 13);
    if rva == 0 {
        return;
    }
    let Some(range) = image.file_range(rva, 32) else {
        out.push(format!(
            "delay-import directory RVA 0x{rva:X} does not map into any file-backed section"
        ));
        return;
    };
    let stride = 32usize;
    for index in 0..MAX_DELAY_DESCRIPTORS {
        let Some(offset) = (index as usize)
            .checked_mul(stride)
            .and_then(|delta| range.start.checked_add(delta))
        else {
            return;
        };
        if offset
            .checked_add(stride)
            .is_none_or(|end| end > image.data.len())
        {
            return;
        }
        let attributes = image.u32_at(offset).unwrap_or(0);
        let name_rva = image.u32_at(offset + 4).unwrap_or(0);
        if attributes == 0 && name_rva == 0 {
            return;
        }
        // Bit 0 says the descriptor's fields are RVAs. Old PE32 images link
        // them as virtual addresses instead; that is legal, but the values
        // cannot be resolved against this image without its load address.
        if attributes & 1 == 0 {
            out.push(format!(
                "delay-import descriptor {index} stores virtual addresses rather than RVAs (legacy form; not validated)"
            ));
            continue;
        }
        if name_rva != 0 {
            // The module name is a plain NUL-terminated string, not a
            // hint/name entry.
            match image.printable_c_string(name_rva) {
                None => out.push(format!(
                    "delay-import descriptor {index} module name RVA 0x{name_rva:X} does not map into any section"
                )),
                Some(false) => out.push(format!(
                    "delay-import descriptor {index} module name RVA 0x{name_rva:X} is not a printable string (left encrypted?)"
                )),
                Some(true) => {}
            }
        }
        let import_names = image.u32_at(offset + 16).unwrap_or(0);
        let import_addresses = image.u32_at(offset + 12).unwrap_or(0);
        let table = if import_names != 0 {
            import_names
        } else {
            import_addresses
        };
        if table == 0 {
            out.push(format!(
                "delay-import descriptor {index} has neither ImportNameTable nor ImportAddressTable"
            ));
            continue;
        }
        if image
            .walk_thunks(
                table,
                &format!("delay-import descriptor {index} name table"),
                true,
                out,
            )
            .is_none()
        {
            out.push(format!(
                "delay-import descriptor {index} name table RVA 0x{table:X} does not map into any file-backed section"
            ));
        }
    }
    out.push(format!(
        "delay-import directory has more than {MAX_DELAY_DESCRIPTORS} descriptors (missing null terminator)"
    ));
}

/// Bound imports (DD[11]): module names are offsets relative to the directory,
/// optionally followed by forwarder references. Unpackers commonly zero this
/// directory; when it survives, its names still has to resolve inside it.
fn collect_bound_imports(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, size) = directory(image, 11);
    if rva == 0 || size < 8 {
        return;
    }
    let Some(range) = image.file_range(rva, size) else {
        out.push(format!(
            "bound-import directory RVA 0x{rva:X} does not map into any file-backed section"
        ));
        return;
    };
    let dir_end = range.end;
    let mut offset = range.start;
    for _ in 0..MAX_BOUND_ENTRIES {
        if offset.checked_add(8).is_none_or(|end| end > dir_end) {
            return;
        }
        let stamp = image.u32_at(offset).unwrap_or(0);
        let flags = image.u32_at(offset + 4).unwrap_or(0);
        let name_offset = (flags & 0xFFFF) as usize;
        let forwarders = flags >> 16;
        if stamp == 0 && flags == 0 {
            return;
        }
        let Some(name_at) = range.start.checked_add(name_offset) else {
            return;
        };
        if name_at >= dir_end {
            out.push(format!(
                "bound-import module name offset 0x{name_offset:X} lies outside the directory"
            ));
        } else if image.u32_at(name_at).is_none() {
            out.push(format!(
                "bound-import module name at directory offset 0x{name_offset:X} is not backed by the file"
            ));
        }
        // Each descriptor is followed by `forwarders` 8-byte references.
        let advance = 8usize.saturating_add(forwarders as usize * 8);
        offset = offset.saturating_add(advance);
    }
    out.push(format!(
        "bound-import directory has more than {MAX_BOUND_ENTRIES} entries (missing null terminator)"
    ));
}

/// DD[12] is published by the loader as `IMAGE_DIRECTORY_ENTRY_IAT`, so it has
/// to resolve inside the image like any other directory.
fn collect_iat(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, size) = directory(image, 12);
    if rva == 0 {
        return;
    }
    if !image.mapped(rva, size.max(1)) {
        out.push(format!(
            "IAT directory RVA 0x{rva:X} (size 0x{size:X}) does not map into the image"
        ));
    }
}

fn collect_tls(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, size) = directory(image, 9);
    if rva == 0 {
        return;
    }
    // IMAGE_TLS_DIRECTORY64 is 40 bytes, the 32-bit form 24.
    let entry_size = if image.is64 { 40u32 } else { 24 };
    if size < entry_size {
        out.push(format!(
            "TLS directory size 0x{size:X} is smaller than the {entry_size}-byte header"
        ));
    }
    let Some(start) = image.file_offset(rva, entry_size) else {
        out.push(format!(
            "TLS directory RVA 0x{rva:X} does not map into any file-backed section"
        ));
        return;
    };
    // The TLS directory stores virtual addresses, not RVAs.
    let mut callbacks = 0_u64;
    for (name, offset) in [
        ("StartAddressOfRawData", 0usize),
        ("EndAddressOfRawData", 8),
        ("AddressOfIndex", 16),
        ("AddressOfCallBacks", 24),
    ] {
        let Some(value) = image.pointer_at(start.saturating_add(offset)) else {
            out.push(format!("TLS {name} field is truncated"));
            continue;
        };
        if value == 0 {
            continue;
        }
        let Some(rva) = value.checked_sub(image.image_base) else {
            out.push(format!(
                "TLS {name} 0x{value:X} lies below the image base 0x{:X}",
                image.image_base
            ));
            continue;
        };
        let Ok(rva) = u32::try_from(rva) else {
            continue;
        };
        if !image.mapped(rva, 1) {
            out.push(format!(
                "TLS {name} 0x{value:X} (RVA 0x{rva:X}) does not map into the image"
            ));
        }
        if name == "AddressOfCallBacks" {
            callbacks = u64::from(rva);
        }
    }
    if callbacks == 0 {
        return;
    }
    let Ok(array_rva) = u32::try_from(callbacks) else {
        return;
    };
    // A null-terminated array of virtual addresses. Their values are data:
    // "mapped and executable" is the strongest structural statement available.
    let stride = image.thunk_size() as usize;
    let Some(array_start) = image.file_offset(array_rva, image.thunk_size()) else {
        out.push("TLS callback array does not map into any file-backed section".to_owned());
        return;
    };
    let slots = image.data.len().saturating_sub(array_start) / stride;
    for slot in 0..slots.min(MAX_TLS_CALLBACKS as usize) {
        let Some(callback) = image.thunk_at(array_start + slot * stride) else {
            break;
        };
        if callback == 0 {
            return;
        }
        // Once the sink is full the remaining slots cannot add anything; stop
        // walking rather than formatting findings that would be dropped.
        if !out.wants_more() {
            return;
        }
        let Some(rva) = callback.checked_sub(image.image_base) else {
            out.push(format!(
                "TLS callback {slot} 0x{callback:X} lies below the image base 0x{:X}",
                image.image_base
            ));
            continue;
        };
        let Ok(rva) = u32::try_from(rva) else {
            continue;
        };
        if !image.mapped(rva, 1) {
            out.push(format!(
                "TLS callback {slot} 0x{callback:X} (RVA 0x{rva:X}) does not map into the image"
            ));
        } else if !image.executable(rva, 1) {
            out.push(format!(
                "TLS callback {slot} 0x{callback:X} (RVA 0x{rva:X}) is not in an executable section"
            ));
        }
    }
    out.push(format!(
        "TLS callback array has no null terminator within {MAX_TLS_CALLBACKS} entries"
    ));
}

/// Walk the base relocation directory and check every block's own framing.
///
/// Only the block header and the entry encoding are checked. The patched words
/// are not inspected: their post-relocation value depends on the load address.
fn collect_relocations(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, size) = directory(image, 5);
    if rva == 0 {
        return;
    }
    if size == 0 {
        out.push("base relocation directory has a zero size".to_owned());
        return;
    }
    let Some(range) = image.file_range(rva, size) else {
        out.push(format!(
            "base relocation directory RVA 0x{rva:X} (size 0x{size:X}) does not map into any file-backed section"
        ));
        return;
    };
    let mut offset = range.start;
    let mut blocks = 0_u32;
    while offset.checked_add(8).is_some_and(|end| end <= range.end) {
        let page = image.u32_at(offset).unwrap_or(0);
        let block_size = image.u32_at(offset + 4).unwrap_or(0);
        // A block is 8 header bytes plus an even number of 2-byte entries.
        if block_size < 8
            || !block_size.is_multiple_of(2)
            || offset
                .checked_add(block_size as usize)
                .is_none_or(|end| end > range.end)
        {
            out.push(format!(
                "relocation block {blocks} declares size 0x{block_size:X}, which does not fit the directory"
            ));
            return;
        }
        if !page.is_multiple_of(0x1000) {
            out.push(format!(
                "relocation block {blocks} page RVA 0x{page:X} is not 4 KiB aligned"
            ));
        }
        if page >= image.size_of_image {
            out.push(format!(
                "relocation block {blocks} page RVA 0x{page:X} lies beyond SizeOfImage 0x{:X}",
                image.size_of_image
            ));
        }
        let entries = (block_size - 8) / 2;
        for index in 0..entries {
            let Some(entry) = image.u16_at(offset + 8 + index as usize * 2) else {
                break;
            };
            let kind = u32::from(entry >> 12);
            // A block whose entries are all corrupt would otherwise produce one
            // message per entry; stop once the directory's sink is full.
            if !out.wants_more() {
                break;
            }
            // Types above IMAGE_REL_BASED_DIR64 (10) are undefined for the
            // AMD64/I386 loader; ABSOLUTE (0) is the NOP/padding type.
            if kind > 10 {
                out.push(format!(
                    "relocation block {blocks} entry {index} has unsupported type {kind}"
                ));
            } else if kind != 0
                && page.saturating_add(u32::from(entry & 0x0FFF)) >= image.size_of_image
            {
                out.push(format!(
                    "relocation block {blocks} entry {index} targets RVA 0x{:X} beyond SizeOfImage",
                    page.saturating_add(u32::from(entry & 0x0FFF))
                ));
            }
        }
        offset += block_size as usize;
        blocks += 1;
        if blocks >= MAX_RELOCATION_BLOCKS {
            out.push(format!(
                "relocation directory has more than {MAX_RELOCATION_BLOCKS} blocks"
            ));
            return;
        }
    }
    if offset != range.end {
        out.push(format!(
            "relocation directory has {} trailing byte(s) after the last block",
            range.end.saturating_sub(offset)
        ));
    }
}

/// Walk the exception (unwind) directory: every entry must describe a range
/// that lives inside the image.
fn collect_exception(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, size) = directory(image, 3);
    if rva == 0 || size == 0 {
        return;
    }
    // PE32+ uses RUNTIME_FUNCTION {begin, end, unwind} at 12 bytes; the x86
    // form has no unwind pointer and is 8 bytes.
    let entry_size = if image.is64 { 12u32 } else { 8 };
    if size % entry_size != 0 {
        out.push(format!(
            "exception directory size 0x{size:X} is not a multiple of the {entry_size}-byte entry size"
        ));
    }
    let usable = size - size % entry_size;
    let Some(start) = image.file_offset(rva, usable) else {
        out.push(format!(
            "exception directory RVA 0x{rva:X} (size 0x{size:X}) does not map into any file-backed section"
        ));
        return;
    };
    let count = (usable / entry_size).min(MAX_EXCEPTION_ENTRIES);
    for index in 0..count {
        if !out.wants_more() {
            return;
        }
        let offset = start + index as usize * entry_size as usize;
        let begin = image.u32_at(offset).unwrap_or(0);
        let end = image.u32_at(offset + 4).unwrap_or(0);
        if begin >= end {
            out.push(format!(
                "exception entry {index} has begin RVA 0x{begin:X} >= end RVA 0x{end:X}"
            ));
            continue;
        }
        if !image.mapped(begin, 1) {
            out.push(format!(
                "exception entry {index} begin RVA 0x{begin:X} does not map into the image"
            ));
        }
        if !image.mapped(end - 1, 1) {
            out.push(format!(
                "exception entry {index} end RVA 0x{end:X} does not map into the image"
            ));
        }
        if image.is64 {
            let unwind = image.u32_at(offset + 8).unwrap_or(0);
            // The low two bits are flags, not part of the RVA.
            if unwind != 0 && !image.mapped(unwind & !3, 1) {
                out.push(format!(
                    "exception entry {index} unwind info RVA 0x{unwind:X} does not map into the image"
                ));
            }
        }
    }
}

/// Check the load-configuration directory's own pointers.
///
/// The security cookie and the guard CF function table are the two fields the
/// loader reads during process start; both are virtual addresses.
fn collect_load_config(image: &Image<'_>, out: &mut Findings<'_>) {
    let (rva, size) = directory(image, 10);
    if rva == 0 || size == 0 {
        return;
    }
    // The security cookie sits at +0x58 (PE32+) / +0x3C (PE32), the guard CF
    // function table at +0x70 / +0x48.
    let (cookie_offset, guard_offset, minimum) = if image.is64 {
        (0x58usize, 0x70usize, 0x70u32)
    } else {
        (0x3C, 0x48, 0x40)
    };
    if size < minimum {
        out.push(format!(
            "load-config directory size 0x{size:X} is smaller than the 0x{minimum:X} header the loader reads"
        ));
    }
    let readable = minimum.min(size);
    let Some(start) = image.file_offset(rva, readable) else {
        out.push(format!(
            "load-config directory RVA 0x{rva:X} does not map into any file-backed section"
        ));
        return;
    };
    for (name, offset) in [
        ("security cookie", cookie_offset),
        ("guard CF function table", guard_offset),
    ] {
        if (offset as u32).saturating_add(image.thunk_size()) > readable {
            // Field lies beyond the declared size; nothing to check.
            continue;
        }
        let Some(value) = image.pointer_at(start + offset) else {
            continue;
        };
        if value == 0 {
            continue;
        }
        let Some(rva) = value.checked_sub(image.image_base) else {
            out.push(format!(
                "load-config {name} 0x{value:X} lies below the image base 0x{:X}",
                image.image_base
            ));
            continue;
        };
        let Ok(rva) = u32::try_from(rva) else {
            continue;
        };
        if !image.mapped(rva, 1) {
            out.push(format!(
                "load-config {name} 0x{value:X} (RVA 0x{rva:X}) does not map into the image"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    // Synthetic-image coverage lives next to the module that builds those
    // images (`super::tests`), so these unit tests stay about the helpers.
    use super::*;

    /// Section table offset used by the synthetic images below. The fixtures
    /// carry a real section table so the offset translation has something to
    /// resolve against.
    const SECTIONS_AT: usize = 0x100;
    const HEADERS_SIZE: u32 = 0x400;

    fn headers() -> senbei_pe::Headers {
        senbei_pe::Headers {
            pe_offset: 0,
            is_pe32_plus: true,
            image_base: 0,
            size_of_image: 0x2000,
            entry_rva: 0x1000,
            sections_offset: SECTIONS_AT,
            sections: 1,
        }
    }

    fn text_section() -> Section {
        Section {
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_offset: 0x1000,
            raw_size: 0x1000,
            characteristics: 0x6000_0020,
        }
    }

    /// A file image whose one `.text` section is at RVA 0x1000 -> offset 0x1000.
    fn image_data() -> Vec<u8> {
        const SIZE: usize = 0x2000;
        let mut data = vec![0_u8; SIZE];
        // SizeOfHeaders, at optional-header +60 for a PE32+ layout based at 0.
        data[24 + 60..24 + 64].copy_from_slice(&HEADERS_SIZE.to_le_bytes());
        for (offset, value) in [
            (8usize, 0x1000u32), // VirtualSize
            (12, 0x1000),        // VirtualAddress
            (16, 0x1000),        // SizeOfRawData
            (20, 0x1000),        // PointerToRawData
            (36, 0x6000_0020),   // Characteristics: executable, readable
        ] {
            let at = SECTIONS_AT + offset;
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    #[test]
    fn thunk_width_and_ordinal_flag_follow_the_optional_header() {
        let data = [0_u8; 8];
        let sections = [text_section()];
        let wide = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: true,
            image_base: 0,
            size_of_image: 0x2000,
        };
        let narrow = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: false,
            image_base: 0,
            size_of_image: 0x2000,
        };
        assert_eq!(wide.thunk_size(), 8);
        assert_eq!(narrow.thunk_size(), 4);
        assert!(narrow.is_ordinal(u64::from(0x8000_0000_u32)));
        assert!(!narrow.is_ordinal(u64::from(0x7FFF_FFFF_u32)));
        assert!(wide.is_ordinal(0x8000_0000_0000_0000));
        assert!(!wide.is_ordinal(0x0000_0000_FFFF_FFFF));
    }

    #[test]
    fn mapped_rejects_ranges_outside_the_image() {
        let sections = [text_section()];
        let data = image_data();
        let image = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: true,
            image_base: 0,
            size_of_image: 0x2000,
        };
        assert!(image.mapped(0, 0x100));
        assert!(image.mapped(0x1000, 0x1000));
        assert!(
            !image.mapped(0x1FFF, 2),
            "a range may not cross SizeOfImage"
        );
        assert!(
            !image.mapped(u32::MAX, 2),
            "an overflowing range is unmapped"
        );
        assert!(
            !image.mapped(0xF00, 0x200),
            "a range stays inside one section"
        );
        assert!(image.executable(0x1000, 1));
        assert!(!image.executable(0x0800, 1), "headers are not executable");
    }

    #[test]
    fn named_thunk_whose_target_is_unmapped_is_reported() {
        // Slot 0 names RVA 0x9000 — outside every section, so the hint/name
        // entry cannot be read at all.
        let mut data = image_data();
        data[0x1000..0x1008].copy_from_slice(&0x9000_u64.to_le_bytes());
        let sections = [text_section()];
        let image = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: true,
            image_base: 0,
            size_of_image: 0x2000,
        };
        let mut out = Vec::new();
        assert_eq!(
            image.walk_thunks(0x1000, "test table", true, &mut Findings::new(&mut out)),
            Some(1)
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("does not map"), "{out:?}");
    }

    #[test]
    fn thunk_whose_name_is_not_printable_is_reported_once() {
        // Slot 0 names RVA 0x1010, whose hint/name bytes are zeroes: mapped,
        // but not a name. That is the "left encrypted" signal.
        let mut data = image_data();
        data[0x1000..0x1008].copy_from_slice(&0x1010_u64.to_le_bytes());
        let sections = [text_section()];
        let image = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: true,
            image_base: 0,
            size_of_image: 0x2000,
        };
        let mut out = Vec::new();
        assert_eq!(
            image.walk_thunks(0x1000, "test table", true, &mut Findings::new(&mut out)),
            Some(1)
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("not a printable string"), "{out:?}");
    }

    #[test]
    fn thunk_table_running_to_the_file_end_is_reported() {
        // Every slot names the same valid string and none is null, so the walk
        // stops only because the file ended: a truncated table has to be said
        // out loud rather than pass as terminated.
        let mut data = image_data();
        // A valid hint/name entry in the header region (RVA 0x200: hint 0,
        // then "f\0"), so every named entry resolves to a printable name.
        data[0x200..0x204].copy_from_slice(&[0x00, 0x00, b'f', 0x00]);
        for slot in 0..(data.len() - 0x1000) / 8 {
            let at = 0x1000 + slot * 8;
            data[at..at + 8].copy_from_slice(&0x200_u64.to_le_bytes());
        }
        let sections = [text_section()];
        let image = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: true,
            image_base: 0,
            size_of_image: 0x2000,
        };
        let mut out = Vec::new();
        let walked = image.walk_thunks(0x1000, "test table", true, &mut Findings::new(&mut out));
        assert!(walked.is_some());
        assert!(
            out.iter()
                .any(|message| message.contains("without a terminating null")),
            "{out:?}"
        );
        assert!(
            !out.iter()
                .any(|message| message.contains("not a printable")),
            "every named entry is valid here, got {out:?}"
        );
    }

    #[test]
    fn cached_file_mapping_matches_senbei_pe_rva_range() {
        // The cached-sections mapping must agree with the format crate for the
        // header region, a section interior, the zero-fill tail, and overflow.
        let mut data = image_data();
        // Give `.text` a memory extent past its file bytes (the zero tail).
        let at = SECTIONS_AT + 8;
        data[at..at + 4].copy_from_slice(&0x1800u32.to_le_bytes()); // VirtualSize
        let sections = [text_section()];
        let image = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: true,
            image_base: 0,
            size_of_image: 0x2000,
        };
        for (rva, size) in [
            (0x100u32, 0x100u32), // header region
            (0x1000, 0x100),      // section interior
            (0x1F00, 0x100),      // last file-backed bytes of `.text`
            (0x1FF0, 0x20),       // runs into the zero-filled tail
            (0x2000, 1),          // past `SizeOfRawData`
            (0x0800, 0x100),      // header region past `SizeOfHeaders`
            (u32::MAX, 4),        // offset overflow
            (0x1000, 0),          // zero length at a valid start
        ] {
            let want = senbei_pe::rva_range(&data, headers(), rva, size)
                .ok()
                .map(|range| range.start);
            assert_eq!(
                image.file_offset(rva, size),
                want,
                "mapping of RVA 0x{rva:X} + 0x{size:X} disagrees with senbei_pe"
            );
        }
    }

    #[test]
    fn unbacked_thunk_table_returns_none() {
        let data = image_data();
        let sections = [text_section()];
        let image = Image {
            data: &data,
            headers: headers(),
            sections: &sections,
            is64: true,
            image_base: 0,
            size_of_image: 0x2000,
        };
        let mut out = Vec::new();
        assert_eq!(
            image.walk_thunks(0x9000, "test table", true, &mut Findings::new(&mut out)),
            None
        );
        assert!(out.is_empty());
    }
}
