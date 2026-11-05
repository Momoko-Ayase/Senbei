//! Bounded structural diagnostics for a restored AArch64 ELF.
//!
//! The restore pipeline already rejects a result whose tables do not match the
//! materialization report, whose required sections are absent, or whose
//! protector artefacts (the `SHT_LOUSER` private section, the protector entry
//! point) survive. This module adds the cross-table invariants that a dynamic
//! linker or a disassembler relies on, and that a partially applied fixup
//! container breaks first:
//!
//! * `PT_LOAD` mapping: alignment, file-vs-memory size, file backing, flag
//!   agreement with the allocated sections it covers, and no overlaps;
//! * `DT_*` agreement: the tags that describe a table must point at that
//!   table's own section, with that section's size;
//! * relocation records: an allowed type for its table, an in-image target,
//!   and a symbol index inside the dynamic symbol table;
//! * the symbol hash table: bucket and chain counts that agree with
//!   `.dynsym`, so a lookup cannot run off its own table;
//! * `.init_array` / `.fini_array`: whole-pointer sizes, tags that agree with
//!   the sections, and a non-zero constructor value that lands in the image.
//!
//! These are *structure* checks. They say a linker could walk the tables; they
//! do not say the library initializes or resolves correctly. In particular the
//! bytes a constructor points at are never inspected, and an undefined symbol
//! is never required to have a local definition — that resolution belongs to
//! the dynamic linker and lives outside the file.
//!
//! Every read is bounds-checked and every loop is capped, so this never panics
//! on a crafted or truncated image.

use crate::findings::Findings;
use senbei_elf::{
    ELF64_RELA_SIZE, ELF64_SYMBOL_SIZE, ElfLayout, SHT_NOBITS, SectionHeader, read_u32, read_u64,
};

/// AArch64 relocation kinds a restored image may carry in its dynamic tables.
const R_AARCH64_ABS64: u32 = 0x101;
const R_AARCH64_GLOB_DAT: u32 = 0x401;
const R_AARCH64_JUMP_SLOT: u32 = 0x402;
const R_AARCH64_RELATIVE: u32 = 0x403;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

const DT_PLTRELSZ: u64 = 2;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_STRSZ: u64 = 10;
const DT_JMPREL: u64 = 23;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_GNU_HASH: u64 = 0x6FFF_FEF5;
const DT_VERSYM: u64 = 0x6FFF_FFF0;
const DT_RELACOUNT: u64 = 0x6FFF_FFF9;
const DT_VERNEED: u64 = 0x6FFF_FFFE;

/// Maximum records walked in one relocation table.
const MAX_RELOCATIONS: u64 = 4_000_000;
/// Maximum dynamic table entries inspected.
const MAX_DYNAMIC_ENTRIES: u64 = 4_096;
/// Maximum constructor slots walked.
const MAX_ARRAY_SLOTS: u64 = 4_096;
/// Maximum GNU-hash buckets inspected. A real image's bucket count is a
/// power of two far below this; the cap only bounds a crafted header.
const MAX_HASH_BUCKETS: u32 = 1 << 20;

/// One loadable segment, as the kernel would map it.
#[derive(Debug, Clone, Copy)]
struct Segment {
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    flags: u32,
    alignment: u64,
}

impl Segment {
    fn file_end(&self) -> Option<u64> {
        self.offset.checked_add(self.file_size)
    }

    fn memory_end(&self) -> Option<u64> {
        self.virtual_address.checked_add(self.memory_size)
    }

    fn contains(&self, address: u64, size: u64) -> bool {
        self.virtual_address <= address
            && address
                .checked_add(size)
                .is_some_and(|end| end <= self.virtual_address.saturating_add(self.memory_size))
    }

    /// File offset for an address in this segment, if the bytes are backed.
    fn file_offset(&self, address: u64, size: u64) -> Option<u64> {
        let end = address.checked_add(size)?;
        if address < self.virtual_address
            || end > self.virtual_address.checked_add(self.file_size)?
        {
            return None;
        }
        self.offset
            .checked_add(address.checked_sub(self.virtual_address)?)
    }
}

/// One restored image, in the terms the checks need.
struct View<'a> {
    data: &'a [u8],
    segments: Vec<Segment>,
    sections: Vec<SectionHeader>,
    names: Vec<String>,
}

impl View<'_> {
    fn segment_for(&self, address: u64, size: u64) -> Option<Segment> {
        self.segments
            .iter()
            .copied()
            .find(|segment| segment.contains(address, size))
    }

    /// File offset backing `[address, address+size)`, when a segment covers it
    /// and the file actually holds the bytes (not just `p_memsz` shadow).
    fn offset_of(&self, address: u64, size: u64) -> Option<usize> {
        let offset = self
            .segments
            .iter()
            .find_map(|segment| segment.file_offset(address, size))?;
        usize::try_from(offset).ok()
    }

    /// The single section with this name; `None` when absent or duplicated.
    /// Duplicates are reported by the caller's required-section lookup.
    fn section(&self, name: &str) -> Option<&SectionHeader> {
        let mut found = None;
        for (index, section_name) in self.names.iter().enumerate() {
            if section_name == name {
                if found.is_some() {
                    return None;
                }
                found = self.sections.get(index);
            }
        }
        found
    }
}

/// Collect every structural defect of a restored image.
///
/// An empty `out` means the tables are internally consistent. It does not mean
/// the library loads: see the module docs.
///
/// This never fails and never panics. It reports what it cannot parse as a
/// diagnostic instead of an error, so adding it to the pipeline cannot turn a
/// restore that previously succeeded into a failure.
pub(super) fn collect(data: &[u8], layout: &ElfLayout, out: &mut Vec<String>) {
    let mut segments = Vec::new();
    for index in 0..layout.program_header_count {
        let Some(offset) = index
            .checked_mul(layout.program_header_size)
            .and_then(|delta| layout.program_header_offset.checked_add(delta))
        else {
            out.push("ELF program header table offset overflows".to_owned());
            return;
        };
        let kind = match read_u32(data, offset) {
            Ok(kind) => kind,
            Err(_) => {
                out.push(format!(
                    "ELF program header {index} is not backed by the file"
                ));
                return;
            }
        };
        if kind != PT_LOAD {
            continue;
        }
        let (
            Ok(flags),
            Ok(file_offset),
            Ok(address),
            Ok(file_size),
            Ok(memory_size),
            Ok(alignment),
        ) = (
            read_u32(data, offset + 4),
            read_u64(data, offset + 8),
            read_u64(data, offset + 0x10),
            read_u64(data, offset + 0x20),
            read_u64(data, offset + 0x28),
            read_u64(data, offset + 0x30),
        )
        else {
            out.push(format!("PT_LOAD {index} is truncated"));
            continue;
        };
        segments.push(Segment {
            offset: file_offset,
            virtual_address: address,
            file_size,
            memory_size,
            flags,
            alignment,
        });
    }
    if segments.is_empty() {
        out.push("restored ELF has no PT_LOAD segment".to_owned());
        return;
    }
    // Section names come from the ELF's own string table. A table that does not
    // resolve is reported as a diagnostic and stops the name-dependent checks;
    // it is not a restore error here.
    let names = match layout.section_names(data) {
        Ok(names) => names,
        Err(error) => {
            out.push(format!("section-name table is unreadable: {error}"));
            return;
        }
    };
    let view = View {
        data,
        segments,
        sections: layout.section_headers.clone(),
        names,
    };
    // One bounded sink per table group: a table whose every row is corrupt
    // cannot flood the report or the allocator, and each group that overflowed
    // still says so. The segment invariants are checked even when the dynamic
    // table is absent or unreadable.
    let mut findings = Findings::new(out);
    check_segments(&view, &mut findings);
    findings.finish();

    let dynamic = dynamic_entries(&view);
    if dynamic.is_empty() {
        return;
    }
    for check in [
        check_dynamic as fn(&View<'_>, &[(u64, u64)], &mut Findings<'_>),
        check_arrays,
    ] {
        let mut findings = Findings::new(out);
        check(&view, &dynamic, &mut findings);
        findings.finish();
    }
    let mut findings = Findings::new(out);
    check_relocations(&view, &mut findings);
    findings.finish();
    let mut findings = Findings::new(out);
    check_hashes(&view, &mut findings);
    findings.finish();
}

fn check_segments(view: &View<'_>, out: &mut Findings<'_>) {
    let file_len = view.data.len() as u64;
    for (index, segment) in view.segments.iter().enumerate() {
        if segment.alignment != 0 && !segment.alignment.is_power_of_two() {
            out.push(format!(
                "PT_LOAD {index} alignment 0x{:X} is not a power of two",
                segment.alignment
            ));
        }
        // The loader requires p_offset and p_vaddr to be congruent modulo the
        // page alignment; otherwise the mapping cannot be established.
        if segment.alignment > 1
            && segment.offset % segment.alignment != segment.virtual_address % segment.alignment
        {
            out.push(format!(
                "PT_LOAD {index} file offset and virtual address are not congruent modulo 0x{:X}",
                segment.alignment
            ));
        }
        if segment.file_size > segment.memory_size {
            out.push(format!(
                "PT_LOAD {index} has p_filesz 0x{:X} greater than p_memsz 0x{:X}",
                segment.file_size, segment.memory_size
            ));
        }
        if segment.file_end().is_none_or(|end| end > file_len) {
            out.push(format!(
                "PT_LOAD {index} file range exceeds the file size 0x{file_len:X}"
            ));
        }
        if segment.memory_end().is_none() {
            out.push(format!("PT_LOAD {index} memory range overflows"));
        }
        if segment.flags & PF_R == 0 {
            out.push(format!("PT_LOAD {index} is not readable"));
        }
    }

    // Sorted by address the mappings must not overlap: two segments covering
    // one page is a link-time error, so an output that has it cannot describe
    // the image it came from.
    let mut sorted = view.segments.clone();
    sorted.sort_by_key(|segment| segment.virtual_address);
    for pair in sorted.windows(2) {
        let (previous, next) = (pair[0], pair[1]);
        if let Some(end) = previous.memory_end()
            && end > next.virtual_address
        {
            out.push(format!(
                "PT_LOAD segments overlap: [0x{:X}..0x{end:X}) and [0x{:X}..)",
                previous.virtual_address, next.virtual_address
            ));
        }
    }

    // Every allocated section with file contents must be reachable through a
    // segment that grants the section's own permissions — otherwise the
    // dynamic linker's page protections disagree with what the fixups write.
    for (index, section) in view.sections.iter().enumerate() {
        if section.section_type == SHT_NOBITS
            || section.section_type == 0
            || section.flags & SHF_ALLOC == 0
            || section.size == 0
        {
            continue;
        }
        let Some(segment) = view.segment_for(section.address, section.size) else {
            out.push(format!(
                "allocated section {index} [0x{:X}..0x{:X}) is not covered by any PT_LOAD",
                section.address,
                section.address.saturating_add(section.size)
            ));
            continue;
        };
        if segment.flags & PF_R == 0 {
            out.push(format!(
                "allocated section {index} lies in a non-readable PT_LOAD"
            ));
        }
        if section.flags & SHF_WRITE != 0 && segment.flags & PF_W == 0 {
            out.push(format!(
                "writable section {index} lies in a read-only PT_LOAD"
            ));
        }
        if section.flags & SHF_EXECINSTR != 0 && segment.flags & PF_X == 0 {
            out.push(format!(
                "executable section {index} lies in a non-executable PT_LOAD"
            ));
        }
        if view.offset_of(section.address, section.size).is_none() {
            out.push(format!(
                "allocated section {index} has no file bytes behind its address range"
            ));
        }
    }
}

/// The dynamic table as `(tag, value)` pairs, up to the null entry.
fn dynamic_entries(view: &View<'_>) -> Vec<(u64, u64)> {
    let Some(dynamic) = view.section(".dynamic") else {
        return Vec::new();
    };
    let Some(start) = view.offset_of(dynamic.address, 0) else {
        return Vec::new();
    };
    let count = (dynamic.size / 16).min(MAX_DYNAMIC_ENTRIES);
    let mut entries = Vec::new();
    for index in 0..count {
        let Some(offset) = index
            .checked_mul(16)
            .and_then(|delta| u64::try_from(start).ok()?.checked_add(delta))
        else {
            break;
        };
        let Ok(offset) = usize::try_from(offset) else {
            break;
        };
        let (Ok(tag), Ok(value)) = (read_u64(view.data, offset), read_u64(view.data, offset + 8))
        else {
            break;
        };
        if tag == 0 {
            break;
        }
        entries.push((tag, value));
    }
    entries
}

fn single_tag(
    entries: &[(u64, u64)],
    tag: u64,
    label: &str,
    out: &mut Findings<'_>,
) -> Option<u64> {
    let values: Vec<u64> = entries
        .iter()
        .filter_map(|&(entry_tag, value)| (entry_tag == tag).then_some(value))
        .collect();
    match values.as_slice() {
        [] => None,
        [value] => Some(*value),
        _ => {
            out.push(format!("{label} (tag 0x{tag:X}) appears more than once"));
            Some(values[0])
        }
    }
}

fn check_dynamic(view: &View<'_>, entries: &[(u64, u64)], out: &mut Findings<'_>) {
    for (tag, name, size_tag) in [
        (DT_SYMTAB, ".dynsym", None),
        (DT_STRTAB, ".dynstr", Some(DT_STRSZ)),
        (DT_RELA, ".rela.dyn", Some(DT_RELASZ)),
        (DT_JMPREL, ".rela.plt", Some(DT_PLTRELSZ)),
        (DT_VERSYM, ".gnu.version", None),
        (DT_VERNEED, ".gnu.version_r", None),
        (DT_GNU_HASH, ".gnu.hash", None),
        (DT_HASH, ".hash", None),
    ] {
        let Some(value) = single_tag(entries, tag, name, out) else {
            continue;
        };
        // A tag naming a section this image does not have is only reported for
        // the tags whose section is mandatory; the hash tags are optional, and
        // the required-section lookup has already rejected a missing core
        // table before this runs.
        let Some(section) = view.section(name) else {
            continue;
        };
        if value != section.address {
            out.push(format!(
                "tag 0x{tag:X} points at 0x{value:X} but {name} starts at 0x{:X}",
                section.address
            ));
        }
        if let Some(size_tag) = size_tag
            && let Some(size) = single_tag(entries, size_tag, name, out)
            && size != section.size
        {
            out.push(format!(
                "tag 0x{size_tag:X} declares 0x{size:X} bytes but {name} is 0x{:X} bytes",
                section.size
            ));
        }
    }

    // DT_RELACOUNT promises the first N records of .rela.dyn are
    // R_AARCH64_RELATIVE, which lets the linker skip the whole prefix.
    let Some(count) = single_tag(entries, DT_RELACOUNT, "DT_RELACOUNT", out) else {
        return;
    };
    let Some(rela_dyn) = view.section(".rela.dyn") else {
        return;
    };
    let total = rela_dyn.size / ELF64_RELA_SIZE as u64;
    if count > total {
        out.push(format!(
            "DT_RELACOUNT {count} exceeds the {total} records in .rela.dyn"
        ));
        return;
    }
    for index in 0..count.min(MAX_RELOCATIONS) {
        let Some(record) = read_relocation(view, *rela_dyn, index, ".rela.dyn", out) else {
            return;
        };
        if record.kind != R_AARCH64_RELATIVE {
            out.push(format!(
                "DT_RELACOUNT prefix record {index} has type 0x{:X}, not R_AARCH64_RELATIVE",
                record.kind
            ));
            return;
        }
    }
}

struct Relocation {
    offset: u64,
    kind: u32,
    symbol: u32,
}

fn read_relocation(
    view: &View<'_>,
    section: SectionHeader,
    index: u64,
    label: &str,
    out: &mut Findings<'_>,
) -> Option<Relocation> {
    let base = view.offset_of(section.address, section.size)?;
    let offset = index
        .checked_mul(ELF64_RELA_SIZE as u64)
        .and_then(|delta| usize::try_from(delta).ok())
        .and_then(|delta| base.checked_add(delta))?;
    let (Ok(target), Ok(info)) = (read_u64(view.data, offset), read_u64(view.data, offset + 8))
    else {
        out.push(format!("{label} record {index} is not backed by the file"));
        return None;
    };
    Some(Relocation {
        offset: target,
        kind: info as u32,
        symbol: u32::try_from(info >> 32).unwrap_or(u32::MAX),
    })
}

fn check_relocations(view: &View<'_>, out: &mut Findings<'_>) {
    let symbol_count = view
        .section(".dynsym")
        .map(|section| section.size / ELF64_SYMBOL_SIZE as u64)
        .unwrap_or(0);
    for (name, allowed) in [
        (
            ".rela.dyn",
            &[R_AARCH64_RELATIVE, R_AARCH64_GLOB_DAT, R_AARCH64_ABS64][..],
        ),
        (".rela.plt", &[R_AARCH64_JUMP_SLOT, R_AARCH64_RELATIVE][..]),
    ] {
        let Some(section) = view.section(name) else {
            continue;
        };
        if section.entry_size != 0 && section.entry_size != ELF64_RELA_SIZE as u64 {
            out.push(format!(
                "{name} entry size is 0x{:X}, expected 0x{ELF64_RELA_SIZE:X}",
                section.entry_size
            ));
        }
        let count = section.size / ELF64_RELA_SIZE as u64;
        for index in 0..count.min(MAX_RELOCATIONS) {
            let Some(record) = read_relocation(view, *section, index, name, out) else {
                return;
            };
            if !allowed.contains(&record.kind) {
                out.push(format!(
                    "{name} record {index} has type 0x{:X}, which this table cannot carry",
                    record.kind
                ));
            }
            // The target is a virtual address a fixup writes to, so it must be
            // inside a PT_LOAD. Whether the page is writable at that moment is
            // the linker's business (RELRO relaxes it), so it is not checked.
            if view.segment_for(record.offset, 8).is_none() {
                out.push(format!(
                    "{name} record {index} targets 0x{:X}, which no PT_LOAD maps",
                    record.offset
                ));
            }
            if record.kind == R_AARCH64_RELATIVE {
                if record.symbol != 0 {
                    out.push(format!(
                        "{name} record {index} is R_AARCH64_RELATIVE but names symbol {}",
                        record.symbol
                    ));
                }
            } else if u64::from(record.symbol) >= symbol_count {
                // A named relocation must index a real dynamic symbol. The
                // symbol itself may stay undefined: the dynamic linker resolves
                // it from another module, which is not this file's business.
                out.push(format!(
                    "{name} record {index} references symbol {} outside the {symbol_count}-entry .dynsym",
                    record.symbol
                ));
            }
        }
    }
}

fn check_hashes(view: &View<'_>, out: &mut Findings<'_>) {
    let symbol_count = view
        .section(".dynsym")
        .map(|section| section.size / ELF64_SYMBOL_SIZE as u64)
        .unwrap_or(0);

    if let Some(hash) = view.section(".hash")
        && let Some(start) = view.offset_of(hash.address, hash.size)
    {
        {
            let (Ok(buckets), Ok(chains)) =
                (read_u32(view.data, start), read_u32(view.data, start + 4))
            else {
                out.push(".hash header is truncated".to_owned());
                return;
            };
            // The SysV layout is nbucket, nchain, buckets[], chains[]. nchain
            // must equal the symbol count or a chain walk leaves the table.
            if u64::from(chains) != symbol_count {
                out.push(format!(
                    ".hash nchain {chains} does not match the {symbol_count}-entry .dynsym"
                ));
            }
            let required = 8u64
                .saturating_add(u64::from(buckets).saturating_mul(4))
                .saturating_add(u64::from(chains).saturating_mul(4));
            if required > hash.size {
                out.push(format!(
                    ".hash needs 0x{required:X} bytes for its buckets and chains but declares 0x{:X}",
                    hash.size
                ));
            }
        }
    }

    let Some(hash) = view.section(".gnu.hash") else {
        return;
    };
    let Some(start) = view.offset_of(hash.address, hash.size) else {
        return;
    };
    let (Ok(buckets), Ok(symoffset), Ok(bloom_size), Ok(bloom_shift)) = (
        read_u32(view.data, start),
        read_u32(view.data, start + 4),
        read_u32(view.data, start + 8),
        read_u32(view.data, start + 12),
    ) else {
        out.push(".gnu.hash header is truncated".to_owned());
        return;
    };
    if buckets == 0 || !buckets.is_power_of_two() {
        out.push(format!(
            ".gnu.hash bucket count {buckets} is not a power of two"
        ));
    }
    if bloom_size == 0 || !bloom_size.is_power_of_two() {
        out.push(format!(
            ".gnu.hash bloom size {bloom_size} is not a power of two"
        ));
    }
    if bloom_shift >= 64 {
        out.push(format!(
            ".gnu.hash bloom shift {bloom_shift} is not below the word size"
        ));
    }
    let header = 16u64
        .saturating_add(u64::from(bloom_size).saturating_mul(8))
        .saturating_add(u64::from(buckets).saturating_mul(4));
    if header > hash.size {
        out.push(format!(
            ".gnu.hash needs 0x{header:X} bytes for its header and buckets but declares 0x{:X}",
            hash.size
        ));
        return;
    }
    if u64::from(symoffset) > symbol_count {
        out.push(format!(
            ".gnu.hash symoffset {symoffset} exceeds the {symbol_count}-entry .dynsym"
        ));
        return;
    }
    // Chains follow the buckets, one per symbol from `symoffset` on.
    let chains = symbol_count.saturating_sub(u64::from(symoffset));
    let required = header.saturating_add(chains.saturating_mul(4));
    if required > hash.size {
        out.push(format!(
            ".gnu.hash needs 0x{required:X} bytes for {chains} chain entries but declares 0x{:X}",
            hash.size
        ));
    }
    let bucket_at = start
        .saturating_add(16)
        .saturating_add((u64::from(bloom_size) * 8) as usize);
    for index in 0..buckets.min(MAX_HASH_BUCKETS) {
        let Some(at) = u64::from(index)
            .checked_mul(4)
            .and_then(|delta| u64::try_from(bucket_at).ok()?.checked_add(delta))
            .and_then(|at| usize::try_from(at).ok())
        else {
            break;
        };
        let Ok(bucket) = read_u32(view.data, at) else {
            break;
        };
        // A bucket pointing past the symbol table sends the lookup off the end.
        if bucket != 0 && u64::from(bucket) >= symbol_count {
            out.push(format!(
                ".gnu.hash bucket {index} points at symbol {bucket}, outside the {symbol_count}-entry .dynsym"
            ));
        }
    }
}

/// Check `.init_array` / `.fini_array` framing and the constructor pointers.
///
/// Only the pointer is validated, and only when it is non-zero: the bytes a
/// constructor points at are never examined, and a zero slot is a legitimate
/// remnant of a partially materialized image.
fn check_arrays(view: &View<'_>, entries: &[(u64, u64)], out: &mut Findings<'_>) {
    for (name, address_tag, size_tag) in [
        (".init_array", DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
        (".fini_array", DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
    ] {
        let section = view.section(name).copied();
        let tag_address = single_tag(entries, address_tag, name, out);
        let tag_size = single_tag(entries, size_tag, name, out);
        let Some(section) = section else {
            if let Some(value) = tag_address {
                out.push(format!(
                    "tag 0x{address_tag:X} points at 0x{value:X} but the image has no {name}"
                ));
            }
            continue;
        };
        if let Some(value) = tag_address
            && section.address != value
        {
            out.push(format!(
                "tag 0x{address_tag:X} points at 0x{value:X} but {name} starts at 0x{:X}",
                section.address
            ));
        }
        if section.size % 8 != 0 {
            out.push(format!(
                "{name} size 0x{:X} is not a whole number of pointers",
                section.size
            ));
        }
        if let Some(size) = tag_size
            && section.size != 0
            && size != section.size
        {
            out.push(format!(
                "tag 0x{size_tag:X} declares 0x{size:X} bytes but {name} is 0x{:X} bytes",
                section.size
            ));
        }
        let Some(start) = view.offset_of(section.address, section.size) else {
            continue;
        };
        let slots = (section.size / 8).min(MAX_ARRAY_SLOTS);
        for slot in 0..slots {
            let Some(at) = slot
                .checked_mul(8)
                .and_then(|delta| u64::try_from(start).ok()?.checked_add(delta))
                .and_then(|at| usize::try_from(at).ok())
            else {
                break;
            };
            let Ok(value) = read_u64(view.data, at) else {
                break;
            };
            if value == 0 {
                continue;
            }
            if view.segment_for(value, 1).is_none() {
                out.push(format!(
                    "{name} slot {slot} holds 0x{value:X}, which no PT_LOAD maps"
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_containment_is_half_open_and_overflow_safe() {
        let segment = Segment {
            offset: 0x1000,
            virtual_address: 0x2000,
            file_size: 0x100,
            memory_size: 0x200,
            flags: PF_R,
            alignment: 0x1000,
        };
        assert!(segment.contains(0x2000, 1));
        assert!(segment.contains(0x21FF, 1));
        assert!(!segment.contains(0x2200, 1), "end is exclusive");
        assert!(!segment.contains(0x1FFF, 1), "before the segment");
        assert!(
            !segment.contains(0x21FF, 2),
            "a range may not straddle the end"
        );
        assert!(!segment.contains(u64::MAX, 2), "overflow is not contained");
        assert_eq!(segment.memory_end(), Some(0x2200));
        assert_eq!(segment.file_end(), Some(0x1100));
    }

    #[test]
    fn segment_file_offset_only_covers_file_backed_bytes() {
        let segment = Segment {
            offset: 0x1000,
            virtual_address: 0x2000,
            file_size: 0x100,
            memory_size: 0x200,
            flags: PF_R,
            alignment: 0x1000,
        };
        assert_eq!(segment.file_offset(0x2000, 1), Some(0x1000));
        assert_eq!(segment.file_offset(0x20FF, 1), Some(0x10FF));
        // Beyond p_filesz but inside p_memsz: the zero-fill tail has no bytes.
        assert_eq!(segment.file_offset(0x2100, 1), None);
        assert_eq!(segment.file_offset(0x20FF, 2), None);
        assert_eq!(segment.file_offset(0x1FFF, 1), None);
    }

    #[test]
    fn single_tag_detects_duplicates() {
        let mut sink = Vec::new();
        let entries = [(DT_STRTAB, 0x100u64), (DT_STRTAB, 0x200), (DT_STRSZ, 0x40)];
        assert_eq!(
            single_tag(
                &entries,
                DT_STRTAB,
                "DT_STRTAB",
                &mut Findings::new(&mut sink)
            ),
            Some(0x100)
        );
        assert_eq!(sink.len(), 1);
        assert!(sink[0].contains("more than once"), "{sink:?}");
        sink.clear();
        assert_eq!(
            single_tag(
                &entries,
                DT_SYMTAB,
                "DT_SYMTAB",
                &mut Findings::new(&mut sink)
            ),
            None
        );
        assert!(sink.is_empty());
    }

    #[test]
    fn empty_image_reports_a_single_missing_segment() {
        let layout = ElfLayout {
            entrypoint: 0,
            program_header_offset: 0,
            program_header_size: 0x38,
            program_header_count: 0,
            program_headers: Vec::new(),
            section_headers: Vec::new(),
            section_name_index: 0,
            private_section_index: usize::MAX,
        };
        let data = [0_u8; 0x40];
        let mut out = Vec::new();
        collect(&data, &layout, &mut out);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("no PT_LOAD"));
    }

    #[test]
    fn truncated_program_header_table_is_reported_not_panicking() {
        let layout = ElfLayout {
            entrypoint: 0,
            program_header_offset: 0x1000,
            program_header_size: 0x38,
            program_header_count: 1,
            program_headers: Vec::new(),
            section_headers: Vec::new(),
            section_name_index: 0,
            private_section_index: usize::MAX,
        };
        let data = [0_u8; 0x40];
        let mut out = Vec::new();
        collect(&data, &layout, &mut out);
        assert!(
            out.iter()
                .any(|message| message.contains("not backed by the file")),
            "{out:?}"
        );
    }
}
