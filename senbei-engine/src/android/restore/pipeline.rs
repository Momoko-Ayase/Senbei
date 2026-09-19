use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use memmap2::{Mmap, MmapMut, MmapOptions};
use senbei_crypto::android::{
    ContainerHeader, HuffmanLzDecoder, Module9bConfig, ProtectedDescriptor, transform_segment,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::super::common;
use super::artifact::load_artifacts;
use super::error::{Error, Result, invalid};
use senbei_elf::{
    DT_GNU_HASH, DT_HASH, DT_JMPREL, DT_PLTRELSZ, DT_RELA, DT_RELACOUNT, DT_RELASZ, DT_STRSZ,
    DT_STRTAB, DT_SYMTAB, DT_VERNEED, DT_VERSYM, ELF64_RELA_SIZE, ELF64_SYMBOL_SIZE, ElfLayout,
    LoadSegment, PF_R, R_AARCH64_ABS64, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT,
    R_AARCH64_RELATIVE, SHF_ALLOC, SHT_LOUSER, SHT_NOBITS, SectionHeader, VER_NDX_GLOBAL, align_up,
    build_gnu_hash, build_sysv_hash, read_i64, read_u32, read_u64, slice, slice_u64,
    usize_from_u64,
};

const CHUNK_SIZE: usize = 16 * 1024 * 1024;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;
const AARCH64_RET: u32 = 0xd65f_03c0;

/// Inputs and optional diagnostics for one `libil2cpp.so` restoration.
#[derive(Debug, Clone)]
pub struct RestoreOptions {
    pub input: PathBuf,
    pub output: PathBuf,
    pub index: PathBuf,
    pub dump_auxiliary: Option<PathBuf>,
    pub outer_only: bool,
    pub preserve_entrypoint: bool,
    /// Print per-phase progress lines to stderr. Off for quiet/batch drivers.
    pub verbose: bool,
}

/// Container decoding counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DecodeStatistics {
    pub segments: usize,
    pub writers: usize,
    pub compressed_writers: usize,
    pub encoded_bytes: u64,
    pub decoded_bytes: u64,
    pub file_bytes_written: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticConfigReport {
    pub header_seed: String,
    pub container_seed: String,
    pub aes_key_sha256: String,
    pub schedule_offset: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DescriptorReport {
    pub command_id: String,
    pub flags: String,
    pub outer_offset: String,
    pub outer_expected_size: String,
    pub auxiliary_offset: String,
    pub auxiliary_expected_size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HiddenSymbolReport {
    pub patch_blob_size: u32,
    pub patched_symbols: u32,
    pub copied_strings: usize,
    pub secondary_record_count: u32,
    pub first_target_index: u32,
    pub last_target_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlacementReport {
    pub offset: u64,
    pub size: usize,
}

struct TablePayload {
    name: &'static str,
    alignment: u64,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfMaterializationReport {
    pub hidden_symbols: HiddenSymbolReport,
    pub old_symbol_count: usize,
    pub auxiliary_symbol_count: u32,
    pub appended_symbols: usize,
    pub new_symbol_count: usize,
    pub old_dynstr_size: usize,
    pub auxiliary_dynstr_size: u32,
    pub new_dynstr_size: usize,
    pub rela_dyn_count: usize,
    pub rela_plt_count: usize,
    pub relative_prefix_count: usize,
    pub metadata_start: u64,
    pub metadata_end: u64,
    pub metadata_capacity_end: u64,
    pub metadata_slack: u64,
    pub placements: BTreeMap<String, PlacementReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleaningReport {
    pub private_section_index: usize,
    pub private_offset: u64,
    pub private_size: u64,
    pub input_entrypoint: u64,
    pub output_entrypoint: u64,
    pub output_section_count: usize,
    pub retained_sections: Vec<String>,
    pub section_header_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub format: String,
    pub machine: String,
    pub sections: usize,
    pub segments: usize,
    pub dynamic_symbols: usize,
    pub dynamic_relocations: usize,
    pub pltgot_relocations: usize,
    pub has_louser: bool,
}

/// Machine-readable result of the restoration.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RestoreReport {
    pub input: String,
    pub input_sha256: String,
    pub output: String,
    pub output_sha256: String,
    pub output_size: u64,
    pub module_index: String,
    pub static_config: StaticConfigReport,
    pub descriptor: DescriptorReport,
    pub primary: DecodeStatistics,
    pub auxiliary: Option<DecodeStatistics>,
    pub elf_materialization: Option<ElfMaterializationReport>,
    pub cleaning: CleaningReport,
    pub validation: ValidationReport,
    pub elapsed_seconds: f64,
}

fn map_read_only(file: &File, path: &Path) -> Result<Mmap> {
    // SAFETY: the mapping is read-only and `file` remains open for the mapping's
    // lifetime. The restoration never mutates or truncates the mapped source.
    unsafe { MmapOptions::new().map(file) }.map_err(|error| Error::io("map", path, error))
}

fn map_mut(file: &File, length: usize, path: &Path) -> Result<MmapMut> {
    // SAFETY: `length` is set on the private temporary output immediately
    // before this call. No other handle mutates or truncates it while mapped.
    unsafe { MmapOptions::new().len(length).map_mut(file) }
        .map_err(|error| Error::io("map temporary output", path, error))
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| Error::io("read", path, error))
}

fn sha256_bytes(data: &[u8]) -> String {
    common::sha256(data)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| Error::io("open", path, error))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::io("hash", path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(senbei_crypto::hex_digest(&digest.finalize()))
}

fn copy_range(source: &[u8], output: &mut File, size: usize, path: &Path) -> Result<()> {
    for chunk in source[..size].chunks(CHUNK_SIZE) {
        output
            .write_all(chunk)
            .map_err(|error| Error::io("write temporary output", path, error))?;
    }
    Ok(())
}

fn checked_add(base: usize, value: usize, field: &str) -> Result<usize> {
    base.checked_add(value)
        .ok_or_else(|| Error::Invalid(format!("{field} overflow")))
}

struct FileLayoutWriter<'a> {
    output: &'a mut [u8],
    layout: &'a ElfLayout,
    load_end: u64,
}

impl FileLayoutWriter<'_> {
    fn write(&mut self, virtual_address: u64, data: &[u8]) -> Result<usize> {
        let data_len = u64::try_from(data.len())
            .map_err(|_| Error::Invalid("decoded write length exceeds u64".to_owned()))?;
        let end = virtual_address
            .checked_add(data_len)
            .ok_or_else(|| Error::Invalid("decoded write range overflow".to_owned()))?;
        if end > self.load_end {
            return invalid(format!(
                "decoded write 0x{virtual_address:x}..0x{end:x} exceeds target load image"
            ));
        }
        let mut written = 0_u64;
        let mut covered_memory = 0_u64;
        for segment in &self.layout.program_headers {
            let memory_end = segment
                .virtual_address
                .checked_add(segment.memory_size)
                .ok_or_else(|| Error::Invalid("PT_LOAD memory end overflow".to_owned()))?;
            let overlap_start = virtual_address.max(segment.virtual_address);
            let overlap_end = end.min(memory_end);
            if overlap_start >= overlap_end {
                continue;
            }
            covered_memory = covered_memory
                .checked_add(overlap_end - overlap_start)
                .ok_or_else(|| Error::Invalid("covered memory count overflow".to_owned()))?;
            let file_end_va = segment
                .virtual_address
                .checked_add(segment.file_size)
                .ok_or_else(|| Error::Invalid("PT_LOAD file VA end overflow".to_owned()))?;
            let file_overlap_end = overlap_end.min(file_end_va);
            if overlap_start < file_overlap_end {
                let source_offset =
                    usize_from_u64(overlap_start - virtual_address, "write source offset")?;
                let file_offset = usize_from_u64(
                    segment
                        .offset
                        .checked_add(overlap_start - segment.virtual_address)
                        .ok_or_else(|| Error::Invalid("write file offset overflow".to_owned()))?,
                    "write file offset",
                )?;
                let count = usize_from_u64(file_overlap_end - overlap_start, "write size")?;
                let destination = self
                    .output
                    .get_mut(file_offset..file_offset + count)
                    .ok_or_else(|| {
                        Error::Invalid("decoded write exceeds temporary output".to_owned())
                    })?;
                destination.copy_from_slice(&data[source_offset..source_offset + count]);
                written += count as u64;
            }
        }
        if covered_memory != data_len {
            return invalid(format!(
                "decoded write 0x{virtual_address:x}..0x{end:x} is not covered by PT_LOAD memory"
            ));
        }
        Ok(usize_from_u64(written, "written byte count")?)
    }
}

fn decode_container<F>(
    payload: &[u8],
    header: &ContainerHeader,
    config: &Module9bConfig,
    verbose: bool,
    mut writer: F,
) -> Result<DecodeStatistics>
where
    F: FnMut(u64, &[u8]) -> Result<usize>,
{
    let decoder = HuffmanLzDecoder::new(&header.tree)?;
    let mut statistics = DecodeStatistics {
        segments: header.segments.len(),
        ..DecodeStatistics::default()
    };
    let decrypt_aes = !(config.skip_aes || header.skip_aes);
    for (segment_index, encoded) in header.segments.iter().enumerate() {
        let start = checked_add(
            header.start,
            encoded.offset as usize,
            "encoded segment start",
        )?;
        let encoded_data = slice(payload, start, encoded.size as usize)?;
        let transformed = transform_segment(
            encoded_data,
            config.container_seed,
            &config.aes_key,
            decrypt_aes,
        )?;
        if transformed.len() < 16 {
            return invalid(format!(
                "decoded segment {segment_index} is shorter than its header"
            ));
        }
        let base_offset = u64::from(read_u32(&transformed, 0)?);
        let writer_count = read_u32(&transformed, 4)? as usize;
        let table_offset = read_u32(&transformed, 8)? as usize;
        let data_offset = read_u32(&transformed, 12)? as usize;
        let table_end = table_offset
            .checked_add(
                writer_count
                    .checked_mul(16)
                    .ok_or_else(|| Error::Invalid("writer table size overflow".to_owned()))?,
            )
            .ok_or_else(|| Error::Invalid("writer table end overflow".to_owned()))?;
        if table_end > transformed.len() || data_offset > transformed.len() {
            return invalid(format!(
                "decoded segment {segment_index} has invalid writer offsets"
            ));
        }
        let mut data_cursor = data_offset;
        for writer_index in 0..writer_count {
            let record = table_offset + writer_index * 16;
            let output_offset = u64::from(read_u32(&transformed, record)?);
            let output_size = read_u32(&transformed, record + 4)? as usize;
            let encoded_size = read_u32(&transformed, record + 8)? as usize;
            let reserved = read_u32(&transformed, record + 12)?;
            let encoded_end = data_cursor
                .checked_add(encoded_size)
                .ok_or_else(|| Error::Invalid("writer data end overflow".to_owned()))?;
            if reserved != 0 || encoded_end > transformed.len() {
                return invalid(format!(
                    "segment {segment_index} writer {writer_index} has invalid bounds"
                ));
            }
            let source = &transformed[data_cursor..encoded_end];
            let decoded = if encoded_size == output_size {
                None
            } else {
                statistics.compressed_writers += 1;
                Some(decoder.decode(source, output_size)?)
            };
            let decoded_slice = decoded.as_deref().unwrap_or(source);
            let target = base_offset
                .checked_add(output_offset)
                .ok_or_else(|| Error::Invalid("writer target address overflow".to_owned()))?;
            statistics.file_bytes_written += writer(target, decoded_slice)? as u64;
            statistics.writers += 1;
            statistics.encoded_bytes += encoded_size as u64;
            statistics.decoded_bytes += output_size as u64;
            data_cursor = encoded_end;
        }
        if verbose {
            eprintln!(
                "[{current:02}/{total:02}] writers={writer_count} encoded=0x{size:x}",
                current = segment_index + 1,
                total = header.segments.len(),
                size = encoded.size,
            );
        }
    }
    Ok(statistics)
}

fn read_c_string(data: &[u8], offset: usize, limit: usize) -> Result<&[u8]> {
    if offset >= limit || limit > data.len() {
        return invalid(format!("invalid string offset 0x{offset:x}/0x{limit:x}"));
    }
    let relative_end = data[offset..limit]
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| Error::Invalid(format!("unterminated string at 0x{offset:x}")))?;
    Ok(&data[offset..offset + relative_end])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuxiliaryElfImage {
    dynstr_offset: u32,
    dynstr_size: u32,
    dynsym_offset: u32,
    dynsym_count: u32,
    relocation1_offset: u32,
    relocation1_count: u32,
    relocation2_offset: u32,
    relocation2_count: u32,
}

impl AuxiliaryElfImage {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 0x40 {
            return invalid("decoded auxiliary ELF image is truncated");
        }
        let mut words = [0_u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            *word = read_u32(data, index * 4)?;
        }
        if [1, 3, 12, 13, 15]
            .into_iter()
            .any(|index| words[index] != 0)
        {
            return invalid("unexpected nonzero auxiliary ELF header field");
        }
        if words[14] != 0xb7 {
            return invalid(format!(
                "unexpected auxiliary ELF machine 0x{:x}",
                words[14]
            ));
        }
        let result = Self {
            dynstr_offset: words[4],
            dynstr_size: words[5],
            dynsym_offset: words[6],
            dynsym_count: words[7],
            relocation1_offset: words[8],
            relocation1_count: words[9],
            relocation2_offset: words[10],
            relocation2_count: words[11],
        };
        if result.dynsym_count == 0 {
            return invalid("auxiliary dynamic symbol table has no null entry");
        }
        if result.relocation1_offset != 0x40 {
            return invalid("auxiliary relocation table does not follow its header");
        }
        let relocation1_end = u64::from(result.relocation1_offset)
            + u64::from(result.relocation1_count) * ELF64_RELA_SIZE as u64;
        let relocation2_end = u64::from(result.relocation2_offset)
            + u64::from(result.relocation2_count) * ELF64_RELA_SIZE as u64;
        let dynsym_end = u64::from(result.dynsym_offset)
            + u64::from(result.dynsym_count) * ELF64_SYMBOL_SIZE as u64;
        let dynstr_end = u64::from(result.dynstr_offset) + u64::from(result.dynstr_size);
        let expected_relocation2 = align_up(relocation1_end, 0x10)?;
        let expected_dynsym = align_up(relocation2_end, 0x10)?;
        if expected_relocation2 != u64::from(result.relocation2_offset)
            || expected_dynsym != u64::from(result.dynsym_offset)
            || dynsym_end != u64::from(result.dynstr_offset)
            || dynstr_end != data.len() as u64
        {
            return invalid(format!(
                "auxiliary ELF layout mismatch: rela1_end=0x{relocation1_end:x}/rela2=0x{:x}, rela2_end=0x{relocation2_end:x}/dynsym=0x{:x}, dynsym_end=0x{dynsym_end:x}/dynstr=0x{:x}, dynstr_end=0x{dynstr_end:x}/size=0x{:x}",
                result.relocation2_offset,
                result.dynsym_offset,
                result.dynstr_offset,
                data.len()
            ));
        }
        for (start, end) in [
            (relocation1_end, expected_relocation2),
            (relocation2_end, expected_dynsym),
        ] {
            if slice_u64(data, start, end - start)?
                .iter()
                .any(|&byte| byte != 0)
            {
                return invalid(format!(
                    "auxiliary ELF alignment padding 0x{start:x}..0x{end:x} is nonzero"
                ));
            }
        }
        if slice(data, result.dynsym_offset as usize, ELF64_SYMBOL_SIZE)?
            .iter()
            .any(|&byte| byte != 0)
        {
            return invalid("auxiliary dynamic symbol zero entry is not empty");
        }
        Ok(result)
    }
}

fn restore_hidden_symbols(
    output: &mut [u8],
    dynsym: SectionHeader,
    dynstr: SectionHeader,
    patch_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, HiddenSymbolReport)> {
    if dynsym.entry_size != ELF64_SYMBOL_SIZE as u64
        || !dynsym.size.is_multiple_of(ELF64_SYMBOL_SIZE as u64)
    {
        return invalid("unexpected .dynsym entry layout");
    }
    let symbol_count = usize_from_u64(
        dynsym.size / ELF64_SYMBOL_SIZE as u64,
        "dynamic symbol count",
    )?;
    let mut symbols = slice_u64(output, dynsym.offset, dynsym.size)?.to_vec();
    let mut strings = slice_u64(output, dynstr.offset, dynstr.size)?.to_vec();
    if patch_data.len() < 0x18 {
        return invalid("0x9E symbol patch data is truncated");
    }
    let blob_size = read_u32(patch_data, 0)?;
    let secondary_record_count = read_u32(patch_data, 4)?;
    let table_base = 8_usize;
    let table_end = table_base
        .checked_add(blob_size as usize)
        .ok_or_else(|| Error::Invalid("0x9E patch blob end overflow".to_owned()))?;
    if table_end > patch_data.len() {
        return invalid("0x9E primary symbol patch blob exceeds its artifact");
    }
    let count = read_u32(patch_data, table_base)?;
    let symbol_offset = read_u32(patch_data, table_base + 4)? as usize;
    let index_offset = read_u32(patch_data, table_base + 8)? as usize;
    let string_offset = read_u32(patch_data, table_base + 12)? as usize;
    let count_usize = count as usize;
    if symbol_offset
        .checked_add(count_usize * ELF64_SYMBOL_SIZE)
        .is_none_or(|end| end > blob_size as usize)
        || index_offset
            .checked_add(count_usize * 4)
            .is_none_or(|end| end > blob_size as usize)
        || string_offset >= blob_size as usize
    {
        return invalid("0x9E symbol patch table has invalid offsets");
    }
    let mut cursor = table_base + string_offset;
    let mut patched_indices = HashSet::with_capacity(count_usize);
    let mut copied_strings = 0_usize;
    for index in 0..count_usize {
        let source_offset = table_base + symbol_offset + index * ELF64_SYMBOL_SIZE;
        let source_symbol = slice(patch_data, source_offset, ELF64_SYMBOL_SIZE)?;
        let target_index = read_u32(patch_data, table_base + index_offset + index * 4)?;
        if target_index == 0 || target_index as usize >= symbol_count {
            return invalid(format!(
                "0x9E target symbol index {target_index} is invalid"
            ));
        }
        if !patched_indices.insert(target_index) {
            return invalid(format!("0x9E patches symbol {target_index} more than once"));
        }
        let name = read_c_string(patch_data, cursor, table_end)?;
        cursor += name.len() + 1;
        let name_offset = read_u32(source_symbol, 0)? as usize;
        if name_offset
            .checked_add(name.len() + 1)
            .is_none_or(|end| end > strings.len())
        {
            return invalid(format!("0x9E symbol {target_index} name exceeds .dynstr"));
        }
        let existing = read_c_string(&strings, name_offset, strings.len())?;
        if existing.is_empty() {
            strings[name_offset..name_offset + name.len()].copy_from_slice(name);
            strings[name_offset + name.len()] = 0;
            copied_strings += 1;
        } else if existing != name {
            return invalid(format!(
                "0x9E symbol {target_index} conflicts with existing .dynstr data"
            ));
        }
        let target_offset = target_index as usize * ELF64_SYMBOL_SIZE;
        symbols[target_offset..target_offset + ELF64_SYMBOL_SIZE].copy_from_slice(source_symbol);
    }
    let string_padding = patch_data.get(cursor..table_end).ok_or_else(|| {
        Error::Invalid("0x9E symbol strings exceed the primary patch blob".to_owned())
    })?;
    if string_padding.len() > 3 || string_padding.iter().any(|&byte| byte != 0) {
        return invalid(format!(
            "0x9E symbol strings have invalid padding at 0x{cursor:x}..0x{table_end:x}"
        ));
    }
    let first_target_index = patched_indices
        .iter()
        .copied()
        .min()
        .ok_or_else(|| Error::Invalid("0x9E patch table is empty".to_owned()))?;
    let last_target_index = patched_indices
        .iter()
        .copied()
        .max()
        .ok_or_else(|| Error::Invalid("0x9E patch table is empty".to_owned()))?;
    Ok((
        symbols,
        strings,
        HiddenSymbolReport {
            patch_blob_size: blob_size,
            patched_symbols: count,
            copied_strings,
            secondary_record_count,
            first_target_index,
            last_target_index,
        },
    ))
}

fn dynamic_symbol_names(symbols: &[u8], strings: &[u8]) -> Result<Vec<Vec<u8>>> {
    if !symbols.len().is_multiple_of(ELF64_SYMBOL_SIZE) {
        return invalid("dynamic symbol table is not entry-aligned");
    }
    symbols
        .as_chunks::<ELF64_SYMBOL_SIZE>()
        .0
        .iter()
        .map(|symbol| {
            let name_offset = read_u32(symbol, 0)? as usize;
            Ok(read_c_string(strings, name_offset, strings.len())?.to_vec())
        })
        .collect()
}

fn discover_auxiliary_symbol_seed(module: &[u8]) -> Result<u32> {
    const PREFIX0: u32 = 0x8f;
    const PREFIX1: u32 = 0x15ec;
    const TYPE_ID: u32 = 0x81;
    const MODE0: u32 = 1;
    const MODE1: u32 = 5;
    const SUFFIX0: u32 = 0x0a54;
    const SUFFIX1: u32 = 0x12008;

    let mut matches = Vec::new();
    for seed_offset in (0x20..module.len().saturating_sub(0x10)).step_by(4) {
        if read_u32(module, seed_offset - 0x20)? == PREFIX0
            && read_u32(module, seed_offset - 0x1c)? == PREFIX1
            && read_u32(module, seed_offset - 0x18)? == TYPE_ID
            && read_u32(module, seed_offset - 0x10)? == TYPE_ID
            && read_u32(module, seed_offset - 8)? == MODE0
            && read_u32(module, seed_offset - 4)? == MODE1
            && read_u32(module, seed_offset + 4)? == SUFFIX0
            && read_u32(module, seed_offset + 8)? == SUFFIX1
            && read_u32(module, seed_offset + 0x0c)? == 0
        {
            matches.push(read_u32(module, seed_offset)?);
        }
    }
    match matches.as_slice() {
        [seed] => Ok(*seed),
        [] => invalid("module 0x96 has no validated auxiliary symbol seed"),
        _ => invalid(format!(
            "module 0x96 has {} validated auxiliary symbol seeds",
            matches.len()
        )),
    }
}

// These libc calls are intentionally omitted from the saved relocation pack.
// Their GOT slots are therefore the five holes left after combining the
// protected and auxiliary PLT relocations. Resolve the holes by call ABI rather
// than by fixed slot numbers; the slot order differs between protected games.
const SPECIAL_PLT_IMPORT_NAMES: [&str; 5] = ["strlen", "strcmp", "memset", "strcpy", "strchr"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PltCallFeatures {
    calls: usize,
    zero_arg1: usize,
    w0_zero_branch: usize,
    pointer_zero_branch_with_immediate_arg1: usize,
    x0_to_x2: usize,
}

fn aarch64_bl_target(instruction: u32, pc: u64) -> Option<u64> {
    if instruction & 0xfc00_0000 != 0x9400_0000 {
        return None;
    }
    let immediate = i64::from(instruction & 0x03ff_ffff);
    let signed = if immediate & (1 << 25) != 0 {
        immediate - (1 << 26)
    } else {
        immediate
    };
    let target = i128::from(pc) + i128::from(signed) * 4;
    u64::try_from(target).ok()
}

fn aarch64_cb_register(instruction: u32) -> Option<(bool, u32)> {
    (instruction & 0x7e00_0000 == 0x3400_0000).then_some((instruction >> 31 != 0, instruction & 31))
}

fn aarch64_mov_x_from_x0(instruction: u32) -> Option<u32> {
    if instruction & 0xffe0_ffe0 == 0xaa00_03e0 && (instruction >> 16) & 31 == 0 {
        Some(instruction & 31)
    } else {
        None
    }
}

fn aarch64_writes_w1_immediate(instruction: u32) -> bool {
    if instruction & 31 != 1 {
        return false;
    }
    matches!(
        instruction & 0x7f80_0000,
        0x5280_0000 | 0x1280_0000 | 0x3200_0000
    )
}

fn plt_call_features(image: &[u8], layout: &ElfLayout, target: u64) -> Result<PltCallFeatures> {
    let mut features = PltCallFeatures::default();
    for segment in &layout.program_headers {
        if segment.flags & 1 == 0 || segment.file_size < 4 {
            continue;
        }
        let segment_offset = usize_from_u64(segment.offset, "executable segment offset")?;
        let segment_size = usize_from_u64(segment.file_size, "executable segment size")?;
        let segment_end = segment_offset
            .checked_add(segment_size)
            .ok_or_else(|| Error::Invalid("executable segment range overflow".to_owned()))?;
        if segment_end > image.len() {
            return invalid("executable segment exceeds restored image");
        }
        for relative in (0..=segment_size - 4).step_by(4) {
            let offset = segment_offset + relative;
            let pc = segment
                .virtual_address
                .checked_add(relative as u64)
                .ok_or_else(|| Error::Invalid("executable PC overflow".to_owned()))?;
            let instruction = read_u32(image, offset)?;
            if aarch64_bl_target(instruction, pc) != Some(target) {
                continue;
            }
            features.calls += 1;
            let previous = |back: usize| -> Option<u32> {
                offset
                    .checked_sub(back.checked_mul(4)?)
                    .and_then(|position| read_u32(image, position).ok())
            };
            let following = |forward: usize| -> Option<u32> {
                offset
                    .checked_add(forward.checked_mul(4)?)
                    .and_then(|position| read_u32(image, position).ok())
            };
            if (1..=5).any(|back| matches!(previous(back), Some(0x2a1f_03e1 | 0xaa1f_03e1))) {
                features.zero_arg1 += 1;
            }
            if following(1).and_then(aarch64_cb_register) == Some((false, 0)) {
                features.w0_zero_branch += 1;
            }
            let pointer_zero_branch = if following(1).and_then(aarch64_cb_register)
                == Some((true, 0))
            {
                true
            } else if let (Some(first), Some(second)) = (following(1), following(2)) {
                aarch64_mov_x_from_x0(first)
                    .is_some_and(|register| aarch64_cb_register(second) == Some((true, register)))
            } else {
                false
            };
            if pointer_zero_branch
                && (1..=4).any(|back| previous(back).is_some_and(aarch64_writes_w1_immediate))
            {
                features.pointer_zero_branch_with_immediate_arg1 += 1;
            }
            if (1..=3).any(|forward| following(forward).and_then(aarch64_mov_x_from_x0) == Some(2))
            {
                features.x0_to_x2 += 1;
            }
        }
    }
    Ok(features)
}

fn classify_special_plt_slots(
    candidates: &[(usize, PltCallFeatures)],
) -> Result<Vec<(usize, &'static str)>> {
    if candidates.len() != SPECIAL_PLT_IMPORT_NAMES.len() {
        return invalid(format!(
            "expected {} unresolved special PLT slots, found {}",
            SPECIAL_PLT_IMPORT_NAMES.len(),
            candidates.len()
        ));
    }
    let mut remaining = candidates.to_vec();
    let mut result = Vec::with_capacity(SPECIAL_PLT_IMPORT_NAMES.len());
    let mut take_unique =
        |name: &'static str, predicate: &dyn Fn(PltCallFeatures) -> bool| -> Result<()> {
            let matches = remaining
                .iter()
                .enumerate()
                .filter_map(|(index, &(_, features))| predicate(features).then_some(index))
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return invalid(format!(
                    "special PLT classifier found {} candidates for {name}",
                    matches.len()
                ));
            }
            let (slot, _) = remaining.remove(matches[0]);
            result.push((slot, name));
            Ok(())
        };
    take_unique("memset", &|features| {
        features.calls != 0 && features.zero_arg1 * 2 > features.calls
    })?;
    take_unique("strcmp", &|features| {
        features.calls != 0 && features.w0_zero_branch * 2 > features.calls
    })?;
    take_unique("strchr", &|features| {
        features.calls != 0 && features.pointer_zero_branch_with_immediate_arg1 == features.calls
    })?;
    take_unique("strlen", &|features| features.x0_to_x2 != 0)?;
    if remaining.len() != 1 {
        return invalid("special PLT classifier did not leave exactly one strcpy slot");
    }
    let (slot, features) = remaining.pop().expect("one strcpy slot");
    if features.calls == 0 {
        return invalid("special PLT strcpy candidate has no direct call sites");
    }
    result.push((slot, "strcpy"));
    result.sort_by_key(|(slot, _)| *slot);
    Ok(result)
}

fn append_undefined_function_symbol(
    symbols: &mut Vec<u8>,
    strings: &mut Vec<u8>,
    name: &str,
) -> Result<usize> {
    let name_offset = u32::try_from(strings.len())
        .map_err(|_| Error::Invalid("dynamic string table exceeds u32".to_owned()))?;
    strings.extend_from_slice(name.as_bytes());
    strings.push(0);
    let index = symbols.len() / ELF64_SYMBOL_SIZE;
    symbols.extend_from_slice(&name_offset.to_le_bytes());
    symbols.push(0x12); // STB_GLOBAL | STT_FUNC
    symbols.push(0);
    symbols.extend_from_slice(&0_u16.to_le_bytes()); // SHN_UNDEF
    symbols.extend_from_slice(&0_u64.to_le_bytes());
    symbols.extend_from_slice(&0_u64.to_le_bytes());
    Ok(index)
}

fn symbol_definition(symbols: &[u8], index: usize) -> Result<(u16, u64)> {
    let start = index
        .checked_mul(ELF64_SYMBOL_SIZE)
        .ok_or_else(|| Error::Invalid("dynamic symbol index overflow".to_owned()))?;
    let symbol = slice(symbols, start, ELF64_SYMBOL_SIZE)?;
    let section_index = u16::from_le_bytes([symbol[6], symbol[7]]);
    let value = read_u64(symbol, 8)?;
    Ok((section_index, value))
}

#[derive(Debug)]
struct ConstructorProfile {
    init_addends: Vec<u64>,
    fini_addend: u64,
}

fn virtual_address_to_file_offset(layout: &ElfLayout, address: u64, size: u64) -> Option<usize> {
    let end = address.checked_add(size)?;
    for segment in &layout.program_headers {
        let segment_end = segment.virtual_address.checked_add(segment.file_size)?;
        if segment.virtual_address <= address && end <= segment_end {
            let offset = segment
                .offset
                .checked_add(address.checked_sub(segment.virtual_address)?)?;
            return usize::try_from(offset).ok();
        }
    }
    None
}

fn discover_suppressed_constructors(
    module: &[u8],
    source: &[u8],
    layout: &ElfLayout,
    max_count: usize,
) -> Result<Option<Vec<u64>>> {
    const RECORD_SIZE: usize = 16;
    const MIN_COUNT: usize = 2;
    const MAX_COUNT: usize = 256;
    let mut matches = Vec::new();
    if module.len() < 8 {
        return Ok(None);
    }
    for base in (0..=module.len() - 8).step_by(4) {
        let count = read_u32(module, base)? as usize;
        if !(MIN_COUNT..=MAX_COUNT.min(max_count)).contains(&count)
            || read_u32(module, base + 4)? != 0
        {
            continue;
        }
        let table_size = 8_usize
            .checked_add(
                count
                    .checked_mul(RECORD_SIZE)
                    .ok_or_else(|| Error::Invalid("constructor table size overflow".to_owned()))?,
            )
            .ok_or_else(|| Error::Invalid("constructor table size overflow".to_owned()))?;
        if base
            .checked_add(table_size)
            .is_none_or(|end| end > module.len())
        {
            continue;
        }
        let mut constructors = Vec::with_capacity(count);
        let mut valid = true;
        for index in 0..count {
            let record = base + 8 + index * RECORD_SIZE;
            let constructor = u64::from(read_u32(module, record)?);
            let fallback = u64::from(read_u32(module, record + 4)?);
            let original = read_u32(module, record + 8)?;
            let reserved = read_u32(module, record + 12)?;
            let constructor_offset = virtual_address_to_file_offset(layout, constructor, 4);
            let fallback_offset = virtual_address_to_file_offset(layout, fallback, 4);
            if constructor == 0
                || fallback == 0
                || reserved != 0
                || constructor_offset.and_then(|offset| read_u32(source, offset).ok())
                    != Some(original)
                || fallback_offset.and_then(|offset| read_u32(source, offset).ok())
                    != Some(AARCH64_RET)
            {
                valid = false;
                break;
            }
            constructors.push(constructor);
        }
        if valid
            && constructors.windows(2).all(|pair| pair[0] < pair[1])
            && constructors.iter().copied().collect::<HashSet<_>>().len() == count
        {
            matches.push(constructors);
        }
    }
    match matches.len() {
        1 => Ok(matches.pop()),
        0 => Ok(None),
        count => invalid(format!(
            "constructor control module has {count} validated suppression tables"
        )),
    }
}

fn constructor_profile(
    module: &[u8],
    source: &[u8],
    layout: &ElfLayout,
    init_array: SectionHeader,
    fini_array: SectionHeader,
    old_dyn: RelocationTable<'_>,
) -> Result<Option<ConstructorProfile>> {
    if !init_array.size.is_multiple_of(8) {
        return invalid("init-array size is not entry-aligned");
    }
    let init_count = usize_from_u64(init_array.size / 8, "init-array count")?;
    let Some(mut init_addends) =
        discover_suppressed_constructors(module, source, layout, init_count)?
    else {
        return Ok(None);
    };
    let max_suppressed = *init_addends
        .last()
        .ok_or_else(|| Error::Invalid("constructor table is empty".to_owned()))?;
    let init_end = init_array
        .address
        .checked_add(init_array.size)
        .ok_or_else(|| Error::Invalid("init-array range overflow".to_owned()))?;
    let existing = old_dyn.collect_where(|relocation| {
        relocation.offset >= init_array.address && relocation.offset < init_end
    })?;
    let extra = existing
        .iter()
        .filter(|relocation| {
            relocation.kind() == R_AARCH64_RELATIVE
                && relocation.symbol() == 0
                && relocation.addend >= 0
        })
        .map(|relocation| relocation.addend as u64)
        .filter(|&addend| {
            addend != layout.entrypoint
                && addend > max_suppressed
                && addend <= max_suppressed.saturating_add(0x1000)
        })
        .collect::<Vec<_>>();
    if extra.len() != 1 {
        return invalid(format!(
            "expected one unsuppressed constructor near the suppression table, found {}",
            extra.len()
        ));
    }
    init_addends.push(extra[0]);
    if init_addends.len() > init_count {
        return invalid(format!(
            "constructor profile produced {} entries for {init_count} init slots",
            init_addends.len()
        ));
    }
    let fini = old_dyn.collect_where(|relocation| relocation.offset == fini_array.address)?;
    if fini.len() != 1
        || fini[0].kind() != R_AARCH64_RELATIVE
        || fini[0].symbol() != 0
        || fini[0].addend < 0
    {
        return invalid("fini-array relocation is not a single RELATIVE record");
    }
    Ok(Some(ConstructorProfile {
        init_addends,
        fini_addend: fini[0].addend as u64,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rela {
    offset: u64,
    info: u64,
    addend: i64,
}

impl Rela {
    fn parse(data: &[u8], offset: usize) -> Result<Self> {
        Ok(Self {
            offset: read_u64(data, offset)?,
            info: read_u64(data, offset + 8)?,
            addend: read_i64(data, offset + 0x10)?,
        })
    }

    fn kind(self) -> u32 {
        self.info as u32
    }

    fn symbol(self) -> u64 {
        self.info >> 32
    }

    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.offset.to_le_bytes());
        output.extend_from_slice(&self.info.to_le_bytes());
        output.extend_from_slice(&self.addend.to_le_bytes());
    }
}

#[derive(Clone, Copy)]
struct RelocationRemap {
    base_symbol_count: usize,
    auxiliary_symbol_count: u32,
    permutation_seed: Option<u32>,
}

fn decode_auxiliary_symbol(encoded: u64, row: usize, symbol_count: u32, seed: u32) -> Result<u64> {
    if encoded == 0 {
        return Ok(0);
    }
    if encoded >= u64::from(symbol_count) || symbol_count < 2 {
        return invalid("auxiliary relocation references an invalid encoded symbol");
    }
    let modulus = symbol_count - 1;
    let squared = seed.wrapping_mul(seed);
    let row = u32::try_from(row)
        .map_err(|_| Error::Invalid("auxiliary relocation row exceeds u32".to_owned()))?;
    let right = (squared >> (row & 0x1b)).wrapping_add(0x1bc5);
    let left = squared.wrapping_shl(row & 3).wrapping_add(0x2048);
    let rotation = (right | left) % modulus;
    let mut decoded = u64::from(symbol_count - 2)
        .checked_add(encoded)
        .and_then(|value| value.checked_sub(u64::from(rotation)))
        .ok_or_else(|| Error::Invalid("auxiliary symbol permutation overflow".to_owned()))?;
    if decoded >= u64::from(modulus) {
        decoded -= u64::from(modulus);
    }
    Ok(decoded + 1)
}

#[derive(Clone, Copy)]
struct RelocationTable<'a> {
    data: &'a [u8],
    offset: usize,
    count: usize,
    remap: Option<RelocationRemap>,
}

impl RelocationTable<'_> {
    fn relocation(self, index: usize) -> Result<Rela> {
        if index >= self.count {
            return invalid("relocation index is out of range");
        }
        let offset = self
            .offset
            .checked_add(
                index
                    .checked_mul(ELF64_RELA_SIZE)
                    .ok_or_else(|| Error::Invalid("relocation index overflow".to_owned()))?,
            )
            .ok_or_else(|| Error::Invalid("relocation offset overflow".to_owned()))?;
        let mut relocation = Rela::parse(self.data, offset)?;
        if let Some(remap) = self.remap {
            let encoded = relocation.symbol();
            if encoded >= u64::from(remap.auxiliary_symbol_count) {
                return invalid("auxiliary relocation references an invalid symbol");
            }
            let symbol = match remap.permutation_seed {
                Some(seed) => {
                    decode_auxiliary_symbol(encoded, index, remap.auxiliary_symbol_count, seed)?
                }
                None => encoded,
            };
            if symbol != 0 {
                let base =
                    u64::try_from(remap.base_symbol_count.checked_sub(1).ok_or_else(|| {
                        Error::Invalid("old dynamic symbol table is empty".to_owned())
                    })?)
                    .map_err(|_| Error::Invalid("old symbol count exceeds u64".to_owned()))?;
                let remapped = symbol
                    .checked_add(base)
                    .ok_or_else(|| Error::Invalid("remapped symbol index overflow".to_owned()))?;
                relocation.info = (remapped << 32) | u64::from(relocation.kind());
            }
        }
        Ok(relocation)
    }

    fn validate(self, allowed: &[u32], description: &str) -> Result<()> {
        for index in 0..self.count {
            let kind = self.relocation(index)?.kind();
            if !allowed.contains(&kind) {
                return invalid(format!(
                    "{description} contains unsupported relocation type 0x{kind:x}"
                ));
            }
        }
        Ok(())
    }

    fn collect_where(self, predicate: impl Fn(Rela) -> bool) -> Result<Vec<Rela>> {
        let mut result = Vec::new();
        for index in 0..self.count {
            let relocation = self.relocation(index)?;
            if predicate(relocation) {
                result.push(relocation);
            }
        }
        Ok(result)
    }
}

fn relocation_references_symbol_range(relocation: Rela, range: Option<(u64, u64)>) -> bool {
    let Some((start, end)) = range else {
        return false;
    };
    let symbol = relocation.symbol();
    symbol >= start && symbol < end
}

fn convert_defined_symbol_relocations(relocations: &mut [Rela], symbols: &[u8]) -> Result<usize> {
    let mut converted = 0_usize;
    for relocation in relocations {
        if relocation.kind() == R_AARCH64_RELATIVE || relocation.symbol() == 0 {
            continue;
        }
        let symbol = usize::try_from(relocation.symbol())
            .map_err(|_| Error::Invalid("relocation symbol exceeds usize".to_owned()))?;
        let (section_index, value) = symbol_definition(symbols, symbol)?;
        if section_index == 0 {
            continue;
        }
        let addend = i128::from(value) + i128::from(relocation.addend);
        relocation.addend = i64::try_from(addend)
            .map_err(|_| Error::Invalid("local relocation addend exceeds i64".to_owned()))?;
        relocation.info = u64::from(R_AARCH64_RELATIVE);
        converted += 1;
    }
    Ok(converted)
}

fn discover_special_plt_imports(
    image: &[u8],
    layout: &ElfLayout,
    names: &[String],
    old_plt: &[Rela],
    auxiliary_plt: &[Rela],
) -> Result<Vec<(usize, &'static str)>> {
    let plt_index = names
        .iter()
        .position(|name| name == ".plt")
        .ok_or_else(|| Error::Invalid("restored image lacks .plt".to_owned()))?;
    let got_plt_index = names
        .iter()
        .position(|name| name == ".got.plt")
        .ok_or_else(|| Error::Invalid("restored image lacks .got.plt".to_owned()))?;
    let plt = layout.section_headers[plt_index];
    let got_plt = layout.section_headers[got_plt_index];
    if got_plt.size < 0x18 || !(got_plt.size - 0x18).is_multiple_of(8) {
        return invalid(".got.plt has an invalid slot layout");
    }
    let slot_count = usize_from_u64((got_plt.size - 0x18) / 8, ".got.plt slot count")?;
    let first_slot = got_plt
        .address
        .checked_add(0x18)
        .ok_or_else(|| Error::Invalid(".got.plt slot address overflow".to_owned()))?;
    let slot_end = first_slot
        .checked_add((slot_count as u64) * 8)
        .ok_or_else(|| Error::Invalid(".got.plt slot range overflow".to_owned()))?;
    let mut occupied = HashSet::new();
    for table in [old_plt, auxiliary_plt] {
        for &relocation in table
            .iter()
            .filter(|relocation| relocation.offset >= first_slot && relocation.offset < slot_end)
        {
            if !(relocation.offset - first_slot).is_multiple_of(8) {
                return invalid("PLT relocation target is not slot-aligned");
            }
            if !occupied.insert(relocation.offset) {
                return invalid(format!(
                    "duplicate PLT relocation target 0x{:x}",
                    relocation.offset
                ));
            }
        }
    }
    let missing = (0..slot_count)
        .filter(|&slot| !occupied.contains(&(first_slot + (slot as u64) * 8)))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    if missing.len() != SPECIAL_PLT_IMPORT_NAMES.len() {
        return invalid(format!(
            ".got.plt has {} unresolved slots, expected {} special libc imports",
            missing.len(),
            SPECIAL_PLT_IMPORT_NAMES.len()
        ));
    }
    if plt.size < 0x20 {
        return invalid(".plt is too small for a PLT0 entry");
    }
    let first_plt = plt
        .address
        .checked_add(0x20)
        .ok_or_else(|| Error::Invalid("first PLT entry overflow".to_owned()))?;
    let required_plt_size = 0x20_u64
        .checked_add((slot_count as u64) * 0x10)
        .ok_or_else(|| Error::Invalid("PLT slot range overflow".to_owned()))?;
    if plt.size < required_plt_size {
        return invalid(format!(
            ".plt size 0x{:x} is too small for {slot_count} GOT slots",
            plt.size
        ));
    }
    let mut candidates = Vec::with_capacity(missing.len());
    for slot in missing {
        let target = first_plt
            .checked_add((slot as u64) * 0x10)
            .ok_or_else(|| Error::Invalid("PLT entry address overflow".to_owned()))?;
        candidates.push((slot, plt_call_features(image, layout, target)?));
    }
    classify_special_plt_slots(&candidates)
}

fn patch_dynamic_tags(
    output: &mut [u8],
    dynamic: SectionHeader,
    values: &BTreeMap<u64, u64>,
) -> Result<()> {
    if !dynamic.size.is_multiple_of(0x10) {
        return invalid(".dynamic size is not entry-aligned");
    }
    let start = usize_from_u64(dynamic.offset, ".dynamic offset")?;
    let size = usize_from_u64(dynamic.size, ".dynamic size")?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::Invalid(".dynamic end overflow".to_owned()))?;
    slice(output, start, size)?;
    let mut found = HashSet::with_capacity(values.len());
    for offset in (start..end).step_by(0x10) {
        let tag = read_u64(output, offset)?;
        if let Some(&value) = values.get(&tag) {
            if !found.insert(tag) {
                return invalid(format!("dynamic tag 0x{tag:x} occurs more than once"));
            }
            output[offset + 8..offset + 0x10].copy_from_slice(&value.to_le_bytes());
        }
        if tag == 0 {
            break;
        }
    }
    let missing = values
        .keys()
        .filter(|tag| !found.contains(tag))
        .map(|tag| format!("0x{tag:x}"))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return invalid(format!("missing dynamic tags: {}", missing.join(", ")));
    }
    Ok(())
}

fn dynamic_contains_tag(output: &[u8], dynamic: SectionHeader, wanted: u64) -> Result<bool> {
    if !dynamic.size.is_multiple_of(0x10) {
        return invalid(".dynamic size is not entry-aligned");
    }
    let start = usize_from_u64(dynamic.offset, ".dynamic offset")?;
    let size = usize_from_u64(dynamic.size, ".dynamic size")?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::Invalid(".dynamic end overflow".to_owned()))?;
    slice(output, start, size)?;
    for offset in (start..end).step_by(0x10) {
        let tag = read_u64(output, offset)?;
        if tag == wanted {
            return Ok(true);
        }
        if tag == 0 {
            break;
        }
    }
    Ok(false)
}

fn required_section_indices(names: &[String]) -> Result<HashMap<&'static str, usize>> {
    let present = senbei_elf::SYMBOL_HASH_SECTION_NAMES
        .iter()
        .filter(|name| names.iter().any(|section| section == *name))
        .count();
    if present == 0 {
        return invalid(
            "ELF must carry at least one of the .gnu.hash / .hash symbol-hash sections",
        );
    }
    let mut result = HashMap::with_capacity(
        senbei_elf::DYNAMIC_SECTION_NAMES.len() + senbei_elf::SYMBOL_HASH_SECTION_NAMES.len(),
    );
    for required in senbei_elf::DYNAMIC_SECTION_NAMES {
        let indices = names
            .iter()
            .enumerate()
            .filter_map(|(index, name)| (name == required).then_some(index))
            .collect::<Vec<_>>();
        match indices.as_slice() {
            [index] => {
                result.insert(required, *index);
            }
            [] => return invalid(format!("ELF lacks required section {required}")),
            _ => return invalid(format!("ELF contains duplicate section {required}")),
        }
    }
    for hash_table in senbei_elf::SYMBOL_HASH_SECTION_NAMES {
        let indices = names
            .iter()
            .enumerate()
            .filter_map(|(index, name)| (name == hash_table).then_some(index))
            .collect::<Vec<_>>();
        match indices.as_slice() {
            [index] => {
                result.insert(hash_table, *index);
            }
            [] => {}
            _ => return invalid(format!("ELF contains duplicate section {hash_table}")),
        }
    }
    Ok(result)
}

fn metadata_capacity_end(
    layout: &ElfLayout,
    indices: &HashMap<&'static str, usize>,
    metadata_start: u64,
) -> Result<u64> {
    let table_indices = indices.values().copied().collect::<HashSet<_>>();
    let file_end = layout.private_section()?.offset;
    let next_section = layout
        .section_headers
        .iter()
        .enumerate()
        .filter(|(index, section)| {
            !table_indices.contains(index)
                && section.section_type != SHT_NOBITS
                && section.size != 0
                && section.offset >= metadata_start
        })
        .map(|(_, section)| section.offset)
        .min()
        .unwrap_or(file_end);
    let capacity_end = next_section.min(file_end);
    // A zero-length window is a valid result: the caller can move the whole
    // table set to a new PT_LOAD instead of overwriting an adjacent section.
    Ok(capacity_end.max(metadata_start))
}

fn metadata_mapping_length(
    source: &[u8],
    layout: &ElfLayout,
    auxiliary_data: &[u8],
) -> Result<usize> {
    let names = layout.section_names(source)?;
    let indices = required_section_indices(&names)?;
    let section = |name: &'static str| -> SectionHeader { layout.section_headers[indices[name]] };
    let dynsym = section(".dynsym");
    let versym = section(".gnu.version");
    let verneed = section(".gnu.version_r");
    let dynstr = section(".dynstr");
    let rela_dyn = section(".rela.dyn");
    let rela_plt = section(".rela.plt");
    if dynsym.entry_size != ELF64_SYMBOL_SIZE as u64
        || dynsym.size % ELF64_SYMBOL_SIZE as u64 != 0
        || versym.entry_size != 2
        || rela_dyn.entry_size != ELF64_RELA_SIZE as u64
        || rela_plt.entry_size != ELF64_RELA_SIZE as u64
        || rela_dyn.size % ELF64_RELA_SIZE as u64 != 0
        || rela_plt.size % ELF64_RELA_SIZE as u64 != 0
    {
        return invalid("unexpected dynamic-table entry layout");
    }
    let auxiliary = AuxiliaryElfImage::parse(auxiliary_data)?;
    let old_symbol_count = usize_from_u64(
        dynsym.size / ELF64_SYMBOL_SIZE as u64,
        "dynamic symbol count",
    )?;
    let auxiliary_appended_count =
        usize::try_from(auxiliary.dynsym_count.checked_sub(1).ok_or_else(|| {
            Error::Invalid("auxiliary symbol table has no null entry".to_owned())
        })?)
        .map_err(|_| Error::Invalid("auxiliary symbol count exceeds usize".to_owned()))?;
    // The legacy 212-symbol auxiliary format omits five libc imports that are
    // reconstructed during materialization. Keep sizing conservative here: the
    // protected table still includes three protector-only symbols that will be
    // removed later, so reserving from the raw count intentionally overallocates
    // by three entries rather than depending on unrelated relocation slack.
    let special_count = SPECIAL_PLT_IMPORT_NAMES.len();
    let appended_count = auxiliary_appended_count
        .checked_add(special_count)
        .ok_or_else(|| Error::Invalid("appended dynamic symbol count overflow".to_owned()))?;
    let new_symbol_count = old_symbol_count
        .checked_add(appended_count)
        .ok_or_else(|| Error::Invalid("merged dynamic symbol count overflow".to_owned()))?;
    let special_string_size = SPECIAL_PLT_IMPORT_NAMES
        .iter()
        .map(|name| name.len() + 1)
        .sum();
    let merged_dynstr_size = usize_from_u64(dynstr.size, ".dynstr size")?
        .checked_add(auxiliary.dynstr_size as usize)
        .and_then(|size| size.checked_add(special_string_size))
        .ok_or_else(|| Error::Invalid("merged dynamic string size overflow".to_owned()))?;
    let merged_rela_dyn_count =
        usize_from_u64(rela_dyn.size / ELF64_RELA_SIZE as u64, ".rela.dyn count")?
            .checked_add(auxiliary.relocation1_count as usize)
            .and_then(|count| count.checked_add(auxiliary.relocation2_count as usize))
            .ok_or_else(|| Error::Invalid("merged .rela.dyn count overflow".to_owned()))?;
    let merged_rela_plt_count =
        usize_from_u64(rela_plt.size / ELF64_RELA_SIZE as u64, ".rela.plt count")?
            .checked_add(auxiliary.relocation2_count as usize)
            .and_then(|count| count.checked_add(special_count))
            .ok_or_else(|| Error::Invalid("merged .rela.plt count overflow".to_owned()))?;
    let gnu_hash_size = if indices.contains_key(".gnu.hash") {
        28_usize
            .checked_add(
                new_symbol_count
                    .checked_sub(1)
                    .ok_or_else(|| {
                        Error::Invalid("dynamic symbol table is unexpectedly empty".to_owned())
                    })?
                    .checked_mul(4)
                    .ok_or_else(|| Error::Invalid("GNU hash size overflow".to_owned()))?,
            )
            .ok_or_else(|| Error::Invalid("GNU hash size overflow".to_owned()))?
    } else {
        0
    };
    let sysv_hash_size = indices.contains_key(".hash").then(|| {
        new_symbol_count
            .checked_mul(2)
            .and_then(|count| count.checked_add(2))
            .and_then(|count| count.checked_mul(4))
            .ok_or_else(|| Error::Invalid("SysV hash size overflow".to_owned()))
    });
    let sysv_hash_size = match sysv_hash_size {
        Some(size) => size?,
        None => 0,
    };
    let program_header_reservation = u64::try_from(layout.additional_program_header_reservation()?)
        .map_err(|_| Error::Invalid("program-header reservation exceeds u64".to_owned()))?;
    let mut cursor = program_header_reservation;
    for (size, alignment) in [
        (
            new_symbol_count
                .checked_mul(ELF64_SYMBOL_SIZE)
                .ok_or_else(|| Error::Invalid("merged .dynsym size overflow".to_owned()))?,
            8,
        ),
        (
            usize_from_u64(versym.size, ".gnu.version size")?
                .checked_add(appended_count.checked_mul(2).ok_or_else(|| {
                    Error::Invalid("merged .gnu.version size overflow".to_owned())
                })?)
                .ok_or_else(|| Error::Invalid("merged .gnu.version size overflow".to_owned()))?,
            2,
        ),
        (usize_from_u64(verneed.size, ".gnu.version_r size")?, 4),
        (gnu_hash_size, 8),
        (sysv_hash_size, 4),
        (merged_dynstr_size, 1),
        (
            merged_rela_dyn_count
                .checked_mul(ELF64_RELA_SIZE)
                .ok_or_else(|| Error::Invalid("merged .rela.dyn size overflow".to_owned()))?,
            8,
        ),
        (
            merged_rela_plt_count
                .checked_mul(ELF64_RELA_SIZE)
                .ok_or_else(|| Error::Invalid("merged .rela.plt size overflow".to_owned()))?,
            8,
        ),
    ] {
        cursor = align_up(cursor, alignment)?;
        cursor = cursor
            .checked_add(size as u64)
            .ok_or_else(|| Error::Invalid("dynamic-table reserve overflow".to_owned()))?;
    }
    let extension_alignment = layout.load_alignment()?;
    let extension_start = align_up(layout.private_section()?.offset, extension_alignment)?;
    let end = extension_start
        .checked_add(cursor)
        .ok_or_else(|| Error::Invalid("dynamic-table mapping end overflow".to_owned()))?;
    Ok(usize_from_u64(end, "dynamic-table mapping length")?)
}

fn table_placements(
    tables: &[TablePayload],
    start: u64,
) -> Result<(BTreeMap<String, PlacementReport>, u64)> {
    let mut cursor = start;
    let mut placements = BTreeMap::new();
    for table in tables {
        cursor = align_up(cursor, table.alignment)?;
        placements.insert(
            table.name.to_owned(),
            PlacementReport {
                offset: cursor,
                size: table.data.len(),
            },
        );
        cursor = cursor
            .checked_add(table.data.len() as u64)
            .ok_or_else(|| Error::Invalid("rebuilt ELF metadata end overflow".to_owned()))?;
    }
    Ok((placements, cursor))
}

fn table_end(tables: &[TablePayload], start: u64) -> Result<u64> {
    table_placements(tables, start).map(|(_, end)| end)
}

fn materialize_static_elf_tables(
    output: &mut [u8],
    source: &[u8],
    layout: &ElfLayout,
    symbol_patch_data: &[u8],
    auxiliary_data: &[u8],
    auxiliary_symbol_seed: Option<u32>,
    constructor_module: Option<&[u8]>,
) -> Result<(ElfLayout, ElfMaterializationReport, u64)> {
    let names = layout.section_names(source)?;
    let indices = required_section_indices(&names)?;
    let section = |name: &'static str| -> SectionHeader { layout.section_headers[indices[name]] };
    let dynsym = section(".dynsym");
    let dynstr = section(".dynstr");
    let versym = section(".gnu.version");
    let verneed = section(".gnu.version_r");
    let rela_dyn = section(".rela.dyn");
    let rela_plt = section(".rela.plt");
    let dynamic = section(".dynamic");

    let (mut old_symbols, old_strings, hidden_symbols) =
        restore_hidden_symbols(output, dynsym, dynstr, symbol_patch_data)?;
    let source_symbol_count = old_symbols.len() / ELF64_SYMBOL_SIZE;
    if versym.size != (source_symbol_count * 2) as u64 {
        return invalid(".gnu.version count does not match .dynsym");
    }
    let mut old_versions = slice_u64(output, versym.offset, versym.size)?.to_vec();
    let version_requirements = slice_u64(output, verneed.offset, verneed.size)?.to_vec();

    let auxiliary = AuxiliaryElfImage::parse(auxiliary_data)?;
    let old_names = dynamic_symbol_names(&old_symbols, &old_strings)?;
    let protector_names = ["dlerror", "__stack_chk_guard", "__stack_chk_fail"];
    let protector_tail_start = usize::try_from(hidden_symbols.last_target_index.saturating_add(1))
        .map_err(|_| Error::Invalid("protector symbol index exceeds usize".to_owned()))?;
    let protector_symbol_range = if protector_tail_start < source_symbol_count {
        let tail = &old_names[protector_tail_start..];
        if tail.iter().all(|name| {
            protector_names
                .iter()
                .any(|protector| name.as_slice() == protector.as_bytes())
        }) {
            old_symbols.truncate(protector_tail_start * ELF64_SYMBOL_SIZE);
            old_versions.truncate(protector_tail_start * 2);
            Some((
                u64::try_from(protector_tail_start)
                    .map_err(|_| Error::Invalid("protector symbol index exceeds u64".to_owned()))?,
                u64::try_from(source_symbol_count)
                    .map_err(|_| Error::Invalid("source symbol count exceeds u64".to_owned()))?,
            ))
        } else {
            None
        }
    } else {
        None
    };
    let old_symbol_count = old_symbols.len() / ELF64_SYMBOL_SIZE;
    let auxiliary_strings = slice(
        auxiliary_data,
        auxiliary.dynstr_offset as usize,
        auxiliary.dynstr_size as usize,
    )?;
    let auxiliary_appended_count =
        usize::try_from(auxiliary.dynsym_count.checked_sub(1).ok_or_else(|| {
            Error::Invalid("auxiliary symbol table has no null entry".to_owned())
        })?)
        .map_err(|_| Error::Invalid("auxiliary symbol count exceeds usize".to_owned()))?;
    let mut appended_symbols = Vec::with_capacity(auxiliary_appended_count * ELF64_SYMBOL_SIZE);
    for index in 1..auxiliary.dynsym_count as usize {
        let offset = auxiliary.dynsym_offset as usize + index * ELF64_SYMBOL_SIZE;
        let symbol = slice(auxiliary_data, offset, ELF64_SYMBOL_SIZE)?;
        let name_offset = read_u32(symbol, 0)? as usize;
        read_c_string(auxiliary_strings, name_offset, auxiliary_strings.len())?;
        let section_index = u16::from_le_bytes([symbol[6], symbol[7]]);
        if section_index != 0 {
            return invalid("auxiliary dynamic symbol is unexpectedly defined");
        }
        let merged_name_offset = old_strings
            .len()
            .checked_add(name_offset)
            .ok_or_else(|| Error::Invalid("merged dynamic string offset overflow".to_owned()))?;
        let merged_name_offset = u32::try_from(merged_name_offset)
            .map_err(|_| Error::Invalid("merged dynamic string offset exceeds u32".to_owned()))?;
        appended_symbols.extend_from_slice(&merged_name_offset.to_le_bytes());
        appended_symbols.extend_from_slice(&symbol[4..]);
    }
    let mut merged_symbols = Vec::with_capacity(old_symbols.len() + appended_symbols.len());
    merged_symbols.extend_from_slice(&old_symbols);
    merged_symbols.extend_from_slice(&appended_symbols);
    let mut merged_strings = Vec::with_capacity(old_strings.len() + auxiliary_strings.len() + 64);
    merged_strings.extend_from_slice(&old_strings);
    merged_strings.extend_from_slice(auxiliary_strings);
    let mut merged_versions =
        Vec::with_capacity(old_versions.len() + (auxiliary_appended_count + 5) * 2);
    merged_versions.extend_from_slice(&old_versions);
    for _ in 0..auxiliary_appended_count {
        merged_versions.extend_from_slice(&VER_NDX_GLOBAL.to_le_bytes());
    }
    if rela_dyn.entry_size != ELF64_RELA_SIZE as u64
        || rela_plt.entry_size != ELF64_RELA_SIZE as u64
        || rela_dyn.size % ELF64_RELA_SIZE as u64 != 0
        || rela_plt.size % ELF64_RELA_SIZE as u64 != 0
    {
        return invalid("unexpected relocation entry layout");
    }
    let old_dyn = RelocationTable {
        data: output,
        offset: usize_from_u64(rela_dyn.offset, ".rela.dyn offset")?,
        count: usize_from_u64(rela_dyn.size / ELF64_RELA_SIZE as u64, ".rela.dyn count")?,
        remap: None,
    };
    let old_plt = RelocationTable {
        data: output,
        offset: usize_from_u64(rela_plt.offset, ".rela.plt offset")?,
        count: usize_from_u64(rela_plt.size / ELF64_RELA_SIZE as u64, ".rela.plt count")?,
        remap: None,
    };
    let auxiliary1 = RelocationTable {
        data: auxiliary_data,
        offset: auxiliary.relocation1_offset as usize,
        count: auxiliary.relocation1_count as usize,
        remap: Some(RelocationRemap {
            base_symbol_count: old_symbol_count,
            auxiliary_symbol_count: auxiliary.dynsym_count,
            permutation_seed: auxiliary_symbol_seed,
        }),
    };
    let auxiliary2 = RelocationTable {
        data: auxiliary_data,
        offset: auxiliary.relocation2_offset as usize,
        count: auxiliary.relocation2_count as usize,
        remap: Some(RelocationRemap {
            base_symbol_count: old_symbol_count,
            auxiliary_symbol_count: auxiliary.dynsym_count,
            permutation_seed: auxiliary_symbol_seed,
        }),
    };
    old_dyn.validate(
        &[R_AARCH64_RELATIVE, R_AARCH64_GLOB_DAT, R_AARCH64_ABS64],
        "existing .rela.dyn",
    )?;
    old_plt.validate(&[R_AARCH64_JUMP_SLOT], "existing .rela.plt")?;
    auxiliary1.validate(
        &[R_AARCH64_RELATIVE, R_AARCH64_GLOB_DAT, R_AARCH64_ABS64],
        "auxiliary relocation table 1",
    )?;
    auxiliary2.validate(
        &[R_AARCH64_RELATIVE, R_AARCH64_JUMP_SLOT],
        "auxiliary relocation table 2",
    )?;

    let old_dyn_relocations = old_dyn.collect_where(|relocation| {
        !relocation_references_symbol_range(relocation, protector_symbol_range)
    })?;
    let old_plt_relocations = old_plt.collect_where(|relocation| {
        !relocation_references_symbol_range(relocation, protector_symbol_range)
    })?;
    let auxiliary1_relocations = auxiliary1.collect_where(|_| true)?;
    let auxiliary2_relocations = auxiliary2.collect_where(|_| true)?;

    let special_imports = discover_special_plt_imports(
        output,
        layout,
        &names,
        &old_plt_relocations,
        &auxiliary2_relocations,
    )?;
    let existing_names = dynamic_symbol_names(&merged_symbols, &merged_strings)?;
    for &name in &SPECIAL_PLT_IMPORT_NAMES {
        if existing_names
            .iter()
            .any(|existing| existing.as_slice() == name.as_bytes())
            && special_imports.iter().any(|(_, special)| *special == name)
        {
            return invalid(format!(
                "special PLT import {name} already exists in the dynamic symbol table"
            ));
        }
    }
    let mut special_plt_symbols = Vec::with_capacity(special_imports.len());
    for &(slot, name) in &special_imports {
        let symbol =
            append_undefined_function_symbol(&mut merged_symbols, &mut merged_strings, name)?;
        merged_versions.extend_from_slice(&VER_NDX_GLOBAL.to_le_bytes());
        special_plt_symbols.push((slot, symbol));
    }
    let appended_count = auxiliary_appended_count + special_plt_symbols.len();
    let merged_names = dynamic_symbol_names(&merged_symbols, &merged_strings)?;
    let sysv_hash = indices
        .contains_key(".hash")
        .then(|| build_sysv_hash(&merged_names))
        .transpose()?;
    let gnu_hash_table = indices
        .contains_key(".gnu.hash")
        .then(|| build_gnu_hash(&merged_names))
        .transpose()?;
    let new_symbol_count = merged_names.len();
    let new_dynstr_size = merged_strings.len();

    let constructors = match constructor_module {
        Some(module) => {
            let init_index = names
                .iter()
                .position(|name| name == ".init_array")
                .ok_or_else(|| {
                    Error::Invalid(
                        "constructor control module 0x98 is present but .init_array is missing"
                            .to_owned(),
                    )
                })?;
            let fini_index = names
                .iter()
                .position(|name| name == ".fini_array")
                .ok_or_else(|| {
                    Error::Invalid(
                        "constructor control module 0x98 is present but .fini_array is missing"
                            .to_owned(),
                    )
                })?;
            let init_array = layout.section_headers[init_index];
            let fini_array = layout.section_headers[fini_index];
            let profile =
                constructor_profile(module, output, layout, init_array, fini_array, old_dyn)?
                    .ok_or_else(|| {
                        Error::Invalid(
                            "constructor control module 0x98 has no validated constructor table"
                                .to_owned(),
                        )
                    })?;
            Some((profile, init_index, fini_index, init_array, fini_array))
        }
        None => None,
    };

    let got_plt_index = names
        .iter()
        .position(|name| name == ".got.plt")
        .ok_or_else(|| Error::Invalid("restored image lacks .got.plt".to_owned()))?;
    let got_plt = layout.section_headers[got_plt_index];
    if got_plt.size < 0x18 || !(got_plt.size - 0x18).is_multiple_of(8) {
        return invalid(".got.plt has an invalid slot layout");
    }
    let slot_count = usize_from_u64((got_plt.size - 0x18) / 8, ".got.plt slot count")?;
    let first_slot = got_plt
        .address
        .checked_add(0x18)
        .ok_or_else(|| Error::Invalid(".got.plt slot address overflow".to_owned()))?;
    let slot_end = first_slot
        .checked_add((slot_count as u64) * 8)
        .ok_or_else(|| Error::Invalid(".got.plt slot end overflow".to_owned()))?;

    let old_plt_outside = old_plt_relocations
        .iter()
        .copied()
        .filter(|relocation| relocation.offset < first_slot || relocation.offset >= slot_end)
        .collect::<Vec<_>>();
    if old_plt_outside.iter().any(|relocation| {
        let symbol = relocation.symbol() as usize;
        symbol < old_symbol_count || symbol >= source_symbol_count
    }) {
        return invalid("protected .rela.plt has a non-protector target outside .got.plt");
    }
    let mut plt_relocations = old_plt_relocations
        .iter()
        .copied()
        .filter(|relocation| relocation.offset >= first_slot && relocation.offset < slot_end)
        .collect::<Vec<_>>();
    plt_relocations.extend(
        auxiliary2_relocations
            .iter()
            .copied()
            .filter(|relocation| relocation.offset >= first_slot && relocation.offset < slot_end),
    );
    for &(slot, symbol) in &special_plt_symbols {
        let offset = first_slot
            .checked_add((slot as u64) * 8)
            .ok_or_else(|| Error::Invalid("special PLT slot overflow".to_owned()))?;
        let symbol = u64::try_from(symbol)
            .map_err(|_| Error::Invalid("special symbol index exceeds u64".to_owned()))?;
        plt_relocations.push(Rela {
            offset,
            info: (symbol << 32) | u64::from(R_AARCH64_JUMP_SLOT),
            addend: 0,
        });
    }
    plt_relocations.sort_by_key(|relocation| relocation.offset);
    if plt_relocations.len() != slot_count {
        return invalid(format!(
            "PLT restoration produced {} slots, expected {slot_count}",
            plt_relocations.len()
        ));
    }
    for (slot, relocation) in plt_relocations.iter().enumerate() {
        let expected = first_slot + (slot as u64) * 8;
        if relocation.offset != expected {
            return invalid(format!(
                "PLT slot {slot} targets 0x{:x}, expected 0x{expected:x}",
                relocation.offset
            ));
        }
    }

    let mut dyn_relocations = old_dyn_relocations;
    dyn_relocations.extend(auxiliary1_relocations);
    let auxiliary2_dynamic = auxiliary2_relocations
        .iter()
        .copied()
        .filter(|relocation| relocation.offset < first_slot || relocation.offset >= slot_end)
        .collect::<Vec<_>>();
    if auxiliary2_dynamic.iter().any(|relocation| {
        !matches!(
            relocation.kind(),
            R_AARCH64_RELATIVE | R_AARCH64_GLOB_DAT | R_AARCH64_ABS64
        )
    }) {
        return invalid("auxiliary PLT table has a non-PLT relocation of an unsupported type");
    }
    dyn_relocations.extend(auxiliary2_dynamic);

    convert_defined_symbol_relocations(&mut dyn_relocations, &merged_symbols)?;
    dyn_relocations
        .sort_by_key(|relocation| (relocation.kind() != R_AARCH64_RELATIVE, relocation.offset));
    let relative_count = dyn_relocations
        .iter()
        .take_while(|relocation| relocation.kind() == R_AARCH64_RELATIVE)
        .count();

    if let Some((profile, _, _, init_array, fini_array)) = &constructors {
        for (slot, &addend) in profile.init_addends.iter().enumerate() {
            let target = init_array
                .address
                .checked_add((slot as u64) * 8)
                .ok_or_else(|| Error::Invalid("init relocation target overflow".to_owned()))?;
            let matches = dyn_relocations
                .iter()
                .enumerate()
                .filter_map(|(index, relocation)| (relocation.offset == target).then_some(index))
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return invalid(format!(
                    "init slot {slot} has {} relocation records",
                    matches.len()
                ));
            }
            let relocation = &mut dyn_relocations[matches[0]];
            if relocation.kind() != R_AARCH64_RELATIVE || relocation.symbol() != 0 {
                return invalid(format!("init slot {slot} is not RELATIVE"));
            }
            relocation.addend = i64::try_from(addend)
                .map_err(|_| Error::Invalid("constructor RVA exceeds i64".to_owned()))?;
        }
        let matches = dyn_relocations
            .iter()
            .enumerate()
            .filter_map(|(index, relocation)| {
                (relocation.offset == fini_array.address).then_some(index)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return invalid(format!(
                "fini slot has {} relocation records",
                matches.len()
            ));
        }
        let relocation = &mut dyn_relocations[matches[0]];
        if relocation.kind() != R_AARCH64_RELATIVE || relocation.symbol() != 0 {
            return invalid("fini slot is not RELATIVE");
        }
        relocation.addend = i64::try_from(profile.fini_addend)
            .map_err(|_| Error::Invalid("fini RVA exceeds i64".to_owned()))?;
    }

    let mut merged_rela_dyn = Vec::with_capacity(dyn_relocations.len() * ELF64_RELA_SIZE);
    for relocation in dyn_relocations {
        relocation.encode(&mut merged_rela_dyn);
    }
    let mut merged_rela_plt = Vec::with_capacity(plt_relocations.len() * ELF64_RELA_SIZE);
    for relocation in plt_relocations {
        relocation.encode(&mut merged_rela_plt);
    }
    let rela_dyn_count = merged_rela_dyn.len() / ELF64_RELA_SIZE;
    let rela_plt_count = merged_rela_plt.len() / ELF64_RELA_SIZE;

    if let Some((profile, _, _, init_array, fini_array)) = &constructors {
        let init_start = usize_from_u64(init_array.offset, "init-array offset")?;
        let init_size = usize_from_u64(init_array.size, "init-array size")?;
        output
            .get_mut(init_start..init_start + init_size)
            .ok_or_else(|| Error::Invalid("init-array exceeds output".to_owned()))?
            .fill(0);
        for (slot, &addend) in profile.init_addends.iter().enumerate() {
            let start = init_start + slot * 8;
            output[start..start + 8].copy_from_slice(&addend.to_le_bytes());
        }
        let fini_start = usize_from_u64(fini_array.offset, "fini-array offset")?;
        let fini_size = usize_from_u64(fini_array.size, "fini-array size")?;
        output
            .get_mut(fini_start..fini_start + fini_size)
            .ok_or_else(|| Error::Invalid("fini-array exceeds output".to_owned()))?
            .fill(0);
        output[fini_start..fini_start + 8].copy_from_slice(&profile.fini_addend.to_le_bytes());
    }

    let gnu_hash = gnu_hash_table.map(|data| TablePayload {
        name: ".gnu.hash",
        alignment: 8,
        data,
    });
    let mut tables = vec![
        TablePayload {
            name: ".dynsym",
            alignment: 8,
            data: merged_symbols,
        },
        TablePayload {
            name: ".gnu.version",
            alignment: 2,
            data: merged_versions,
        },
        TablePayload {
            name: ".gnu.version_r",
            alignment: 4,
            data: version_requirements,
        },
    ];
    if let Some(payload) = gnu_hash {
        tables.push(payload);
    }
    if let Some(data) = sysv_hash {
        tables.push(TablePayload {
            name: ".hash",
            alignment: 4,
            data,
        });
    }
    tables.extend([
        TablePayload {
            name: ".dynstr",
            alignment: 1,
            data: merged_strings,
        },
        TablePayload {
            name: ".rela.dyn",
            alignment: 8,
            data: merged_rela_dyn,
        },
        TablePayload {
            name: ".rela.plt",
            alignment: 8,
            data: merged_rela_plt,
        },
    ]);
    let mut placement_layout = layout.clone();
    let mut metadata_start = dynsym.offset;
    let (mut placements, mut cursor) = table_placements(&tables, metadata_start)?;
    let mut capacity_end = metadata_capacity_end(layout, &indices, metadata_start)?;
    if cursor > capacity_end {
        let alignment = layout.load_alignment()?;
        let program_header_reservation = layout.additional_program_header_reservation()?;
        let extension_start = align_up(layout.private_section()?.offset, alignment)?;
        let extension_metadata_start = extension_start
            .checked_add(program_header_reservation as u64)
            .ok_or_else(|| Error::Invalid("dynamic-table extension start overflow".to_owned()))?;
        let extension_end = table_end(&tables, extension_metadata_start)?;
        let extension_size = extension_end
            .checked_sub(extension_start)
            .ok_or_else(|| Error::Invalid("dynamic-table extension underflow".to_owned()))?;
        let extension_address = align_up(layout.load_end()?, alignment)?;
        placement_layout = layout.append_load_segment(
            output,
            LoadSegment {
                offset: extension_start,
                virtual_address: extension_address,
                file_size: extension_size,
                memory_size: extension_size,
                flags: PF_R,
                alignment,
            },
            program_header_reservation,
        )?;
        metadata_start = extension_metadata_start;
        (placements, cursor) = table_placements(&tables, metadata_start)?;
        capacity_end = cursor;
    }
    let zero_start = usize_from_u64(dynsym.offset, "metadata start")?;
    let zero_end = usize_from_u64(
        metadata_capacity_end(layout, &indices, dynsym.offset)?,
        "metadata capacity end",
    )?;
    output
        .get_mut(zero_start..zero_end)
        .ok_or_else(|| Error::Invalid("metadata capacity exceeds output mapping".to_owned()))?
        .fill(0);
    if metadata_start != dynsym.offset {
        let extension_start = usize_from_u64(metadata_start, "dynamic-table extension start")?;
        let extension_end = usize_from_u64(cursor, "dynamic-table extension end")?;
        output
            .get_mut(extension_start..extension_end)
            .ok_or_else(|| {
                Error::Invalid("dynamic-table extension exceeds output mapping".to_owned())
            })?
            .fill(0);
    }

    let mut updated_sections = layout.section_headers.clone();
    for table in &tables {
        let placement = placements
            .get(table.name)
            .ok_or_else(|| Error::Invalid("table placement disappeared".to_owned()))?;
        let offset = usize_from_u64(placement.offset, "table placement offset")?;
        let end = offset
            .checked_add(table.data.len())
            .ok_or_else(|| Error::Invalid("table placement end overflow".to_owned()))?;
        output
            .get_mut(offset..end)
            .ok_or_else(|| Error::Invalid("table placement exceeds output mapping".to_owned()))?
            .copy_from_slice(&table.data);
        let index = indices[table.name];
        let mut updated = updated_sections[index];
        updated.address = placement_layout
            .file_offset_to_virtual_address(placement.offset, table.data.len() as u64)?;
        updated.offset = placement.offset;
        updated.size = table.data.len() as u64;
        updated_sections[index] = updated;
    }
    if let Some((profile, init_index, fini_index, _, _)) = &constructors {
        let init_size = u64::try_from(profile.init_addends.len())
            .map_err(|_| Error::Invalid("constructor count exceeds u64".to_owned()))?
            .checked_mul(8)
            .ok_or_else(|| Error::Invalid("init-array size overflow".to_owned()))?;
        updated_sections[*init_index].size = init_size;
        updated_sections[*fini_index].size = 8;
    }

    let section_address = |name: &'static str| -> u64 { updated_sections[indices[name]].address };
    let mut dynamic_values = BTreeMap::from([
        (DT_PLTRELSZ, (rela_plt_count * ELF64_RELA_SIZE) as u64),
        (DT_STRTAB, section_address(".dynstr")),
        (DT_SYMTAB, section_address(".dynsym")),
        (DT_RELA, section_address(".rela.dyn")),
        (DT_RELASZ, (rela_dyn_count * ELF64_RELA_SIZE) as u64),
        (DT_STRSZ, new_dynstr_size as u64),
        (DT_JMPREL, section_address(".rela.plt")),
        (DT_VERSYM, section_address(".gnu.version")),
        (DT_VERNEED, section_address(".gnu.version_r")),
    ]);
    if let Some((profile, _, _, _, _)) = &constructors {
        let init_size = u64::try_from(profile.init_addends.len())
            .map_err(|_| Error::Invalid("constructor count exceeds u64".to_owned()))?
            .checked_mul(8)
            .ok_or_else(|| Error::Invalid("init-array size overflow".to_owned()))?;
        dynamic_values.insert(DT_INIT_ARRAYSZ, init_size);
        dynamic_values.insert(DT_FINI_ARRAYSZ, 8);
    }
    if indices.contains_key(".gnu.hash") {
        dynamic_values.insert(DT_GNU_HASH, section_address(".gnu.hash"));
    }
    if dynamic_contains_tag(output, dynamic, DT_RELACOUNT)? {
        dynamic_values.insert(DT_RELACOUNT, relative_count as u64);
    }
    if indices.contains_key(".hash") {
        dynamic_values.insert(DT_HASH, section_address(".hash"));
    }
    patch_dynamic_tags(output, dynamic, &dynamic_values)?;

    let mut restored_layout = placement_layout;
    restored_layout.section_headers = updated_sections;
    let data_end = if metadata_start == dynsym.offset {
        layout.private_section()?.offset
    } else {
        cursor
    };
    Ok((
        restored_layout,
        ElfMaterializationReport {
            hidden_symbols,
            old_symbol_count,
            auxiliary_symbol_count: auxiliary.dynsym_count,
            appended_symbols: appended_count,
            new_symbol_count,
            old_dynstr_size: old_strings.len(),
            auxiliary_dynstr_size: auxiliary.dynstr_size,
            new_dynstr_size,
            rela_dyn_count,
            rela_plt_count,
            relative_prefix_count: relative_count,
            metadata_start,
            metadata_end: cursor,
            metadata_capacity_end: capacity_end,
            metadata_slack: capacity_end.saturating_sub(cursor),
            placements,
        },
        data_end,
    ))
}

fn write_padding(file: &mut File, size: u64, path: &Path) -> Result<()> {
    const ZEROES: [u8; 4096] = [0; 4096];
    let mut remaining = size;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(ZEROES.len() as u64))
            .map_err(|_| Error::Invalid("padding size exceeds usize".to_owned()))?;
        file.write_all(&ZEROES[..count])
            .map_err(|error| Error::io("write padding", path, error))?;
        remaining -= count as u64;
    }
    Ok(())
}

fn finalize_clean_elf(
    stream: &mut File,
    temporary_path: &Path,
    source: &[u8],
    layout: &ElfLayout,
    data_start: u64,
    preserve_entrypoint: bool,
) -> Result<CleaningReport> {
    let private = layout.private_section()?;
    if data_start < private.offset {
        return invalid("ELF data start precedes the private section");
    }
    let names = layout.section_names(source)?;
    if layout.private_section_index + 1 != layout.section_headers.len() {
        return invalid("SHT_LOUSER section is not the final section");
    }
    let retained = &layout.section_headers[..layout.private_section_index];
    let mut updated = Vec::with_capacity(retained.len());
    stream
        .seek(SeekFrom::Start(data_start))
        .map_err(|error| Error::io("seek temporary output", temporary_path, error))?;
    for &section in retained {
        if section.section_type == SHT_NOBITS || section.flags & SHF_ALLOC != 0 || section.size == 0
        {
            updated.push(section);
            continue;
        }
        let section_data = slice_u64(source, section.offset, section.size)?;
        let alignment = section.alignment.max(1);
        let position = stream
            .stream_position()
            .map_err(|error| Error::io("query temporary output position", temporary_path, error))?;
        let padding = (alignment - position % alignment) % alignment;
        write_padding(stream, padding, temporary_path)?;
        let new_offset = stream
            .stream_position()
            .map_err(|error| Error::io("query temporary output position", temporary_path, error))?;
        stream
            .write_all(section_data)
            .map_err(|error| Error::io("append ELF section", temporary_path, error))?;
        let mut relocated = section;
        relocated.offset = new_offset;
        updated.push(relocated);
    }
    let position = stream
        .stream_position()
        .map_err(|error| Error::io("query temporary output position", temporary_path, error))?;
    write_padding(stream, (8 - position % 8) % 8, temporary_path)?;
    let section_header_offset = stream
        .stream_position()
        .map_err(|error| Error::io("query section-header position", temporary_path, error))?;
    for section in &updated {
        stream
            .write_all(&section.encode())
            .map_err(|error| Error::io("write section header", temporary_path, error))?;
    }
    let mut elf_header = [0_u8; 0x40];
    stream
        .seek(SeekFrom::Start(0))
        .and_then(|_| stream.read_exact(&mut elf_header))
        .map_err(|error| Error::io("read ELF header", temporary_path, error))?;
    if !preserve_entrypoint {
        elf_header[0x18..0x20].copy_from_slice(&0_u64.to_le_bytes());
    }
    elf_header[0x28..0x30].copy_from_slice(&section_header_offset.to_le_bytes());
    let section_count = u16::try_from(updated.len())
        .map_err(|_| Error::Invalid("output section count exceeds u16".to_owned()))?;
    elf_header[0x3c..0x3e].copy_from_slice(&section_count.to_le_bytes());
    stream
        .seek(SeekFrom::Start(0))
        .and_then(|_| stream.write_all(&elf_header))
        .map_err(|error| Error::io("patch ELF header", temporary_path, error))?;
    stream
        .flush()
        .and_then(|_| stream.sync_all())
        .map_err(|error| Error::io("flush temporary output", temporary_path, error))?;
    Ok(CleaningReport {
        private_section_index: layout.private_section_index,
        private_offset: private.offset,
        private_size: private.size,
        input_entrypoint: layout.entrypoint,
        output_entrypoint: if preserve_entrypoint {
            layout.entrypoint
        } else {
            0
        },
        output_section_count: updated.len(),
        retained_sections: names[..layout.private_section_index].to_vec(),
        section_header_offset,
    })
}

fn section_by_name<'a>(
    layout: &'a ElfLayout,
    names: &[String],
    wanted: &str,
) -> Result<&'a SectionHeader> {
    let indices = names
        .iter()
        .enumerate()
        .filter_map(|(index, name)| (name == wanted).then_some(index))
        .collect::<Vec<_>>();
    match indices.as_slice() {
        [index] => Ok(&layout.section_headers[*index]),
        [] => invalid(format!("restored ELF lacks {wanted}")),
        _ => invalid(format!("restored ELF contains duplicate {wanted}")),
    }
}

fn validate_restored_binary(
    data: &[u8],
    preserve_entrypoint: bool,
    materialization: Option<&ElfMaterializationReport>,
) -> Result<ValidationReport> {
    let layout = ElfLayout::parse(data, false)?;
    let has_louser = layout
        .section_headers
        .iter()
        .any(|section| section.section_type == SHT_LOUSER);
    if has_louser {
        return invalid("restored output still contains SHT_LOUSER");
    }
    if !preserve_entrypoint && layout.entrypoint != 0 {
        return invalid("restored output retains the protector entrypoint");
    }
    let names = layout.section_names(data)?;
    let dynsym = section_by_name(&layout, &names, ".dynsym")?;
    let rela_dyn = section_by_name(&layout, &names, ".rela.dyn")?;
    let rela_plt = section_by_name(&layout, &names, ".rela.plt")?;
    let dynamic_symbols = usize_from_u64(
        dynsym.size / ELF64_SYMBOL_SIZE as u64,
        "restored dynamic symbol count",
    )?;
    let dynamic_relocations = usize_from_u64(
        rela_dyn.size / ELF64_RELA_SIZE as u64,
        "restored dynamic relocation count",
    )?;
    let pltgot_relocations = usize_from_u64(
        rela_plt.size / ELF64_RELA_SIZE as u64,
        "restored PLT relocation count",
    )?;
    if let Some(expected) = materialization
        && (dynamic_symbols != expected.new_symbol_count
            || dynamic_relocations != expected.rela_dyn_count
            || pltgot_relocations != expected.rela_plt_count)
    {
        return invalid("restored ELF table counts do not match materialization report");
    }
    Ok(ValidationReport {
        format: "ELF64".to_owned(),
        machine: "AARCH64".to_owned(),
        sections: layout.section_headers.len(),
        segments: layout.program_headers.len(),
        dynamic_symbols,
        dynamic_relocations,
        pltgot_relocations,
        has_louser,
    })
}

fn absolute(path: &Path) -> Result<PathBuf> {
    common::absolute(path).map_err(|error| Error::io("query current directory", path, error))
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    common::write_atomic(path, data).map_err(|error| Error::io("write temporary file", path, error))
}

/// Restore the current protected `libil2cpp.so` without executing protector code.
pub fn restore_libil2cpp(options: &RestoreOptions) -> Result<RestoreReport> {
    let started = Instant::now();
    let input_path = absolute(&options.input)?;
    let output_path = absolute(&options.output)?;
    let index_path = absolute(&options.index)?;
    if input_path == output_path
        || (output_path.exists()
            && std::fs::canonicalize(&input_path).ok() == std::fs::canonicalize(&output_path).ok())
    {
        return invalid("refusing to overwrite the protected input in place");
    }
    let artifacts = load_artifacts(&index_path)?;
    let module = read_file(&artifacts[&0x9b].path)?;
    let symbol_patch_data = read_file(&artifacts[&0x9e].path)?;
    let auxiliary_symbol_seed = artifacts
        .get(&0x96)
        .map(|artifact| read_file(&artifact.path))
        .transpose()?
        .as_deref()
        .map(discover_auxiliary_symbol_seed)
        .transpose()?;
    let constructor_module = artifacts
        .get(&0x98)
        .map(|artifact| read_file(&artifact.path))
        .transpose()?;
    let config = Module9bConfig::parse(&module)?;

    let input_file = File::open(&input_path)
        .map_err(|error| Error::io("open protected input", &input_path, error))?;
    let source = map_read_only(&input_file, &input_path)?;
    let payload_path = &artifacts[&0x9d].path;
    let payload_file = File::open(payload_path)
        .map_err(|error| Error::io("open 0x9D artifact", payload_path, error))?;
    let payload = map_read_only(&payload_file, payload_path)?;
    let layout = ElfLayout::parse(&source, true)?;
    let private = layout.private_section()?;
    let file_load_end = layout.file_load_end()?;
    let aligned_load_end = align_up(file_load_end, 0x10)?;
    if private.offset != aligned_load_end {
        return invalid(format!(
            "SHT_LOUSER offset 0x{:x} != aligned file-backed PT_LOAD end 0x{aligned_load_end:x} (raw 0x{file_load_end:x})",
            private.offset
        ));
    }
    let load_padding = slice_u64(&source, file_load_end, private.offset - file_load_end)?;
    if load_padding.iter().any(|&byte| byte != 0) {
        return invalid(format!(
            "nonzero padding between PT_LOAD end 0x{file_load_end:x} and SHT_LOUSER 0x{:x}",
            private.offset
        ));
    }
    let descriptor = ProtectedDescriptor::decrypt(&payload, config.header_seed)?;
    let load_end = layout.load_end()?;
    if u64::from(descriptor.outer_expected_size) != load_end {
        return invalid(format!(
            "0x9D target size 0x{:x} != ELF load size 0x{load_end:x}",
            descriptor.outer_expected_size
        ));
    }
    let outer = ContainerHeader::parse(
        &payload,
        descriptor.outer_offset as usize,
        config.container_seed,
    )?;
    if u64::from(outer.output_size) != load_end {
        return invalid(format!(
            "primary container output 0x{:x} != ELF load size 0x{load_end:x}",
            outer.output_size
        ));
    }
    let auxiliary_header = ContainerHeader::parse(
        &payload,
        descriptor.auxiliary_offset as usize,
        config.container_seed,
    )?;
    if auxiliary_header.output_size != descriptor.auxiliary_expected_size {
        return invalid("auxiliary container output size does not match the 0x9D descriptor");
    }
    if outer.encoded_end()? != descriptor.auxiliary_offset as usize {
        return invalid("primary and auxiliary 0x9D containers are not contiguous");
    }

    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| Error::io("create output directory", parent, error))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| Error::io("create temporary output", parent, error))?;
    let temporary_path = temporary.path().to_path_buf();
    let private_size = usize_from_u64(private.offset, "private section offset")?;
    copy_range(
        &source,
        temporary.as_file_mut(),
        private_size,
        &temporary_path,
    )?;
    temporary
        .as_file_mut()
        .flush()
        .map_err(|error| Error::io("flush initial output", &temporary_path, error))?;
    temporary
        .as_file()
        .set_len(private.offset)
        .map_err(|error| Error::io("size temporary output", &temporary_path, error))?;

    let mut restored_layout = layout.clone();
    let mut auxiliary_stats = None;
    let mut materialization = None;
    let mut temporary_end = private.offset;
    let primary_stats;
    {
        let mut output = map_mut(temporary.as_file(), private_size, &temporary_path)?;
        if options.verbose {
            eprintln!("Decoding primary 0x9D target-image container...");
        }
        let mut writer = FileLayoutWriter {
            output: &mut output,
            layout: &layout,
            load_end,
        };
        primary_stats = decode_container(
            &payload,
            &outer,
            &config,
            options.verbose,
            |address, data| writer.write(address, data),
        )?;
        output
            .flush()
            .map_err(|error| Error::io("flush restored image", &temporary_path, error))?;
    }

    if !options.outer_only {
        if options.verbose {
            eprintln!("Decoding auxiliary 0x9D ELF materialization container...");
        }
        let mut decoded = vec![0_u8; auxiliary_header.output_size as usize];
        let stats = decode_container(
            &payload,
            &auxiliary_header,
            &config,
            options.verbose,
            |offset, data| {
                let start = usize_from_u64(offset, "auxiliary write offset")?;
                let end = start
                    .checked_add(data.len())
                    .ok_or_else(|| Error::Invalid("auxiliary decoded write overflow".to_owned()))?;
                let destination = decoded.get_mut(start..end).ok_or_else(|| {
                    Error::Invalid("auxiliary decoded write is out of range".to_owned())
                })?;
                destination.copy_from_slice(data);
                Ok(data.len())
            },
        )?;
        if let Some(path) = &options.dump_auxiliary {
            write_atomic(&absolute(path)?, &decoded)?;
        }
        let mapping_length = metadata_mapping_length(&source, &layout, &decoded)?;
        if mapping_length < private_size {
            return invalid("dynamic-table mapping is shorter than the ELF image");
        }
        temporary
            .as_file()
            .set_len(mapping_length as u64)
            .map_err(|error| Error::io("extend temporary output", &temporary_path, error))?;
        if options.verbose {
            eprintln!("Rebuilding static ELF dynamic-linker tables...");
        }
        {
            let mut output = map_mut(temporary.as_file(), mapping_length, &temporary_path)?;
            let (new_layout, report, data_end) = materialize_static_elf_tables(
                &mut output,
                &source,
                &layout,
                &symbol_patch_data,
                &decoded,
                auxiliary_symbol_seed,
                constructor_module.as_deref(),
            )?;
            restored_layout = new_layout;
            materialization = Some(report);
            auxiliary_stats = Some(stats);
            temporary_end = data_end;
            output
                .flush()
                .map_err(|error| Error::io("flush restored image", &temporary_path, error))?;
        }
        temporary
            .as_file()
            .set_len(temporary_end)
            .map_err(|error| Error::io("trim temporary output", &temporary_path, error))?;
    }

    let cleaning = finalize_clean_elf(
        temporary.as_file_mut(),
        &temporary_path,
        &source,
        &restored_layout,
        temporary_end,
        options.preserve_entrypoint,
    )?;
    let validation = {
        let restored = map_read_only(temporary.as_file(), &temporary_path)?;
        validate_restored_binary(
            &restored,
            options.preserve_entrypoint,
            materialization.as_ref(),
        )?
    };
    temporary
        .persist(&output_path)
        .map_err(|error| Error::io("replace restored output", &output_path, error.error))?;

    Ok(RestoreReport {
        input: input_path.display().to_string(),
        input_sha256: sha256_file(&input_path)?,
        output: output_path.display().to_string(),
        output_sha256: sha256_file(&output_path)?,
        output_size: std::fs::metadata(&output_path)
            .map_err(|error| Error::io("inspect restored output", &output_path, error))?
            .len(),
        module_index: index_path.display().to_string(),
        static_config: StaticConfigReport {
            header_seed: format!("0x{:08X}", config.header_seed),
            container_seed: format!("0x{:08X}", config.container_seed),
            aes_key_sha256: sha256_bytes(&config.aes_key),
            schedule_offset: format!("0x{:X}", config.schedule_offset),
        },
        descriptor: DescriptorReport {
            command_id: format!("0x{:X}", descriptor.command_id),
            flags: format!("0x{:X}", descriptor.flags),
            outer_offset: format!("0x{:X}", descriptor.outer_offset),
            outer_expected_size: format!("0x{:X}", descriptor.outer_expected_size),
            auxiliary_offset: format!("0x{:X}", descriptor.auxiliary_offset),
            auxiliary_expected_size: format!("0x{:X}", descriptor.auxiliary_expected_size),
        },
        primary: primary_stats,
        auxiliary: auxiliary_stats,
        elf_materialization: materialization,
        cleaning,
        validation,
        elapsed_seconds: started.elapsed().as_secs_f64(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn auxiliary_image(symbol_count: u32) -> Vec<u8> {
        let mut data = vec![0_u8; 0x279];
        let words = [
            0x40_u32,
            0,
            0x40,
            0,
            0x278,
            1,
            0x260,
            symbol_count,
            0x40,
            3,
            0x90,
            19,
            0,
            0,
            0xb7,
            0,
        ];
        for (index, word) in words.into_iter().enumerate() {
            data[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        data
    }

    #[test]
    fn auxiliary_accepts_null_only_dynamic_symbol_table() {
        let parsed = AuxiliaryElfImage::parse(&auxiliary_image(1)).expect("null-only dynsym");
        assert_eq!(parsed.dynsym_count, 1);
    }

    #[test]
    fn auxiliary_rejects_missing_null_dynamic_symbol() {
        let error = AuxiliaryElfImage::parse(&auxiliary_image(0)).expect_err("missing null symbol");
        assert!(error.to_string().contains("no null entry"));
    }

    fn dynamic_section_names(hash_sections: &[&str]) -> Vec<String> {
        senbei_elf::DYNAMIC_SECTION_NAMES
            .into_iter()
            .chain(hash_sections.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn required_sections_accept_each_hash_layout() {
        for hashes in [
            [".gnu.hash"].as_slice(),
            [".hash"].as_slice(),
            [".gnu.hash", ".hash"].as_slice(),
        ] {
            let indices = required_section_indices(&dynamic_section_names(hashes))
                .expect("valid hash layout");
            for hash in hashes {
                assert!(indices.contains_key(hash));
            }
        }
    }

    #[test]
    fn required_sections_reject_missing_symbol_hash() {
        let error =
            required_section_indices(&dynamic_section_names(&[])).expect_err("missing hash");
        assert!(error.to_string().contains("at least one"));
    }
    #[test]
    fn seeded_auxiliary_symbol_permutation_decodes_known_vector() {
        assert_eq!(
            decode_auxiliary_symbol(120, 268, 0xd4, 0xbd93_5573).expect("decode"),
            171
        );
    }

    #[test]
    fn protector_tail_relocations_are_identified_before_auxiliary_remap() {
        let tail = Some((500, 503));
        assert!(relocation_references_symbol_range(
            Rela {
                offset: 0x1000,
                info: (501_u64 << 32) | u64::from(R_AARCH64_GLOB_DAT),
                addend: 0,
            },
            tail,
        ));
        assert!(!relocation_references_symbol_range(
            Rela {
                offset: 0x1008,
                info: (499_u64 << 32) | u64::from(R_AARCH64_GLOB_DAT),
                addend: 0,
            },
            tail,
        ));
    }

    #[test]
    fn converts_defined_symbol_relocations_without_profile_fingerprint() {
        let mut symbols = vec![0_u8; ELF64_SYMBOL_SIZE * 3];
        // Symbol 1 is image-defined at value 0x1234, symbol 2 is undefined.
        symbols[ELF64_SYMBOL_SIZE + 6..ELF64_SYMBOL_SIZE + 8].copy_from_slice(&1_u16.to_le_bytes());
        symbols[ELF64_SYMBOL_SIZE + 8..ELF64_SYMBOL_SIZE + 16]
            .copy_from_slice(&0x1234_u64.to_le_bytes());
        let mut relocations = vec![
            Rela {
                offset: 0x2000,
                info: (1_u64 << 32) | u64::from(R_AARCH64_GLOB_DAT),
                addend: 4,
            },
            Rela {
                offset: 0x2008,
                info: (2_u64 << 32) | u64::from(R_AARCH64_ABS64),
                addend: 0,
            },
        ];
        assert_eq!(
            convert_defined_symbol_relocations(&mut relocations, &symbols)
                .expect("convert local relocation"),
            1
        );
        assert_eq!(relocations[0].kind(), R_AARCH64_RELATIVE);
        assert_eq!(relocations[0].symbol(), 0);
        assert_eq!(relocations[0].addend, 0x1238);
        assert_eq!(relocations[1].kind(), R_AARCH64_ABS64);
        assert_eq!(relocations[1].symbol(), 2);
    }

    #[test]
    fn discovers_auxiliary_symbol_permutation_seed() {
        let mut module = vec![0_u8; 0x80];
        let seed_offset = 0x40;
        for (offset, value) in [
            (seed_offset - 0x20, 0x8f_u32),
            (seed_offset - 0x1c, 0x15ec),
            (seed_offset - 0x18, 0x81),
            (seed_offset - 0x10, 0x81),
            (seed_offset - 8, 1),
            (seed_offset - 4, 5),
            (seed_offset, 0x4db4_d9ec),
            (seed_offset + 4, 0x0a54),
            (seed_offset + 8, 0x12008),
            (seed_offset + 0x0c, 0),
        ] {
            module[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(
            discover_auxiliary_symbol_seed(&module).expect("symbol seed"),
            0x4db4_d9ec
        );
    }

    #[test]
    fn classifies_special_plt_slots_from_call_shapes() {
        let candidates = [
            (
                20,
                PltCallFeatures {
                    calls: 2427,
                    zero_arg1: 2363,
                    ..PltCallFeatures::default()
                },
            ),
            (
                71,
                PltCallFeatures {
                    calls: 58,
                    x0_to_x2: 1,
                    ..PltCallFeatures::default()
                },
            ),
            (
                136,
                PltCallFeatures {
                    calls: 76,
                    w0_zero_branch: 63,
                    ..PltCallFeatures::default()
                },
            ),
            (
                158,
                PltCallFeatures {
                    calls: 5,
                    ..PltCallFeatures::default()
                },
            ),
            (
                283,
                PltCallFeatures {
                    calls: 7,
                    pointer_zero_branch_with_immediate_arg1: 7,
                    ..PltCallFeatures::default()
                },
            ),
        ];
        assert_eq!(
            classify_special_plt_slots(&candidates).expect("special imports"),
            vec![
                (20, "memset"),
                (71, "strlen"),
                (136, "strcmp"),
                (158, "strcpy"),
                (283, "strchr"),
            ]
        );
    }

    #[test]
    fn discovers_validated_constructor_table() {
        const COUNT: usize = 43;
        let mut source = vec![0_u8; 0x1000];
        let mut module = vec![0_u8; 0x1000];
        let table = 0x40;
        module[table..table + 4].copy_from_slice(&(COUNT as u32).to_le_bytes());
        for index in 0..COUNT {
            let constructor = 0x100 + index * 4;
            let fallback = 0x500 + index * 4;
            let instruction = 0xa000_0000_u32 + index as u32;
            source[constructor..constructor + 4].copy_from_slice(&instruction.to_le_bytes());
            source[fallback..fallback + 4].copy_from_slice(&AARCH64_RET.to_le_bytes());
            let record = table + 8 + index * 16;
            module[record..record + 4].copy_from_slice(&(constructor as u32).to_le_bytes());
            module[record + 4..record + 8].copy_from_slice(&(fallback as u32).to_le_bytes());
            module[record + 8..record + 12].copy_from_slice(&instruction.to_le_bytes());
        }
        let layout = ElfLayout {
            entrypoint: 0,
            program_header_offset: 0,
            program_header_size: 0x38,
            program_header_count: 1,
            program_headers: vec![LoadSegment {
                offset: 0,
                virtual_address: 0,
                file_size: source.len() as u64,
                memory_size: source.len() as u64,
                flags: PF_R,
                alignment: 0x1000,
            }],
            section_headers: Vec::new(),
            section_name_index: 0,
            private_section_index: 0,
        };
        let constructors = discover_suppressed_constructors(&module, &source, &layout, COUNT)
            .expect("constructor table")
            .expect("validated constructor table");
        assert_eq!(constructors.len(), COUNT);
        assert_eq!(constructors[0], 0x100);
        assert_eq!(constructors[COUNT - 1], 0x100 + ((COUNT - 1) * 4) as u64);
    }
}
