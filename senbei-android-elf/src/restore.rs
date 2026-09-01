use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use memmap2::{Mmap, MmapMut, MmapOptions};
use senbei_android_crypto::{
    ContainerHeader, HuffmanLzDecoder, Module9bConfig, ProtectedDescriptor, transform_segment,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::artifact::load_artifacts;
use crate::error::{Error, Result, invalid};
use crate::hash::{build_gnu_hash, build_sysv_hash};
use crate::layout::{
    ElfLayout, SHF_ALLOC, SHT_LOUSER, SHT_NOBITS, SectionHeader, align_up, read_i64, read_u32,
    read_u64, slice, slice_u64, usize_from_u64,
};

const CHUNK_SIZE: usize = 16 * 1024 * 1024;
const ELF64_SYMBOL_SIZE: usize = 0x18;
const ELF64_RELA_SIZE: usize = 0x18;
const R_AARCH64_ABS64: u32 = 0x101;
const R_AARCH64_GLOB_DAT: u32 = 0x401;
const R_AARCH64_JUMP_SLOT: u32 = 0x402;
const R_AARCH64_RELATIVE: u32 = 0x403;
const VER_NDX_GLOBAL: u16 = 1;

const DT_PLTRELSZ: u64 = 2;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_STRSZ: u64 = 10;
const DT_JMPREL: u64 = 23;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_VERSYM: u64 = 0x6fff_fff0;
const DT_RELACOUNT: u64 = 0x6fff_fff9;
const DT_VERNEED: u64 = 0x6fff_fffe;

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
    let mut digest = Sha256::new();
    digest.update(data);
    hex_digest(&digest.finalize())
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
    Ok(hex_digest(&digest.finalize()))
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
        usize_from_u64(written, "written byte count")
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
        if result.dynsym_count < 2 {
            return invalid("auxiliary dynamic symbol table is empty");
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
    if dynsym.entry_size != ELF64_SYMBOL_SIZE as u64 || dynsym.size % ELF64_SYMBOL_SIZE as u64 != 0
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
    if symbols.len() % ELF64_SYMBOL_SIZE != 0 {
        return invalid("dynamic symbol table is not entry-aligned");
    }
    symbols
        .chunks_exact(ELF64_SYMBOL_SIZE)
        .map(|symbol| {
            let name_offset = read_u32(symbol, 0)? as usize;
            Ok(read_c_string(strings, name_offset, strings.len())?.to_vec())
        })
        .collect()
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
struct RelocationTable<'a> {
    data: &'a [u8],
    offset: usize,
    count: usize,
    remap: Option<(usize, u32)>,
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
        if let Some((old_symbol_count, auxiliary_symbol_count)) = self.remap {
            let symbol = relocation.symbol();
            if symbol >= u64::from(auxiliary_symbol_count) {
                return invalid("auxiliary relocation references an invalid symbol");
            }
            if symbol != 0 {
                let base = u64::try_from(old_symbol_count.checked_sub(1).ok_or_else(|| {
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

    fn append_where(self, output: &mut Vec<u8>, predicate: impl Fn(u32) -> bool) -> Result<usize> {
        let mut count = 0_usize;
        for index in 0..self.count {
            let relocation = self.relocation(index)?;
            if predicate(relocation.kind()) {
                relocation.encode(output);
                count += 1;
            }
        }
        Ok(count)
    }
}

fn patch_dynamic_tags(
    output: &mut [u8],
    dynamic: SectionHeader,
    values: &BTreeMap<u64, u64>,
) -> Result<()> {
    if dynamic.size % 0x10 != 0 {
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

fn required_section_indices(names: &[String]) -> Result<HashMap<&'static str, usize>> {
    const REQUIRED: [&str; 9] = [
        ".dynsym",
        ".gnu.version",
        ".gnu.version_r",
        ".gnu.hash",
        ".dynstr",
        ".rela.dyn",
        ".rela.plt",
        ".dynamic",
        ".rodata",
    ];
    let mut result = HashMap::with_capacity(REQUIRED.len());
    for required in REQUIRED {
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
    let sysv_hash = names
        .iter()
        .enumerate()
        .filter_map(|(index, name)| (name == ".hash").then_some(index))
        .collect::<Vec<_>>();
    match sysv_hash.as_slice() {
        [index] => {
            result.insert(".hash", *index);
        }
        [] => {}
        _ => return invalid("ELF contains duplicate section .hash"),
    }
    Ok(result)
}

fn materialize_static_elf_tables(
    output: &mut [u8],
    source: &[u8],
    layout: &ElfLayout,
    symbol_patch_data: &[u8],
    auxiliary_data: &[u8],
) -> Result<(ElfLayout, ElfMaterializationReport)> {
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
    let rodata = section(".rodata");

    let (old_symbols, old_strings, hidden_symbols) =
        restore_hidden_symbols(output, dynsym, dynstr, symbol_patch_data)?;
    let old_symbol_count = old_symbols.len() / ELF64_SYMBOL_SIZE;
    if versym.size != (old_symbol_count * 2) as u64 {
        return invalid(".gnu.version count does not match .dynsym");
    }
    let old_versions = slice_u64(output, versym.offset, versym.size)?.to_vec();
    let version_requirements = slice_u64(output, verneed.offset, verneed.size)?.to_vec();

    let auxiliary = AuxiliaryElfImage::parse(auxiliary_data)?;
    let auxiliary_strings = slice(
        auxiliary_data,
        auxiliary.dynstr_offset as usize,
        auxiliary.dynstr_size as usize,
    )?;
    let appended_count = auxiliary.dynsym_count as usize - 1;
    let mut appended_symbols = Vec::with_capacity(appended_count * ELF64_SYMBOL_SIZE);
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
    let mut merged_strings = Vec::with_capacity(old_strings.len() + auxiliary_strings.len());
    merged_strings.extend_from_slice(&old_strings);
    merged_strings.extend_from_slice(auxiliary_strings);
    let mut merged_versions = Vec::with_capacity(old_versions.len() + appended_count * 2);
    merged_versions.extend_from_slice(&old_versions);
    for _ in 0..appended_count {
        merged_versions.extend_from_slice(&VER_NDX_GLOBAL.to_le_bytes());
    }
    let merged_names = dynamic_symbol_names(&merged_symbols, &merged_strings)?;
    let sysv_hash = indices
        .contains_key(".hash")
        .then(|| build_sysv_hash(&merged_names))
        .transpose()?;
    let gnu_hash_table = build_gnu_hash(&merged_names)?;
    let new_symbol_count = merged_names.len();
    let new_dynstr_size = merged_strings.len();

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
        remap: Some((old_symbol_count, auxiliary.dynsym_count)),
    };
    let auxiliary2 = RelocationTable {
        data: auxiliary_data,
        offset: auxiliary.relocation2_offset as usize,
        count: auxiliary.relocation2_count as usize,
        remap: Some((old_symbol_count, auxiliary.dynsym_count)),
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

    let estimated_dyn = (old_dyn.count + auxiliary1.count + auxiliary2.count)
        .checked_mul(ELF64_RELA_SIZE)
        .ok_or_else(|| Error::Invalid("merged .rela.dyn capacity overflow".to_owned()))?;
    let mut merged_rela_dyn = Vec::with_capacity(estimated_dyn);
    let mut relative_count = 0_usize;
    for table in [old_dyn, auxiliary1, auxiliary2] {
        relative_count +=
            table.append_where(&mut merged_rela_dyn, |kind| kind == R_AARCH64_RELATIVE)?;
    }
    for table in [old_dyn, auxiliary1] {
        table.append_where(&mut merged_rela_dyn, |kind| kind != R_AARCH64_RELATIVE)?;
    }
    let mut merged_rela_plt = Vec::with_capacity(
        (old_plt.count + auxiliary2.count)
            .checked_mul(ELF64_RELA_SIZE)
            .ok_or_else(|| Error::Invalid("merged .rela.plt capacity overflow".to_owned()))?,
    );
    old_plt.append_where(&mut merged_rela_plt, |_| true)?;
    auxiliary2.append_where(&mut merged_rela_plt, |kind| kind == R_AARCH64_JUMP_SLOT)?;
    let rela_dyn_count = merged_rela_dyn.len() / ELF64_RELA_SIZE;
    let rela_plt_count = merged_rela_plt.len() / ELF64_RELA_SIZE;

    struct TablePayload {
        name: &'static str,
        alignment: u64,
        data: Vec<u8>,
    }
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
        TablePayload {
            name: ".gnu.hash",
            alignment: 8,
            data: gnu_hash_table,
        },
    ];
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
    let metadata_start = dynsym.offset;
    let mut cursor = metadata_start;
    let mut placements = BTreeMap::new();
    for table in &tables {
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
    if cursor > rodata.offset {
        return invalid(format!(
            "rebuilt ELF tables end at 0x{cursor:x}, beyond .rodata 0x{:x}",
            rodata.offset
        ));
    }
    let zero_start = usize_from_u64(metadata_start, "metadata start")?;
    let zero_end = usize_from_u64(rodata.offset, ".rodata offset")?;
    output
        .get_mut(zero_start..zero_end)
        .ok_or_else(|| Error::Invalid("metadata capacity exceeds output mapping".to_owned()))?
        .fill(0);

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
        updated.address =
            layout.file_offset_to_virtual_address(placement.offset, table.data.len() as u64)?;
        updated.offset = placement.offset;
        updated.size = table.data.len() as u64;
        updated_sections[index] = updated;
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
        (DT_GNU_HASH, section_address(".gnu.hash")),
        (DT_VERSYM, section_address(".gnu.version")),
        (DT_RELACOUNT, relative_count as u64),
        (DT_VERNEED, section_address(".gnu.version_r")),
    ]);
    if indices.contains_key(".hash") {
        dynamic_values.insert(DT_HASH, section_address(".hash"));
    }
    patch_dynamic_tags(output, dynamic, &dynamic_values)?;

    let mut restored_layout = layout.clone();
    restored_layout.section_headers = updated_sections;
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
            metadata_capacity_end: rodata.offset,
            metadata_slack: rodata.offset - cursor,
            placements,
        },
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
    preserve_entrypoint: bool,
) -> Result<CleaningReport> {
    let private = layout.private_section()?;
    let names = layout.section_names(source)?;
    if layout.private_section_index + 1 != layout.section_headers.len() {
        return invalid("SHT_LOUSER section is not the final section");
    }
    let retained = &layout.section_headers[..layout.private_section_index];
    let mut updated = Vec::with_capacity(retained.len());
    stream
        .seek(SeekFrom::Start(private.offset))
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
    if let Some(expected) = materialization {
        if dynamic_symbols != expected.new_symbol_count
            || dynamic_relocations != expected.rela_dyn_count
            || pltgot_relocations != expected.rela_plt_count
        {
            return invalid("restored ELF table counts do not match materialization report");
        }
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
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|error| Error::io("query current directory", path, error))
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| Error::io("create output directory", parent, error))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| Error::io("create temporary file", parent, error))?;
    temporary
        .write_all(data)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| Error::io("write temporary file", temporary.path(), error))?;
    temporary
        .persist(path)
        .map_err(|error| Error::io("replace output", path, error.error))?;
    Ok(())
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
    let mut auxiliary_data = None;
    let mut auxiliary_stats = None;
    let mut materialization = None;
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
                    let end = start.checked_add(data.len()).ok_or_else(|| {
                        Error::Invalid("auxiliary decoded write overflow".to_owned())
                    })?;
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
            if options.verbose {
                eprintln!("Rebuilding static ELF dynamic-linker tables...");
            }
            let (new_layout, report) = materialize_static_elf_tables(
                &mut output,
                &source,
                &layout,
                &symbol_patch_data,
                &decoded,
            )?;
            restored_layout = new_layout;
            materialization = Some(report);
            auxiliary_stats = Some(stats);
            auxiliary_data = Some(decoded);
        }
        output
            .flush()
            .map_err(|error| Error::io("flush restored image", &temporary_path, error))?;
    }
    drop(auxiliary_data);

    let cleaning = finalize_clean_elf(
        temporary.as_file_mut(),
        &temporary_path,
        &source,
        &restored_layout,
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
/// Lowercase hex of a digest output (sha2 0.11's `Array` no longer formats as
/// hex directly).
fn hex_digest(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
