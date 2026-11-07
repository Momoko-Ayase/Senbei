//! Native/managed-DLL unpack pipeline for the older protected-DLL layout.
//!
//! Naming note: the stage names used by this layout do NOT line up 1:1 with the
//! shared primitives. Mapping used here:
//!   DecryptData1 (XOR+ROR over dwords)  -> primitives::decrypt_data3
//!   DecryptData3 (shift-5 byte rotate)  -> local `decrypt_data3_shift5`
//!   DecryptData4/5 (AES+XORROR+huff)    -> local `decrypt_data4`
//!   DecryptData6 (shift-6 byte rotate)  -> local `decrypt_data6_shift6`
//!   DecryptData7 (nibble-swap rolling)  -> primitives::decrypt_data7
//!   Decompress (LFSR keystream)         -> primitives::decrypt_data6
//!   HuffmanDecompress                   -> primitives::decompress
//!   AesDecrypt                          -> primitives::aes_decrypt
//!   CalculateChecksumWithSizeXor        -> primitives::calculate_checksum
//!   CalculateCrc32                      -> crc32::compute (via above)

use super::super::research::{self, AddressSpace, ResearchStage, TraceValue};
use super::super::{
    BufferOperation, BytecodeStage, DecompressionStage, DescriptorTable, SectionPipeline,
    UnpackError,
};
use senbei_crypto::bytecode::{Op, OpsLut, generate};
use senbei_crypto::primitives::{self, *};
use senbei_i18n::Step;

/// Per-code-block index for trace events. The four blocks share one research
/// stage, so an explicit index keeps their events orderable.
fn code_block_index(stage: DecompressionStage) -> u32 {
    match stage {
        DecompressionStage::DllCodeBlock1 => 1,
        DecompressionStage::DllCodeBlock2 => 2,
        DecompressionStage::DllCodeBlock3 => 3,
        DecompressionStage::DllCodeBlock4 => 4,
        _ => 0,
    }
}

/// Address/offset as an unsigned trace value. Every field fed here is a
/// computed working-image or file offset; the packer's values are 32-bit and
/// negative encodings are still reported as their 32-bit bit pattern.
fn trace_offset(value: i32) -> u64 {
    u64::from(value as u32)
}

/// Section-block samples are bounded: a large image can hold thousands of
/// blocks, and the sink limit must not be what stops the trace.
const TRACE_BLOCK_SAMPLE: usize = 16;

/// Read a signed 32-bit little-endian value.
fn get_i32(d: &[u8], offset: i32) -> i32 {
    get_u32(d, offset as u32) as i32
}

/// Write a signed 32-bit little-endian value.
fn write_i32(d: &mut [u8], offset: i32, value: i32) {
    write_u32(d, offset as u32, value as u32);
}

/// `DecryptData3` (shift-5): byte-level bit rotation over a (addr,size) pair.
fn decrypt_data3_shift5(d: &mut [u8], offset: i32) {
    let addr = get_i32(d, offset);
    let size = get_i32(d, offset + 4);
    let mut key1: u8 = (addr as u8).wrapping_add((addr >> 8) as u8);
    let mut key2: u8 = key1.wrapping_add(1);
    for i in 0..size {
        let idx = (addr + i) as usize;
        let val = d[idx];
        let step1 = key2 ^ val.rotate_left(3);
        let step2 = key1 ^ step1.rotate_left(3);
        d[idx] = step2.rotate_left(3);
        key1 = key1.wrapping_add(1);
        key2 = key2.wrapping_add(1);
    }
}

/// `DecryptData6` (shift-6): byte-level bit rotation over an explicit
/// (offset, size) range, with the low byte of `offset` as the rolling key.
fn decrypt_data6_shift6(d: &mut [u8], offset: i32, size: i32) {
    let mut key1: u8 = offset as u8;
    let mut key2: u8 = (offset as u8).wrapping_add(1);
    for i in 0..size {
        let idx = (offset + i) as usize;
        let val = d[idx];
        let step1 = key2 ^ val.rotate_left(2);
        let step2 = key1 ^ step1.rotate_left(2);
        d[idx] = step2.rotate_left(2);
        key1 = key1.wrapping_add(1);
        key2 = key2.wrapping_add(1);
    }
}

/// `DecryptData4`/`DecryptData5`: AES-CBC decrypt + XOR/ROR (DecryptData1
/// with rotate 19) + optional per-byte transform + Huffman decompress.
fn decrypt_data4(
    d: &mut [u8],
    offset: i32,
    key: i32,
    decomp_params: &[i32; 4],
    transform: Option<&[Op]>,
    stage: DecompressionStage,
) -> Result<(), UnpackError> {
    let addr = get_i32(d, offset);
    let size = get_i32(d, offset + 4);
    let compressed_addr = get_i32(d, offset + 8);
    let decompressed_size = get_i32(d, offset + 12);

    if research::trace_enabled() {
        // One descriptor event per block; `block` makes the shared stage
        // orderable without a stage variant per block.
        research::emit_at(
            ResearchStage::DllStages,
            "code_block_descriptor",
            TraceValue::U32s(vec![
                code_block_index(stage),
                addr as u32,
                size as u32,
                compressed_addr as u32,
                decompressed_size as u32,
            ]),
            AddressSpace::WorkingImageRva,
            trace_offset(offset),
        );
        research::emit_u32_at(
            ResearchStage::DllStages,
            "aes_key_schedule",
            decomp_params[3] as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(decomp_params[3]),
        );
        research::emit_u32_at(
            ResearchStage::DllStages,
            "huffman_table",
            decomp_params[1] as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(decomp_params[1]),
        );
    }

    aes_decrypt(d, addr as u32, size as u32, decomp_params[3] as u32);
    // DecryptData1(offset, key, 19) == primitives::decrypt_data3 with shift 19
    decrypt_data3(d, offset as u32, key as u32, 19);

    if let Some(ops) = transform
        && size > 0
    {
        if research::trace_enabled() {
            research::emit_u32(ResearchStage::DllStages, "bytecode_ops", ops.len() as u32);
        }
        OpsLut::new(ops).map_region(d, addr as usize, size as usize);
    }
    if size > 0 {
        research::emit_range(
            ResearchStage::DllStages,
            "block_decrypted",
            AddressSpace::WorkingImageRva,
            trace_offset(addr),
            size as u64,
        );
    }

    if size != decompressed_size
        && let Err(reason) = primitives::decompress_detailed(
            d,
            addr as u32,
            compressed_addr as u32,
            decomp_params[1] as u32,
            size as u32,
            decompressed_size as u32,
        )
    {
        research::emit_note(
            ResearchStage::DllStages,
            "block_decompression",
            TraceValue::Bool(false),
            "block_decompression_failed",
        );
        return Err(UnpackError::StageDecompressionFailed { stage, reason });
    }
    if size != decompressed_size {
        research::emit_range(
            ResearchStage::DllStages,
            "block_decompression",
            AddressSpace::WorkingImageRva,
            trace_offset(compressed_addr),
            decompressed_size.max(0) as u64,
        );
    }
    Ok(())
}

/// `InitializeKeys`.
fn initialize_keys(file_data: &[u8]) -> [i32; 8] {
    let mut keys = [0i32; 8];
    keys[0] = get_i32(file_data, 4096);
    let mut prev_key = keys[0];
    for i in 0..7i32 {
        let val = get_i32(file_data, 4 * i + 4100);
        keys[(i + 1) as usize] = val ^ prev_key;
        prev_key = (i * i) ^ (val.wrapping_add(prev_key).wrapping_sub(i));
    }
    keys
}

/// `ProcessRelocBlock`.
fn process_reloc_block(d: &mut [u8], mut pos: i32) {
    loop {
        decrypt_data6_shift6(d, pos, 16);
        let src_addr = get_i32(d, pos);
        let size = get_i32(d, pos + 4);
        let dst_addr = get_i32(d, pos + 8);
        let verify = get_i32(d, pos + 12);
        pos += 16;

        if src_addr != 0 && size != 0 && dst_addr != 0 && verify == size {
            let s = src_addr as usize;
            let dd = dst_addr as usize;
            let n = size as usize;
            d.copy_within(s..s + n, dd);
        }
        if size == 0 {
            break;
        }
    }
}

/// Number of section headers to walk, and the guard the walks share.
///
/// The section table has no sentinel entry, so "iterate until VirtualSize is 0"
/// silently truncates the walk at the first section with a legitimately zero
/// VirtualSize (or a corrupt early field) — the later sections then keep the
/// packer's raw pointers and the image is broken with no error. Walk by
/// `NumberOfSections` instead, capped, with an all-zero-name break to guard the
/// other direction (a corrupt, overstated count): real sections always have a
/// name, header padding is all zero.
const MAX_SECTIONS: i32 = 96;

fn section_count(file_data: &[u8], pe_offset: i32) -> i32 {
    (get_u16(file_data, (pe_offset + 6) as u32) as i32).min(MAX_SECTIONS)
}

fn section_header_blank(file_data: &[u8], off: i32) -> bool {
    let s = off as usize;
    match file_data.get(s..s + 8) {
        Some(name) => name.iter().all(|&b| b == 0),
        None => true,
    }
}

/// `ProcessImportTable`.
fn process_import_table(d: &mut [u8], mut import_table_offset: i32) {
    let table_start = import_table_offset;
    let mut descriptors: u32 = 0;
    let mut thunks: u64 = 0;
    while get_i32(d, import_table_offset + 12) != 0 {
        let name_offset = get_i32(d, import_table_offset + 12);
        decrypt_data7(d, name_offset as u32, name_offset as u8);

        let thunk_addr0 = get_i32(d, import_table_offset);
        let orig_thunk_addr = get_i32(d, import_table_offset + 16);
        let mut thunk_addr = if thunk_addr0 == 0 {
            orig_thunk_addr
        } else {
            thunk_addr0
        };

        loop {
            // PE32+ thunks are 8 bytes: an ordinal import carries bit 63 with
            // the ordinal in the low word; only a by-name thunk holds a
            // hint/name RVA (in the low dword). Reading just the low dword
            // would mistake an ordinal for a tiny RVA and scribble over the
            // image header.
            let v = get_u64(d, thunk_addr as u32);
            if v == 0 {
                break;
            }
            if (v & 0x8000_0000_0000_0000) == 0 {
                let entry = v as u32;
                decrypt_data7(d, entry.wrapping_add(2), entry as u8);
                d[entry as usize] = 0;
                d[entry.wrapping_add(1) as usize] = 0;
            }
            thunks += 1;
            thunk_addr += 8;
        }
        descriptors += 1;
        import_table_offset += 20;
    }
    // `table_start` is a working-image RVA; the pipeline reached this walk
    // only after the import descriptor was validated by the caller.
    research::emit_u32_at(
        ResearchStage::Imports,
        "import_descriptors",
        descriptors,
        AddressSpace::WorkingImageRva,
        trace_offset(table_start),
    );
    research::emit_u64(ResearchStage::Imports, "import_thunks", thunks);
}

/// `DecryptAndDecompressData`.
fn decrypt_and_decompress_data(
    d: &mut [u8],
    clean: &[u8],
    section_image_base: i32,
    mut section_data_offset: i32,
    decrypt_func: &[Op],
    decomp_params: &[i32; 4],
) -> Result<(), UnpackError> {
    // Entry loop — Pass 1 (sequential): the 16-byte descriptors are decrypted
    // in a position-keyed chain (decrypt_data6_shift6) terminated by a zero-size
    // record, so collection cannot be parallelized.
    struct Blk {
        dest_offset: i32,
        size: i32,
        src_offset: i32,
        expected_crc: i32,
    }
    let block_table_offset = section_data_offset;
    let mut blocks: Vec<Blk> = Vec::new();
    loop {
        // Guard: need 16 bytes at section_data_offset in `d`
        let off = section_data_offset as usize;
        if off.saturating_add(16) > d.len() {
            research::emit_u32_at(
                ResearchStage::Sections,
                "block_table_out_of_bounds",
                off as u32,
                AddressSpace::WorkingImageRva,
                trace_offset(section_data_offset),
            );
            return Err(UnpackError::DescriptorOutOfBounds {
                table: DescriptorTable::DllSectionBlocks,
                offset: off,
                image_len: d.len(),
            });
        }
        decrypt_data6_shift6(d, section_data_offset, 16);
        let dest_offset = get_i32(d, section_data_offset);
        let size = get_i32(d, section_data_offset + 4);
        let src_offset = get_i32(d, section_data_offset + 8);
        let expected_crc = get_i32(d, section_data_offset + 12);
        section_data_offset += 16;

        if size == 0 {
            break;
        }
        // The descriptor table itself is working-image data; its records are
        // emitted (bounded) below after the loop has the totals.
        blocks.push(Blk {
            dest_offset,
            size,
            src_offset,
            expected_crc,
        });
    }
    if research::trace_enabled() {
        let mut raw_total: u64 = 0;
        let mut out_total: u64 = 0;
        let mut compressed = 0u32;
        for (index, block) in blocks.iter().enumerate() {
            raw_total += block.size.max(0) as u64;
            out_total += block.expected_crc.max(0) as u64;
            if block.size != block.expected_crc {
                compressed += 1;
            }
            if index < TRACE_BLOCK_SAMPLE {
                research::emit_u32(
                    ResearchStage::Sections,
                    "block_descriptor",
                    block.dest_offset as u32,
                );
                research::emit_u32(
                    ResearchStage::Sections,
                    "block_src",
                    block.src_offset as u32,
                );
                research::emit_u32(ResearchStage::Sections, "block_raw_len", block.size as u32);
                research::emit_u32(
                    ResearchStage::Sections,
                    "block_out_len",
                    block.expected_crc as u32,
                );
            }
        }
        research::emit_u32_at(
            ResearchStage::Sections,
            "block_count",
            blocks.len() as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(block_table_offset),
        );
        research::emit_u32(ResearchStage::Sections, "compressed_blocks", compressed);
        research::emit_u64(ResearchStage::Sections, "raw_total_len", raw_total);
        research::emit_u64(ResearchStage::Sections, "output_total_len", out_total);
        research::emit_u32_at(
            ResearchStage::Sections,
            "section_image_base",
            section_image_base as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(section_image_base),
        );
    }
    // Pass 2: each block writes only [src_offset, src_offset+max(size,crc)) and
    // reads only immutable input + the (snapshotted) key tables, so blocks with
    // disjoint write spans are independent. `parallel_for` carves the spans
    // into safe disjoint &mut slices (these blocks are only ever laid out
    // disjointly; overlapping spans degrade to a sequential pass).
    {
        let lut = OpsLut::new(decrypt_func);
        let ko0 = decomp_params[0];
        let ko2 = decomp_params[2];
        if research::trace_enabled() {
            research::emit_u32_at(
                ResearchStage::Sections,
                "aes_key_schedule",
                ko2 as u32,
                AddressSpace::WorkingImageRva,
                trace_offset(ko2),
            );
            research::emit_u32_at(
                ResearchStage::Sections,
                "huffman_table",
                ko0 as u32,
                AddressSpace::WorkingImageRva,
                trace_offset(ko0),
            );
        }
        let ks_snap = primitives::aes_schedule_snapshot(d, ko2 as u32).ok_or_else(|| {
            research::emit_u32_at(
                ResearchStage::Sections,
                "aes_schedule_invalid",
                ko2 as u32,
                AddressSpace::WorkingImageRva,
                trace_offset(ko2),
            );
            UnpackError::InvalidAesKeySchedule { offset: ko2 as u32 }
        })?;
        let tab_snap = primitives::huffman_table_snapshot(d, ko0 as u32).ok_or_else(|| {
            research::emit_u32_at(
                ResearchStage::Sections,
                "huffman_table_invalid",
                ko0 as u32,
                AddressSpace::WorkingImageRva,
                trace_offset(ko0),
            );
            UnpackError::InvalidHuffmanTable { offset: ko0 as u32 }
        })?;
        let spans: Vec<(usize, usize)> = blocks
            .iter()
            .map(|b| {
                let s = b.src_offset as usize;
                (s, s + b.size.max(b.expected_crc) as usize)
            })
            .collect();
        let do_block = |i: usize, base: usize, span: &mut [u8]| -> Result<(), UnpackError> {
            let b = &blocks[i];
            let src = (b.dest_offset as i64 + section_image_base as i64) as usize;
            let rel = (b.src_offset as usize) - base;
            let n = b.size as usize;
            // Bounds-checked copy from `clean` (potentially truncated input).
            primitives::try_copy_from_slice(span, rel, n, clean, src)?;
            aes_decrypt_ks(&ks_snap, span, rel as u32, b.size as u32);
            lut.map_region(span, rel, n);
            if b.size != b.expected_crc {
                // decompress reports corruption (after partial writes) via its
                // bool; surface it instead of shipping a garbage block.
                if !decompress_tbl(
                    &tab_snap,
                    span,
                    rel as u32,
                    rel as u32,
                    b.size as u32,
                    b.expected_crc as u32,
                ) {
                    return Err(UnpackError::SectionDecompressionFailed {
                        pipeline: SectionPipeline::Dll,
                        block: i,
                    });
                }
            }
            Ok(())
        };
        // Workers cannot emit into the trace (the sink is thread-local), so
        // the driver records the outcome after the fan-out returns.
        if let Err(error) = super::super::parallel::parallel_for(d, &spans, 1, do_block) {
            match &error {
                UnpackError::SectionDecompressionFailed { block, .. } => {
                    research::emit_u32(
                        ResearchStage::Sections,
                        "block_decompression_failed",
                        *block as u32,
                    );
                }
                _ => research::emit_note(
                    ResearchStage::Sections,
                    "block_pass_failed",
                    TraceValue::Bool(false),
                    "section block pass failed",
                ),
            }
            return Err(error);
        }
    }

    // Zero-fill loop.
    let zero_fill_table = section_data_offset;
    let mut zero_fill_records: u32 = 0;
    let mut zero_fill_bytes: u64 = 0;
    loop {
        let off = section_data_offset as usize;
        // The entry block loop above correctly requires 16 bytes; this loop
        // decrypts 16 too, so guard 16 (an 8-byte guard would let
        // decrypt_data6_shift6 index past the end of a truncated descriptor).
        if off.saturating_add(16) > d.len() {
            research::emit_u32_at(
                ResearchStage::Sections,
                "zero_fill_out_of_bounds",
                off as u32,
                AddressSpace::WorkingImageRva,
                trace_offset(section_data_offset),
            );
            return Err(UnpackError::DescriptorOutOfBounds {
                table: DescriptorTable::DllZeroFill,
                offset: off,
                image_len: d.len(),
            });
        }
        decrypt_data6_shift6(d, section_data_offset, 16);
        let zero_offset = get_i32(d, section_data_offset);
        let zero_size = get_i32(d, section_data_offset + 4);
        section_data_offset += 16;

        if zero_size == 0 {
            break;
        }
        zero_fill_records += 1;
        zero_fill_bytes += zero_size.max(0) as u64;
        for i in 0..zero_size {
            let idx = (zero_offset + i) as usize;
            if idx >= d.len() {
                return Err(UnpackError::BufferRangeOutOfBounds {
                    operation: BufferOperation::ZeroFill,
                    offset: idx,
                    size: 1,
                    buffer_len: d.len(),
                });
            }
            d[idx] = 0;
        }
    }
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::Sections,
            "zero_fill_count",
            zero_fill_records,
            AddressSpace::WorkingImageRva,
            trace_offset(zero_fill_table),
        );
        research::emit_u64(ResearchStage::Sections, "zero_fill_bytes", zero_fill_bytes);
    }
    Ok(())
}

/// Unpack a native/managed DLL in the older protected-DLL layout. Returns the
/// unpacked image bytes.
pub fn unpack_dll(input: &[u8]) -> Result<Vec<u8>, UnpackError> {
    unpack_dll_v(input, false)
}

/// Like [`unpack_dll`], but prints detailed `[N/9]` step progress to stdout when
/// `verbose` is true. Output bytes are identical regardless.
pub fn unpack_dll_v(input: &[u8], verbose: bool) -> Result<Vec<u8>, UnpackError> {
    // Trap any out-of-bounds panic from a truncated/garbled file and report it
    // as a clean error so the public API stays panic-free.
    super::super::catch_unpack(move || unpack_dll_inner(input, verbose))
}

fn unpack_dll_inner(input: &[u8], verbose: bool) -> Result<Vec<u8>, UnpackError> {
    const HEADER_LEN: usize = 4128;
    if input.len() < HEADER_LEN {
        return Err(UnpackError::InputTooShort {
            actual: input.len(),
            required: HEADER_LEN,
        });
    }

    // `file_data` and `original_file_data` both borrow the same protected input.
    let file_data = input;
    let original_file_data = input;

    let keys = initialize_keys(file_data);
    if research::trace_enabled() {
        research::emit_u32s(
            ResearchStage::Header,
            "header_keys",
            keys.iter().map(|key| *key as u32).collect(),
        );
        // keys[1] is the magic; keys[3] is the payload base, keys[6] the anchor.
        research::emit_u32_at(
            ResearchStage::Header,
            "magic",
            keys[1] as u32,
            AddressSpace::ProtectedHeaderOffset,
            4100,
        );
        // `keys[3]` is the destination base inside the working image; the
        // payload's source bytes begin at `keys[4] + 4096` in the file.
        research::emit_u32_at(
            ResearchStage::Header,
            "payload_base",
            keys[3] as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(keys[3]),
        );
        research::emit_u32(ResearchStage::Header, "payload_len", keys[5] as u32);
        research::emit_u32_at(
            ResearchStage::Header,
            "payload_src",
            (keys[4] as u32).wrapping_add(4096),
            AddressSpace::FileOffset,
            trace_offset(keys[4]).wrapping_add(4096),
        );
        research::emit_u32_at(
            ResearchStage::Header,
            "anchor",
            keys[6] as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(keys[6]),
        );
    }
    if verbose {
        crate::progress::step(1, 9, Step::InitKeys);
        crate::progress::detail(format_args!(
            "  keys[0] key       = 0x{:08X}",
            keys[0] as u32
        ));
        crate::progress::detail(format_args!(
            "  keys[1] signature = 0x{:08X}",
            keys[1] as u32
        ));
        crate::progress::detail(format_args!(
            "  keys[3] base      = 0x{:08X}",
            keys[3] as u32
        ));
        crate::progress::detail(format_args!(
            "  keys[4] src_off   = 0x{:08X}",
            keys[4] as u32
        ));
        crate::progress::detail(format_args!(
            "  keys[5] size      = 0x{:08X}",
            keys[5] as u32
        ));
        crate::progress::detail(format_args!(
            "  keys[6] anchor    = 0x{:08X}",
            keys[6] as u32
        ));
    }

    if !super::super::is_supported_magic(keys[1] as u32) {
        return Err(UnpackError::HeaderMagicMismatch {
            found: keys[1] as u32,
        });
    }

    let pe_offset = get_i32(file_data, 60);
    if pe_offset < 0 || (pe_offset as usize).saturating_add(84) > file_data.len() {
        return Err(UnpackError::InvalidPeOffset {
            offset: i64::from(pe_offset),
            input_len: file_data.len(),
        });
    }
    // This pipeline is PE32+-only: its header fixups write the data
    // directories at PE32+ offsets (pe+144..180, pe+136 for the DD blob). On a
    // PE32 image those land in the wrong optional-header fields and produce a
    // structurally plausible but unloadable file. Reject early with a clear
    // error so `unpack_auto`'s EXE-pipeline fallback handles PE32 DLLs (that
    // path is PE32-aware — see run_pe32), instead of us mangling them here.
    let optional_magic = get_u16(file_data, (pe_offset + 24) as u32);
    if optional_magic != 0x20B {
        return Err(UnpackError::UnsupportedDllPeMagic {
            found: optional_magic,
        });
    }
    let size_of_image = get_i32(file_data, pe_offset + 80);
    if size_of_image <= 0 || size_of_image as u64 > super::super::MAX_IMAGE_SIZE {
        return Err(UnpackError::InvalidImageSize {
            size: i64::from(size_of_image),
            max: super::super::MAX_IMAGE_SIZE,
        });
    }
    let mut out = vec![0u8; size_of_image as usize];
    let base_offset = keys[6] - keys[3] + 0x2000;
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::Payload,
            "pe_offset",
            pe_offset as u32,
            AddressSpace::FileOffset,
            trace_offset(pe_offset),
        );
        research::emit_u32(
            ResearchStage::Payload,
            "size_of_image",
            size_of_image as u32,
        );
        research::emit_u32_at(
            ResearchStage::Payload,
            "base_offset",
            base_offset as u32,
            AddressSpace::DecodedPayloadOffset,
            trace_offset(base_offset),
        );
        research::emit_u32_at(
            ResearchStage::Payload,
            "key_table_src",
            (keys[4] as u32).wrapping_add(4096),
            AddressSpace::FileOffset,
            trace_offset(keys[4]).wrapping_add(4096),
        );
        research::emit_range(
            ResearchStage::Payload,
            "key_table",
            AddressSpace::WorkingImageRva,
            trace_offset(keys[3]),
            (base_offset >> 2) as u64 * 4,
        );
    }
    if verbose {
        crate::progress::step(2, 9, Step::DecryptKeyTable);
        crate::progress::detail(format_args!(
            "  size_of_image = 0x{:08X}",
            size_of_image as u32
        ));
        crate::progress::detail(format_args!(
            "  base_offset   = 0x{:08X}",
            base_offset as u32
        ));
    }

    // DecryptKeyTable.
    {
        let src_base = keys[4] + 4096;
        let mut scramble = (!base_offset).wrapping_add(keys[0]);
        let count = base_offset >> 2;
        for i in 0..count {
            let dst_offset = keys[3] + 4 * i;
            let src_val = get_i32(file_data, src_base + 4 * i);
            write_i32(&mut out, dst_offset, src_val ^ scramble);
            scramble = (i * i) ^ (i.wrapping_add(src_val).wrapping_add(scramble));
        }
    }

    // Array.Copy(fileData, keys[4]+baseOffset+4096, outputData, keys[3]+baseOffset, keys[5]-baseOffset)
    {
        let src = (keys[4] + base_offset + 4096) as usize;
        let dst = (keys[3] + base_offset) as usize;
        let n = (keys[5] - base_offset) as usize;
        primitives::try_copy_from_slice(&mut out, dst, n, file_data, src)?;
        research::emit_range(
            ResearchStage::Payload,
            "payload_copy",
            AddressSpace::FileOffset,
            src as u64,
            n as u64,
        );
        research::emit_range(
            ResearchStage::Payload,
            "payload_dest",
            AddressSpace::WorkingImageRva,
            dst as u64,
            n as u64,
        );
    }
    write_i32(&mut out, keys[3], 4096);
    out[..4096].copy_from_slice(&file_data[..4096]);

    let v144 = get_i32(&out, keys[6] + 5600);
    let v148 = get_i32(&out, keys[6] + 5596);
    let v152 = get_i32(&out, keys[6] + 5632);
    let v156 = get_i32(&out, keys[6] + 5636);
    write_i32(&mut out, pe_offset + 144, v144);
    write_i32(&mut out, pe_offset + 148, v148);
    write_i32(&mut out, pe_offset + 152, v152);
    write_i32(&mut out, pe_offset + 156, v156);
    write_i32(&mut out, pe_offset + 176, 0);
    write_i32(&mut out, pe_offset + 180, 0);
    if research::trace_enabled() {
        // The four header dwords restored from the anchor area. Their source
        // is a working-image read, and the destination is an RVA too.
        research::emit_u32s(
            ResearchStage::Payload,
            "header_fixups",
            vec![
                v144 as u32,
                v148 as u32,
                v152 as u32,
                v156 as u32,
                (pe_offset + 144) as u32,
            ],
        );
    }

    let mut checksum_offset1 = keys[6] + 5776;
    let mut xor_accumulator: u32 = 0;
    while get_i32(&out, checksum_offset1 + 4) != 0 {
        xor_accumulator ^= calculate_checksum(&out, checksum_offset1 as u32);
        checksum_offset1 += 8;
    }

    let checksum1 = calculate_checksum(&out, (keys[6] + 5648) as u32) as i32;
    let enc_key = get_u32(&out, (keys[6] + 5612) as u32);
    let decrypt_offset1 = keys[6] + 5712;
    decrypt_data3(
        &mut out,
        decrypt_offset1 as u32,
        xor_accumulator ^ (checksum1 as u32) ^ enc_key,
        21,
    );

    let decrypted_addr1 = get_i32(&out, decrypt_offset1);
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "descriptor_key",
            xor_accumulator ^ (checksum1 as u32) ^ enc_key,
            AddressSpace::WorkingImageRva,
            trace_offset(decrypt_offset1),
        );
        research::emit_u32(ResearchStage::DllStages, "xor_accumulator", xor_accumulator);
        research::emit_u32(ResearchStage::DllStages, "checksum1", checksum1 as u32);
        research::emit_u32(ResearchStage::DllStages, "descriptor_shift", 21);
    }
    if verbose {
        crate::progress::step(3, 9, Step::DecryptPrimary);
        crate::progress::detail(format_args!(
            "  xor_accumulator = 0x{:08X}",
            xor_accumulator
        ));
        crate::progress::detail(format_args!(
            "  checksum1       = 0x{:08X}",
            checksum1 as u32
        ));
        crate::progress::detail(format_args!(
            "  decrypted_addr1 = 0x{:08X}",
            decrypted_addr1 as u32
        ));
    }
    let primary_end = decrypted_addr1.checked_add(3856);
    if decrypted_addr1 < keys[3]
        || primary_end.is_none_or(|end| end < 0 || end as usize > out.len())
    {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "primary_descriptor_invalid",
            decrypted_addr1 as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(decrypted_addr1),
        );
        return Err(UnpackError::InvalidDllPrimaryDescriptor {
            address: decrypted_addr1 as u32,
            minimum: keys[3] as u32,
            image_len: out.len(),
        });
    }
    let import_offset = get_i32(&out, decrypted_addr1 + 3444);
    let decrypted_addr2_size = get_i32(&out, decrypted_addr1 + 3632);
    research::emit_range(
        ResearchStage::DllStages,
        "primary_descriptor",
        AddressSpace::WorkingImageRva,
        trace_offset(decrypted_addr1),
        3856,
    );
    research::emit_u32_at(
        ResearchStage::DllStages,
        "import_offset",
        import_offset as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(decrypted_addr1 + 3444),
    );
    decrypt_data3(
        &mut out,
        (decrypted_addr1 + 3632) as u32,
        import_offset as u32,
        19,
    );

    let addr2 = decrypted_addr2_size;
    research::emit_u32_at(
        ResearchStage::DllStages,
        "secondary_descriptor",
        addr2 as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(addr2),
    );
    let reloc_block_offset = addr2 + 9248;
    let reloc_type = get_i32(&out, reloc_block_offset);

    if (reloc_type & 0x0F) == 1 {
        research::emit_u32(ResearchStage::DllStages, "reloc_shift", 5);
        decrypt_data3_shift5(&mut out, addr2 + 9252);
    } else if reloc_type == 2 {
        let p = get_i32(&out, addr2 + 9252);
        research::emit_u32_at(
            ResearchStage::DllStages,
            "reloc_block",
            p as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(addr2 + 9252),
        );
        process_reloc_block(&mut out, p);
    } else {
        research::emit_u32(ResearchStage::DllStages, "reloc_type", reloc_type as u32);
    }

    let reloc_block_offset2 = reloc_block_offset + 16;
    let reloc_type2 = get_i32(&out, reloc_block_offset2);

    if (reloc_type2 & 0x0F) == 1 {
        research::emit_u32(ResearchStage::DllStages, "reloc2_shift", 5);
        decrypt_data3_shift5(&mut out, reloc_block_offset2 + 4);
    } else if reloc_type2 == 2 {
        let p = get_i32(&out, reloc_block_offset2 + 4);
        research::emit_u32_at(
            ResearchStage::DllStages,
            "reloc2_block",
            p as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(reloc_block_offset2 + 4),
        );
        process_reloc_block(&mut out, p);
    } else {
        research::emit_u32(ResearchStage::DllStages, "reloc2_type", reloc_type2 as u32);
    }

    let mut decomp_params = [0i32; 4];
    let param_base = addr2 + 9160;
    decrypt_data3_shift5(&mut out, param_base);
    decomp_params[0] = get_i32(&out, param_base);
    decrypt_data3_shift5(&mut out, param_base + 8);
    decomp_params[1] = get_i32(&out, param_base + 8);
    decrypt_data3_shift5(&mut out, param_base + 32);
    decomp_params[2] = get_i32(&out, param_base + 32);
    decrypt_data3_shift5(&mut out, param_base + 40);
    decomp_params[3] = get_i32(&out, param_base + 40);
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "decomp_params",
            param_base as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(param_base),
        );
        research::emit_u32s(
            ResearchStage::DllStages,
            "decomp_param_values",
            decomp_params.iter().map(|value| *value as u32).collect(),
        );
        // param[0] is the Huffman table, param[2] the AES key schedule; both
        // are working-image offsets read through the same buffer.
        research::emit_u32_at(
            ResearchStage::DllStages,
            "huffman_table",
            decomp_params[0] as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(decomp_params[0]),
        );
        research::emit_u32_at(
            ResearchStage::DllStages,
            "aes_key_schedule",
            decomp_params[2] as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(decomp_params[2]),
        );
    }
    if verbose {
        crate::progress::step(4, 9, Step::RelocsParams);
        crate::progress::detail(format_args!("  addr2          = 0x{:08X}", addr2 as u32));
        crate::progress::detail(format_args!(
            "  decomp_params  = [0x{:08X}, 0x{:08X}, 0x{:08X}, 0x{:08X}]",
            decomp_params[0] as u32,
            decomp_params[1] as u32,
            decomp_params[2] as u32,
            decomp_params[3] as u32
        ));
    }

    let checksum2 = calculate_checksum(&out, (keys[6] + 5640) as u32) as i32;
    let mut table_val = get_i32(&out, decrypted_addr1 + 3448);
    for k in 1..=100 {
        table_val = table_val.wrapping_add(k);
    }
    for k in 1..=200 {
        table_val = table_val.wrapping_add(k);
    }
    for k in 1..=300 {
        table_val = table_val.wrapping_add(k);
    }
    for k in 1..=400 {
        table_val = table_val.wrapping_add(k);
    }

    if research::trace_enabled() {
        research::emit_u32(ResearchStage::DllStages, "checksum2", checksum2 as u32);
        research::emit_u32(ResearchStage::DllStages, "table_key", table_val as u32);
    }
    let addr3_offset = decrypted_addr1 + 3712;
    decrypt_data4(
        &mut out,
        addr3_offset,
        table_val ^ checksum2 ^ (xor_accumulator as i32),
        &decomp_params,
        None,
        DecompressionStage::DllCodeBlock1,
    )?;

    let addr3b = get_i32(&out, decrypted_addr1 + 3728);
    if verbose {
        crate::progress::step(5, 9, Step::DecryptBlock1);
        crate::progress::detail(format_args!("  checksum2 = 0x{:08X}", checksum2 as u32));
        crate::progress::detail(format_args!("  addr3b    = 0x{:08X}", addr3b as u32));
    }

    let crc_data_offset = decrypted_addr1 + 3488;
    let crc_data_addr = get_i32(&out, crc_data_offset);
    let crc_data_size = get_i32(&out, crc_data_offset + 4);
    let crc_val = {
        let a = crc_data_addr as usize;
        let n = crc_data_size as usize;
        senbei_crypto::crc32::compute(&out[a..a + n]) as i32
    };
    let crc_xored = crc_data_size ^ crc_val;
    let trailing_val = get_i32(&out, crc_data_addr + crc_data_size - 4);
    decrypt_data4(
        &mut out,
        decrypted_addr1 + 3728,
        crc_xored ^ (xor_accumulator as i32) ^ trailing_val,
        &decomp_params,
        None,
        DecompressionStage::DllCodeBlock2,
    )?;

    let checksum3 = calculate_checksum(&out, (decrypted_addr1 + 3480) as u32) as i32;
    let not_val = !get_u32(&out, (addr3b + 1968) as u32);
    let addr4_offset = decrypted_addr1 + 3760;
    let xor_key = (xor_accumulator as i32) ^ checksum3;
    decrypt_data4(
        &mut out,
        addr4_offset,
        (not_val ^ (xor_key as u32)) as i32,
        &decomp_params,
        None,
        DecompressionStage::DllCodeBlock3,
    )?;

    let addr4 = get_i32(&out, addr4_offset);
    let lfsr = addr4 + 3200;
    // Decompress == primitives::decrypt_data6 (LFSR keystream, len at +95).
    decrypt_data6(&mut out, lfsr as u32);
    research::emit_u32_at(
        ResearchStage::DllStages,
        "file_lfsr",
        lfsr as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(lfsr),
    );
    research::emit_u32_at(
        ResearchStage::DllStages,
        "addr3b",
        addr3b as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(addr3b),
    );
    research::emit_u32_at(
        ResearchStage::DllStages,
        "addr4",
        addr4 as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(addr4),
    );
    research::emit_u32(ResearchStage::DllStages, "crc_val", crc_val as u32);
    research::emit_u32(ResearchStage::DllStages, "checksum3", checksum3 as u32);
    if verbose {
        crate::progress::step(6, 9, Step::DecryptBlocks2To3);
        crate::progress::detail(format_args!("  crc_val   = 0x{:08X}", crc_val as u32));
        crate::progress::detail(format_args!("  checksum3 = 0x{:08X}", checksum3 as u32));
        crate::progress::detail(format_args!("  addr4     = 0x{:08X}", addr4 as u32));
    }

    let checksum4 = calculate_checksum(&out, (decrypted_addr1 + 3472) as u32) as i32;
    let mut lfsr_seed_val = get_i32(&out, addr4 + 3160);
    for k in 1..=100 {
        lfsr_seed_val = lfsr_seed_val.wrapping_add(k);
    }
    for k in 1..=200 {
        lfsr_seed_val = lfsr_seed_val.wrapping_add(k);
    }
    for k in 1..=300 {
        lfsr_seed_val = lfsr_seed_val.wrapping_add(k);
    }

    research::emit_u32_at(
        ResearchStage::DllStages,
        "lfsr_seed",
        lfsr_seed_val as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(addr4 + 3160),
    );
    research::emit_u32(ResearchStage::DllStages, "checksum4", checksum4 as u32);
    let decrypt_func = generate(&out, lfsr as u32).ok_or_else(|| {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "bytecode_invalid",
            lfsr as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(lfsr),
        );
        UnpackError::BytecodeGenerationFailed(BytecodeStage::DllPrimaryDecryptor)
    })?;
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "bytecode_primary",
            lfsr as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(lfsr),
        );
        research::emit_u32(
            ResearchStage::DllStages,
            "bytecode_ops",
            decrypt_func.len() as u32,
        );
    }

    let addr5_offset = decrypted_addr1 + 3840;
    let addr5 = get_i32(&out, addr5_offset);
    decrypt_data4(
        &mut out,
        addr5_offset,
        lfsr_seed_val ^ xor_key ^ checksum4,
        &decomp_params,
        Some(&decrypt_func),
        DecompressionStage::DllCodeBlock4,
    )?;
    if verbose {
        crate::progress::step(7, 9, Step::DecryptBlock4);
        crate::progress::detail(format_args!("  checksum4 = 0x{:08X}", checksum4 as u32));
        crate::progress::detail(format_args!("  addr5     = 0x{:08X}", addr5 as u32));
    }

    let metadata_offset = addr5 + 12312;
    let mut metadata_addr = get_i32(&out, metadata_offset);
    let metadata_table = metadata_addr;

    while get_i32(&out, metadata_addr + 4) != 0 {
        decrypt_data6_shift6(&mut out, metadata_addr, 16);
        metadata_addr += 16;
    }
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "metadata_descriptor",
            metadata_table as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(metadata_table),
        );
        research::emit_u64(
            ResearchStage::DllStages,
            "metadata_descriptor_bytes",
            (metadata_addr - metadata_table).max(0) as u64,
        );
    }

    let lfsr2 = metadata_offset + 88;
    decrypt_data6(&mut out, lfsr2 as u32);
    research::emit_u32_at(
        ResearchStage::DllStages,
        "metadata_lfsr",
        lfsr2 as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(lfsr2),
    );

    let decrypt_func2 = generate(&out, lfsr2 as u32).ok_or_else(|| {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "bytecode_invalid",
            lfsr2 as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(lfsr2),
        );
        UnpackError::BytecodeGenerationFailed(BytecodeStage::DllSectionDecryptor)
    })?;
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::DllStages,
            "bytecode_section",
            lfsr2 as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(lfsr2),
        );
        research::emit_u32(
            ResearchStage::DllStages,
            "bytecode_section_ops",
            decrypt_func2.len() as u32,
        );
    }

    let section_image_base = 4095 - get_i32(original_file_data, 4224);
    let section_data_offset = get_i32(&out, addr5 + 11976);
    research::emit_u32_at(
        ResearchStage::Sections,
        "descriptor_table",
        section_data_offset as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(section_data_offset),
    );
    research::emit_u32_at(
        ResearchStage::Sections,
        "section_image_base",
        section_image_base as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(section_image_base),
    );
    if verbose {
        crate::progress::step(8, 9, Step::DllSections);
        crate::progress::detail(format_args!(
            "  section_image_base  = 0x{:08X}",
            section_image_base as u32
        ));
        crate::progress::detail(format_args!(
            "  section_data_offset = 0x{:08X}",
            section_data_offset as u32
        ));
    }

    // Managed-only pre-fill of .text (Task 3.2). No-op for native (clr_rva == 0).
    // Data directories start at optional-header +96 on PE32, +112 on PE32+ —
    // hardcoding +112 misreads the CLR RVA on a 32-bit image.
    let dd_base = if get_u16(file_data, (pe_offset + 24) as u32) == 0x20B {
        112
    } else {
        96
    };
    let clr_dir_rva = get_i32(file_data, pe_offset + 24 + dd_base + 14 * 8);
    research::emit_bool(ResearchStage::Sections, "managed_prefill", clr_dir_rva != 0);
    if clr_dir_rva != 0 {
        let sh_start = get_u16(file_data, (pe_offset + 20) as u32) as i32 + pe_offset + 24;
        for i in 0..section_count(file_data, pe_offset) {
            let off = sh_start + i * 40;
            if section_header_blank(file_data, off) {
                break;
            }
            let sec_va = get_i32(file_data, off + 12);
            let sec_vsize = get_i32(file_data, off + 8);
            let sec_raw = get_i32(file_data, off + 20);
            let sec_raw_size = get_i32(file_data, off + 16);
            if clr_dir_rva >= sec_va && clr_dir_rva < sec_va + sec_vsize {
                let avail = sec_raw_size.min(file_data.len() as i32 - sec_raw);
                let copy_len = avail.min(out.len() as i32 - sec_va);
                if copy_len > 0 {
                    let s = sec_raw as usize;
                    let dd = sec_va as usize;
                    let n = copy_len as usize;
                    out[dd..dd + n].copy_from_slice(&file_data[s..s + n]);
                    research::emit_range(
                        ResearchStage::Sections,
                        "managed_prefill_src",
                        AddressSpace::FileOffset,
                        s as u64,
                        n as u64,
                    );
                    research::emit_range(
                        ResearchStage::Sections,
                        "managed_prefill_dst",
                        AddressSpace::WorkingImageRva,
                        dd as u64,
                        n as u64,
                    );
                }
                break;
            }
        }
    }

    decrypt_and_decompress_data(
        &mut out,
        original_file_data,
        section_image_base,
        section_data_offset,
        &decrypt_func2,
        &decomp_params,
    )?;

    let import_table_offset = get_i32(&out, addr5 + 12016);
    research::emit_u32_at(
        ResearchStage::Imports,
        "import_table",
        import_table_offset as u32,
        AddressSpace::WorkingImageRva,
        trace_offset(addr5 + 12016),
    );
    if import_table_offset != 0 {
        process_import_table(&mut out, import_table_offset);
    } else {
        research::emit_note(
            ResearchStage::Imports,
            "import_table",
            TraceValue::Bool(false),
            "no import table",
        );
    }

    out[..4096].copy_from_slice(&file_data[..4096]);
    if verbose {
        crate::progress::step(9, 9, Step::FixHeaders);
    }

    let section_header_base = get_u16(file_data, (pe_offset + 20) as u32) as i32 + pe_offset;
    let section_start = section_header_base + 24;
    let image_data_addr = get_i32(original_file_data, section_start - 128);
    let image_data_size = get_i32(original_file_data, section_start - 124);
    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::Finalize,
            "original_entry_field",
            image_data_addr as u32,
            AddressSpace::FileOffset,
            trace_offset(section_start - 128),
        );
        research::emit_u32_at(
            ResearchStage::Finalize,
            "image_data_addr",
            image_data_addr as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(image_data_addr),
        );
        research::emit_u32_at(
            ResearchStage::Finalize,
            "image_data_size",
            image_data_size as u32,
            AddressSpace::FileOffset,
            trace_offset(section_start - 124),
        );
        research::emit_u32_at(
            ResearchStage::Finalize,
            "section_header_base",
            section_header_base as u32,
            AddressSpace::FileOffset,
            trace_offset(section_header_base),
        );
    }

    let mut entry_point_adjustment = 0i32;
    {
        for i in 0..section_count(file_data, pe_offset) {
            let offset = section_start + i * 40;
            if section_header_blank(file_data, offset) {
                break;
            }
            let virtual_size = get_i32(file_data, offset + 8);
            let virtual_addr = get_i32(file_data, offset + 12);
            let raw_data_offset = get_i32(file_data, offset + 20);

            if image_data_addr >= virtual_addr
                && image_data_addr + image_data_size <= virtual_addr + virtual_size
            {
                entry_point_adjustment = raw_data_offset + image_data_addr - virtual_addr;
            }

            write_i32(&mut out, offset + 16, virtual_size);
            write_i32(&mut out, offset + 20, virtual_addr);
        }
    }

    if image_data_size != 0 {
        let s = entry_point_adjustment as usize;
        let dd = image_data_addr as usize;
        let n = image_data_size as usize;
        out[dd..dd + n].copy_from_slice(&file_data[s..s + n]);
        research::emit_range(
            ResearchStage::Finalize,
            "image_data_src",
            AddressSpace::FileOffset,
            s as u64,
            n as u64,
        );
        research::emit_range(
            ResearchStage::Finalize,
            "image_data_dst",
            AddressSpace::WorkingImageRva,
            dd as u64,
            n as u64,
        );
        research::emit_u32_at(
            ResearchStage::Finalize,
            "entry_point_adjustment",
            entry_point_adjustment as u32,
            AddressSpace::FileOffset,
            trace_offset(entry_point_adjustment),
        );
    }

    // Managed-only CLR header recopy (Task 3.2). No-op for native.
    let clr_rva = get_i32(file_data, pe_offset + 24 + dd_base + 14 * 8);
    let clr_size = get_i32(file_data, pe_offset + 24 + dd_base + 14 * 8 + 4);
    if clr_rva != 0 && clr_size != 0 {
        for i in 0..section_count(file_data, pe_offset) {
            let offset = section_start + i * 40;
            if section_header_blank(file_data, offset) {
                break;
            }
            let sec_va = get_i32(file_data, offset + 12);
            let sec_raw = get_i32(file_data, offset + 20);
            let sec_vsize = get_i32(file_data, offset + 8);
            if clr_rva >= sec_va && clr_rva + clr_size <= sec_va + sec_vsize {
                let clr_file_off = sec_raw + (clr_rva - sec_va);
                let s = clr_file_off as usize;
                let dd = clr_rva as usize;
                let n = clr_size as usize;
                out[dd..dd + n].copy_from_slice(&file_data[s..s + n]);
                research::emit_u32_at(
                    ResearchStage::Finalize,
                    "clr_header",
                    clr_rva as u32,
                    AddressSpace::WorkingImageRva,
                    trace_offset(clr_rva),
                );
                research::emit_range(
                    ResearchStage::Finalize,
                    "clr_header_src",
                    AddressSpace::FileOffset,
                    s as u64,
                    n as u64,
                );
                break;
            }
        }
    } else {
        research::emit_bool(ResearchStage::Finalize, "clr_header", false);
    }

    // The anchor page rewrites the last stage of the header; the source and
    // destination below are both readings of the working image.
    decrypt_data6_shift6(&mut out, keys[3] + 16, 656);
    research::emit_range(
        ResearchStage::Finalize,
        "anchor_header",
        AddressSpace::WorkingImageRva,
        trace_offset(keys[3] + 16),
        656,
    );
    let pe_offset2 = get_i32(&out, 60);
    let final_size_of_image = get_i32(&out, keys[3] + 32);
    write_i32(&mut out, pe_offset2 + 40, final_size_of_image);
    {
        let s = (keys[3] + 48) as usize;
        let dd = (pe_offset2 + 136) as usize;
        out.copy_within(s..s + 128, dd);
        research::emit_range(
            ResearchStage::Finalize,
            "data_directories",
            AddressSpace::WorkingImageRva,
            dd as u64,
            128,
        );
    }

    if research::trace_enabled() {
        research::emit_u32_at(
            ResearchStage::Finalize,
            "final_pe_offset",
            pe_offset2 as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(pe_offset2),
        );
        research::emit_u32(
            ResearchStage::Output,
            "final_size_of_image",
            final_size_of_image as u32,
        );
        research::emit_u64(ResearchStage::Output, "output_len", out.len() as u64);
        research::emit_u32_at(
            ResearchStage::Output,
            "output_base",
            keys[3] as u32,
            AddressSpace::WorkingImageRva,
            trace_offset(keys[3]),
        );
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::MAGIC_KONN;
    use crate::windows::research::{ResearchTrace, with_research_trace};

    /// A protected-shaped header `unpack_dll_inner` accepts far enough to emit
    /// the header key events, then rejects at the PE offset check. Detection
    /// fields are the same shape the synthetic detection test uses.
    fn protected_header_input() -> Vec<u8> {
        let mut data = vec![0u8; 0x1200];
        let pe = 0x80i32;
        data[60..64].copy_from_slice(&pe.to_le_bytes());
        data[pe as usize..pe as usize + 4].copy_from_slice(b"PE\0\0");
        // PE32+ optional header magic at pe + 24.
        data[pe as usize + 24..pe as usize + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
        // Header key derivation: keys[0] = word(4096); keys[1] = keys[0] ^ word(4100).
        let key0 = 1u32;
        data[4096..4100].copy_from_slice(&key0.to_le_bytes());
        data[4100..4104].copy_from_slice(&(key0 ^ MAGIC_KONN).to_le_bytes());
        data
    }

    fn event_names(trace: &ResearchTrace) -> Vec<&'static str> {
        trace.events.iter().map(|event| event.name).collect()
    }

    #[test]
    fn trace_disabled_emits_nothing_and_keeps_the_result() {
        let input = protected_header_input();
        assert!(!research::trace_enabled());
        let result = unpack_dll(&input);
        // The synthetic header cannot recover an image; the point is that the
        // untraced path is unaffected and no sink was installed.
        assert!(result.is_err());
        assert!(!research::trace_enabled());
    }

    #[test]
    fn trace_records_header_facts_and_the_real_failure() {
        let input = protected_header_input();
        let (trace, result) = with_research_trace(|| unpack_dll(&input));
        assert!(result.is_err(), "synthetic header must fail recovery");

        let names = event_names(&trace);
        assert!(
            names.contains(&"header_keys"),
            "header key table must be traced: {names:?}"
        );
        assert!(names.contains(&"magic"));
        assert!(names.contains(&"payload_base"));

        // Scalar header facts are real computed values, and the magic keeps
        // the KONN encoding under the protected-header space.
        let keys = trace
            .events
            .iter()
            .find(|event| event.name == "header_keys")
            .expect("header_keys event");
        // keys[0] is the raw first word and keys[1] carries the magic; later
        // entries are chained, so only these two are fixed by this input.
        match &keys.value {
            TraceValue::U32s(values) => {
                assert_eq!(values.len(), 8);
                assert_eq!(values[0], 1);
                assert_eq!(values[1], MAGIC_KONN);
            }
            other => panic!("header_keys must be a word list, got {other:?}"),
        }
        let magic = trace
            .events
            .iter()
            .find(|event| event.name == "magic")
            .expect("magic event");
        assert_eq!(magic.value, TraceValue::U32(MAGIC_KONN));
        assert_eq!(
            magic.address,
            Some(crate::windows::research::TraceAddress {
                space: AddressSpace::ProtectedHeaderOffset,
                offset: 4100,
            })
        );

        let anchor = trace
            .events
            .iter()
            .find(|event| event.name == "anchor")
            .expect("anchor event");
        assert_eq!(
            anchor.address.as_ref().map(|address| address.space),
            Some(AddressSpace::WorkingImageRva)
        );
        let TraceValue::U32(anchor_rva) = &anchor.value else {
            panic!("anchor must be an RVA");
        };
        assert_eq!(
            anchor.address.as_ref().map(|address| address.offset),
            Some(u64::from(*anchor_rva))
        );

        // Nothing may claim a layout selection or a validated image: the
        // synthetic input never reaches section recovery.
        assert!(
            !names.iter().any(|name| name.contains("selected")),
            "no selection claim on a failed recovery: {names:?}"
        );
        assert!(!names.contains(&"output_len"));
    }
}
