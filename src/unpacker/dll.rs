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

use super::bytecode::{Op, OpsLut, generate};
use super::primitives::{self, *};
use super::{
    BufferOperation, BytecodeStage, DecompressionStage, DescriptorTable, SectionPipeline,
    UnpackError,
};

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

    aes_decrypt(d, addr as u32, size as u32, decomp_params[3] as u32);
    // DecryptData1(offset, key, 19) == primitives::decrypt_data3 with shift 19
    decrypt_data3(d, offset as u32, key as u32, 19);

    if let Some(ops) = transform
        && size > 0
    {
        OpsLut::new(ops).map_region(d, addr as usize, size as usize);
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
        return Err(UnpackError::StageDecompressionFailed { stage, reason });
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
            thunk_addr += 8;
        }
        import_table_offset += 20;
    }
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
    let mut blocks: Vec<Blk> = Vec::new();
    loop {
        // Guard: need 16 bytes at section_data_offset in `d`
        let off = section_data_offset as usize;
        if off.saturating_add(16) > d.len() {
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
        blocks.push(Blk {
            dest_offset,
            size,
            src_offset,
            expected_crc,
        });
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
        let ks_snap = primitives::aes_schedule_snapshot(d, ko2 as u32)
            .ok_or(UnpackError::InvalidAesKeySchedule { offset: ko2 as u32 })?;
        let tab_snap = primitives::huffman_table_snapshot(d, ko0 as u32)
            .ok_or(UnpackError::InvalidHuffmanTable { offset: ko0 as u32 })?;
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
        super::parallel::parallel_for(d, &spans, 1, do_block)?;
    }

    // Zero-fill loop.
    loop {
        let off = section_data_offset as usize;
        // The entry block loop above correctly requires 16 bytes; this loop
        // decrypts 16 too, so guard 16 (an 8-byte guard would let
        // decrypt_data6_shift6 index past the end of a truncated descriptor).
        if off.saturating_add(16) > d.len() {
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
    super::catch_unpack(move || unpack_dll_inner(input, verbose))
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
    if verbose {
        println!("[1/9] Initializing keys...");
        println!("  keys[0] key       = 0x{:08X}", keys[0] as u32);
        println!("  keys[1] signature = 0x{:08X}", keys[1] as u32);
        println!("  keys[3] base      = 0x{:08X}", keys[3] as u32);
        println!("  keys[4] src_off   = 0x{:08X}", keys[4] as u32);
        println!("  keys[5] size      = 0x{:08X}", keys[5] as u32);
        println!("  keys[6] anchor    = 0x{:08X}", keys[6] as u32);
    }

    if !super::is_supported_magic(keys[1] as u32) {
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
    if size_of_image <= 0 || size_of_image as u64 > super::MAX_IMAGE_SIZE {
        return Err(UnpackError::InvalidImageSize {
            size: i64::from(size_of_image),
            max: super::MAX_IMAGE_SIZE,
        });
    }
    let mut out = vec![0u8; size_of_image as usize];
    let base_offset = keys[6] - keys[3] + 0x2000;
    if verbose {
        println!("[2/9] Decrypting key table...");
        println!("  size_of_image = 0x{:08X}", size_of_image as u32);
        println!("  base_offset   = 0x{:08X}", base_offset as u32);
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
    if verbose {
        println!("[3/9] Decrypting primary descriptor...");
        println!("  xor_accumulator = 0x{:08X}", xor_accumulator);
        println!("  checksum1       = 0x{:08X}", checksum1 as u32);
        println!("  decrypted_addr1 = 0x{:08X}", decrypted_addr1 as u32);
    }
    let primary_end = decrypted_addr1.checked_add(3856);
    if decrypted_addr1 < keys[3]
        || primary_end.is_none_or(|end| end < 0 || end as usize > out.len())
    {
        return Err(UnpackError::InvalidDllPrimaryDescriptor {
            address: decrypted_addr1 as u32,
            minimum: keys[3] as u32,
            image_len: out.len(),
        });
    }
    let import_offset = get_i32(&out, decrypted_addr1 + 3444);
    let decrypted_addr2_size = get_i32(&out, decrypted_addr1 + 3632);
    decrypt_data3(
        &mut out,
        (decrypted_addr1 + 3632) as u32,
        import_offset as u32,
        19,
    );

    let addr2 = decrypted_addr2_size;
    let reloc_block_offset = addr2 + 9248;
    let reloc_type = get_i32(&out, reloc_block_offset);

    if (reloc_type & 0x0F) == 1 {
        decrypt_data3_shift5(&mut out, addr2 + 9252);
    } else if reloc_type == 2 {
        let p = get_i32(&out, addr2 + 9252);
        process_reloc_block(&mut out, p);
    }

    let reloc_block_offset2 = reloc_block_offset + 16;
    let reloc_type2 = get_i32(&out, reloc_block_offset2);

    if (reloc_type2 & 0x0F) == 1 {
        decrypt_data3_shift5(&mut out, reloc_block_offset2 + 4);
    } else if reloc_type2 == 2 {
        let p = get_i32(&out, reloc_block_offset2 + 4);
        process_reloc_block(&mut out, p);
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
    if verbose {
        println!("[4/9] Processing relocations & decomp params...");
        println!("  addr2          = 0x{:08X}", addr2 as u32);
        println!(
            "  decomp_params  = [0x{:08X}, 0x{:08X}, 0x{:08X}, 0x{:08X}]",
            decomp_params[0] as u32,
            decomp_params[1] as u32,
            decomp_params[2] as u32,
            decomp_params[3] as u32
        );
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
        println!("[5/9] Decrypting code block 1 (addr3)...");
        println!("  checksum2 = 0x{:08X}", checksum2 as u32);
        println!("  addr3b    = 0x{:08X}", addr3b as u32);
    }

    let crc_data_offset = decrypted_addr1 + 3488;
    let crc_data_addr = get_i32(&out, crc_data_offset);
    let crc_data_size = get_i32(&out, crc_data_offset + 4);
    let crc_val = {
        let a = crc_data_addr as usize;
        let n = crc_data_size as usize;
        super::crc32::compute(&out[a..a + n]) as i32
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
    if verbose {
        println!("[6/9] Decrypting code blocks 2-3 (addr3b, addr4)...");
        println!("  crc_val   = 0x{:08X}", crc_val as u32);
        println!("  checksum3 = 0x{:08X}", checksum3 as u32);
        println!("  addr4     = 0x{:08X}", addr4 as u32);
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

    let decrypt_func = generate(&out, lfsr as u32).ok_or(UnpackError::BytecodeGenerationFailed(
        BytecodeStage::DllPrimaryDecryptor,
    ))?;

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
        println!("[7/9] Decrypting code block 4 (addr5)...");
        println!("  checksum4 = 0x{:08X}", checksum4 as u32);
        println!("  addr5     = 0x{:08X}", addr5 as u32);
    }

    let metadata_offset = addr5 + 12312;
    let mut metadata_addr = get_i32(&out, metadata_offset);

    while get_i32(&out, metadata_addr + 4) != 0 {
        decrypt_data6_shift6(&mut out, metadata_addr, 16);
        metadata_addr += 16;
    }

    let lfsr2 = metadata_offset + 88;
    decrypt_data6(&mut out, lfsr2 as u32);

    let decrypt_func2 = generate(&out, lfsr2 as u32).ok_or(
        UnpackError::BytecodeGenerationFailed(BytecodeStage::DllSectionDecryptor),
    )?;

    let section_image_base = 4095 - get_i32(original_file_data, 4224);
    let section_data_offset = get_i32(&out, addr5 + 11976);
    if verbose {
        println!("[8/9] Decrypting & decompressing sections...");
        println!(
            "  section_image_base  = 0x{:08X}",
            section_image_base as u32
        );
        println!(
            "  section_data_offset = 0x{:08X}",
            section_data_offset as u32
        );
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
    if import_table_offset != 0 {
        process_import_table(&mut out, import_table_offset);
    }

    out[..4096].copy_from_slice(&file_data[..4096]);
    if verbose {
        println!("[9/9] Fixing up PE header & section table...");
    }

    let section_header_base = get_u16(file_data, (pe_offset + 20) as u32) as i32 + pe_offset;
    let section_start = section_header_base + 24;
    let image_data_addr = get_i32(original_file_data, section_start - 128);
    let image_data_size = get_i32(original_file_data, section_start - 124);

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
                break;
            }
        }
    }

    decrypt_data6_shift6(&mut out, keys[3] + 16, 656);
    let pe_offset2 = get_i32(&out, 60);
    let final_size_of_image = get_i32(&out, keys[3] + 32);
    write_i32(&mut out, pe_offset2 + 40, final_size_of_image);
    {
        let s = (keys[3] + 48) as usize;
        let dd = (pe_offset2 + 136) as usize;
        out.copy_within(s..s + 128, dd);
    }

    Ok(out)
}
