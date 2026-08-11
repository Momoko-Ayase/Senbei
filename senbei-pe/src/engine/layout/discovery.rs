//! Structural locators for protected PE stages.

use senbei_crypto::primitives::{get_u32, lfsr_keystream};

/// Find the 4-byte v_val that follows the LAST occurrence of `48 EB 01 B9`
/// (REX.W jmp+1; mov ecx,imm32) plus any 0xCC padding. Used to locate
/// stage4's accum2 seed. Works across builds even when API-name anchors are
/// absent.
pub fn find_v_after_pad(data: &[u8], base: u32, len: u32) -> Option<u32> {
    let start = base as usize;
    let end = (base.saturating_add(len)) as usize;
    if end > data.len() {
        return None;
    }
    let sig = [0x48u8, 0xEB, 0x01, 0xB9];
    let slice = &data[start..end];
    // last occurrence
    let mut last = None;
    let mut i = 0usize;
    while i + sig.len() <= slice.len() {
        if slice[i..i + sig.len()] == sig {
            last = Some(i);
        }
        i += 1;
    }
    let pos = last?;
    // skip CCs after the `48 EB 01 B9`
    let mut after = pos + sig.len();
    while after < slice.len() && slice[after] == 0xCC {
        after += 1;
    }
    if after + 4 > slice.len() {
        return None;
    }
    Some((start + after) as u32)
}

/// Predict the 4 bytes that DecryptData5(va, size) would produce at va+0..va+4
/// without mutating the buffer. The cipher's per-byte transform depends only
/// on the byte itself and the low 8 bits of (va+i), with no cross-byte state,
/// so each byte can be decrypted in isolation. Used to detect the EP/DD layout
/// offset before committing to the actual call.
pub fn trial_decrypt5_u32(data: &[u8], va: u32) -> u32 {
    let mut out = [0u8; 4];
    for i in 0..4u32 {
        let b3 = data[(va + i) as usize];
        let b = (va + i) as u8;
        let b2 = b.wrapping_add(1);
        let b4 = b3.rotate_left(2) ^ b2;
        let b5 = b4.rotate_left(2) ^ b;
        out[i as usize] = b5.rotate_left(2);
    }
    u32::from_le_bytes(out)
}

/// Scan stage4/stage5 for the encrypted custom-decryptor bytecode block. The
/// raw byte at p+95 is used by decrypt_data6 as the iteration count. We trial-
/// decrypt that many bytes with the LFSR keystream and accept the first
/// position where the byte stream parses as a valid opcode sequence ending in
/// 195 (ret).
pub fn find_bytecode_offset(data: &[u8], base: u32, len: u32) -> Option<u32> {
    let start = base as usize;
    let end = (base.saturating_add(len)) as usize;
    if end > data.len() {
        return None;
    }
    let mut ks = [0u8; 256];
    lfsr_keystream(&mut ks);
    // Scan forward from `start+16` on 16-byte boundaries relative to `start`.
    // The bytecode block is positioned a fixed offset into stage4/stage5; the
    // lowest parseable candidate is the real one (later ones are coincidental
    // parses of trailing filler bytes that happen to map to valid opcodes).
    // The enclosing buffer isn't necessarily 16-aligned to its absolute
    // address in newer builds, so we anchor the stride to `start`.
    let mut p = start + 16;
    while p + 96 <= end {
        let count = data[p + 95] as usize;
        if count >= 8 && p + count <= end {
            let mut buf = [0u8; 256];
            let take = count.min(256);
            for i in 0..take {
                buf[i] = data[p + i] ^ ks[i];
            }
            if let Some(nops) = parse_bytecode_check(&buf[..take])
                && nops >= 4
            {
                return Some(p as u32);
            }
        }
        p += 16;
    }
    None
}

/// Validate bytecode structure without allocating a `Vec` of ops. Returns
/// `Some(non_nop_op_count)` if the byte stream parses successfully as a valid
/// opcode sequence ending in 195 (ret), `None` otherwise. Allows non-trivial
/// bytecode filtering by op count.
pub fn parse_bytecode_check(buf: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    let mut nops: usize = 0;
    while i < buf.len() {
        let b = buf[i];
        i += 1;
        match b {
            4 | 44 | 52 => {
                if i >= buf.len() {
                    return None;
                }
                i += 1;
                nops += 1;
            }
            144 => {}
            192 | 254 => {
                if i >= buf.len() {
                    return None;
                }
                let mb = buf[i];
                i += 1;
                let rm = mb & 7;
                let mod_ = (mb >> 6) & 3;
                let reg = (mb >> 3) & 7;
                if mod_ != 3 || rm != 0 {
                    return None;
                }
                if reg > 1 {
                    return None;
                }
                if b == 192 {
                    if i >= buf.len() {
                        return None;
                    }
                    i += 1;
                }
                nops += 1;
            }
            195 => return Some(nops),
            _ => return None,
        }
    }
    None
}

/// Locate stage3's v4_val: the last non-zero dword in the buffer, anchored
/// by the `C3 CC CC CC` (ret + 3 int3) immediately before it.
pub fn find_v4_offset(data: &[u8], base: u32, len: u32) -> Option<u32> {
    let start = base as usize;
    let end = (base.saturating_add(len)) as usize;
    if end > data.len() || end < start + 4 {
        return None;
    }
    // walk backwards looking for the first non-zero byte
    let mut i = end;
    while i > start && data[i - 1] == 0 {
        i -= 1;
    }
    if i < start + 4 {
        return None;
    }
    // v_val occupies the 4 bytes ending at i (rounded up to dword boundary)
    let v_end = i;
    let v_start = ((v_end + 3) & !3).saturating_sub(4);
    // require that the 4 bytes preceding v_val match `C3 CC CC CC`
    if v_start < start + 4 || data[v_start - 4..v_start] != [0xC3, 0xCC, 0xCC, 0xCC] {
        return None;
    }
    Some(v_start as u32)
}

/// Scan a sub-buffer for an ASCII needle; return its absolute position.
pub fn find_str_pos(data: &[u8], base: u32, len: u32, needle: &[u8]) -> Option<u32> {
    let start = base as usize;
    let end = (base.saturating_add(len)) as usize;
    if end > data.len() || needle.is_empty() {
        return None;
    }
    data[start..end]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|rel| (start + rel) as u32)
}

pub fn get_string_to_null(data: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= data.len() {
        return String::new();
    }
    // Bounded: an unterminated run must never walk off the end of the buffer
    // (panic) or scan unboundedly into unrelated data.
    let limit = start.saturating_add(4096).min(data.len());
    let mut i = start;
    while i < limit && data[i] != 0 {
        i += 1;
    }
    String::from_utf8_lossy(&data[start..i]).into_owned()
}

/// Read a PE section-name field: exactly 8 bytes, NOT necessarily
/// NUL-terminated (a full-width name like `.textbss` has no NUL at all).
/// Returns the name with trailing NULs stripped. Using `get_string_to_null`
/// here would run past the field into the VirtualSize/VirtualAddress dwords.
pub fn section_name(data: &[u8], offset: u32) -> String {
    let start = offset as usize;
    let Some(field) = data.get(start..start + 8) else {
        return String::new();
    };
    let end = field.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&field[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// PE32 (32-bit) helpers
// ---------------------------------------------------------------------------

/// PE32 shell-table locator. Walks the shell region (`info[6]`) for a dword
/// equal to `info[6]` followed by a plausible shell size, returning the table
/// base (`candidate = off - 0x88`) when `candidate+0x58` holds a valid pointer.
pub fn find_tbl_pe32(data: &[u8], info: &[u32; 8]) -> Option<u32> {
    let shell = info[6];
    if (data.len() as u64) < 0x100 {
        return None;
    }
    let hi = (shell as u64)
        .saturating_add(0x3000)
        .min(data.len() as u64 - 0x100) as u32;
    let mut off = shell;
    while off < hi {
        if off as usize + 8 <= data.len() {
            let candidate = off.wrapping_sub(0x88);
            if candidate >= shell && get_u32(data, off) == info[6] {
                let shell_size_val = get_u32(data, off.wrapping_add(4));
                if shell_size_val > 0x1000 && shell_size_val < 0x100000 {
                    let v58_off = candidate.wrapping_add(0x58);
                    if (v58_off as usize + 4) <= data.len() {
                        let v58 = get_u32(data, v58_off);
                        if v58 > 0 && (v58 as usize) < data.len() {
                            return Some(candidate);
                        }
                    }
                }
            }
        }
        off = off.wrapping_add(4);
    }
    None
}

/// Locate an LFSR-encrypted bytecode block (decrypt_data6 form) in a region.
/// `start_off` is the byte offset to begin scanning at, `scan_backward`
/// controls direction. Returns the relative offset of the block. Includes full
/// opcode-walk validation of candidate blocks.
pub fn find_lfsr_block(
    data: &[u8],
    base: u32,
    size: u32,
    start_off: u32,
    scan_backward: bool,
) -> Option<u32> {
    if size < 96 {
        return None;
    }
    let mut ks = [0u8; 128];
    lfsr_keystream(&mut ks);
    let check = |scan_off: u32| -> bool {
        let abs_off = base.wrapping_add(scan_off) as usize;
        if abs_off + 96 > data.len() {
            return false;
        }
        let sz = data[abs_off + 95] as usize;
        if !(10..=95).contains(&sz) {
            return false;
        }
        let mut decoded = [0u8; 95];
        for bi in 0..sz {
            decoded[bi] = data[abs_off + bi] ^ ks[bi];
        }
        // Full bytecode validation (shared with the stage4/5 locator): every
        // opcode must decode with a valid ModR/M and the stream must REACH a
        // RET (0xC3) as an opcode. The previous check only required a 0xC3
        // byte *anywhere* in the window and accepted a walk that ran off the
        // end without hitting RET — a `0x04 0xC3` (ADD 0xC3) tail passed, so
        // coincidental LFSR-shaped garbage was accepted as a decryptor block.
        parse_bytecode_check(&decoded[..sz]).is_some()
    };
    if scan_backward {
        let hi = size - 96;
        if hi >= start_off {
            let mut scan_off = hi;
            loop {
                if check(scan_off) {
                    return Some(scan_off);
                }
                if scan_off == start_off {
                    break;
                }
                scan_off -= 1;
            }
        }
    } else {
        let hi = size - 95;
        let mut scan_off = start_off;
        while scan_off < hi {
            if check(scan_off) {
                return Some(scan_off);
            }
            scan_off += 1;
        }
    }
    None
}

/// Slots discovered in the eighthStage for the marker-less layout.
pub struct EighthSlots {
    /// Absolute address of the file-data decryptor LFSR bytecode block. The
    /// fileCS chain pointer is derived downstream as `file_lfsr - 0x58`.
    pub file_lfsr: u32,
    /// Absolute address of the compressedInfo (ptr,size) table pointer slot.
    pub compressed_info_ptr: u32,
}

/// Marker-independent eighthStage slot discovery (PE32+ branch).
///
/// Newer Crackproof builds (e.g. some native/managed DLLs) omit the
/// `pm\0\0cm\0\0` and `00 00 00 40 01 00 00 00` markers that the older layout's
/// walk3/walk4/walk5 slot derivation relies on. Instead this discovers the
/// slots structurally:
///   * Scan the eighthStage for every LFSR (decrypt_data6) bytecode block.
///   * The file decryptor is the LFSR block whose `fileCS = lfsr - 0x58` holds
///     a pointer sitting just past `info[3]` (smallest positive distance).
///   * `compressedInfo` is the pointer slot whose 16-byte target, after a
///     trial `decrypt_data5`, parses as a plausible (src,sSize,dst,dSize)
///     descriptor.
///
/// Returns `None` if no plausible file LFSR is found. `eighth_start`/`eighth_dsz`
/// bound the search region; `info3` is `info[3]`; `compress_data_offset` is
/// `(!u32(file_data,0x1080)) + 0x1000`; `file_data_len` is the protected file
/// length.
#[allow(clippy::too_many_arguments)]
pub fn discover_eighth_slots(
    data: &[u8],
    eighth_start: u32,
    eighth_dsz: u32,
    info3: u32,
    compress_data_offset: u32,
    file_data_len: u32,
) -> Option<EighthSlots> {
    // Collect all LFSR candidates (forward scan).
    //
    // Advance by 1 after each hit, NOT by 96. A false-positive LFSR match can sit
    // just before the real file-decryptor block (observed on an il2cpp game
    // assembly build, 2026-07-13: junk at rel=0x31C1, real block at 0x3210).
    // Stepping by the LFSR body size then skips the real block and discovery
    // fails. Byte-stepping is cheap: eighthStage is only a few KB.
    let mut all_lfsrs: Vec<u32> = Vec::new();
    let mut scan_off: u32 = 0;
    while scan_off + 95 < eighth_dsz {
        match find_lfsr_block(data, eighth_start, eighth_dsz, scan_off, false) {
            Some(found) => {
                all_lfsrs.push(found);
                scan_off = found + 1;
            }
            None => break,
        }
    }

    // Pick the file LFSR: prefer the candidate whose fileCS pointer sits the
    // smallest positive distance past info[3].
    let mut off_file_lfsr: Option<u32> = None;
    let mut best_dist: Option<u32> = None;
    for &lfsr_off in &all_lfsrs {
        if lfsr_off < 0x58 {
            continue;
        }
        let cs_off = lfsr_off - 0x58;
        let cs_val = get_u32(data, eighth_start.wrapping_add(cs_off));
        if !(0x1000 < cs_val && (cs_val as usize) < data.len()) {
            continue;
        }
        if cs_val < info3 {
            continue;
        }
        let dist = cs_val - info3;
        if best_dist.is_none_or(|b| dist < b) {
            best_dist = Some(dist);
            off_file_lfsr = Some(lfsr_off);
        }
    }
    // Fallback: last LFSR with any in-image fileCS pointer.
    if off_file_lfsr.is_none() {
        for &lfsr_off in all_lfsrs.iter().rev() {
            if lfsr_off < 0x58 {
                continue;
            }
            let cs_val = get_u32(data, eighth_start.wrapping_add(lfsr_off - 0x58));
            if 0x1000 < cs_val && (cs_val as usize) < data.len() {
                off_file_lfsr = Some(lfsr_off);
                break;
            }
        }
    }
    let off_file_lfsr = off_file_lfsr?;
    let off_file_cs = off_file_lfsr - 0x58;

    // Trial-decrypt to find compressedInfo: the pointer slot in the data area
    // (between fileCS region start and the LFSR) whose target parses as a valid
    // (src,sSize,dst,dSize) descriptor after a transient decrypt_data5.
    let scan_from = off_file_lfsr.saturating_sub(0x400);
    let mut off_compressed_info: Option<u32> = None;
    let mut doff = scan_from;
    while doff < off_file_lfsr {
        if doff == off_file_cs {
            doff += 4;
            continue;
        }
        let ptr_val = get_u32(data, eighth_start.wrapping_add(doff));
        if !(0x1000 < ptr_val && (ptr_val as usize) < data.len().saturating_sub(16)) {
            doff += 4;
            continue;
        }
        // Predict decrypt_data5(ptr_val, 16) without mutating: each dword is
        // position-keyed and independent, so trial_decrypt5_u32 per dword.
        let src2 = trial_decrypt5_u32(data, ptr_val);
        let s_sz2 = trial_decrypt5_u32(data, ptr_val + 4);
        let dst2 = trial_decrypt5_u32(data, ptr_val + 8);
        let d_sz2 = trial_decrypt5_u32(data, ptr_val + 12);
        let src_file_off = src2.wrapping_add(compress_data_offset);
        let valid = s_sz2 > 0
            && s_sz2 < 0x200000
            && (src_file_off as u64 + s_sz2 as u64) <= file_data_len as u64
            && dst2 >= 0x1000
            && (dst2 as u64 + d_sz2 as u64) <= data.len() as u64
            && d_sz2 >= s_sz2
            && d_sz2 < 0x200000;
        if valid {
            off_compressed_info = Some(doff);
            break;
        }
        doff += 4;
    }
    let off_compressed_info = off_compressed_info?;

    Some(EighthSlots {
        file_lfsr: eighth_start.wrapping_add(off_file_lfsr),
        compressed_info_ptr: eighth_start.wrapping_add(off_compressed_info),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Task 4.1 regression: build a synthetic buffer whose valid bytecode block
    /// sits PAST `len` but within `len*2`. Assert that the smaller window misses
    /// it and the doubled window finds it.
    #[test]
    fn bytecode_locate_double_window_retry() {
        // We place the block at offset (base + len + 16) which is inside
        // the len*2 window but outside the len window.
        let base: u32 = 0;
        let len: u32 = 256;
        // Block sits at base + len + 16 = 272, aligned to 16.
        let block_pos: usize = (base + len + 16) as usize; // 272

        // The buffer must be large enough for the block (block_pos + 96 bytes).
        let buf_len = block_pos + 256;
        let mut buf = vec![0u8; buf_len];

        // Build a valid plaintext op stream:
        //   [4, 0, 4, 0, 4, 0, 4, 0, 195]  (4 ADD-AL ops then RET)
        // Padded to 10 bytes total; count >= 8.
        let count: usize = 10;
        let mut plain = [0u8; 256];
        plain[0] = 4;
        plain[1] = 0;
        plain[2] = 4;
        plain[3] = 0;
        plain[4] = 4;
        plain[5] = 0;
        plain[6] = 4;
        plain[7] = 0;
        plain[8] = 195; // ret

        // Compute the LFSR keystream and XOR the first `count` bytes to get the
        // encrypted representation that the scanner would decrypt back.
        let mut ks = [0u8; 256];
        lfsr_keystream(&mut ks);
        for i in 0..count {
            buf[block_pos + i] = plain[i] ^ ks[i];
        }
        // Raw count byte at block_pos+95 (outside the XOR range since count=10 < 95).
        buf[block_pos + 95] = count as u8;

        // Verify our construction: find_bytecode_offset with len should NOT find it.
        assert_eq!(
            find_bytecode_offset(&buf, base, len),
            None,
            "smaller window should not find the block"
        );

        // The doubled window should find it at block_pos.
        assert_eq!(
            find_bytecode_offset(&buf, base, len.saturating_mul(2)),
            Some(block_pos as u32),
            "doubled window should locate the block"
        );
    }
}
