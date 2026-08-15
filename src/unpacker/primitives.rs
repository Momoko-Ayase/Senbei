//! Shared crypto primitives and helper utilities.
//!
//! All functions here are `pub(crate)` so that both the EXE unpacker (`exe.rs`)
//! and the future DLL unpacker (`dll.rs`) can call them without duplication.
//! Each free function is self-contained: it takes the relevant byte buffer(s)
//! and parameters explicitly, with no coupling to the EXE `Unpacker` struct.

use super::bytecode::{Op, OpsLut};
use super::crc32;
use super::tables::{COLUMMIX1, COLUMMIX2, COLUMMIX3, COLUMMIX4, SBOX};
use std::cell::RefCell;

thread_local! {
    /// Reusable scratch for `decompress`. A single unpack runs `decompress`
    /// hundreds of times over small blocks; reusing one growable buffer avoids a
    /// fresh allocation each call. Thread-local, so it stays correct (one buffer
    /// per worker) under the parallel block fan-out.
    static DECOMPRESS_SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

// ---------------------------------------------------------------------------
// Byte-order accessors
// ---------------------------------------------------------------------------

pub(crate) fn get_u16(data: &[u8], offset: u32) -> u16 {
    let i = offset as usize;
    u16::from_le_bytes([data[i], data[i + 1]])
}

pub(crate) fn get_u32(data: &[u8], offset: u32) -> u32 {
    let i = offset as usize;
    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
}

pub(crate) fn get_u64(data: &[u8], offset: u32) -> u64 {
    let i = offset as usize;
    u64::from_le_bytes([
        data[i],
        data[i + 1],
        data[i + 2],
        data[i + 3],
        data[i + 4],
        data[i + 5],
        data[i + 6],
        data[i + 7],
    ])
}

pub(crate) fn write_u16(data: &mut [u8], offset: u32, value: u32) {
    let i = offset as usize;
    let v = value as u16;
    let b = v.to_le_bytes();
    data[i] = b[0];
    data[i + 1] = b[1];
}

pub(crate) fn write_u32(data: &mut [u8], offset: u32, value: u32) {
    let i = offset as usize;
    let b = value.to_le_bytes();
    data[i] = b[0];
    data[i + 1] = b[1];
    data[i + 2] = b[2];
    data[i + 3] = b[3];
}

// ---------------------------------------------------------------------------
// Checked accessors (return Err instead of panicking on OOB)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) fn try_u32(d: &[u8], off: usize) -> Result<u32, super::UnpackError> {
    d.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(super::UnpackError::OutOfBounds(off))
}

#[allow(dead_code)]
pub(crate) fn try_i32(d: &[u8], off: usize) -> Result<i32, super::UnpackError> {
    try_u32(d, off).map(|v| v as i32)
}

/// Checked copy: returns OutOfBounds if src or dst ranges exceed their respective slices.
pub(crate) fn try_copy_from_slice(
    dst: &mut [u8],
    dst_off: usize,
    dst_len: usize,
    src: &[u8],
    src_off: usize,
) -> Result<(), super::UnpackError> {
    let dst_end = dst_off
        .checked_add(dst_len)
        .ok_or(super::UnpackError::OutOfBounds(dst_off))?;
    let src_end = src_off
        .checked_add(dst_len)
        .ok_or(super::UnpackError::OutOfBounds(src_off))?;
    if dst_end > dst.len() {
        return Err(super::UnpackError::OutOfBounds(dst_off));
    }
    if src_end > src.len() {
        return Err(super::UnpackError::OutOfBounds(src_off));
    }
    dst[dst_off..dst_end].copy_from_slice(&src[src_off..src_end]);
    Ok(())
}

// ---------------------------------------------------------------------------
// Locator helpers
// ---------------------------------------------------------------------------

/// Find the 4-byte v_val that follows the LAST occurrence of `48 EB 01 B9`
/// (REX.W jmp+1; mov ecx,imm32) plus any 0xCC padding. Used to locate
/// stage4's accum2 seed. Works across builds even when API-name anchors are
/// absent.
pub(crate) fn find_v_after_pad(data: &[u8], base: u32, len: u32) -> Option<u32> {
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
pub(crate) fn trial_decrypt5_u32(data: &[u8], va: u32) -> u32 {
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

/// Reproduce the LFSR keystream that decrypt_data6 XORs in. Used to
/// trial-decrypt candidate bytecode positions without mutating the buffer.
pub(crate) fn lfsr_keystream(out: &mut [u8]) {
    let mut state: u32 = 1;
    for byte in out.iter_mut() {
        let mut b: u8 = 0;
        for k in 0..8u32 {
            b |= ((state & 1) << k) as u8;
            state <<= 1;
            if state & 0x8000 != 0 {
                state ^= 0x8003;
            }
        }
        *byte = b;
    }
}

/// Scan stage4/stage5 for the encrypted custom-decryptor bytecode block. The
/// raw byte at p+95 is used by decrypt_data6 as the iteration count. We trial-
/// decrypt that many bytes with the LFSR keystream and accept the first
/// position where the byte stream parses as a valid opcode sequence ending in
/// 195 (ret).
pub(crate) fn find_bytecode_offset(data: &[u8], base: u32, len: u32) -> Option<u32> {
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
pub(crate) fn parse_bytecode_check(buf: &[u8]) -> Option<usize> {
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
pub(crate) fn find_v4_offset(data: &[u8], base: u32, len: u32) -> Option<u32> {
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
pub(crate) fn find_str_pos(data: &[u8], base: u32, len: u32, needle: &[u8]) -> Option<u32> {
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

pub(crate) fn get_string_to_null(data: &[u8], offset: u32) -> String {
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
pub(crate) fn section_name(data: &[u8], offset: u32) -> String {
    let start = offset as usize;
    let Some(field) = data.get(start..start + 8) else {
        return String::new();
    };
    let end = field.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&field[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// AES primitives
// ---------------------------------------------------------------------------

/// One AES-CBC-like round over a 16-byte block in `d` at `pos`, using the
/// expanded key schedule stored in `d` at `key_offset`. Works entirely within
/// the single `d` buffer (both ciphertext and key schedule live there).
pub(crate) fn aes_round(d: &mut [u8], pos: u32, key_offset: u32, round: u32) {
    let cm1 = &COLUMMIX1;
    let cm2 = &COLUMMIX2;
    let cm3 = &COLUMMIX3;
    let cm4 = &COLUMMIX4;
    let sbox = &SBOX;

    let mut n0 = get_u32(d, pos).swap_bytes() ^ get_u32(d, key_offset);
    let mut n1 =
        get_u32(d, pos.wrapping_add(4)).swap_bytes() ^ get_u32(d, key_offset.wrapping_add(4));
    let mut n2 =
        get_u32(d, pos.wrapping_add(8)).swap_bytes() ^ get_u32(d, key_offset.wrapping_add(8));
    let mut n3 =
        get_u32(d, pos.wrapping_add(12)).swap_bytes() ^ get_u32(d, key_offset.wrapping_add(12));

    let mut r = 1u32;
    while r < round {
        let off = key_offset.wrapping_add(r.wrapping_mul(16));
        let a = get_u32(cm2, ((n3 >> 16) & 0xFF) * 4)
            ^ get_u32(cm3, ((n2 >> 8) & 0xFF) * 4)
            ^ get_u32(cm1, ((n0 >> 24) & 0xFF) * 4)
            ^ get_u32(cm4, (n1 & 0xFF) * 4)
            ^ get_u32(d, off);
        let b = get_u32(cm2, ((n0 >> 16) & 0xFF) * 4)
            ^ get_u32(cm1, ((n1 >> 24) & 0xFF) * 4)
            ^ get_u32(cm3, ((n3 >> 8) & 0xFF) * 4)
            ^ get_u32(cm4, (n2 & 0xFF) * 4)
            ^ get_u32(d, off.wrapping_add(4));
        let c = get_u32(cm2, ((n1 >> 16) & 0xFF) * 4)
            ^ get_u32(cm3, ((n0 >> 8) & 0xFF) * 4)
            ^ get_u32(cm1, ((n2 >> 24) & 0xFF) * 4)
            ^ get_u32(cm4, (n3 & 0xFF) * 4)
            ^ get_u32(d, off.wrapping_add(8));
        let e = get_u32(cm3, ((n1 >> 8) & 0xFF) * 4)
            ^ get_u32(cm2, ((n2 >> 16) & 0xFF) * 4)
            ^ get_u32(cm1, ((n3 >> 24) & 0xFF) * 4)
            ^ get_u32(cm4, (n0 & 0xFF) * 4)
            ^ get_u32(d, off.wrapping_add(12));
        n0 = a;
        n1 = b;
        n2 = c;
        n3 = e;
        r = r.wrapping_add(1);
    }

    let s0 = (get_u32(sbox, ((n0 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n3 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n2 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n1 & 0xFF) * 4) & 0x0000_00FF);
    let s1 = (get_u32(sbox, ((n1 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n0 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n3 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n2 & 0xFF) * 4) & 0x0000_00FF);
    let s2 = (get_u32(sbox, ((n2 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n1 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n0 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n3 & 0xFF) * 4) & 0x0000_00FF);
    let s3 = (get_u32(sbox, ((n3 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n2 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n1 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n0 & 0xFF) * 4) & 0x0000_00FF);

    let last = key_offset.wrapping_add(round.wrapping_mul(16));
    n0 = s0 ^ get_u32(d, last);
    n1 = s1 ^ get_u32(d, last.wrapping_add(4));
    n2 = s2 ^ get_u32(d, last.wrapping_add(8));
    n3 = s3 ^ get_u32(d, last.wrapping_add(12));

    write_u32(d, pos, n0.swap_bytes());
    write_u32(d, pos.wrapping_add(4), n1.swap_bytes());
    write_u32(d, pos.wrapping_add(8), n2.swap_bytes());
    write_u32(d, pos.wrapping_add(12), n3.swap_bytes());
}

/// AES-CBC-like decryption over `size` bytes starting at `pos` in `d`.
/// The key schedule lives at `key_offset` within the same buffer `d`.
pub(crate) fn aes_decrypt(d: &mut [u8], pos: u32, size: u32, key_offset: u32) {
    let mut prev = [0u8; 16];
    let mut cur = [0u8; 16];
    let round = get_u16(d, key_offset.wrapping_add(2)) as u32;
    let blocks = size >> 4;
    for i in 0..blocks {
        let p = pos.wrapping_add(i.wrapping_mul(16));
        let pi = p as usize;
        cur.copy_from_slice(&d[pi..pi + 16]);
        aes_round(d, p, key_offset.wrapping_add(4), round);
        for j in 0..16 {
            d[pi + j] ^= prev[j];
        }
        prev = cur;
    }
}

/// [`aes_decrypt`] variant reading the key schedule from a separate snapshot
/// slice instead of the data buffer. `ks` is a snapshot of `d[key_offset..]`
/// taken by [`aes_schedule_snapshot`] (round count at `ks[2]`, round keys from
/// `ks[4]`), so the schedule extent is exactly right by construction. Used by
/// the parallel block fan-out, where each worker owns a disjoint `&mut` span
/// of the image and cannot read the schedule out of the shared buffer.
pub(crate) fn aes_decrypt_ks(ks: &[u8], d: &mut [u8], pos: u32, size: u32) {
    let mut prev = [0u8; 16];
    let mut cur = [0u8; 16];
    let round = u16::from_le_bytes([ks[2], ks[3]]) as u32;
    let sched = &ks[4..];
    let blocks = size >> 4;
    for i in 0..blocks {
        let p = pos.wrapping_add(i.wrapping_mul(16));
        let pi = p as usize;
        cur.copy_from_slice(&d[pi..pi + 16]);
        aes_round_ks(sched, d, p, round);
        for j in 0..16 {
            d[pi + j] ^= prev[j];
        }
        prev = cur;
    }
}

/// [`aes_round`] with the round keys in a separate slice (see
/// [`aes_decrypt_ks`]). Identical math; only the key source differs.
fn aes_round_ks(ks: &[u8], d: &mut [u8], pos: u32, round: u32) {
    let cm1 = &COLUMMIX1;
    let cm2 = &COLUMMIX2;
    let cm3 = &COLUMMIX3;
    let cm4 = &COLUMMIX4;
    let sbox = &SBOX;
    let k = |i: u32| get_u32(ks, i);

    let mut n0 = get_u32(d, pos).swap_bytes() ^ k(0);
    let mut n1 = get_u32(d, pos.wrapping_add(4)).swap_bytes() ^ k(4);
    let mut n2 = get_u32(d, pos.wrapping_add(8)).swap_bytes() ^ k(8);
    let mut n3 = get_u32(d, pos.wrapping_add(12)).swap_bytes() ^ k(12);

    let mut r = 1u32;
    while r < round {
        let off = r.wrapping_mul(16);
        let a = get_u32(cm2, ((n3 >> 16) & 0xFF) * 4)
            ^ get_u32(cm3, ((n2 >> 8) & 0xFF) * 4)
            ^ get_u32(cm1, ((n0 >> 24) & 0xFF) * 4)
            ^ get_u32(cm4, (n1 & 0xFF) * 4)
            ^ k(off);
        let b = get_u32(cm2, ((n0 >> 16) & 0xFF) * 4)
            ^ get_u32(cm1, ((n1 >> 24) & 0xFF) * 4)
            ^ get_u32(cm3, ((n3 >> 8) & 0xFF) * 4)
            ^ get_u32(cm4, (n2 & 0xFF) * 4)
            ^ k(off.wrapping_add(4));
        let c = get_u32(cm2, ((n1 >> 16) & 0xFF) * 4)
            ^ get_u32(cm3, ((n0 >> 8) & 0xFF) * 4)
            ^ get_u32(cm1, ((n2 >> 24) & 0xFF) * 4)
            ^ get_u32(cm4, (n3 & 0xFF) * 4)
            ^ k(off.wrapping_add(8));
        let e = get_u32(cm3, ((n1 >> 8) & 0xFF) * 4)
            ^ get_u32(cm2, ((n2 >> 16) & 0xFF) * 4)
            ^ get_u32(cm1, ((n3 >> 24) & 0xFF) * 4)
            ^ get_u32(cm4, (n0 & 0xFF) * 4)
            ^ k(off.wrapping_add(12));
        n0 = a;
        n1 = b;
        n2 = c;
        n3 = e;
        r = r.wrapping_add(1);
    }

    let s0 = (get_u32(sbox, ((n0 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n3 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n2 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n1 & 0xFF) * 4) & 0x0000_00FF);
    let s1 = (get_u32(sbox, ((n1 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n0 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n3 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n2 & 0xFF) * 4) & 0x0000_00FF);
    let s2 = (get_u32(sbox, ((n2 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n1 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n0 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n3 & 0xFF) * 4) & 0x0000_00FF);
    let s3 = (get_u32(sbox, ((n3 >> 24) & 0xFF) * 4) & 0xFF00_0000)
        | (get_u32(sbox, ((n2 >> 16) & 0xFF) * 4) & 0x00FF_0000)
        | (get_u32(sbox, ((n1 >> 8) & 0xFF) * 4) & 0x0000_FF00)
        | (get_u32(sbox, (n0 & 0xFF) * 4) & 0x0000_00FF);

    let last = round.wrapping_mul(16);
    n0 = s0 ^ k(last);
    n1 = s1 ^ k(last.wrapping_add(4));
    n2 = s2 ^ k(last.wrapping_add(8));
    n3 = s3 ^ k(last.wrapping_add(12));

    write_u32(d, pos, n0.swap_bytes());
    write_u32(d, pos.wrapping_add(4), n1.swap_bytes());
    write_u32(d, pos.wrapping_add(8), n2.swap_bytes());
    write_u32(d, pos.wrapping_add(12), n3.swap_bytes());
}

/// Snapshot the AES key schedule at `key_offset` for [`aes_decrypt_ks`]:
/// `d[key_offset .. key_offset + 4 + (round+1)*16]` where `round` is read from
/// the schedule header. Returns `None` when the header is truncated or the
/// round count is implausible (corrupt input — the same bytes would otherwise
/// drive reads past the buffer).
pub(crate) fn aes_schedule_snapshot(d: &[u8], key_offset: u32) -> Option<Vec<u8>> {
    let base = key_offset as usize;
    let round = u16::from_le_bytes([*d.get(base + 2)?, *d.get(base + 3)?]) as usize;
    if round > 64 {
        return None;
    }
    let end = base.checked_add(4 + (round + 1) * 16)?;
    if end > d.len() {
        return None;
    }
    Some(d[base..end].to_vec())
}

// ---------------------------------------------------------------------------
// Checksum primitives
// ---------------------------------------------------------------------------

/// CRC32-based checksum over a (offset, length) descriptor pair embedded in
/// `d` at `pos`. Returns `crc32(d[offset..offset+length]) ^ length`.
pub(crate) fn calculate_checksum(d: &[u8], pos: u32) -> u32 {
    let offset = get_u32(d, pos);
    let length = get_u32(d, pos.wrapping_add(4));
    crc32::compute(&d[offset as usize..(offset + length) as usize]) ^ length
}

/// CRC32 chained checksum. The (offset, length) descriptor at `pos` is read
/// from `d`; the bytes themselves are read from the separate `clean` buffer
/// (the original file image). `start` is the initial CRC accumulator.
pub(crate) fn calculate_checksum2(d: &[u8], clean: &[u8], pos: u32, start: u32) -> u32 {
    let offset = get_u32(d, pos);
    let length = get_u32(d, pos.wrapping_add(4));
    crc32::append(start, &clean[offset as usize..(offset + length) as usize])
}

// ---------------------------------------------------------------------------
// Decompression (Huffman/LZ)
// ---------------------------------------------------------------------------

/// Huffman/LZ decompression operating entirely within a single `d` buffer.
/// Reads `s_size` bytes from `src`, writes `d_size` bytes to `dest`.
/// The Huffman table lives at `key_offset` within `d`.
///
/// Returns `true` when exactly `d_size` bytes were written (full success),
/// `false` on any corruption-triggered early exit. The PE32 eighth-stage key
/// brute force uses this status to discriminate the correct key.
pub(crate) fn decompress(
    d: &mut [u8],
    src: u32,
    mut dest: u32,
    key_offset: u32,
    s_size: u32,
    d_size: u32,
) -> bool {
    // Bound the scratch allocation: a corrupt descriptor could request a
    // multi-gigabyte source size, and an allocation failure aborts the process
    // (uncatchable). Real payloads are far below this.
    if s_size as u64 > super::MAX_IMAGE_SIZE {
        return false;
    }
    DECOMPRESS_SCRATCH.with_borrow_mut(|buf| {
        let mut bit_pos: i32 = 0;
        let need = (s_size as usize).saturating_add(3);
        if buf.len() < need {
            buf.resize(need, 0);
        }
        let mut buf_off: u32 = 0;
        let mut src_consumed: i32 = 0;
        let mut pending: u32 = 0;
        let mut written: u32 = 0;
        let src_u = src as usize;
        let s_size_u = s_size as usize;
        // The bit-reader's final get_u32 may read up to 3 bytes past s_size; those
        // must be zero. Reused scratch can hold stale bytes there, so zero them
        // before copying the (exactly s_size) source over the head.
        buf[s_size_u] = 0;
        buf[s_size_u + 1] = 0;
        buf[s_size_u + 2] = 0;
        buf[..s_size_u].copy_from_slice(&d[src_u..src_u + s_size_u]);

        while (src_consumed as u32) < s_size && written < d_size {
            let word = get_u32(&buf[..], buf_off) >> bit_pos;
            let tab_addr = key_offset.wrapping_add((word & 0xFF).wrapping_mul(3));
            let mut tab = get_u16(d, tab_addr);
            let bits: u8;
            if (tab & 0x8000) != 0 {
                tab &= 0x7FFF;
                bits = d[tab_addr as usize + 2];
            } else {
                let mut b2 = d[tab_addr as usize + 2];
                // A Huffman code longer than 32 bits cannot exist; a larger
                // length byte comes from a corrupt table, and `1 << b2` would
                // panic (debug) or wrap (release) on it.
                if b2 >= 32 {
                    return false;
                }
                let mut mask: u32 = 1u32 << b2;
                b2 = b2.wrapping_add(1);
                let mut idx = (tab & 0x7FFF) as u32 + if (word & mask) != 0 { 1 } else { 0 };
                let mut t2 = get_u16(d, key_offset.wrapping_add(idx.wrapping_mul(3)));
                // A corrupt table can form a non-terminal cycle; cap the walk so it
                // fails instead of spinning forever.
                let mut depth = 0u32;
                while (t2 & 0x8000) == 0 {
                    depth += 1;
                    if depth > 64 {
                        return false;
                    }
                    mask <<= 1;
                    b2 = b2.wrapping_add(1);
                    idx = (t2 & 0x7FFF) as u32 + if (word & mask) != 0 { 1 } else { 0 };
                    t2 = get_u16(d, key_offset.wrapping_add(idx.wrapping_mul(3)));
                }
                tab = t2 & 0x7FFF;
                bits = b2;
            }
            bit_pos += bits as i32;
            let advance = bit_pos / 8;
            buf_off = buf_off.wrapping_add(advance as u32);
            src_consumed += advance;
            bit_pos %= 8;

            let mode = (tab as u32) & 0x300;
            let payload = (tab as u32) & 0xFF;
            let step: u32;
            match mode {
                0 => {
                    step = 1;
                    d[dest as usize] = payload as u8;
                }
                0x100 => {
                    step = 0;
                    if pending >= 256 {
                        // corrupt input: stop decompressing (diagnostics go to caller/log, not stdout)
                        return false;
                    }
                    pending = if pending == 0 {
                        payload
                    } else {
                        (pending << 8) | payload
                    };
                }
                0x200 => {
                    if pending == 0 {
                        pending = 1;
                    }
                    step = pending.wrapping_mul(payload);
                    if step.wrapping_add(written) > d_size {
                        return false;
                    }
                    // Run-fill replicates the unit just written before `dest`. A
                    // corrupt stream can emit one of these before anything has been
                    // written, so guard against reading before the buffer start
                    // (an unsigned underflow would index astronomically far OOB).
                    match payload {
                        1 => {
                            if dest < 1 {
                                return false;
                            }
                            let v = d[(dest as usize) - 1];
                            for k in 0..pending {
                                d[(dest + k) as usize] = v;
                            }
                        }
                        2 => {
                            if dest < 2 {
                                return false;
                            }
                            let v = get_u16(d, dest.wrapping_sub(2));
                            for k in 0..pending {
                                write_u16(d, dest.wrapping_add(k.wrapping_mul(2)), v as u32);
                            }
                        }
                        4 => {
                            if dest < 4 {
                                return false;
                            }
                            let v = get_u32(d, dest.wrapping_sub(4));
                            for k in 0..pending {
                                write_u32(d, dest.wrapping_add(k.wrapping_mul(4)), v);
                            }
                        }
                        _ => {
                            // Only unit widths 1/2/4 exist. Any other payload comes
                            // from a corrupt stream: previously this wrote nothing
                            // yet still counted `step` bytes as written, leaving
                            // stale-buffer holes that later stages treated as
                            // plaintext. Report corruption instead.
                            return false;
                        }
                    }
                    pending = 0;
                }
                _ => {
                    step = payload;
                    if written.wrapping_add(payload) > d_size
                        || pending.wrapping_add(payload) > written
                    {
                        return false;
                    }
                    let back = pending.wrapping_add(payload);
                    for k in 0..payload {
                        d[(dest + k) as usize] = d[(dest + k - back) as usize];
                    }
                    pending = 0;
                }
            }

            dest = dest.wrapping_add(step);
            written = written.wrapping_add(step);
            if bits == 0 && step == 0 {
                // Corrupt table: no input bits consumed and no output bytes
                // written, so the loop condition can never advance — an
                // infinite loop (and `catch_unpack` traps panics, not hangs).
                // Every real symbol consumes ≥ 1 bit, so a valid stream can
                // never hit this.
                return false;
            }
        }
        src_consumed += if bit_pos != 0 { 1 } else { 0 };
        // Mismatch in consumed/written sizes indicates corrupt input; the unpack
        // result will then fail downstream checks. No stdout diagnostics here —
        // the pure core stays I/O-free; surface errors via the caller/logfile.
        let _ = src_consumed;
        written == d_size
    })
}

/// Walk the Huffman table at `key_offset` and snapshot its bytes for
/// [`decompress_tbl`]. The table is a forest of 256 root entries (3 bytes
/// each); non-terminal entries point at a child index pair. Returns `None`
/// when the table is truncated or self-referential past the buffer (corrupt
/// input — the same bytes would otherwise drive reads out of bounds).
pub(crate) fn huffman_table_snapshot(d: &[u8], key_offset: u32) -> Option<Vec<u8>> {
    let mut visited = vec![false; 0x1_0000usize];
    let mut stack: Vec<u32> = (0..256).collect();
    let mut max_idx: u32 = 255;
    while let Some(idx) = stack.pop() {
        if idx >= 0x1_0000 || visited[idx as usize] {
            continue;
        }
        visited[idx as usize] = true;
        let off = key_offset as usize + idx as usize * 3;
        if off + 3 > d.len() {
            return None;
        }
        let t = get_u16(d, key_offset.wrapping_add(idx.wrapping_mul(3)));
        if (t & 0x8000) == 0 {
            let child = (t & 0x7FFF) as u32;
            max_idx = max_idx.max(child).max(child.wrapping_add(1));
            stack.push(child);
            stack.push(child.wrapping_add(1));
        }
    }
    let end = key_offset as usize + (max_idx as usize + 1) * 3;
    if end > d.len() {
        return None;
    }
    Some(d[key_offset as usize..end].to_vec())
}

/// [`decompress`] variant reading the Huffman table from a separate snapshot
/// slice (see [`huffman_table_snapshot`]) instead of the data buffer. Used by
/// the parallel block fan-out, where each worker owns a disjoint `&mut` span
/// and cannot read the table out of the shared image. Table reads are bounds
/// checked against the snapshot — past-the-end means corrupt table, reported
/// as `false` rather than a panic.
pub(crate) fn decompress_tbl(
    tab: &[u8],
    d: &mut [u8],
    src: u32,
    mut dest: u32,
    s_size: u32,
    d_size: u32,
) -> bool {
    if s_size as u64 > super::MAX_IMAGE_SIZE {
        return false;
    }
    DECOMPRESS_SCRATCH.with_borrow_mut(|buf| {
        // Table reads, bounds-checked against the snapshot.
        let tab16 = |addr: usize| -> Option<u16> {
            let b = tab.get(addr..addr + 3)?;
            Some(u16::from_le_bytes([b[0], b[1]]))
        };
        let tab8 = |addr: usize| -> Option<u8> { tab.get(addr + 2).copied() };

        let mut bit_pos: i32 = 0;
        let need = (s_size as usize).saturating_add(3);
        if buf.len() < need {
            buf.resize(need, 0);
        }
        let mut buf_off: u32 = 0;
        let mut src_consumed: i32 = 0;
        let mut pending: u32 = 0;
        let mut written: u32 = 0;
        let src_u = src as usize;
        let s_size_u = s_size as usize;
        buf[s_size_u] = 0;
        buf[s_size_u + 1] = 0;
        buf[s_size_u + 2] = 0;
        buf[..s_size_u].copy_from_slice(&d[src_u..src_u + s_size_u]);

        while (src_consumed as u32) < s_size && written < d_size {
            let word = get_u32(&buf[..], buf_off) >> bit_pos;
            let tab_addr = ((word & 0xFF).wrapping_mul(3)) as usize;
            let mut tab = match tab16(tab_addr) {
                Some(t) => t,
                None => {
                    return false;
                }
            };
            let bits: u8;
            if (tab & 0x8000) != 0 {
                tab &= 0x7FFF;
                bits = match tab8(tab_addr) {
                    Some(b) => b,
                    None => return false,
                };
            } else {
                let mut b2 = match tab8(tab_addr) {
                    Some(b) => b,
                    None => return false,
                };
                if b2 >= 32 {
                    return false;
                }
                let mut mask: u32 = 1u32 << b2;
                b2 = b2.wrapping_add(1);
                let mut idx = (tab & 0x7FFF) as u32 + if (word & mask) != 0 { 1 } else { 0 };
                let mut t2 = match tab16(idx as usize * 3) {
                    Some(t) => t,
                    None => {
                        return false;
                    }
                };
                // A corrupt table can form a non-terminal cycle; cap the walk so it
                // fails instead of spinning forever.
                let mut depth = 0u32;
                while (t2 & 0x8000) == 0 {
                    depth += 1;
                    if depth > 64 {
                        return false;
                    }
                    mask <<= 1;
                    b2 = b2.wrapping_add(1);
                    idx = (t2 & 0x7FFF) as u32 + if (word & mask) != 0 { 1 } else { 0 };
                    t2 = match tab16(idx as usize * 3) {
                        Some(t) => t,
                        None => {
                            return false;
                        }
                    };
                }
                tab = t2 & 0x7FFF;
                bits = b2;
            }
            bit_pos += bits as i32;
            let advance = bit_pos / 8;
            buf_off = buf_off.wrapping_add(advance as u32);
            src_consumed += advance;
            bit_pos %= 8;

            let mode = (tab as u32) & 0x300;
            let payload = (tab as u32) & 0xFF;
            let step: u32;
            match mode {
                0 => {
                    step = 1;
                    d[dest as usize] = payload as u8;
                }
                0x100 => {
                    step = 0;
                    if pending >= 256 {
                        return false;
                    }
                    pending = if pending == 0 {
                        payload
                    } else {
                        (pending << 8) | payload
                    };
                }
                0x200 => {
                    if pending == 0 {
                        pending = 1;
                    }
                    step = pending.wrapping_mul(payload);
                    if step.wrapping_add(written) > d_size {
                        return false;
                    }
                    // Run-fill replicates the unit just written before `dest`
                    // (see `decompress` for the underflow rationale).
                    match payload {
                        1 => {
                            if dest < 1 {
                                return false;
                            }
                            let v = d[(dest as usize) - 1];
                            for k in 0..pending {
                                d[(dest + k) as usize] = v;
                            }
                        }
                        2 => {
                            if dest < 2 {
                                return false;
                            }
                            let v = get_u16(d, dest.wrapping_sub(2));
                            for k in 0..pending {
                                write_u16(d, dest.wrapping_add(k.wrapping_mul(2)), v as u32);
                            }
                        }
                        4 => {
                            if dest < 4 {
                                return false;
                            }
                            let v = get_u32(d, dest.wrapping_sub(4));
                            for k in 0..pending {
                                write_u32(d, dest.wrapping_add(k.wrapping_mul(4)), v);
                            }
                        }
                        _ => {
                            return false;
                        }
                    }
                    pending = 0;
                }
                _ => {
                    step = payload;
                    if written.wrapping_add(payload) > d_size
                        || pending.wrapping_add(payload) > written
                    {
                        return false;
                    }
                    let back = pending.wrapping_add(payload);
                    for k in 0..payload {
                        d[(dest + k) as usize] = d[(dest + k - back) as usize];
                    }
                    pending = 0;
                }
            }

            dest = dest.wrapping_add(step);
            written = written.wrapping_add(step);
            if bits == 0 && step == 0 {
                return false;
            }
        }
        src_consumed += if bit_pos != 0 { 1 } else { 0 };
        let _ = src_consumed;
        written == d_size
    })
}
// Decrypt primitives (free-function wrappers)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PE32 (32-bit) helpers
// ---------------------------------------------------------------------------

/// PE32 shell-table locator. Walks the shell region (`info[6]`) for a dword
/// equal to `info[6]` followed by a plausible shell size, returning the table
/// base (`candidate = off - 0x88`) when `candidate+0x58` holds a valid pointer.
pub(crate) fn find_tbl_pe32(data: &[u8], info: &[u32; 8]) -> Option<u32> {
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
pub(crate) fn find_lfsr_block(
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
pub(crate) struct EighthSlots {
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
pub(crate) fn discover_eighth_slots(
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

/// PE32 `.text` dd8 key-formula selection with a skip decision. The packer keys
/// the per-page XOR either with `page+1` or `0x8000*(page+1)`; the formula is
/// not recorded. Replays the dd8 page pass on a scratch copy of sample pages
/// (25/50/75% of `.text`) under each formula and counts how many positions
/// decode to `0xCC` (int3 padding).
///
/// Returns `Some(true)` for the `0x8000*(page+1)` formula, `Some(false)` for
/// `page+1`, or `None` when `.text` must NOT be dd8-decrypted at all. The packer
/// dd8-encrypts `.text` on EXEs (so unpacking must replay it) but leaves a native
/// DLL's `.text` plaintext; replaying dd8 there scrambles ~1 byte per 16-byte
/// block. The decision: dd8 only *restores* int3 padding when `.text` was
/// genuinely encrypted, so apply it only when the chosen formula's whole-page
/// 0xCC count rises *clearly* above the no-dd8 baseline; otherwise skip.
///
/// "Clearly" matters: dd8 XORs 255 positions per page with pseudo-random bytes,
/// so on an already-plaintext `.text` it manufactures ~1 spurious `0xCC` per
/// sampled page for free (255/256 expected). A bare `best > baseline` test is
/// therefore biased towards *applying* dd8 on exactly the inputs that must skip
/// it — and a wrongly-applied dd8 is silent: it scrambles ~1 byte per 16 with no
/// error and nothing downstream (not even `integrity::check`, which only reads
/// 16 bytes at the entry point) notices. The [`MIN_DD8_NET_GAIN`] floor below is
/// the PE32 counterpart of the margin+floor `select_dd8_shift` already applies
/// on PE32+ for the same failure mode.
pub(crate) fn select_dd8_formula_pe32(data: &[u8], text_off: u32, text_size: u32) -> Option<bool> {
    let num_pages_total = text_size / 0x1000;
    let mut sample_pages: Vec<u32> = Vec::new();
    for frac in [0.25f64, 0.5, 0.75] {
        let pg = (num_pages_total as f64 * frac) as u32;
        if pg > 0 && pg < num_pages_total {
            sample_pages.push(pg);
        }
    }
    if sample_pages.is_empty() && num_pages_total > 1 {
        sample_pages.push(num_pages_total / 2);
    }
    let score = |big: bool| -> i64 {
        let mut total = 0i64;
        for &sp in &sample_pages {
            let pg_off = (text_off + sp * 0x1000) as usize;
            if pg_off + 0x1000 > data.len() {
                continue;
            }
            let mut buf = [0u8; 0x1000];
            buf.copy_from_slice(&data[pg_off..pg_off + 0x1000]);
            let pk = if big {
                0x8000u32.wrapping_mul(sp.wrapping_add(1))
            } else {
                sp.wrapping_add(1)
            };
            let mut k = pk;
            let rk = k.rotate_right(15);
            k = rk;
            for bi in 1..256u32 {
                let rk = k.rotate_right(15);
                let ri = rk.wrapping_add(bi);
                k = ri.wrapping_add(bi);
                let tidx = (bi.wrapping_mul(16).wrapping_add(ri & 0xF)) as usize;
                if tidx < buf.len() {
                    buf[tidx] ^= k as u8;
                }
            }
            total += buf.iter().filter(|&&b| b == 0xCC).count() as i64;
        }
        total
    };
    let s_small = score(false);
    let s_big = score(true);
    // Baseline: whole-page 0xCC over the same sample pages with NO dd8. dd8 only
    // rewrites 255 bytes per page, so comparing the chosen formula's whole-page
    // 0xCC against this baseline reveals whether dd8 *restores* int3 padding
    // (count rises -> .text was packer-encrypted, apply) or merely scrambles
    // already-plaintext code (count falls -> native-DLL .text left intact, skip).
    let mut baseline: i64 = 0;
    for &sp in &sample_pages {
        let pg_off = (text_off + sp * 0x1000) as usize;
        if pg_off + 0x1000 > data.len() {
            continue;
        }
        baseline += data[pg_off..pg_off + 0x1000]
            .iter()
            .filter(|&&b| b == 0xCC)
            .count() as i64;
    }
    let big = s_big > s_small;
    let best = s_small.max(s_big);
    // Minimum net 0xCC gain over the baseline before dd8 is applied. Noise on an
    // already-plaintext `.text` is ~1 manufactured 0xCC per sampled page (3 pages
    // -> ~3); every corpus build that genuinely needs dd8 gains +154 or more
    // (observed +154 and +312), and the one native DLL that must skip scores -18.
    // A floor of 32 sits ~10x above the noise and ~5x below the smallest true
    // positive, so it changes no existing decision.
    const MIN_DD8_NET_GAIN: i64 = 32;
    let apply = best.saturating_sub(baseline) >= MIN_DD8_NET_GAIN;
    if std::env::var("SEL_DIAG").is_ok() {
        eprintln!(
            "SEL pe32 dd8 s_small={} s_big={} baseline={} gain={} big={} apply={}",
            s_small,
            s_big,
            baseline,
            best - baseline,
            big,
            apply
        );
    }
    // When no interior pages could be sampled (tiny .text) we cannot measure the
    // effect; preserve the historical behavior of applying dd8.
    if sample_pages.is_empty() || apply {
        Some(big)
    } else {
        None
    }
}

/// Read a NUL-terminated byte string starting at `off`, bounded to 512 bytes.
/// Returns the raw bytes up to the terminator (excluding it).
fn read_cstr_bounded(data: &[u8], off: u32) -> Vec<u8> {
    let start = off as usize;
    if start >= data.len() {
        return Vec::new();
    }
    let limit = (start + 512).min(data.len());
    let mut end = start;
    while end < limit && data[end] != 0 {
        end += 1;
    }
    data[start..end].to_vec()
}

fn align_up_u32(value: u32, alignment: u32) -> u32 {
    ((value.wrapping_add(alignment - 1)) / alignment).wrapping_mul(alignment)
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

#[derive(Clone)]
enum ImportFunc {
    Ordinal(u32),
    Name(u16, Vec<u8>),
}

struct ImportDesc {
    time_date: u32,
    fwd_chain: u32,
    dll_name: Vec<u8>,
    iat_rva: u32,
    functions: Vec<ImportFunc>,
}

/// Return true when PE32 imports already sit in the original `.idata` layout
/// (so no relocation to `.kmiat` is needed). May write the IAT data directory
/// (pe+0xD8).
pub(crate) fn pe32_imports_already_match_idata_layout(data: &mut [u8], pe_header: u32) -> bool {
    let opt_hdr_size = get_u16(data, pe_header.wrapping_add(20)) as u32;
    let sec_table = pe_header.wrapping_add(24).wrapping_add(opt_hdr_size);
    let num_sections = get_u16(data, pe_header.wrapping_add(6)) as u32;
    let import_rva = get_u32(data, pe_header.wrapping_add(0x80));
    let import_size = get_u32(data, pe_header.wrapping_add(0x84));
    let len = data.len() as u32;
    if !(import_rva > 0 && import_size > 0) {
        return false;
    }
    for idx in 0..num_sections {
        let sec_off = sec_table.wrapping_add(idx * 40);
        if (sec_off as usize + 40) > data.len() {
            return false;
        }
        if &data[sec_off as usize..sec_off as usize + 6] != b".idata" {
            continue;
        }
        let sec_va = get_u32(data, sec_off.wrapping_add(12));
        let sec_size =
            get_u32(data, sec_off.wrapping_add(8)).max(get_u32(data, sec_off.wrapping_add(16)));
        let sec_end = sec_va.wrapping_add(sec_size);
        if !(sec_va <= import_rva
            && import_rva < sec_end
            && import_rva.wrapping_add(import_size) <= sec_end)
        {
            continue;
        }
        let first_oft = get_u32(data, import_rva);
        let first_name = get_u32(data, import_rva.wrapping_add(12));
        let first_iat = get_u32(data, import_rva.wrapping_add(16));
        if !(sec_va <= first_oft
            && first_oft < sec_end
            && sec_va <= first_iat
            && first_iat < sec_end)
        {
            return false;
        }
        if !(0x1000 < first_name && first_name < len) {
            return false;
        }
        let dll_name = read_cstr_bounded(data, first_name);
        let lower: Vec<u8> = dll_name.iter().map(|b| b.to_ascii_lowercase()).collect();
        if !lower.ends_with(b".dll") {
            return false;
        }
        let mut iat_min = first_iat;
        let mut iat_max = first_iat;
        let mut idt_pos = import_rva;
        while idt_pos.wrapping_add(20) <= len {
            let oft_rva = get_u32(data, idt_pos);
            let name_rva = get_u32(data, idt_pos.wrapping_add(12));
            let iat_rva = get_u32(data, idt_pos.wrapping_add(16));
            if oft_rva == 0 && name_rva == 0 && iat_rva == 0 {
                break;
            }
            if !(sec_va <= oft_rva && oft_rva < sec_end && sec_va <= iat_rva && iat_rva < sec_end) {
                return false;
            }
            let mut thunk = iat_rva;
            while thunk.wrapping_add(4) <= sec_end {
                let tv = get_u32(data, thunk);
                thunk = thunk.wrapping_add(4);
                if tv == 0 {
                    break;
                }
            }
            iat_min = iat_min.min(iat_rva);
            iat_max = iat_max.max(thunk);
            idt_pos = idt_pos.wrapping_add(20);
        }
        if iat_max > iat_min {
            write_u32(data, pe_header.wrapping_add(0xD8), iat_min);
            write_u32(data, pe_header.wrapping_add(0xDC), iat_max - iat_min);
        }
        return true;
    }
    false
}

/// Rebuild PE32 import metadata (descriptors, lookup tables, names) into the
/// last section as `.kmiat`, leaving the loader-written IAT in place. Mutates
/// `data` (may grow it).
pub(crate) fn move_pe32_imports_to_kmiat(data: &mut Vec<u8>, pe_header: u32) {
    const SECTION_SIZE: u32 = 0x7000;
    let opt_hdr_size = get_u16(data, pe_header.wrapping_add(20)) as u32;
    let opt_hdr = pe_header.wrapping_add(24);
    let sec_table = opt_hdr.wrapping_add(opt_hdr_size);
    let num_sections = get_u16(data, pe_header.wrapping_add(6)) as u32;
    if num_sections == 0 {
        return;
    }
    let import_rva = get_u32(data, pe_header.wrapping_add(0x80));
    let import_size = get_u32(data, pe_header.wrapping_add(0x84));
    let len = data.len() as u32;
    if !(0x1000 < import_rva && import_rva < len && import_size > 0 && import_size < SECTION_SIZE) {
        return;
    }

    let mut descriptors: Vec<ImportDesc> = Vec::new();
    let mut idt_pos = import_rva;
    while idt_pos.wrapping_add(20) <= len {
        let oft_rva = get_u32(data, idt_pos);
        let time_date = get_u32(data, idt_pos.wrapping_add(4));
        let fwd_chain = get_u32(data, idt_pos.wrapping_add(8));
        let name_rva = get_u32(data, idt_pos.wrapping_add(12));
        let iat_rva = get_u32(data, idt_pos.wrapping_add(16));
        if oft_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }
        if !(0x1000 < name_rva && name_rva < len) {
            break;
        }
        let dll_name = read_cstr_bounded(data, name_rva);
        let thunk_rva = if 0x1000 < oft_rva && oft_rva < len {
            oft_rva
        } else {
            iat_rva
        };
        let mut functions: Vec<ImportFunc> = Vec::new();
        let mut thunk_pos = thunk_rva;
        while 0x1000 < thunk_pos.wrapping_add(4) && thunk_pos.wrapping_add(4) <= len {
            let thunk_val = get_u32(data, thunk_pos);
            if thunk_val == 0 {
                break;
            }
            if thunk_val & 0x8000_0000 != 0 {
                functions.push(ImportFunc::Ordinal(thunk_val & 0xFFFF));
            } else {
                let hint = if thunk_val.wrapping_add(2) <= len {
                    get_u16(data, thunk_val)
                } else {
                    0
                };
                let func_name = if thunk_val.wrapping_add(2) < len {
                    read_cstr_bounded(data, thunk_val.wrapping_add(2))
                } else {
                    Vec::new()
                };
                functions.push(ImportFunc::Name(hint, func_name));
            }
            thunk_pos = thunk_pos.wrapping_add(4);
        }
        descriptors.push(ImportDesc {
            time_date,
            fwd_chain,
            dll_name,
            iat_rva,
            functions,
        });
        idt_pos = idt_pos.wrapping_add(20);
    }
    if descriptors.is_empty() {
        return;
    }

    for desc in &mut descriptors {
        let lower: Vec<u8> = desc
            .dll_name
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect();
        if lower.starts_with(b"api-ms-win-crt-") {
            desc.dll_name = b"ucrtbase.dll".to_vec();
        } else {
            desc.dll_name = lower;
        }
    }
    descriptors.sort_by_key(|d| d.iat_rva);

    let last_sec = sec_table.wrapping_add((num_sections - 1) * 40);
    let kmiat_rva = get_u32(data, last_sec.wrapping_add(12));
    // A zero last-section VA means a corrupt section table: building .kmiat at
    // RVA 0 would zero the DOS/PE headers and emit a structurally broken image
    // with no error. Bail and keep the original import table.
    if kmiat_rva == 0 {
        return;
    }
    // Grow the image when .kmiat overruns it, but cap the growth: a corrupt VA
    // could otherwise request a multi-gigabyte allocation, which aborts the
    // process (uncatchable). Use u64 math so a near-u32::MAX VA cannot wrap the
    // end calculation the way the previous wrapping/plain-add mix could.
    let kmiat_end = kmiat_rva as u64 + SECTION_SIZE as u64;
    if kmiat_end > super::MAX_IMAGE_SIZE {
        return;
    }
    if kmiat_end > data.len() as u64 {
        data.resize(kmiat_end as usize, 0);
    }
    // Zero the .kmiat region.
    for b in &mut data[kmiat_rva as usize..kmiat_end as usize] {
        *b = 0;
    }

    let idt_size = (descriptors.len() as u32 + 1) * 20;
    let oft_start = kmiat_rva;
    let mut idt_rva = oft_start;
    for desc in &descriptors {
        idt_rva = idt_rva.wrapping_add((desc.functions.len() as u32 + 1) * 4);
    }
    idt_rva = align_up_u32(idt_rva.wrapping_add(0x2C), 4);

    // Size check: compute the final name_pos and bail if it overruns .kmiat.
    let mut name_pos_check = idt_rva.wrapping_add(idt_size);
    for desc in &descriptors {
        name_pos_check = name_pos_check.wrapping_add(desc.dll_name.len() as u32 + 1);
        for func in &desc.functions {
            if let ImportFunc::Name(_, fname) = func {
                name_pos_check = name_pos_check.wrapping_add(2 + fname.len() as u32 + 1);
            }
        }
    }
    if name_pos_check > kmiat_rva.wrapping_add(SECTION_SIZE) {
        // Section too small; keep existing import table untouched.
        return;
    }

    let mut oft_pos = oft_start;
    let mut name_pos = idt_rva.wrapping_add(idt_size);
    for (idx, desc) in descriptors.iter().enumerate() {
        let idt_entry = idt_rva.wrapping_add(idx as u32 * 20);
        let current_oft = oft_pos;
        write_u32(data, idt_entry, current_oft);
        write_u32(data, idt_entry.wrapping_add(4), desc.time_date);
        write_u32(data, idt_entry.wrapping_add(8), desc.fwd_chain);
        let dll_name_pos = name_pos;
        write_u32(data, idt_entry.wrapping_add(12), dll_name_pos);
        write_u32(data, idt_entry.wrapping_add(16), desc.iat_rva);

        let dnp = dll_name_pos as usize;
        data[dnp..dnp + desc.dll_name.len()].copy_from_slice(&desc.dll_name);
        data[dnp + desc.dll_name.len()] = 0;
        name_pos = name_pos.wrapping_add(desc.dll_name.len() as u32 + 1);

        for func in &desc.functions {
            match func {
                ImportFunc::Ordinal(ord) => {
                    write_u32(data, oft_pos, 0x8000_0000 | ord);
                }
                ImportFunc::Name(hint, fname) => {
                    let hint_name_rva = name_pos;
                    write_u32(data, oft_pos, hint_name_rva);
                    write_u16(data, hint_name_rva, *hint as u32);
                    let fp = (hint_name_rva + 2) as usize;
                    data[fp..fp + fname.len()].copy_from_slice(fname);
                    data[fp + fname.len()] = 0;
                    name_pos = name_pos.wrapping_add(2 + fname.len() as u32 + 1);
                }
            }
            oft_pos = oft_pos.wrapping_add(4);
        }
        write_u32(data, oft_pos, 0);
        oft_pos = oft_pos.wrapping_add(4);
    }
    // Null-terminator IDT entry (20 zero bytes) after the last descriptor.
    let term = idt_rva.wrapping_add(descriptors.len() as u32 * 20) as usize;
    for b in &mut data[term..term + 20] {
        *b = 0;
    }

    let ls = last_sec as usize;
    data[ls..ls + 8].copy_from_slice(b".kmiat\x00\x00");
    write_u32(data, last_sec.wrapping_add(8), SECTION_SIZE);
    write_u32(data, last_sec.wrapping_add(16), SECTION_SIZE);
    write_u32(data, last_sec.wrapping_add(36), 0xE000_0060);
    write_u32(data, pe_header.wrapping_add(0x80), idt_rva);
    write_u32(data, pe_header.wrapping_add(0x84), idt_size);
    write_u32(
        data,
        pe_header.wrapping_add(80),
        kmiat_rva.wrapping_add(SECTION_SIZE),
    );
}

/// Convert the unpacked RVA-addressed image back to a compact PE file layout
/// (headers at 0x400, sections packed consecutively, FileAlignment 0x200).
/// Returns `None` if the accumulated output size wraps or exceeds
/// [`super::MAX_IMAGE_SIZE`]: the final allocation is sized from header-derived
/// section data, and an uncapped `vec![0; n]` from a corrupt header would abort
/// the process (which `catch_unpack` cannot trap).
pub(crate) fn compact_memory_image_to_pe(data: &[u8], pe_header: u32) -> Option<Vec<u8>> {
    const FILE_ALIGNMENT: u32 = 0x200;
    const HEADER_SIZE: u32 = 0x400;
    let opt_hdr_size = get_u16(data, pe_header.wrapping_add(20)) as u32;
    let opt_hdr = pe_header.wrapping_add(24);
    let sec_table = opt_hdr.wrapping_add(opt_hdr_size);
    let num_sections = get_u16(data, pe_header.wrapping_add(6)) as u32;

    struct SecLayout {
        sec_off: u32,
        va: u32,
        vsize: u32,
        raw_ptr: u32,
        raw_size: u32,
    }

    let mut raw_cursor: u64 = HEADER_SIZE as u64;
    let mut raw_layout: Vec<SecLayout> = Vec::new();
    for idx in 0..num_sections {
        let sec_off = sec_table.wrapping_add(idx * 40);
        let vsize = get_u32(data, sec_off.wrapping_add(8));
        let va = get_u32(data, sec_off.wrapping_add(12));
        let sd_start = va as usize;
        let sd_end = if (va.wrapping_add(vsize) as usize) <= data.len() {
            va.wrapping_add(vsize) as usize
        } else {
            data.len()
        };
        let section_data: &[u8] = if sd_start <= sd_end && sd_start <= data.len() {
            &data[sd_start..sd_end]
        } else {
            &[]
        };

        let mut last_nonzero: i64 = -1;
        for pos in (0..section_data.len()).rev() {
            if section_data[pos] != 0 {
                last_nonzero = pos as i64;
                break;
            }
        }
        let meaningful = if last_nonzero >= 0 {
            (last_nonzero + 1) as u32
        } else {
            0
        };
        let mut raw_size = if meaningful != 0 {
            align_up_u32(meaningful, FILE_ALIGNMENT)
        } else {
            0
        };
        if vsize != 0 && raw_size == 0 {
            raw_size = FILE_ALIGNMENT;
        }
        raw_size = raw_size.min(align_up_u32(section_data.len() as u32, FILE_ALIGNMENT));

        let raw_ptr = if raw_size != 0 { raw_cursor as u32 } else { 0 };
        raw_layout.push(SecLayout {
            sec_off,
            va,
            vsize,
            raw_ptr,
            raw_size,
        });
        if raw_size != 0 {
            // Accumulate in u64 and cap: section sizes are header-derived, and
            // a corrupt table could otherwise wrap raw_cursor (small alloc,
            // huge recorded raw_ptrs → OOB panic) or request an abort-sized
            // allocation.
            raw_cursor = align_up_u64(raw_cursor + raw_size as u64, FILE_ALIGNMENT as u64);
            if raw_cursor > super::MAX_IMAGE_SIZE {
                return None;
            }
        }
    }

    let mut compact = vec![0u8; raw_cursor as usize];
    let hdr_copy = (HEADER_SIZE as usize).min(data.len());
    compact[..hdr_copy].copy_from_slice(&data[..hdr_copy]);
    write_u32(&mut compact, opt_hdr.wrapping_add(36), FILE_ALIGNMENT);
    write_u32(&mut compact, opt_hdr.wrapping_add(60), HEADER_SIZE);

    for sl in &raw_layout {
        write_u32(&mut compact, sl.sec_off.wrapping_add(16), sl.raw_size);
        write_u32(&mut compact, sl.sec_off.wrapping_add(20), sl.raw_ptr);
        if sl.raw_size != 0 {
            let sd_start = sl.va as usize;
            let sd_end = if (sl.va.wrapping_add(sl.vsize) as usize) <= data.len() {
                sl.va.wrapping_add(sl.vsize) as usize
            } else {
                data.len()
            };
            let section_data: &[u8] = if sd_start <= sd_end {
                &data[sd_start..sd_end]
            } else {
                &[]
            };
            let copy_size = (sl.raw_size as usize).min(section_data.len());
            let rp = sl.raw_ptr as usize;
            compact[rp..rp + copy_size].copy_from_slice(&section_data[..copy_size]);
        }
    }
    Some(compact)
}

/// decrypt_data3: XOR+rotate cipher. Reads/writes dwords in `d` starting at
/// the address stored at `d[pos]`, for `d[pos+4]>>2` words. `shift` is the
/// right-rotate amount (19 or 21 depending on caller).
pub(crate) fn decrypt_data3(d: &mut [u8], pos: u32, mut key: u32, shift: u32) {
    let base_addr = get_u32(d, pos);
    let length = get_u32(d, pos.wrapping_add(4));
    let words = length >> 2;
    for i in 0..words {
        let off = base_addr.wrapping_add(i.wrapping_mul(4));
        let v = get_u32(d, off) ^ key;
        key = key.wrapping_add(i);
        let rotated = v.rotate_right(shift);
        write_u32(d, off, rotated.wrapping_sub(i));
    }
}

/// decrypt_data1 (called `decrypt_data` in the original): decode the 8-dword
/// info header from `file_data` at offset 4096 and write results into `info`.
pub(crate) fn decrypt_data1(file_data: &[u8], info: &mut [u32; 8]) {
    info[0] = get_u32(file_data, 4096);
    let mut k = get_u32(file_data, 4096);
    for i in 0..7u32 {
        let off = i.wrapping_mul(4).wrapping_add(4);
        let cell = get_u32(file_data, 4096u32.wrapping_add(off));
        info[(i + 1) as usize] = k ^ cell;
        k = i.wrapping_mul(i) ^ (k.wrapping_add(cell).wrapping_sub(i));
    }
}

/// decrypt_data6: LFSR XOR decryption of a bytecode block at `pos` in `d`.
/// The block length is read from `d[pos + 95]`.
pub(crate) fn decrypt_data6(d: &mut [u8], pos: u32) {
    let len = d[(pos + 95) as usize] as usize;
    // The keystream is exactly `lfsr_keystream`'s — generate it once (len is a
    // byte, so 256 always covers it) instead of keeping a second copy of the
    // LFSR that a future poly fix would have to update separately.
    let mut ks = [0u8; 256];
    lfsr_keystream(&mut ks);
    let pos = pos as usize;
    for i in 0..len {
        d[pos + i] ^= ks[i];
    }
}

/// decrypt_data7: nibble-swap + key-rolling byte cipher applied to a
/// null-terminated string in `d` starting at `pos`.
pub(crate) fn decrypt_data7(d: &mut [u8], pos: u32, mut key: u8) {
    let mut i: u32 = 0;
    loop {
        let idx = (pos + i) as usize;
        if d[idx] == 0 {
            break;
        }
        let mut b = d[idx];
        b = b.rotate_right(4);
        b = b.wrapping_sub(key);
        if b == 0 {
            b = 0u8.wrapping_sub(key);
        }
        d[idx] = b;
        key = key.wrapping_add(67);
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Higher-level composite: AES + decrypt3 + optional bytecode + decompress
// ---------------------------------------------------------------------------

/// Decrypt and optionally decompress a stage payload descriptor.
/// `pos` points to a (src, src_len, dest, dest_len) quad of dwords in `d`.
/// - AES-decrypts `src..src+src_len` using key at `key3_offset`
/// - XOR+rotate-decrypts with `decrypt_data3(pos, key, 19)`
/// - Applies optional custom `ops` bytecode per-byte
/// - If `src_len != dest_len`, Huffman/LZ-decompresses `src..` → `dest..`
///
/// Returns the decompression success status (always `true` when no
/// decompression was needed). The PE32 eighth-stage key search relies on this.
pub(crate) fn decrypt_and_decompress_data(
    d: &mut [u8],
    pos: u32,
    key: u32,
    key1_offset: u32,
    key3_offset: u32,
    ops: Option<&[Op]>,
) -> bool {
    let src = get_u32(d, pos);
    let src_len = get_u32(d, pos.wrapping_add(4));
    aes_decrypt(d, src, src_len, key3_offset);
    decrypt_data3(d, pos, key, 19);
    if let Some(ops) = ops
        && src_len != 0
    {
        OpsLut::new(ops).map_region(d, src as usize, src_len as usize);
    }
    let dest = get_u32(d, pos.wrapping_add(8));
    let dest_len = get_u32(d, pos.wrapping_add(12));
    if src_len != dest_len {
        return decompress(d, src, dest, key1_offset, src_len, dest_len);
    }
    true
}

// ---------------------------------------------------------------------------
// dd8 page-XOR shift selection.
//
// The packer scrambles ~1 byte per 16-byte block of .text via decrypt_data8,
// keyed by `page_idx << shift` (absolute page index = text_va >> 12). Observed
// shifts are 0 and 15. The shift is NOT stored in any header/config field:
// two otherwise-unrelated builds can carry byte-identical config-version stamps
// (0x40327253) yet require different shifts, so the only reliable discriminator
// is the .text content itself.
//
// Detection replays the three candidate states — no dd8 (already plaintext),
// shift 0, shift 15 — over a few sample pages (head/tail margin skipped:
// entry/exit regions have atypical padding density) and picks the state whose
// decoded pages look most like real x64 code. The primary signal is a
// *structural* fingerprint: the MSVC function-end padding pattern, a 0xC3 RET
// opcode followed by a run of >= 4 0xCC int3 bytes. dd8 XORs one pseudo-random
// byte per 16-byte block, so an already-plaintext page keeps its padding runs
// only under "no dd8", while a packer-encrypted page restores them only under
// the correct shift — a wrong candidate destroys every run it touches and
// essentially never manufactures a RET followed by a long int3 run by chance.
// This separates the states far more cleanly than a bare 0xCC count, which a
// wrong candidate inflates for free (~255 coincidences per page at p=1/256).
//
// When no candidate produces any RET-anchored padding (sampled pages with
// dense code and no padded epilogues), the fingerprint is silent, so the
// decision falls back to the older mutated-position 0xCC count. Both signals
// use the same decision rule: a candidate must beat the no-dd8 baseline by a
// clear 2x margin AND an absolute floor, otherwise dd8 is skipped — a wrongly
// applied dd8 scrambles ~1 byte per 16 with no error surfaced downstream.
//
// This replaces an earlier entry-stub oracle that matched the 14 fixed CRT-stub
// bytes at the AEP. That oracle false-positived on a newer EXE-64 build: dd8
// corrupted only the call rel32 (bytes 5-8, the wildcard region), so the stub
// matched under BOTH shifts and the selector defaulted to 0 when the truth was
// 15. A whole-page padding statistic samples hundreds of positions per page
// and is not fooled by a stub whose fixed bytes happen to survive.
// ---------------------------------------------------------------------------

/// Minimum 0xCC run length after a RET for the run to count as MSVC
/// function-end padding.
const MIN_CC_RUN: u32 = 4;

/// Total length of MSVC function-end padding runs in a page: each 0xC3 byte
/// followed by >= [`MIN_CC_RUN`] 0xCC bytes contributes the run length.
fn ret_int3_score(page: &[u8]) -> u32 {
    let mut total = 0u32;
    let mut i = 0;
    while i < page.len() {
        if page[i] == 0xC3 {
            let mut j = i + 1;
            while j < page.len() && page[j] == 0xCC {
                j += 1;
            }
            let run = (j - i - 1) as u32;
            if run >= MIN_CC_RUN {
                total += run;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    total
}

/// Replay the dd8 page-XOR in place on one sample page.
fn dd8_apply(buf: &mut [u8; 0x1000], abs_page: u32, shift: u32) {
    let mut key = abs_page << shift;
    for bi in 0..256u32 {
        let mixed = key.rotate_right(15).wrapping_add(bi);
        key = mixed.wrapping_add(bi);
        // The packer's dd8 loop does not XOR block i=0 (see decrypt_data8).
        if bi == 0 {
            continue;
        }
        let tidx = (bi.wrapping_mul(16).wrapping_add(mixed & 0xF)) as usize;
        buf[tidx] ^= key as u8;
    }
}

/// Sum the RET+int3 fingerprint over the sample pages for one candidate
/// (`None` = the no-dd8 baseline, page as-is).
fn fingerprint_score(
    data: &[u8],
    text_off: usize,
    abs_base: u32,
    sample_pages: &[u32],
    shift: Option<u32>,
) -> u32 {
    let mut total = 0u32;
    for &sp in sample_pages {
        let pg_off = text_off + (sp as usize) * 0x1000;
        if pg_off + 0x1000 > data.len() {
            continue;
        }
        let mut page = [0u8; 0x1000];
        page.copy_from_slice(&data[pg_off..pg_off + 0x1000]);
        if let Some(sh) = shift {
            dd8_apply(&mut page, abs_base.wrapping_add(sp), sh);
        }
        total += ret_int3_score(&page);
    }
    total
}

pub(crate) fn select_dd8_shift(data: &[u8], text_va: u32, text_size: u32, _info3: u32) -> u32 {
    let num_pages_total = text_size >> 12;
    // Fewer than two pages: nothing meaningful to sample; preserve the
    // historical behavior (shift 0 — the dd8 loop is empty or single-page).
    if num_pages_total < 2 {
        return 0;
    }
    let text_off = text_va as usize;

    // Sample up to 4 pages, skipping a head/tail margin. Small .text: sample
    // every page.
    let mut sample_pages: Vec<u32> = Vec::new();
    if num_pages_total <= 4 {
        sample_pages.extend(0..num_pages_total);
    } else {
        let margin = (num_pages_total / 8).max(1);
        let lo = margin;
        let hi = num_pages_total - margin;
        if hi <= lo {
            sample_pages.extend(0..num_pages_total);
        } else {
            let step = ((hi - lo) / 4).max(1);
            let mut i = 0;
            while i < 4 {
                let p = lo + i * step;
                if p < num_pages_total {
                    sample_pages.push(p);
                }
                i += 1;
            }
        }
    }
    if sample_pages.is_empty() {
        return 0;
    }

    let abs_base = text_va >> 12;
    // Require a clear 2x margin over the already-plaintext baseline AND an
    // absolute floor. The 2x test alone trips on noise when the counts are
    // tiny: an external-companion DLL whose .text is already plaintext scores
    // s15=4 vs none=1 — a spurious 4x — and gets dd8 wrongly applied,
    // corrupting ~1 byte per 16. The floor rejects that noise while sitting
    // far below every genuinely-encrypted build's score.
    const MIN_DD8_HITS: u32 = 8;
    let margin_pick = |none: u32, s0: u32, s15: u32| -> u32 {
        let mut best_score = none;
        let mut best_shift = 99u32; // 99 == skip dd8
        for (shift, hits) in [(0u32, s0), (15u32, s15)] {
            if hits > best_score {
                best_score = hits;
                best_shift = shift;
            }
        }
        if best_shift != 99 && (best_score < none * 2 || best_score < MIN_DD8_HITS) {
            best_shift = 99;
        }
        best_shift
    };

    // Primary: RET+int3 padding fingerprint. The fingerprint is diluted across
    // the whole page (dd8 touches only 255 of 4096 bytes, so even an encrypted
    // page keeps most of its padding runs), so instead of the fallback's 2x
    // margin the gate is a *positive delta* over the no-dd8 baseline: on an
    // already-plaintext .text each wrong shift destroys runs (scores below the
    // baseline), while the correct shift on an encrypted page restores them
    // (scores above it). The floor on the delta rejects noise-level gains.
    let r_none = fingerprint_score(data, text_off, abs_base, &sample_pages, None);
    let r0 = fingerprint_score(data, text_off, abs_base, &sample_pages, Some(0));
    let r15 = fingerprint_score(data, text_off, abs_base, &sample_pages, Some(15));
    // Fallback: mutated-position 0xCC count, for pages whose code has no
    // RET-anchored padding at all (the fingerprint is silent there).
    let (none_hits, s0, s15);
    let best_shift = if r_none != 0 || r0 != 0 || r15 != 0 {
        none_hits = 0;
        s0 = 0;
        s15 = 0;
        let mut best_score = r_none;
        let mut shift = 99u32;
        for (s, score) in [(0u32, r0), (15u32, r15)] {
            if score > best_score {
                best_score = score;
                shift = s;
            }
        }
        if shift != 99 && best_score.saturating_sub(r_none) < MIN_DD8_HITS {
            shift = 99;
        }
        shift
    } else {
        none_hits = score_dd8_baseline(data, text_off, &sample_pages);
        s0 = score_dd8_shift(data, text_off, text_va, &sample_pages, 0);
        s15 = score_dd8_shift(data, text_off, text_va, &sample_pages, 15);
        margin_pick(none_hits, s0, s15)
    };
    if std::env::var("SEL_DIAG").is_ok() {
        eprintln!(
            "SEL dd8 best_shift={} fp=({},{},{}) cc=({},{},{}) samples={:?}",
            best_shift, r_none, r0, r15, none_hits, s0, s15, sample_pages
        );
    }
    best_shift
}

// Baseline: count int3 pads already present at the first byte of each 16-byte
// block, i.e. the positions dd8 would target if its in-block offset were 0.
fn score_dd8_baseline(data: &[u8], text_off: usize, sample_pages: &[u32]) -> u32 {
    let mut hits = 0u32;
    for &sp in sample_pages {
        let pg_off = text_off + (sp as usize) * 0x1000;
        if pg_off + 0x1000 > data.len() {
            continue;
        }
        for bi in 1..256usize {
            if data[pg_off + bi * 16] == 0xCC {
                hits += 1;
            }
        }
    }
    hits
}

// Replay decrypt_data8 on each sample page under `shift` and count how many of
// the 255 mutated positions decode to 0xCC.
fn score_dd8_shift(
    data: &[u8],
    text_off: usize,
    text_va: u32,
    sample_pages: &[u32],
    shift: u32,
) -> u32 {
    let abs_base = text_va >> 12;
    let mut hits = 0u32;
    for &sp in sample_pages {
        let pg_off = text_off + (sp as usize) * 0x1000;
        if pg_off + 0x1000 > data.len() {
            continue;
        }
        let abs_page = abs_base.wrapping_add(sp);
        let mut key = abs_page << shift;
        for bi in 0..256u32 {
            let mixed = key.rotate_right(15).wrapping_add(bi);
            key = mixed.wrapping_add(bi);
            if bi == 0 {
                continue;
            }
            let tidx = (bi.wrapping_mul(16).wrapping_add(mixed & 0xF)) as usize;
            if tidx < 0x1000 {
                let mutated = data[pg_off + tidx] ^ (key as u8);
                if mutated == 0xCC {
                    hits += 1;
                }
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_ks_variant_matches_single_buffer() {
        // Random-ish key schedule at ko and data block; both variants must
        // produce identical output.
        let ko: usize = 0x40;
        let mut d = vec![0u8; 0x400];
        let mut x: u32 = 0x12345678;
        for b in d.iter_mut() {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (x >> 24) as u8;
        }
        d[ko + 2] = 10; // round count = 10
        d[ko + 3] = 0;
        let snap = aes_schedule_snapshot(&d, ko as u32).expect("snapshot");

        let mut a = d.clone();
        aes_decrypt(&mut a, 0x100, 0x80, ko as u32);
        let mut b = d.clone();
        aes_decrypt_ks(&snap, &mut b, 0x100, 0x80);
        if a != b {
            let idx = (0..a.len()).find(|&i| a[i] != b[i]).unwrap();
            panic!(
                "first diff at {idx:#x}: a={:02x} b={:02x}\n a[..]: {:02x?}\n b[..]: {:02x?}",
                a[idx],
                b[idx],
                &a[idx..idx + 16],
                &b[idx..idx + 16]
            );
        }
    }

    #[test]
    fn dtbl_variant_matches_single_buffer() {
        // Real table + real compressed block lifted from an actual unpack is
        // covered by the golden suite; here we just check a trivial stream:
        // build a table where every byte is a literal (mode 0, 8 bits), then
        // a source stream of N bytes should expand to N identical bytes.
        let ko: usize = 0x100;
        let mut d = vec![0u8; 0x1000];
        for e in 0..256usize {
            let off = ko + e * 3;
            let sym = 0x8000u16 | (e as u16 & 0xFF); // terminal, mode 0, payload=e
            d[off] = (sym & 0xFF) as u8;
            d[off + 1] = (sym >> 8) as u8;
            d[off + 2] = 8; // 8 bits per symbol
        }
        // Source: 16 bytes 0x00..0x0F at src.
        let src = 0x600u32;
        for i in 0..16u32 {
            d[(src + i) as usize] = i as u8;
        }
        let snap = huffman_table_snapshot(&d, ko as u32).expect("table snapshot");

        let mut a = vec![0u8; 0x1000];
        a[..d.len()].copy_from_slice(&d);
        assert!(decompress(&mut a, src, 0x800, ko as u32, 16, 16));
        let mut b = d.clone();
        assert!(decompress_tbl(&snap, &mut b, src, 0x800, 16, 16));
        assert_eq!(&a[0x800..0x810], &b[0x800..0x810]);
        assert_eq!(&b[0x800..0x810], &(0u8..16).collect::<Vec<_>>()[..]);
    }

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

    /// Review regression: a run-fill token with a unit width other than 1/2/4
    /// comes from a corrupt stream and must report failure — previously it
    /// wrote nothing yet still counted the bytes as written, leaving stale
    /// holes that later stages treated as plaintext.
    #[test]
    fn decompress_rejects_unknown_run_fill_width() {
        // Huffman table at key_offset 0, entry 0: terminal symbol with
        // mode 0x200 (run-fill), payload 3 (invalid width), code length 8.
        let mut d = vec![0u8; 0x100];
        let sym: u16 = 0x8000 | 0x203;
        d[0..2].copy_from_slice(&sym.to_le_bytes());
        d[2] = 8;
        // All-zero source -> symbol index 0 -> the invalid run-fill.
        assert!(!decompress(&mut d, 0x40, 0x80, 0, 4, 3));
    }

    /// Control for the above: a width-1 run-fill is legal and succeeds.
    #[test]
    fn decompress_accepts_width1_run_fill() {
        let mut d = vec![0u8; 0x100];
        d[0x7F] = 0x5A; // unit to replicate
        let sym: u16 = 0x8000 | 0x201;
        d[0..2].copy_from_slice(&sym.to_le_bytes());
        d[2] = 8;
        assert!(decompress(&mut d, 0x40, 0x80, 0, 4, 3));
        assert_eq!(&d[0x80..0x83], &[0x5A, 0x5A, 0x5A]);
    }

    /// Seed the first `count` dd8-targeted positions of each sampled page with
    /// the byte that decodes to `0xCC` under the `page+1` formula — i.e. an
    /// encrypted `.text` whose plaintext is int3 padding. Positions whose key
    /// byte would make the *ciphertext* itself `0xCC` are skipped so the
    /// fixture contains no `0xCC` at all and every post-dd8 `0xCC` is a genuine
    /// gain over a zero baseline.
    fn seed_dd8_int3(data: &mut [u8], text_off: u32, pages: &[u32], count: u32) {
        for &sp in pages {
            let pg_off = (text_off + sp * 0x1000) as usize;
            let mut k = sp.wrapping_add(1);
            k = k.rotate_right(15);
            let mut planted = 0u32;
            for bi in 1..256u32 {
                let ri = k.rotate_right(15).wrapping_add(bi);
                k = ri.wrapping_add(bi);
                if planted >= count {
                    continue;
                }
                let ct = 0xCCu8 ^ (k as u8);
                if ct == 0xCC {
                    continue;
                }
                let tidx = (bi.wrapping_mul(16).wrapping_add(ri & 0xF)) as usize;
                data[pg_off + tidx] = ct;
                planted += 1;
            }
        }
    }

    /// Review regression: a near-plaintext `.text` must NOT be dd8-decrypted.
    /// dd8 XORs 255 positions per page with pseudo-random bytes, so it
    /// manufactures a few `0xCC` for free — under the old bare
    /// `best > baseline` test any positive gain was enough to "apply" dd8 and
    /// scramble ~1 byte per 16 of a native DLL's already-plaintext code,
    /// silently (nothing downstream, including the integrity check, notices).
    /// Here the gain is real but small; the floor must still reject it.
    #[test]
    fn pe32_dd8_skips_text_whose_gain_is_only_noise_sized() {
        let text_off: u32 = 0x1000;
        let text_size: u32 = 8 * 0x1000;
        let mut data = vec![0u8; (text_off + text_size) as usize];
        seed_dd8_int3(&mut data, text_off, &[2, 4, 6], 5);
        assert!(
            !data.contains(&0xCC),
            "fixture must have a zero 0xCC baseline"
        );
        assert_eq!(
            select_dd8_formula_pe32(&data, text_off, text_size),
            None,
            "a gain this small is indistinguishable from dd8's own noise"
        );
    }

    /// Control for the above: a `.text` whose dd8 pass restores a large amount
    /// of int3 padding clears the floor and is decrypted. Same fixture shape,
    /// only the amount of restored padding differs.
    #[test]
    fn pe32_dd8_applies_when_padding_is_restored() {
        let text_off: u32 = 0x1000;
        let text_size: u32 = 8 * 0x1000;
        let mut data = vec![0u8; (text_off + text_size) as usize];
        seed_dd8_int3(&mut data, text_off, &[2, 4, 6], 255);
        assert_eq!(
            select_dd8_formula_pe32(&data, text_off, text_size),
            Some(false),
            "encrypted .text must be decrypted with the page+1 formula"
        );
    }

    /// Review regression: a zero last-section VA (corrupt section table) must
    /// bail instead of building .kmiat at RVA 0 — the old code zeroed
    /// `[0, 0x7000)`, wiping the DOS/PE headers, and returned the broken image
    /// as a success. A near-2 GiB VA must likewise refuse to grow the image
    /// past [`super::MAX_IMAGE_SIZE`].
    #[test]
    fn kmiat_bogus_section_va_bails_without_wiping_headers() {
        for last_sec_va in [0u32, 0x5000_0000] {
            let pe: u32 = 0x80;
            let mut data = vec![0xAAu8; 0x8000];
            // COFF header: 1 section, optional header size 0xE0 (PE32).
            write_u16(&mut data, pe + 6, 1);
            write_u16(&mut data, pe + 20, 0xE0);
            // Import directory at pe+0x80: one descriptor + null terminator.
            write_u32(&mut data, pe + 0x80, 0x1100);
            write_u32(&mut data, pe + 0x84, 0x28);
            write_u32(&mut data, 0x1100, 0x1200); // OFT rva
            write_u32(&mut data, 0x1100 + 12, 0x1300); // name rva
            write_u32(&mut data, 0x1100 + 16, 0x1400); // IAT rva
            for b in &mut data[0x1100 + 20..0x1100 + 40] {
                *b = 0; // null terminator descriptor
            }
            data[0x1300..0x1300 + 13].copy_from_slice(b"KERNEL32.dll\0");
            write_u32(&mut data, 0x1200, 0x1500); // thunk -> hint/name
            write_u32(&mut data, 0x1204, 0); // thunk terminator
            data[0x1500..0x1502].copy_from_slice(&0u16.to_le_bytes());
            data[0x1502..0x1502 + 12].copy_from_slice(b"ExitProcess\0");
            // Section table at pe+24+0xE0 = 0x178; VA field at +12.
            write_u32(&mut data, 0x178 + 12, last_sec_va);

            let head_before: Vec<u8> = data[..0x400].to_vec();
            let len_before = data.len();
            move_pe32_imports_to_kmiat(&mut data, pe);
            assert_eq!(
                data.len(),
                len_before,
                "VA 0x{last_sec_va:08X}: image must not grow"
            );
            assert_eq!(
                &data[..0x400],
                &head_before[..],
                "VA 0x{last_sec_va:08X}: headers must be untouched"
            );
        }
    }
}
