//! Shared crypto primitives and helper utilities.
//!
//! These functions form the low-level API used by the PE pipelines.
//! Each free function is self-contained: it takes the relevant byte buffer(s)
//! and parameters explicitly, with no coupling to the EXE `Unpacker` struct.

use crate::bytecode::{Op, OpsLut};
use crate::crc32;
use crate::tables::{COLUMMIX1, COLUMMIX2, COLUMMIX3, COLUMMIX4, SBOX};
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

pub fn get_u16(data: &[u8], offset: u32) -> u16 {
    let i = offset as usize;
    u16::from_le_bytes([data[i], data[i + 1]])
}

pub fn get_u32(data: &[u8], offset: u32) -> u32 {
    let i = offset as usize;
    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
}

pub fn get_u64(data: &[u8], offset: u32) -> u64 {
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

pub fn write_u16(data: &mut [u8], offset: u32, value: u32) {
    let i = offset as usize;
    let v = value as u16;
    let b = v.to_le_bytes();
    data[i] = b[0];
    data[i + 1] = b[1];
}

pub fn write_u32(data: &mut [u8], offset: u32, value: u32) {
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
pub fn try_u32(d: &[u8], off: usize) -> Result<u32, crate::Error> {
    let end = off
        .checked_add(4)
        .ok_or(crate::Error::BufferRangeOutOfBounds {
            operation: crate::BufferOperation::Read,
            offset: off,
            size: 4,
            buffer_len: d.len(),
        })?;
    d.get(off..end)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or(crate::Error::BufferRangeOutOfBounds {
            operation: crate::BufferOperation::Read,
            offset: off,
            size: 4,
            buffer_len: d.len(),
        })
}

#[allow(dead_code)]
pub fn try_i32(d: &[u8], off: usize) -> Result<i32, crate::Error> {
    try_u32(d, off).map(|v| v as i32)
}

/// Checked copy with distinct source and destination range errors.
pub fn try_copy_from_slice(
    dst: &mut [u8],
    dst_off: usize,
    dst_len: usize,
    src: &[u8],
    src_off: usize,
) -> Result<(), crate::Error> {
    let dst_end = dst_off
        .checked_add(dst_len)
        .ok_or(crate::Error::BufferRangeOutOfBounds {
            operation: crate::BufferOperation::CopyDestination,
            offset: dst_off,
            size: dst_len,
            buffer_len: dst.len(),
        })?;
    let src_end = src_off
        .checked_add(dst_len)
        .ok_or(crate::Error::BufferRangeOutOfBounds {
            operation: crate::BufferOperation::CopySource,
            offset: src_off,
            size: dst_len,
            buffer_len: src.len(),
        })?;
    if dst_end > dst.len() {
        return Err(crate::Error::BufferRangeOutOfBounds {
            operation: crate::BufferOperation::CopyDestination,
            offset: dst_off,
            size: dst_len,
            buffer_len: dst.len(),
        });
    }
    if src_end > src.len() {
        return Err(crate::Error::BufferRangeOutOfBounds {
            operation: crate::BufferOperation::CopySource,
            offset: src_off,
            size: dst_len,
            buffer_len: src.len(),
        });
    }
    dst[dst_off..dst_end].copy_from_slice(&src[src_off..src_end]);
    Ok(())
}

/// Reproduce the LFSR keystream that decrypt_data6 XORs in. Used to
/// trial-decrypt candidate bytecode positions without mutating the buffer.
pub fn lfsr_keystream(out: &mut [u8]) {
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

// ---------------------------------------------------------------------------
// AES primitives
// ---------------------------------------------------------------------------

/// One AES-CBC-like round over a 16-byte block in `d` at `pos`, using the
/// expanded key schedule stored in `d` at `key_offset`. Works entirely within
/// the single `d` buffer (both ciphertext and key schedule live there).
pub fn aes_round(d: &mut [u8], pos: u32, key_offset: u32, round: u32) {
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
pub fn aes_decrypt(d: &mut [u8], pos: u32, size: u32, key_offset: u32) {
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
pub fn aes_decrypt_ks(ks: &[u8], d: &mut [u8], pos: u32, size: u32) {
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
pub fn aes_schedule_snapshot(d: &[u8], key_offset: u32) -> Option<Vec<u8>> {
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
pub fn calculate_checksum(d: &[u8], pos: u32) -> u32 {
    let offset = get_u32(d, pos);
    let length = get_u32(d, pos.wrapping_add(4));
    crc32::compute(&d[offset as usize..(offset + length) as usize]) ^ length
}

/// CRC32 chained checksum. The (offset, length) descriptor at `pos` is read
/// from `d`; the bytes themselves are read from the separate `clean` buffer
/// (the original file image). `start` is the initial CRC accumulator. Returns
/// a range error instead of panicking when a descriptor points past `clean`.
pub fn calculate_checksum2(
    d: &[u8],
    clean: &[u8],
    pos: u32,
    start: u32,
) -> Result<u32, crate::Error> {
    let offset = get_u32(d, pos);
    let length = get_u32(d, pos.wrapping_add(4));
    let data_start = offset as usize;
    let size = length as usize;
    let end = data_start.checked_add(size);
    let Some(end) = end.filter(|&end| end <= clean.len()) else {
        return Err(crate::Error::BufferRangeOutOfBounds {
            operation: crate::BufferOperation::Read,
            offset: data_start,
            size,
            buffer_len: clean.len(),
        });
    };
    Ok(crc32::append(start, &clean[data_start..end]))
}

// ---------------------------------------------------------------------------
// Decompression (Huffman/LZ)
// ---------------------------------------------------------------------------

/// Huffman/LZ decompression operating entirely within a single `d` buffer.
/// Reads `s_size` bytes from `src`, writes `d_size` bytes to `dest`.
/// The Huffman table lives at `key_offset` within `d`.
///
/// Returns a structured reason when the stream cannot produce exactly
/// `d_size` bytes.
pub fn decompress_detailed(
    d: &mut [u8],
    src: u32,
    mut dest: u32,
    key_offset: u32,
    s_size: u32,
    d_size: u32,
) -> Result<(), crate::DecompressionFailure> {
    use crate::DecompressionFailure;

    // Bound the scratch allocation: a corrupt descriptor could request a
    // multi-gigabyte source size, and an allocation failure aborts the process
    // (uncatchable). Real payloads are far below this.
    if s_size as u64 > crate::MAX_IMAGE_SIZE {
        return Err(DecompressionFailure::SourceTooLarge {
            size: s_size,
            max: crate::MAX_IMAGE_SIZE,
        });
    }
    DECOMPRESS_SCRATCH.with_borrow_mut(|buf| -> Result<(), DecompressionFailure> {
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
                    return Err(DecompressionFailure::InvalidCodeLength { bits: b2 });
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
                        return Err(DecompressionFailure::HuffmanTraversalLimit);
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
                        return Err(DecompressionFailure::PendingLengthOverflow { pending });
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
                        return Err(DecompressionFailure::OutputOverflow {
                            written,
                            step,
                            expected: d_size,
                        });
                    }
                    // Run-fill replicates the unit just written before `dest`. A
                    // corrupt stream can emit one of these before anything has been
                    // written, so guard against reading before the buffer start
                    // (an unsigned underflow would index astronomically far OOB).
                    match payload {
                        1 => {
                            if dest < 1 {
                                return Err(DecompressionFailure::RunFillBeforeOutput {
                                    width: payload,
                                    destination: dest,
                                });
                            }
                            let v = d[(dest as usize) - 1];
                            for k in 0..pending {
                                d[(dest + k) as usize] = v;
                            }
                        }
                        2 => {
                            if dest < 2 {
                                return Err(DecompressionFailure::RunFillBeforeOutput {
                                    width: payload,
                                    destination: dest,
                                });
                            }
                            let v = get_u16(d, dest.wrapping_sub(2));
                            for k in 0..pending {
                                write_u16(d, dest.wrapping_add(k.wrapping_mul(2)), v as u32);
                            }
                        }
                        4 => {
                            if dest < 4 {
                                return Err(DecompressionFailure::RunFillBeforeOutput {
                                    width: payload,
                                    destination: dest,
                                });
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
                            return Err(DecompressionFailure::InvalidRunFillWidth {
                                width: payload,
                            });
                        }
                    }
                    pending = 0;
                }
                _ => {
                    step = payload;
                    if written.wrapping_add(payload) > d_size
                        || pending.wrapping_add(payload) > written
                    {
                        let distance = pending.wrapping_add(payload);
                        if distance > written {
                            return Err(DecompressionFailure::InvalidBackReference {
                                distance,
                                written,
                            });
                        }
                        return Err(DecompressionFailure::OutputOverflow {
                            written,
                            step: payload,
                            expected: d_size,
                        });
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
                return Err(DecompressionFailure::NoProgress);
            }
        }
        src_consumed += if bit_pos != 0 { 1 } else { 0 };
        if written != d_size {
            return Err(DecompressionFailure::OutputSizeMismatch {
                written,
                expected: d_size,
                consumed: src_consumed.max(0) as u32,
                source_size: s_size,
            });
        }
        Ok(())
    })
}

/// Boolean compatibility wrapper used by candidate searches and block fan-out.
pub fn decompress(
    d: &mut [u8],
    src: u32,
    dest: u32,
    key_offset: u32,
    s_size: u32,
    d_size: u32,
) -> bool {
    decompress_detailed(d, src, dest, key_offset, s_size, d_size).is_ok()
}

/// Walk the Huffman table at `key_offset` and snapshot its bytes for
/// [`decompress_tbl`]. The table is a forest of 256 root entries (3 bytes
/// each); non-terminal entries point at a child index pair. Returns `None`
/// when the table is truncated or self-referential past the buffer (corrupt
/// input — the same bytes would otherwise drive reads out of bounds).
pub fn huffman_table_snapshot(d: &[u8], key_offset: u32) -> Option<Vec<u8>> {
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
pub fn decompress_tbl(
    tab: &[u8],
    d: &mut [u8],
    src: u32,
    mut dest: u32,
    s_size: u32,
    d_size: u32,
) -> bool {
    if s_size as u64 > crate::MAX_IMAGE_SIZE {
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

/// decrypt_data3: XOR+rotate cipher. Reads/writes dwords in `d` starting at
/// the address stored at `d[pos]`, for `d[pos+4]>>2` words. `shift` is the
/// right-rotate amount (19 or 21 depending on caller).
pub fn decrypt_data3(d: &mut [u8], pos: u32, mut key: u32, shift: u32) {
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
pub fn decrypt_data1(file_data: &[u8], info: &mut [u32; 8]) {
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
pub fn decrypt_data6(d: &mut [u8], pos: u32) {
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
pub fn decrypt_data7(d: &mut [u8], pos: u32, mut key: u8) {
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
pub fn decrypt_and_decompress_data_detailed(
    d: &mut [u8],
    pos: u32,
    key: u32,
    key1_offset: u32,
    key3_offset: u32,
    ops: Option<&[Op]>,
) -> Result<(), crate::DecompressionFailure> {
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
        return decompress_detailed(d, src, dest, key1_offset, src_len, dest_len);
    }
    Ok(())
}

/// Boolean compatibility wrapper used by key searches that trial candidates.
pub fn decrypt_and_decompress_data(
    d: &mut [u8],
    pos: u32,
    key: u32,
    key1_offset: u32,
    key3_offset: u32,
    ops: Option<&[Op]>,
) -> bool {
    decrypt_and_decompress_data_detailed(d, pos, key, key1_offset, key3_offset, ops).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_copy_distinguishes_source_and_destination_ranges() {
        let mut short_destination = [0u8; 2];
        let source = [1u8; 4];
        let error = try_copy_from_slice(&mut short_destination, 0, 3, &source, 0)
            .expect_err("destination must be rejected");
        assert!(matches!(
            error,
            crate::Error::BufferRangeOutOfBounds {
                operation: crate::BufferOperation::CopyDestination,
                offset: 0,
                size: 3,
                buffer_len: 2,
            }
        ));

        let mut destination = [0u8; 4];
        let short_source = [1u8; 2];
        let error = try_copy_from_slice(&mut destination, 0, 3, &short_source, 0)
            .expect_err("source must be rejected");
        assert!(matches!(
            error,
            crate::Error::BufferRangeOutOfBounds {
                operation: crate::BufferOperation::CopySource,
                offset: 0,
                size: 3,
                buffer_len: 2,
            }
        ));
    }

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
        assert_eq!(
            decompress_detailed(&mut d, 0x40, 0x80, 0, 4, 3),
            Err(crate::DecompressionFailure::InvalidRunFillWidth { width: 3 })
        );
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

    #[test]
    fn checksum2_rejects_source_range_outside_clean_image() {
        let mut descriptor = [0u8; 8];
        descriptor[0..4].copy_from_slice(&448u32.to_le_bytes());
        descriptor[4..8].copy_from_slice(&634_432u32.to_le_bytes());
        let clean = vec![0u8; 590_896];
        let error = calculate_checksum2(&descriptor, &clean, 0, 0).expect_err("range must fail");
        assert!(matches!(
            error,
            crate::Error::BufferRangeOutOfBounds {
                operation: crate::BufferOperation::Read,
                offset: 448,
                size: 634_432,
                buffer_len: 590_896,
            }
        ));
    }
}
