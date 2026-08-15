use super::bytecode::{Op, OpsLut, generate};
use super::primitives;
use super::primitives::*;

#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    #[error("input too short for header (need at least 4096 bytes, got {0})")]
    InputTooShort(usize),

    #[error("info[1] mismatch — corrupt data or wrong offset")]
    HeaderMismatch,

    #[error("anchor field not found — corrupt data or wrong offset")]
    AnchorNotFound,

    #[error("stage2 field not found — corrupt data or wrong offset")]
    Stage2NotFound,

    #[error("chk_src_start not found — corrupt data or wrong offset")]
    ChkSrcStartNotFound,

    #[error("table_start not found — corrupt data or wrong offset")]
    TableStartNotFound,

    #[error("stage4 bytecode generation failed — corrupt data or wrong offset")]
    BytecodeGenFailed,

    #[error("stage5 marker not found — this build's layout is not supported by this unpacker")]
    Stage5MarkerNotFound,

    #[error("stage5 bytecode generation failed — corrupt data or wrong offset")]
    Stage5BytecodeGenFailed,

    #[error("DLL unpack failed: {0}")]
    DllUnpack(String),

    #[error("not a Crackproof-protected file")]
    NotCrackproof,

    #[error("out-of-bounds access at offset {0}")]
    OutOfBounds(usize),

    #[error("PE32 tbl not found — corrupt data or wrong offset")]
    Pe32TblNotFound,

    #[error("PE32 thirdStage decrypt failed — corrupt data or wrong offset")]
    Pe32ThirdStageFailed,

    #[error("PE32 customDecryptor not found in sevenStage")]
    Pe32CustomDecryptorNotFound,

    #[error("PE32 stage bytecode generation failed")]
    Pe32BytecodeGenFailed,

    #[error("PE32 eighthStageKey not found")]
    Pe32EighthKeyNotFound,

    #[error("PE32 file LFSR not found in eighthStage")]
    Pe32FileLfsrNotFound,

    #[error("decompression failed — corrupt data or wrong offset")]
    DecompressFailed,

    #[error("input is corrupt or not a supported Crackproof layout")]
    Corrupt,
}

pub fn unpack(input: &[u8]) -> Result<Vec<u8>, UnpackError> {
    unpack_v(input, false)
}

/// Map an RVA to a file offset using the protected file's section table.
/// Used by the new-layout managed (CLR) metadata restore to locate the COR20
/// header and BSJB MetaData stream in the original protected file.
fn prot_rva_to_off(file_data: &[u8], pe_header: u32, rva: u32) -> Option<u32> {
    let nsec = get_u16(file_data, pe_header + 6) as u32;
    let opt = get_u16(file_data, pe_header + 20) as u32;
    let tab = pe_header + 24 + opt;
    for i in 0..nsec {
        let s = tab + i * 40;
        if (s as usize + 24) > file_data.len() {
            return None;
        }
        let va = get_u32(file_data, s + 12);
        let vs = get_u32(file_data, s + 8);
        let rsz = get_u32(file_data, s + 16);
        let rp = get_u32(file_data, s + 20);
        if va <= rva && rva < va + vs.max(rsz) {
            return Some(rp + (rva - va));
        }
    }
    None
}

pub fn unpack_v(input: &[u8], verbose: bool) -> Result<Vec<u8>, UnpackError> {
    if input.len() < 4096 {
        return Err(UnpackError::InputTooShort(input.len()));
    }
    // The pipeline chases offsets read out of the decrypted image; on a
    // truncated/garbled-but-detected file those run out of bounds. Trap any
    // such panic and report it as corrupt input so the library never unwinds
    // into the caller (same role as the DLL path's explicit bounds checks).
    // `input` is read-only for the entire unpack (the payload is decrypted into a
    // separate `decompressed` buffer), so the unpacker borrows it directly — no
    // owned copy is made here. catch_unwind uses AssertUnwindSafe, so a borrowing
    // (non-'static) closure is fine.
    super::catch_unpack(move || Unpacker::run(input, verbose))
}

struct Unpacker<'a> {
    file_data: &'a [u8],
    decompressed: Vec<u8>,
    info: [u32; 8],
    key_offsets: [u32; 4],
    decrypt_size: u32,
}

impl<'a> Unpacker<'a> {
    // Strategy (a): delegate to primitives::aes_decrypt
    fn aes_decrypt(&mut self, pos: u32, size: u32, key_offset: u32) {
        primitives::aes_decrypt(&mut self.decompressed, pos, size, key_offset);
    }

    // Strategy (a): delegate to primitives::calculate_checksum
    fn calculate_checksum(&self, pos: u32) -> u32 {
        primitives::calculate_checksum(&self.decompressed, pos)
    }

    // Strategy (a): delegate to primitives::calculate_checksum2
    fn calculate_checksum2(&self, pos: u32, start: u32) -> u32 {
        primitives::calculate_checksum2(&self.decompressed, self.file_data, pos, start)
    }

    // Strategy (a): delegate to primitives::decrypt_data1
    fn decrypt_data(&mut self) {
        primitives::decrypt_data1(self.file_data, &mut self.info);
    }

    // Strategy (b): decrypt_data2 is tightly coupled to Unpacker fields
    // (file_data, decompressed, info, decrypt_size); left on Unpacker.
    // The DLL port will need a different driver state anyway.
    fn decrypt_data2(&mut self) {
        let base_src = self.info[4].wrapping_add(4096);
        let mut k = self.info[0].wrapping_add(!self.decrypt_size);
        let words = self.decrypt_size >> 2;
        for i in 0..words {
            let off = i.wrapping_mul(4);
            let cell = get_u32(self.file_data, base_src.wrapping_add(off));
            write_u32(
                &mut self.decompressed,
                self.info[3].wrapping_add(off),
                k ^ cell,
            );
            k = i.wrapping_mul(i) ^ (k.wrapping_add(cell).wrapping_add(i));
        }
    }

    // Strategy (a): delegate to primitives::decrypt_data3
    fn decrypt_data3(&mut self, pos: u32, key: u32, shift: u32) {
        primitives::decrypt_data3(&mut self.decompressed, pos, key, shift);
    }

    // Strategy (b): decrypt_data4 is specific to EXE key-offset layout;
    // left on Unpacker. DLL port will need its own variant.
    fn decrypt_data4(&mut self, pos: u32) {
        let base_addr = get_u32(&self.decompressed, pos);
        let length = get_u32(&self.decompressed, pos.wrapping_add(4));
        let mut b: u8 = (((base_addr >> 8).wrapping_add(base_addr)) & 0xFF) as u8;
        let mut b2: u8 = b.wrapping_add(1);
        for i in 0..length {
            let idx = (base_addr + i) as usize;
            let b3 = self.decompressed[idx];
            let b4 = b3.rotate_left(3) ^ b2;
            let b5 = b4.rotate_left(3) ^ b;
            self.decompressed[idx] = b5.rotate_left(3);
            b = b.wrapping_add(1);
            b2 = b2.wrapping_add(1);
        }
    }

    // Strategy (b): decrypt_data5 is frequently called with the EXE's virtual
    // address convention; kept on Unpacker to avoid signature changes at call
    // sites. DLL port can call primitives directly with explicit slice.
    fn decrypt_data5(&mut self, va: u32, size: u32) {
        let mut b: u8 = va as u8;
        let mut b2: u8 = b.wrapping_add(1);
        for i in 0..size {
            let idx = (va + i) as usize;
            let b3 = self.decompressed[idx];
            let b4 = b3.rotate_left(2) ^ b2;
            let b5 = b4.rotate_left(2) ^ b;
            self.decompressed[idx] = b5.rotate_left(2);
            b = b.wrapping_add(1);
            b2 = b2.wrapping_add(1);
        }
    }

    // Strategy (a): delegate to primitives::decrypt_data6
    fn decrypt_data6(&mut self, pos: u32) {
        primitives::decrypt_data6(&mut self.decompressed, pos);
    }

    // Strategy (a): delegate to primitives::decrypt_data7
    fn decrypt_data7(&mut self, pos: u32, key: u8) {
        primitives::decrypt_data7(&mut self.decompressed, pos, key);
    }

    // Strategy (b): decrypt_data8 is specific to the EXE's .text page-level
    // XOR pass; left on Unpacker. DLL port won't need this.
    fn decrypt_data8(&mut self, va: u32, size: u32, mut key: u32) {
        let blocks = size >> 4;
        for i in 0..blocks {
            let mixed = key.rotate_right(15).wrapping_add(i);
            key = mixed.wrapping_add(i);
            // The packer's dd8 loop does not XOR block i=0; its key state still
            // advances. For shift-0 builds the i=0 XOR value is always 0 (a
            // no-op), so this is byte-identical for the older EXE-64 family;
            // for shift-15 builds it is the difference between a clean
            // .text and one corrupt byte per page.
            if i == 0 {
                continue;
            }
            let target = va
                .wrapping_add(i.wrapping_mul(16))
                .wrapping_add(mixed & 0xF);
            self.decompressed[target as usize] ^= key as u8;
        }
    }

    // Strategy (a): delegate to primitives::decrypt_and_decompress_data
    fn decrypt_and_decompress_data(&mut self, pos: u32, key: u32, custom: Option<&[Op]>) -> bool {
        primitives::decrypt_and_decompress_data(
            &mut self.decompressed,
            pos,
            key,
            self.key_offsets[1],
            self.key_offsets[3],
            custom,
        )
    }

    /// New-layout (marker-less) import reconstruction from the PE Import Directory.
    /// Walks each IMAGE_IMPORT_DESCRIPTOR at `import_rva`, decrypt_data7-decrypts
    /// and lowercases the DLL name, then walks the (OFT|IFT) thunk array
    /// decrypting each by-name import's hint/name string, and recovers the IAT
    /// directory (DD[12]) bounds.
    fn process_imports_idt(&mut self, import_rva: u32, mut import_size: u32, pe_off2: u32) {
        let len = self.decompressed.len() as u32;
        let mut dll_count: u32 = 0;
        let mut iat_min: u32 = 0xFFFF_FFFF;
        let mut iat_max: u32 = 0;
        let mut pos = import_rva;
        let find_nul = |d: &[u8], from: u32, to: u32| -> u32 {
            let hi = (to as usize).min(d.len());
            let mut i = from as usize;
            while i < hi {
                if d[i] == 0 {
                    return i as u32;
                }
                i += 1;
            }
            hi as u32
        };
        let all_ascii = |d: &[u8], a: u32, b: u32| -> bool {
            d[a as usize..b as usize]
                .iter()
                .all(|&c| (0x20..0x7F).contains(&c))
        };
        while pos + 20 <= len {
            let name_rva = get_u32(&self.decompressed, pos + 12);
            if name_rva == 0 || name_rva >= len {
                break;
            }
            // Decrypt the DLL name unless it already reads as a plain ASCII
            // *.dll / *.exe string.
            let end = find_nul(&self.decompressed, name_rva, name_rva + 64);
            let mut already_plain = false;
            if end > name_rva
                && end - name_rva <= 60
                && all_ascii(&self.decompressed, name_rva, end)
            {
                let s = &self.decompressed[name_rva as usize..end as usize];
                let lower: Vec<u8> = s.iter().map(|c| c.to_ascii_lowercase()).collect();
                if lower.ends_with(b".dll") || lower.ends_with(b".exe") {
                    already_plain = true;
                }
            }
            if !already_plain {
                self.decrypt_data7(name_rva, name_rva as u8);
            }
            // Normalize to lowercase.
            let end = find_nul(&self.decompressed, name_rva, name_rva + 64);
            if end > name_rva && all_ascii(&self.decompressed, name_rva, end) {
                for b in &mut self.decompressed[name_rva as usize..end as usize] {
                    b.make_ascii_lowercase();
                }
            }

            let oft = get_u32(&self.decompressed, pos);
            let ift = get_u32(&self.decompressed, pos + 16);
            let mut thunk = if oft != 0 { oft } else { ift };
            if 0 < ift && ift < len {
                iat_min = iat_min.min(ift);
            }
            while thunk != 0 && thunk + 8 <= len {
                let v = get_u64(&self.decompressed, thunk);
                if v == 0 {
                    break;
                }
                if (v & 0x8000_0000_0000_0000) == 0 {
                    let r = (v & 0xFFFF_FFFF) as u32;
                    if r + 2 < len {
                        let fend = find_nul(&self.decompressed, r + 2, r + 2 + 256);
                        let already = fend > r + 2
                            && fend - (r + 2) <= 250
                            && all_ascii(&self.decompressed, r + 2, fend);
                        if !already {
                            self.decrypt_data7(r + 2, r as u8);
                            write_u16(&mut self.decompressed, r, 0);
                        }
                    }
                }
                thunk += 8;
            }
            if 0 < ift && ift < len {
                let mut tp = ift;
                while tp + 8 <= len {
                    let v2 = get_u64(&self.decompressed, tp);
                    tp += 8;
                    if v2 == 0 {
                        break;
                    }
                }
                iat_max = iat_max.max(tp);
            }
            dll_count += 1;
            pos += 20;
        }
        if import_size == 0 {
            import_size = (dll_count + 1) * 20;
            write_u32(
                &mut self.decompressed,
                pe_off2.wrapping_add(0x94),
                import_size,
            );
        }
        if iat_min < iat_max {
            write_u32(&mut self.decompressed, pe_off2.wrapping_add(0xE8), iat_min);
            write_u32(
                &mut self.decompressed,
                pe_off2.wrapping_add(0xEC),
                iat_max - iat_min,
            );
        }
    }

    fn run(file_data: &'a [u8], verbose: bool) -> Result<Vec<u8>, UnpackError> {
        let mut u = Unpacker {
            file_data,
            decompressed: Vec::new(),
            info: [0u32; 8],
            key_offsets: [0u32; 4],
            decrypt_size: 0,
        };

        u.decrypt_data();
        if verbose {
            println!("[1/9] Decrypting file header...");
            println!("  info[0] key        = 0x{:08X}", u.info[0]);
            println!("  info[1] signature  = 0x{:08X}", u.info[1]);
            println!("  info[2]            = 0x{:08X}", u.info[2]);
            println!("  info[3] base       = 0x{:08X}", u.info[3]);
            println!("  info[4] src_off    = 0x{:08X}", u.info[4]);
            println!("  info[5] total_size = 0x{:08X}", u.info[5]);
            println!("  info[6] end_mark   = 0x{:08X}", u.info[6]);
            println!("  info[7]            = 0x{:08X}", u.info[7]);
        }
        if !super::is_supported_magic(u.info[1]) {
            return Err(UnpackError::HeaderMismatch);
        }

        let pe_off = get_u32(u.file_data, 60);
        let size_of_image = get_u32(u.file_data, pe_off.wrapping_add(80));
        if size_of_image == 0 || size_of_image as u64 > super::MAX_IMAGE_SIZE {
            return Err(UnpackError::Corrupt);
        }
        u.decompressed = vec![0u8; size_of_image as usize];
        u.decrypt_size = u.info[6].wrapping_sub(u.info[3]).wrapping_add(8192);
        if verbose {
            println!("[2/9] Decrypting payload...");
        }
        u.decrypt_data2();

        {
            let src_start = u.info[4].wrapping_add(4096).wrapping_add(u.decrypt_size) as usize;
            let dst_start = u.info[3].wrapping_add(u.decrypt_size) as usize;
            let len = u.info[5].wrapping_sub(u.decrypt_size) as usize;
            u.decompressed[dst_start..dst_start + len]
                .copy_from_slice(&u.file_data[src_start..src_start + len]);
        }
        write_u32(&mut u.decompressed, u.info[3], 4096);
        u.decompressed[..4096].copy_from_slice(&u.file_data[..4096]);

        // PE32 (32-bit) images use an entirely different config layout and
        // final-output transform than PE32+ (64-bit). Dispatch here, after the
        // shared header/payload setup (the PE32 branch follows the common
        // Stage 1/2 work). pe_magic at pe_off+24: 0x10B = PE32, 0x20B = PE32+.
        if get_u16(u.file_data, pe_off.wrapping_add(24)) == 0x10B {
            return u.run_pe32(pe_off, verbose);
        }

        // The config block layout in the decrypted region varies between Crackproof
        // versions. Find the anchor field — a dword equal to info[3], immediately
        // followed by 0x28 and then info[6]-0x200 — and derive every other field
        // offset relative to it. Observed anchor positions: +6728 (older EXE
        // builds), +6744 (another old-layout build, +16), +5592 (managed-assembly
        // builds, -1136).
        let info6 = u.info[6];
        let mut anchor: Option<u32> = None;
        let mut probe = info6.wrapping_add(1000);
        let probe_end = info6.wrapping_add(8000);
        while probe + 12 <= probe_end && (probe as usize + 12) <= u.decompressed.len() {
            if get_u32(&u.decompressed, probe) == u.info[3] {
                let v8 = get_u32(&u.decompressed, probe.wrapping_add(8));
                // v8 must be slightly less than info[6], aligned to 0x200, and
                // close to it. Older EXE builds stay within 0x800; the
                // external-companion DLLs reach 0xC00, so the window is 0x1000.
                // The dword==info[3] equality is already a 32-bit match on the
                // base RVA, making this secondary bound's exact value
                // non-critical for false-positive rejection.
                if v8 < info6 {
                    let delta = info6.wrapping_sub(v8);
                    if delta <= 0x1000 && delta.is_multiple_of(0x200) {
                        anchor = Some(probe);
                        break;
                    }
                }
            }
            probe = probe.wrapping_add(4);
        }
        let anchor = match anchor {
            Some(a) => a,
            None => {
                return Err(UnpackError::AnchorNotFound);
            }
        };

        // Detect config-block layout version. Newer Crackproof builds (observed
        // across several EXE families) shift every anchor-relative field from
        // offset 40 onward by +8 bytes. The config-version stamp sits at
        // anchor+104 in the old layout and anchor+112 in the new one. Across
        // the whole corpus the stamp's top nibble is always 0x4 (top byte 0x40
        // or 0x44), whereas the +8 layout's anchor+104 holds an inserted small
        // count (top nibble 0), so the stamp position is a reliable layout
        // discriminator.
        let stamp_at = |off: u32| -> bool {
            (anchor + off + 4) as usize <= u.decompressed.len()
                && (get_u32(&u.decompressed, anchor + off) >> 28) == 0x4
        };
        let magic_off: u32 = if stamp_at(104) {
            104
        } else if stamp_at(112) {
            112
        } else {
            104
        };
        let anchor_extra: u32 = magic_off - 104;

        let p1 = get_u32(&u.decompressed, anchor.wrapping_add(8));
        let p2 = get_u32(&u.decompressed, anchor.wrapping_add(4));
        let p3 = get_u32(&u.decompressed, anchor.wrapping_add(40 + anchor_extra));
        let p4 = get_u32(&u.decompressed, anchor.wrapping_add(44 + anchor_extra));
        // Save the anchor-stage import dir (`saved_import_rva` / `saved_import_size`).
        // On the new layout the metadata data-dirs may carry a zero import entry
        // (esp. managed DLLs); this anchor value is the fallback.
        let saved_import_rva = p1;
        let saved_import_size = p2;
        write_u32(&mut u.decompressed, pe_off.wrapping_add(144), p1);
        write_u32(&mut u.decompressed, pe_off.wrapping_add(148), p2);
        write_u32(&mut u.decompressed, pe_off.wrapping_add(152), p3);
        write_u32(&mut u.decompressed, pe_off.wrapping_add(156), p4);
        write_u32(&mut u.decompressed, pe_off.wrapping_add(176), 0);
        write_u32(&mut u.decompressed, pe_off.wrapping_add(180), 0);

        let mut walk = anchor.wrapping_add(184 + anchor_extra);
        let mut xor_acc: u32 = 0;
        while get_u32(&u.decompressed, walk.wrapping_add(4)) != 0 {
            xor_acc ^= u.calculate_checksum(walk);
            walk = walk.wrapping_add(8);
        }
        let chk1 = u.calculate_checksum(anchor.wrapping_add(56 + anchor_extra));
        let v_at = anchor.wrapping_add(20);
        let v = get_u32(&u.decompressed, v_at);
        let tgt = anchor.wrapping_add(120 + anchor_extra);
        u.decrypt_data3(tgt, xor_acc ^ chk1 ^ v, 21);
        let stage1 = get_u32(&u.decompressed, tgt);
        if verbose {
            println!("[3/9] Locating config layout...");
            println!("  stage1 = 0x{:08X}", stage1);
        }

        // Field offsets inside stage1 vary between Crackproof versions. Locate
        // stage2 (the only 16-byte entry where dword[0]==dword[2], dword[1] is the
        // large encrypted size and dword[3] is a smaller decompressed size), then
        // derive every other field as fixed offsets from there. Observed
        // stage2_off: 3632 (older EXE builds), 3616 (another old-layout build),
        // 3624 (managed-assembly builds).
        let stage1_len = get_u32(&u.decompressed, tgt.wrapping_add(4));
        let info3 = u.info[3];
        let info5 = u.info[5];
        // Use the full info[3]..info[3]+info[5] range: stage entries may live in
        // either the decrypt_data2 zone or the raw-copy zone (managed-assembly
        // builds' stage3 sits just before the raw-copy boundary).
        let raw_lo = info3;
        let raw_hi = info3.wrapping_add(info5);
        let mut stage2_off: Option<u32> = None;
        let scan_lo: u32 = 3000;
        let scan_hi: u32 = stage1_len.saturating_sub(16);
        let mut off = scan_lo;
        while off < scan_hi {
            let p = stage1.wrapping_add(off);
            if (p as usize + 16) <= u.decompressed.len() {
                let d0 = get_u32(&u.decompressed, p);
                let d1 = get_u32(&u.decompressed, p.wrapping_add(4));
                let d2 = get_u32(&u.decompressed, p.wrapping_add(8));
                let d3 = get_u32(&u.decompressed, p.wrapping_add(12));
                if d0 == d2 && d0 >= raw_lo && d0 < raw_hi && d1 > 0x10000 && d3 > 0 && d3 < d1 {
                    stage2_off = Some(off);
                    break;
                }
            }
            off = off.wrapping_add(4);
        }
        let stage2_off = match stage2_off {
            Some(x) => x,
            None => {
                return Err(UnpackError::Stage2NotFound);
            }
        };

        // Find chk_src_start by walking back from stage2 looking for the first
        // position where 4 consecutive (src, len) entries all sit in the raw-copy
        // range with sensible lengths. The table holds chks for stage5/4/3b/3 in
        // that order; stage1+3472/3480/3488 correspond to chk_src_start + 8 / +16
        // / +24.
        let mut chk_src_start: Option<u32> = None;
        let mut probe = stage2_off.wrapping_sub(200);
        while probe + 32 <= stage2_off {
            let mut all_valid = true;
            for i in 0..4u32 {
                let pp = stage1.wrapping_add(probe + i * 8);
                let s = get_u32(&u.decompressed, pp);
                let l = get_u32(&u.decompressed, pp.wrapping_add(4));
                if s < raw_lo || s >= raw_hi || l == 0 || l >= 0x10000 {
                    all_valid = false;
                    break;
                }
            }
            if all_valid {
                chk_src_start = Some(probe);
                break;
            }
            probe = probe.wrapping_add(4);
        }
        let chk_src_start = match chk_src_start {
            Some(x) => x,
            None => {
                return Err(UnpackError::ChkSrcStartNotFound);
            }
        };

        let key_at = stage1.wrapping_add(chk_src_start.wrapping_sub(20));
        let key2 = get_u32(&u.decompressed, key_at);
        let stage1b = stage1.wrapping_add(stage2_off);
        u.decrypt_data3(stage1b, key2, 19);
        let stage2 = get_u32(&u.decompressed, stage1b);
        if verbose {
            println!("[4/9] Decrypting stage2...");
            println!("  stage2 = 0x{:08X}", stage2);
        }

        // The stage2 head/walk2 tables shift between Crackproof versions. The 4-entry
        // table starts with a `kind=1, 0, info[3], 0` 16-byte entry; head is two
        // entries (32 bytes) past that, walk2 sits 88 bytes before head. Observed
        // table_start: 9136 (older EXE builds) and 9216 (another old-layout build
        // / managed-assembly builds).
        let mut table_start: Option<u32> = None;
        let mut sc = 8000u32;
        while sc + 16 < 12000 {
            let p = stage2.wrapping_add(sc);
            if (p as usize + 16) <= u.decompressed.len() {
                let d0 = get_u32(&u.decompressed, p);
                let d1 = get_u32(&u.decompressed, p.wrapping_add(4));
                let d2 = get_u32(&u.decompressed, p.wrapping_add(8));
                let d3 = get_u32(&u.decompressed, p.wrapping_add(12));
                if d0 == 1 && d1 == 0 && d2 == info3 && d3 == 0 {
                    table_start = Some(sc);
                    break;
                }
            }
            sc = sc.wrapping_add(4);
        }
        let table_start = match table_start {
            Some(x) => x,
            None => {
                return Err(UnpackError::TableStartNotFound);
            }
        };
        let head_off = table_start.wrapping_add(32);
        let walk2_off = head_off.wrapping_sub(88);

        let mut head = stage2.wrapping_add(head_off);
        for _iter in 0..2 {
            let kind = get_u32(&u.decompressed, head);
            // Some builds use kind=0x11 in place of kind=1 for the same operation
            // (the upper nibble appears to be a build-version stamp).
            if kind & 0x0F == 1 {
                u.decrypt_data4(head.wrapping_add(4));
            } else if kind == 2 {
                let mut p = get_u32(&u.decompressed, head.wrapping_add(4));
                loop {
                    u.decrypt_data5(p, 16);
                    let p0 = p;
                    let s = get_u32(&u.decompressed, p0);
                    let n = get_u32(&u.decompressed, p0.wrapping_add(4));
                    let dst = get_u32(&u.decompressed, p0.wrapping_add(8));
                    let chk = get_u32(&u.decompressed, p0.wrapping_add(12));
                    p = p.wrapping_add(16);
                    if s != 0 && n != 0 && dst != 0 && chk == n {
                        let ss = s as usize;
                        let dd = dst as usize;
                        let nn = n as usize;
                        u.decompressed.copy_within(ss..ss + nn, dd);
                    }
                    if get_u32(&u.decompressed, p.wrapping_sub(16).wrapping_add(4)) == 0 {
                        break;
                    }
                }
            }
            head = head.wrapping_add(16);
        }

        let mut walk2 = stage2.wrapping_add(walk2_off);
        for j in 0..2usize {
            let mut p = walk2;
            for k in 0..2usize {
                u.decrypt_data4(p);
                u.key_offsets[j * 2 + k] = get_u32(&u.decompressed, p);
                p = p.wrapping_add(8);
            }
            walk2 = walk2.wrapping_add(32);
        }

        let chk2 = u.calculate_checksum(anchor.wrapping_add(48 + anchor_extra));
        let accum_at = stage1.wrapping_add(chk_src_start.wrapping_sub(16));
        let mut accum = get_u32(&u.decompressed, accum_at);
        for l in 0..4u32 {
            let bound = (l + 1).wrapping_mul(25) << 2;
            let mut i: u32 = 1;
            while i <= bound {
                accum = accum.wrapping_add(i);
                i = i.wrapping_add(1);
            }
        }

        let at1 = stage1.wrapping_add(stage2_off.wrapping_add(88));
        let stage3_field = get_u32(&u.decompressed, at1);
        let stage3_dlen = get_u32(&u.decompressed, at1.wrapping_add(12));
        if verbose {
            println!("[5/9] Decrypting stages 3-5...");
            println!("  stage3  = 0x{:08X}", stage3_field);
        }
        if !u.decrypt_and_decompress_data(at1, xor_acc ^ chk2 ^ accum, None) {
            return Err(UnpackError::DecompressFailed);
        }

        let at2 = stage1.wrapping_add(stage2_off.wrapping_add(104));
        let stage3b_field = get_u32(&u.decompressed, at2);
        let stage3b_dlen = get_u32(&u.decompressed, at2.wrapping_add(12));
        if verbose {
            println!("  stage3b = 0x{:08X}", stage3b_field);
        }
        let chk3 = u.calculate_checksum(stage1.wrapping_add(chk_src_start.wrapping_add(24)));
        // v4_val lives at the end of stage3, immediately following `C3 CC CC CC`
        // (function epilogue + 3-byte int3 padding), with zeros to end of buffer.
        // Scan stage3 from the end for the last non-zero dword anchored by the
        // C3+CC pattern.
        let v4 = find_v4_offset(&u.decompressed, stage3_field, stage3_dlen)
            .unwrap_or_else(|| stage3_field.wrapping_add(4692));
        let v4_val = get_u32(&u.decompressed, v4);
        if !u.decrypt_and_decompress_data(at2, xor_acc ^ chk3 ^ v4_val, None) {
            return Err(UnpackError::DecompressFailed);
        }

        let chk4 = u.calculate_checksum(stage1.wrapping_add(chk_src_start.wrapping_add(16)));
        // v5_val sits 8 bytes before the first API name string in stage3b's
        // hash/slot/name table. The table starts with hash(VirtualFree) +
        // slot(8 bytes total before the "Virtual..." ASCII). The hardcoded
        // offset 1960 corresponds to (string_pos - 8) for older EXE builds.
        let v5 = find_str_pos(&u.decompressed, stage3b_field, stage3b_dlen, b"Virtual")
            .map(|p| p.wrapping_sub(8))
            .unwrap_or_else(|| stage3b_field.wrapping_add(1960));
        let v5_val = !get_u32(&u.decompressed, v5);
        let at3 = stage1.wrapping_add(stage2_off.wrapping_add(136));
        let stage4_field = get_u32(&u.decompressed, at3);
        let stage4_dlen = get_u32(&u.decompressed, at3.wrapping_add(12));
        if verbose {
            println!("  stage4  = 0x{:08X}", stage4_field);
        }
        if !u.decrypt_and_decompress_data(at3, xor_acc ^ chk4 ^ v5_val, None) {
            return Err(UnpackError::DecompressFailed);
        }

        // Inside stage4, two locations vary by build:
        //   accum2 source (offset 3504) sits 24 bytes before "IsDebuggerPresent"
        //   bytecode block  (offset 3584) sits at the first 16-byte aligned
        //     boundary at or after the end of "CheckRemoteDebuggerPresent\0".
        let idb_pos = find_str_pos(
            &u.decompressed,
            stage4_field,
            stage4_dlen,
            b"IsDebuggerPresent",
        )
        .unwrap_or_else(|| stage4_field.wrapping_add(3528));
        let crdp_pos = find_str_pos(
            &u.decompressed,
            stage4_field,
            stage4_dlen,
            b"CheckRemoteDebuggerPresent",
        )
        .unwrap_or_else(|| stage4_field.wrapping_add(3553));
        // Trial-decrypt every 16-byte aligned position to find the bytecode block.
        // Works whether or not the build has IsDebuggerPresent/CRDP API strings.
        let data_offset = find_bytecode_offset(&u.decompressed, stage4_field, stage4_dlen)
            .or_else(|| {
                find_bytecode_offset(&u.decompressed, stage4_field, stage4_dlen.saturating_mul(2))
            })
            .unwrap_or_else(|| {
                let crdp_end = crdp_pos.wrapping_add("CheckRemoteDebuggerPresent\0".len() as u32);
                (crdp_end.wrapping_add(15)) & !15u32
            });
        u.decrypt_data6(data_offset);
        let chk5 = u.calculate_checksum(stage1.wrapping_add(chk_src_start.wrapping_add(8)));
        // accum2 sits 4 bytes past the function-end `48 EB 01 B9` + any CC padding
        // (i.e., the 4 bytes immediately after the last instance of that pattern).
        let v6 = find_v_after_pad(&u.decompressed, stage4_field, stage4_dlen)
            .unwrap_or_else(|| idb_pos.wrapping_sub(24));
        let mut accum2 = get_u32(&u.decompressed, v6);
        for m in 0..3u32 {
            let bound = (m + 1).wrapping_mul(25) << 2;
            let mut i: u32 = 1;
            while i <= bound {
                accum2 = accum2.wrapping_add(i);
                i = i.wrapping_add(1);
            }
        }

        let ops1 = match generate(&u.decompressed, data_offset) {
            Some(v) => v,
            None => {
                return Err(UnpackError::BytecodeGenFailed);
            }
        };

        let at4 = stage1.wrapping_add(stage2_off.wrapping_add(216));
        let stage5_field = get_u32(&u.decompressed, at4);
        // at4 is a (src, src_len, dest, dest_len) quad; only src and dest_len
        // are needed here, the other two are consumed by the decrypt below.
        let stage5_dlen = get_u32(&u.decompressed, at4.wrapping_add(12));
        if verbose {
            println!("  stage5  = 0x{:08X}", stage5_field);
        }
        if !u.decrypt_and_decompress_data(at4, xor_acc ^ chk4 ^ chk5 ^ accum2, Some(&ops1)) {
            return Err(UnpackError::DecompressFailed);
        }

        // Inside stage5, the loader stores a table of (ptr, size) pairs at a
        // fixed offset from the `70 6D 00 00 63 6D 00 00` marker. The first two
        // pairs are walk4 (raw data load) and walk3 (chk2 chain). Then a variable
        // number of additional entries, followed by a `0x40000000, 0x1` kind
        // marker, then walk5 (string-table pointer). The secondary custom
        // decryptor bytecode sits at marker+960.
        let s5_marker_opt = find_str_pos(
            &u.decompressed,
            stage5_field,
            stage5_dlen,
            &[0x70, 0x6D, 0x00, 0x00, 0x63, 0x6D, 0x00, 0x00],
        );
        // Older builds embed the `pm\0\0cm\0\0` marker right before the stage5
        // (ptr,size) table, so it's a tight search base. Newer builds
        // (marker-less native/managed DLLs) omit the marker entirely — the slots
        // are discovered by scanning the whole eighthStage instead. When the
        // marker is absent, fall back to the start of the stage5 region as the
        // search base; the downstream kind-marker + bytecode scans (which derive
        // the real walk3/walk4/walk5 slots) then run over the full region.
        let s5_marker = s5_marker_opt.unwrap_or(stage5_field);
        // The (ptr, size) entry table after the marker ends with a fixed tail:
        //   walk4 (raw data load)      = kind_pos - 0x20
        //   walk3 (checksum chain)     = kind_pos - 0x18
        //   <large raw-section entry>  = kind_pos - 0x10
        //   <0x40000000, 0x1 kind>     = kind_pos       (walk5 = kind_pos + 8)
        // The kind-marker is the only stable anchor: older builds place it at
        // marker+0x58, newer ones at marker+0x60, and walk3's entry size differs
        // (0x50 vs 0x30). Deriving walk3/walk4 relative to the kind-marker
        // handles every observed variant.
        let kind_pos_opt = find_str_pos(
            &u.decompressed,
            s5_marker,
            stage5_dlen.saturating_sub(s5_marker.wrapping_sub(stage5_field)),
            &[0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00],
        );
        // Layout discriminator. Older builds (the 7 EXE + 2 DLL goldens) embed
        // the `00 00 00 40 01 00 00 00` kind-marker, from which walk3/walk4/walk5
        // are derived at fixed offsets. Newer builds (marker-less native +
        // managed DLLs) omit BOTH the `pm\0\0cm\0\0` and kind markers; their
        // eighthStage slots are discovered structurally (LFSR scan +
        // trial-decrypt), and imports are rebuilt from the PE Import Directory
        // rather than the walk5 encrypted-pointer table. `new_layout` selects
        // that path.
        let new_layout = kind_pos_opt.is_none();
        let kind_pos = kind_pos_opt.unwrap_or_else(|| s5_marker.wrapping_add(88));
        let walk4_slot = kind_pos.wrapping_sub(0x20);
        let walk3_slot = kind_pos.wrapping_sub(0x18);
        let walk5_slot = kind_pos.wrapping_add(8);
        // Stage5 bytecode block. Anchor by trial-decryption + parse; fall back to
        // marker+960 (older EXE build layout).
        let bc2_search_base = s5_marker;
        let bc2_search_len = stage5_dlen.saturating_sub(s5_marker.wrapping_sub(stage5_field));
        let mut bc2_off = find_bytecode_offset(&u.decompressed, bc2_search_base, bc2_search_len)
            .or_else(|| {
                find_bytecode_offset(
                    &u.decompressed,
                    bc2_search_base,
                    bc2_search_len.saturating_mul(2),
                )
            })
            .unwrap_or_else(|| s5_marker.wrapping_add(960));
        // walk4 is the section-load (compressedInfo) descriptor table; in the
        // old layout it sits at a fixed offset from the kind-marker.
        let mut walk4_slot = walk4_slot;
        // New-layout discovery: the kind-marker is absent, so derive the
        // compressedInfo table pointer (walk4) and file-decryptor LFSR (bc2)
        // structurally. fileCS stays at bc2_off-0x58 as in the old layout.
        if new_layout {
            let compress_data_offset = (!get_u32(u.file_data, 0x1080)).wrapping_add(0x1000);
            let slots = primitives::discover_eighth_slots(
                &u.decompressed,
                stage5_field,
                stage5_dlen,
                u.info[3],
                compress_data_offset,
                u.file_data.len() as u32,
            )
            .ok_or(UnpackError::Stage5MarkerNotFound)?;
            walk4_slot = slots.compressed_info_ptr;
            bc2_off = slots.file_lfsr;
        }
        let at5 = walk3_slot;
        let mut walk3 = get_u32(&u.decompressed, at5);
        // walk3 is a checksum-validation walk: its chain_crc is computed and
        // discarded. Each 16-byte entry is decrypted only transiently (to feed
        // the checksum); the on-disk bytes stay encrypted. Back up each block
        // before decrypting and restore after, so the output matches the golden
        // (which keeps this chain encrypted). The new layout has no walk3 chain
        // (the kind-marker that anchors it is absent), so this whole transient
        // checksum walk is skipped there.
        let mut walk3_backups: Vec<(usize, [u8; 16])> = Vec::new();
        let snap16 = |buf: &[u8], addr: u32| -> [u8; 16] {
            let s = addr as usize;
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[s..s + 16]);
            b
        };
        if !new_layout {
            walk3_backups.push((walk3 as usize, snap16(&u.decompressed, walk3)));
            u.decrypt_data5(walk3, 16);
            walk3 = walk3.wrapping_add(16);
            let mut chain_crc: u32 = 0;
            loop {
                walk3_backups.push((walk3 as usize, snap16(&u.decompressed, walk3)));
                u.decrypt_data5(walk3, 16);
                let p = walk3;
                let n = get_u32(&u.decompressed, p.wrapping_add(4));
                walk3 = walk3.wrapping_add(16);
                if n != 0 {
                    chain_crc = u.calculate_checksum2(walk3.wrapping_sub(16), chain_crc);
                }
                if get_u32(&u.decompressed, walk3.wrapping_sub(16).wrapping_add(4)) == 0 {
                    break;
                }
            }
            if verbose {
                println!("[6/9] Decrypting section data...");
                println!(
                    "  integrity  = 0x{:08X}",
                    get_u32(u.file_data, 56).wrapping_add(1985229329)
                );
                println!("  chain_crc  = 0x{:08X}", chain_crc);
            }
            for (addr, bytes) in walk3_backups {
                u.decompressed[addr..addr + 16].copy_from_slice(&bytes);
            }
        } else if verbose {
            println!("[6/9] Decrypting section data (new layout)...");
        }

        let data_offset2 = bc2_off;
        // fileCS chain: the file-checksum table is permanently decrypted in
        // place. Its pointer lives 0x58 bytes before the file LFSR/decryptor
        // block (fileDecryptorAddress = fileChecksumAddresses + 0x58). Walk
        // 16-byte entries until the size dword (offset +4) is zero, decrypting
        // each.
        {
            let mut fcs = get_u32(&u.decompressed, bc2_off.wrapping_sub(0x58));
            while get_u32(&u.decompressed, fcs.wrapping_add(4)) != 0 {
                u.decrypt_data5(fcs, 16);
                fcs = fcs.wrapping_add(16);
            }
        }
        u.decrypt_data6(data_offset2);
        let ops2 = match generate(&u.decompressed, data_offset2) {
            Some(v) => v,
            None => {
                return Err(UnpackError::Stage5BytecodeGenFailed);
            }
        };
        // The new layout picked its file decryptor by distance (no marker, no
        // content check). Prove the choice before shipping it: a wrong pick
        // would garble every section block, and raw blocks would carry that
        // garbling into the output without any error (see the validator).
        let rebase = (!get_u32(u.file_data, 4224)).wrapping_add(4096);
        if new_layout && !u.new_layout_file_ops_validate(walk4_slot, &ops2, rebase) {
            return Err(UnpackError::DecompressFailed);
        }

        let at6 = walk4_slot;
        if verbose {
            println!("[7/9] Loading and decompressing sections...");
        }
        let mut walk4 = get_u32(&u.decompressed, at6);
        // Pass 1 (sequential): the 16-byte descriptors are decrypted in a
        // position-keyed chain (`decrypt_data5`) that terminates on the next
        // record's length field, so collection cannot be parallelized.
        struct Blk {
            src: u32,
            len: u32,
            dst: u32,
            plain_len: u32,
        }
        let mut blocks: Vec<Blk> = Vec::new();
        loop {
            u.decrypt_data5(walk4, 16);
            let p = walk4;
            let src = get_u32(&u.decompressed, p);
            let len = get_u32(&u.decompressed, p.wrapping_add(4));
            let dst = get_u32(&u.decompressed, p.wrapping_add(8));
            let plain_len = get_u32(&u.decompressed, p.wrapping_add(12));
            walk4 = walk4.wrapping_add(16);
            if len != 0 {
                blocks.push(Blk {
                    src,
                    len,
                    dst,
                    plain_len,
                });
            }
            if get_u32(&u.decompressed, walk4.wrapping_sub(16).wrapping_add(4)) == 0 {
                break;
            }
        }
        // Pass 2: each block writes only its own [dst, dst+max(len,plain_len))
        // span and reads only immutable input + the (snapshotted) key tables,
        // so blocks with disjoint dst spans are independent. `parallel_for`
        // carves the spans into safe disjoint &mut slices and fans out when
        // worthwhile (see its docs for the soundness argument).
        {
            let lut = OpsLut::new(&ops2);
            let clean = &u.file_data;
            let ko = u.key_offsets;
            // Snapshot the shared tables before the fan-out: workers get
            // disjoint span slices, not the whole buffer.
            let ks_snap = primitives::aes_schedule_snapshot(&u.decompressed, ko[2])
                .ok_or(UnpackError::Corrupt)?;
            let tab_snap = primitives::huffman_table_snapshot(&u.decompressed, ko[0])
                .ok_or(UnpackError::DecompressFailed)?;
            let spans: Vec<(usize, usize)> = blocks
                .iter()
                .map(|b| {
                    let s = b.dst as usize;
                    (s, s + b.len.max(b.plain_len) as usize)
                })
                .collect();
            let do_block = |i: usize, base: usize, span: &mut [u8]| -> Result<(), UnpackError> {
                let b = &blocks[i];
                let cs = b.src.wrapping_add(rebase) as usize;
                let rel = b.dst as usize - base;
                let ll = b.len as usize;
                span[rel..rel + ll].copy_from_slice(&clean[cs..cs + ll]);
                primitives::aes_decrypt_ks(&ks_snap, span, rel as u32, b.len);
                lut.map_region(span, rel, ll);
                if b.len != b.plain_len {
                    // decompress reports corruption (after partial writes) via
                    // its bool; surface it instead of shipping a garbage block.
                    if !primitives::decompress_tbl(
                        &tab_snap,
                        span,
                        rel as u32,
                        rel as u32,
                        b.len,
                        b.plain_len,
                    ) {
                        return Err(UnpackError::DecompressFailed);
                    }
                }
                Ok(())
            };
            super::parallel::parallel_for(&mut u.decompressed, &spans, 1, do_block)?;
        }
        loop {
            u.decrypt_data5(walk4, 16);
            let p = walk4;
            let dst = get_u32(&u.decompressed, p);
            let len = get_u32(&u.decompressed, p.wrapping_add(4));
            walk4 = walk4.wrapping_add(16);
            if len != 0 {
                for k in 0..len {
                    u.decompressed[(dst + k) as usize] = 0;
                }
            }
            if get_u32(&u.decompressed, walk4.wrapping_sub(16).wrapping_add(4)) == 0 {
                break;
            }
        }

        let at7 = walk5_slot;
        if verbose {
            println!("[8/9] Decrypting import strings...");
        }
        // walk5 is the old layout's encrypted import-name pointer table. The new
        // layout has no such table — imports are rebuilt from the PE Import
        // Directory after the header is reconstructed (see `process_imports_idt`
        // below). Skip the walk5 pass entirely for the new layout.
        //
        // Managed assemblies leave the walk5 slot null as well: their imports
        // are just the CLR bootstrap stub, so there is no encrypted name table
        // to walk. Reading the table at address 0 would chase header garbage as
        // a pointer chain, so a null slot means "nothing to decrypt".
        let mut walk5 = get_u32(&u.decompressed, at7);
        if !new_layout && walk5 != 0 {
            loop {
                let outer = get_u32(&u.decompressed, walk5.wrapping_add(12));
                if outer == 0 {
                    break;
                }
                u.decrypt_data7(outer, outer as u8);
                // Normalize the DLL name to lowercase (e.g. 'UnityPlayer.dll' ->
                // 'unityplayer.dll'). Only when the name is all printable ASCII.
                {
                    let start = outer as usize;
                    let mut end = start;
                    while end < u.decompressed.len() && u.decompressed[end] != 0 {
                        end += 1;
                    }
                    if end > start
                        && u.decompressed[start..end]
                            .iter()
                            .all(|&b| (0x20..0x7F).contains(&b))
                    {
                        for b in &mut u.decompressed[start..end] {
                            b.make_ascii_lowercase();
                        }
                    }
                }
                let a = get_u32(&u.decompressed, walk5);
                let b = get_u32(&u.decompressed, walk5.wrapping_add(16));
                let mut chain = if a == 0 { b } else { a };
                loop {
                    // PE32+ thunks are 8 bytes: an ordinal import carries bit 63
                    // with the ordinal in the low word; only a by-name thunk holds
                    // a hint/name RVA (in the low dword). Reading just the low
                    // dword would mistake an ordinal for a tiny RVA and scribble
                    // over the image header.
                    let v = get_u64(&u.decompressed, chain);
                    if v == 0 {
                        break;
                    }
                    if (v & 0x8000_0000_0000_0000) == 0 {
                        let inner = v as u32;
                        u.decrypt_data7(inner.wrapping_add(2), inner as u8);
                        write_u16(&mut u.decompressed, inner, 0);
                    }
                    chain = chain.wrapping_add(8);
                }
                walk5 = walk5.wrapping_add(20);
            }
        } // end !new_layout (walk5)

        if verbose {
            println!("[9/9] Reconstructing PE headers...");
        }
        u.decompressed[..4096].copy_from_slice(&u.file_data[..4096]);
        let opt_hdr_size = get_u16(u.file_data, pe_off.wrapping_add(20));
        let sect_table = pe_off.wrapping_add(24).wrapping_add(opt_hdr_size as u32);
        let payload_va = get_u32(
            u.file_data,
            pe_off
                .wrapping_add(24)
                .wrapping_add(opt_hdr_size as u32)
                .wrapping_sub(128),
        );
        let payload_size = get_u32(
            u.file_data,
            pe_off
                .wrapping_add(24)
                .wrapping_add(opt_hdr_size as u32)
                .wrapping_sub(124),
        );
        // Walk the section table by NumberOfSections, not "until a zero
        // VirtualSize": PE has no sentinel entry, so a section whose
        // VirtualSize is legitimately 0 (or a corrupt early field) would
        // silently truncate the fixups — .text, and the export payload below,
        // would then be missed entirely. The all-zero-name break guards the
        // other direction (a corrupt, overstated NumberOfSections): real
        // sections always have a name, header padding is all zero.
        let num_sections = get_u16(u.file_data, pe_off.wrapping_add(6)) as u32;
        let mut text_va: u32 = 0;
        let mut text_size: u32 = 0;
        let mut payload_off: u32 = 0;
        for i in 0..num_sections.min(96) {
            let sect = sect_table.wrapping_add(i.wrapping_mul(40));
            if u.file_data[sect as usize..sect as usize + 8]
                .iter()
                .all(|&b| b == 0)
            {
                break;
            }
            let sec_va = get_u32(u.file_data, sect.wrapping_add(12));
            let sec_size = get_u32(u.file_data, sect.wrapping_add(8));
            let sec_raw = get_u32(u.file_data, sect.wrapping_add(20));
            if section_name(u.file_data, sect) == ".text" {
                text_size = sec_size;
                text_va = sec_va;
            }
            if payload_size != 0
                && payload_va >= sec_va
                && payload_va.wrapping_add(payload_size) <= sec_va.wrapping_add(sec_size)
            {
                payload_off = payload_va.wrapping_sub(sec_va).wrapping_add(sec_raw);
            }
            write_u32(&mut u.decompressed, sect.wrapping_add(16), sec_size);
            write_u32(&mut u.decompressed, sect.wrapping_add(20), sec_va);
            // NOTE: do NOT flag .rdata writable. The Windows loader already
            // makes the IAT pages temporarily writable while snapping imports
            // (it knows the range from the IAT data directory DD[12]), so the
            // original read-only .rdata characteristics are sufficient.
            //
            // Marking .rdata MEM_WRITE actively breaks statically-linked
            // MSVC/UCRT EXEs: the CRT's float-format init (`_cfltcvt_init`,
            // which populates `_cfltcvt_tab`) is gated by a security check that
            // refuses to call an init function whose descriptor lives in a
            // *writable* section. With .rdata writable that init is skipped,
            // `_cfltcvt_tab` keeps its R6002 stubs, and the first `%f` aborts
            // with "R6002 - floating point support not loaded" (observed on some
            // statically-linked MSVC/UCRT EXEs).
        }
        // Guard `payload_off != 0` like the PE32 path does: if no section
        // contained the export range, offset 0 would copy the DOS stub over
        // the image's export directory.
        if payload_size != 0 && payload_off != 0 {
            let s = payload_off as usize;
            let d = payload_va as usize;
            let n = payload_size as usize;
            u.decompressed[d..d + n].copy_from_slice(&u.file_data[s..s + n]);
        }
        // EP/data-directory layout. For the new layout (marker-less), the
        // metadata block (EP@info[3]+0x20, dirs@info[3]+0x30, "Layout B") is read
        // BEFORE running the .text dd8 pass, then the encrypted bytes are
        // restored so dd8 operates on them like the golden. Because info[3]
        // sits inside .text on these builds, reading after dd8 (as the old
        // layout does) would see dd8-corrupted metadata. So capture EP + 128
        // dir bytes here, pre-dd8.
        let new_ep_dirs: Option<(u32, [u8; 128])> = if new_layout {
            let ms = u.info[3].wrapping_add(32) as usize;
            let backup: Vec<u8> = u.decompressed[ms..ms + 144].to_vec();
            u.decrypt_data5(u.info[3].wrapping_add(32), 144);
            let ep = get_u32(&u.decompressed, u.info[3].wrapping_add(32));
            let mut dirs = [0u8; 128];
            dirs.copy_from_slice(
                &u.decompressed[(u.info[3] + 48) as usize..(u.info[3] + 48 + 128) as usize],
            );
            u.decompressed[ms..ms + 144].copy_from_slice(&backup);
            Some((ep, dirs))
        } else {
            None
        };
        // Old layout runs dd8 here (its metadata/.text regions don't overlap the
        // not-yet-restored COR20/BSJB metadata). The new layout defers dd8 until
        // AFTER the CLR metadata restore + section fixup (dd8 is the final .text
        // step), because on managed DLLs the restored BSJB stream lives inside
        // .text and must itself be dd8-processed to match the golden — and the
        // shift is re-selected there over the restored bytes, so selecting it
        // here would be wasted work on stale content.
        if !new_layout {
            // The packer keys the dd8 page-XOR with `page_idx << shift`. Most
            // builds use shift 0; some newer builds use shift 15. The shift is
            // NOT recorded in any header/config field — some older and newer
            // builds carry byte-identical config-version stamps yet need
            // different shifts — so it must be derived from the .text content
            // (see `select_dd8_shift`). An explicit DD8_SHIFT env var (incl.
            // 99 = skip) overrides for analysis.
            let dd8_shift: u32 = match std::env::var("DD8_SHIFT").ok().and_then(|s| s.parse().ok())
            {
                Some(s) => s,
                None => {
                    primitives::select_dd8_shift(&u.decompressed, text_va, text_size, u.info[3])
                }
            };
            if dd8_shift != 99 {
                let mut page = text_va >> 12;
                let end_page = text_va.wrapping_add(text_size) >> 12;
                while page < end_page {
                    u.decrypt_data8(page << 12, 4096, page << dd8_shift);
                    page = page.wrapping_add(1);
                }
            }
        }
        // EP/DD layout in info[3] varies between Crackproof versions. Old
        // layout: EP at info[3]+64, ImageBase at info[3]+68, DD[0..15] at
        // info[3]+80..info[3]+208 — total 144 bytes encrypted starting at +64.
        // New layout: everything shifts 32 bytes earlier — EP at info[3]+32,
        // DD at info[3]+48, encrypted region at info[3]+32..info[3]+176. Probe
        // both candidates and pick the one whose ImageBase-low matches info[3]
        // (the dword right after EP in the PE optional header).
        let ep_off: u32 = if new_layout {
            // New-layout (marker-less) builds always use "Layout B": EP at
            // info[3]+0x20, data dirs at info[3]+0x30. The old ImageBase-low
            // probe assumes ImageBase==info[3], which does not hold for these
            // builds (esp. managed DLLs), so pin the offset directly.
            32
        } else {
            [32u32, 64]
                .iter()
                .copied()
                .find(|&off| {
                    trial_decrypt5_u32(&u.decompressed, u.info[3].wrapping_add(off + 4))
                        == u.info[3]
                })
                .unwrap_or(64)
        };
        let dd_off = ep_off.wrapping_add(16);
        // The metadata block (EP + data directories) is read transiently: decrypt
        // it, copy EP and dirs into the PE header, then RESTORE the original
        // encrypted bytes. The packer leaves this region encrypted in its output,
        // so leaving it decrypted in-place would diverge from the golden (the
        // first byte at info[3]+ep_off would carry the decrypted EP low byte).
        let pe_off2 = get_u32(&u.decompressed, 60);
        if let Some((ep, dirs)) = new_ep_dirs {
            // New layout: EP and dirs were captured pre-dd8 (Layout B). Write the
            // EP and the 128-byte data-directory block into the PE header.
            write_u32(&mut u.decompressed, pe_off2.wrapping_add(40), ep);
            u.decompressed[(pe_off2 + 136) as usize..(pe_off2 + 136) as usize + 128]
                .copy_from_slice(&dirs);
            // Import-RVA selection. Prefer the metadata import dir (dirs[1] @ +8)
            // when it points at a plausible IDT; otherwise fall back to the
            // anchor-stage value saved earlier whenever it is set at all (a
            // non-zero-but-implausible anchor value still beats a metadata dir
            // we already rejected). Managed DLLs leave the metadata import dir
            // zero, so the anchor value is used there.
            let image_size = get_u32(&u.decompressed, pe_off2.wrapping_add(80));
            let meta_imp_rva = u32::from_le_bytes([dirs[8], dirs[9], dirs[10], dirs[11]]);
            let meta_imp_size = u32::from_le_bytes([dirs[12], dirs[13], dirs[14], dirs[15]]);
            let idt_plausible = |rva: u32, sz: u32, d: &[u8]| -> bool {
                if !(0x1000 < rva && rva < image_size && 0 < sz && sz < 0x10000) {
                    return false;
                }
                ((rva + 12) as usize + 4) <= d.len() && get_u32(d, rva + 12) != 0
            };
            let (imp_rva, imp_size) = if idt_plausible(meta_imp_rva, meta_imp_size, &u.decompressed)
                || saved_import_rva == 0
            {
                (meta_imp_rva, meta_imp_size)
            } else {
                (saved_import_rva, saved_import_size)
            };
            write_u32(&mut u.decompressed, pe_off2.wrapping_add(0x90), imp_rva);
            write_u32(&mut u.decompressed, pe_off2.wrapping_add(0x94), imp_size);
        } else {
            // The metadata block (EP + data directories) is read transiently:
            // decrypt it, copy EP and dirs into the PE header, then RESTORE the
            // original encrypted bytes. The packer leaves this region encrypted
            // in its output, so leaving it decrypted in-place would diverge from
            // the golden (the first byte at info[3]+ep_off would carry the
            // decrypted EP low byte).
            let meta_start = u.info[3].wrapping_add(ep_off) as usize;
            let backup: Vec<u8> = u.decompressed[meta_start..meta_start + 144].to_vec();
            u.decrypt_data5(u.info[3].wrapping_add(ep_off), 144);
            let ep = get_u32(&u.decompressed, u.info[3].wrapping_add(ep_off));
            // Managed assemblies store 0 as the entry point here (their EP is a
            // property of the CLR header, not the PE). Keep the protected
            // header's EP in that case — overwriting with 0 would produce an
            // image whose entry point is the DOS header.
            if ep != 0 {
                write_u32(&mut u.decompressed, pe_off2.wrapping_add(40), ep);
            }
            for n in 0..128 {
                u.decompressed[(pe_off2 + 136 + n) as usize] =
                    u.decompressed[(u.info[3] + dd_off + n) as usize];
            }
            u.decompressed[meta_start..meta_start + 144].copy_from_slice(&backup);
        }

        // New-layout import reconstruction runs AFTER the deferred .text dd8
        // pass (see below): dd8 precedes the IDT name/thunk decryption. The
        // import RVA lives inside .text on these builds, so decrypting names
        // before dd8 would let dd8 re-scramble them. The actual call is placed
        // after the dd8 block.

        // New-layout managed (CLR) metadata restore happens AFTER the .text dd8
        // pass below. CrackProof preserves the COR20 header + BSJB MetaData
        // verbatim in the protected file; both live inside .text on these
        // builds. Restoring them before dd8 would let dd8 corrupt the metadata
        // (~1 byte per 16) and leave an invalid COR20 header signature. We
        // restore after dd8 so the copied-back bytes are final. `restored_clr`
        // (set in that later block) suppresses the native COR20-directory
        // clearing.
        let mut restored_clr = false;

        // Deferred .text dd8 for the new layout (dd8 is the final .text step).
        // The shift/formula is re-selected here over the now-fully-restored
        // .text so the 0xCC-padding heuristic scores the real post-restore
        // bytes. Only run dd8 when the entry point falls inside .text.
        if new_layout {
            let ep_final = get_u32(&u.decompressed, pe_off2.wrapping_add(40));
            let ep_in_text = text_size > 0
                && text_va > 0
                && text_va <= ep_final
                && ep_final < text_va + text_size;
            if ep_in_text {
                let shift = match std::env::var("DD8_SHIFT").ok().and_then(|s| s.parse().ok()) {
                    Some(s) => s,
                    None => {
                        primitives::select_dd8_shift(&u.decompressed, text_va, text_size, u.info[3])
                    }
                };
                if shift != 99 {
                    let mut page = text_va >> 12;
                    let end_page = text_va.wrapping_add(text_size) >> 12;
                    while page < end_page {
                        u.decrypt_data8(page << 12, 4096, page << shift);
                        page = page.wrapping_add(1);
                    }
                }
            }
            // IDT name/thunk decryption, after dd8. The PE Import Directory
            // points at the IDT; decrypt+lowercase each DLL name and each
            // by-name import's hint/name, and recover the IAT (DD[12]).
            let import_rva = get_u32(&u.decompressed, pe_off2.wrapping_add(0x90));
            let import_size = get_u32(&u.decompressed, pe_off2.wrapping_add(0x94));
            if import_rva != 0 {
                u.process_imports_idt(import_rva, import_size, pe_off2);
            }

            // Managed (CLR) COR20 + BSJB MetaData restore — AFTER dd8 so the
            // verbatim-copied bytes are final. CrackProof preserves these regions
            // in the protected file at their RVA-mapped offsets; they live inside
            // .text but must NOT be dd8-processed (they are not packer-encrypted
            // code, just copied through). Restoring post-dd8 overwrites whatever
            // dd8 scribbled, yielding a valid CLR header + BSJB stream.
            let clr_rva = get_u32(&u.decompressed, pe_off2.wrapping_add(0xF8));
            let clr_size = get_u32(&u.decompressed, pe_off2.wrapping_add(0xFC));
            if clr_rva != 0
                && clr_size != 0
                && (clr_rva as u64 + clr_size as u64) <= u.decompressed.len() as u64
                && let Some(cor_off) = prot_rva_to_off(u.file_data, pe_off, clr_rva)
                && (cor_off as u64 + 0x48) <= u.file_data.len() as u64
                && get_u32(u.file_data, cor_off) == 0x48
            {
                // Restore the COR20 header from the protected file (its
                // MetaData RVA/size fields are authoritative).
                let s = cor_off as usize;
                let d = clr_rva as usize;
                u.decompressed[d..d + 0x48].copy_from_slice(&u.file_data[s..s + 0x48]);
                restored_clr = true;
                // Read MetaData RVA/size from the just-restored header.
                let md_rva = get_u32(&u.decompressed, clr_rva + 0x08);
                let md_size = get_u32(&u.decompressed, clr_rva + 0x0C);
                if md_rva != 0
                    && md_size != 0
                    && (md_rva as u64 + md_size as u64) <= u.decompressed.len() as u64
                    && let Some(md_off) = prot_rva_to_off(u.file_data, pe_off, md_rva)
                    && (md_off as u64 + md_size as u64) <= u.file_data.len() as u64
                    && &u.file_data[md_off as usize..md_off as usize + 4] == b"BSJB"
                {
                    let s = md_off as usize;
                    let d = md_rva as usize;
                    let n = md_size as usize;
                    u.decompressed[d..d + n].copy_from_slice(&u.file_data[s..s + n]);
                }
            }
        }

        // Old-layout managed (CLR) restore: same verbatim regions as the
        // new-layout restore above (COR20 header + BSJB MetaData stream) plus
        // the COR20 resources blob. Crackproof preserves only these regions
        // verbatim in the protected file — the IL method bodies between the
        // COR20 header and the resources ARE packer-encrypted and arrive via
        // the section-block pass, so copying the whole section's raw data (as
        // the older-DLL pipeline does for its layout) would clobber them with
        // the placeholder zeros the protected file carries there. Runs after
        // the old-layout dd8 pass, so the restored bytes are final.
        if !new_layout {
            let clr_rva = get_u32(&u.decompressed, pe_off2.wrapping_add(0xF8));
            let clr_size = get_u32(&u.decompressed, pe_off2.wrapping_add(0xFC));
            if clr_rva != 0
                && clr_size != 0
                && (clr_rva as u64 + clr_size as u64) <= u.decompressed.len() as u64
                && let Some(cor_off) = prot_rva_to_off(u.file_data, pe_off, clr_rva)
                && (cor_off as u64 + 0x48) <= u.file_data.len() as u64
                && get_u32(u.file_data, cor_off) == 0x48
            {
                let s = cor_off as usize;
                let d = clr_rva as usize;
                u.decompressed[d..d + 0x48].copy_from_slice(&u.file_data[s..s + 0x48]);
                restored_clr = true;
                // MetaData RVA/size from the just-restored COR20 header.
                let md_rva = get_u32(&u.decompressed, clr_rva + 0x08);
                let md_size = get_u32(&u.decompressed, clr_rva + 0x0C);
                if md_rva != 0
                    && md_size != 0
                    && (md_rva as u64 + md_size as u64) <= u.decompressed.len() as u64
                    && let Some(md_off) = prot_rva_to_off(u.file_data, pe_off, md_rva)
                    && (md_off as u64 + md_size as u64) <= u.file_data.len() as u64
                    && &u.file_data[md_off as usize..md_off as usize + 4] == b"BSJB"
                {
                    let s = md_off as usize;
                    let d = md_rva as usize;
                    let n = md_size as usize;
                    u.decompressed[d..d + n].copy_from_slice(&u.file_data[s..s + n]);
                }
                // COR20 resources (managed .resources blob), verbatim too.
                let res_rva = get_u32(&u.decompressed, clr_rva + 0x18);
                let res_size = get_u32(&u.decompressed, clr_rva + 0x1C);
                if res_rva != 0
                    && res_size != 0
                    && (res_rva as u64 + res_size as u64) <= u.decompressed.len() as u64
                    && let Some(res_off) = prot_rva_to_off(u.file_data, pe_off, res_rva)
                    && (res_off as u64 + res_size as u64) <= u.file_data.len() as u64
                {
                    let s = res_off as usize;
                    let d = res_rva as usize;
                    let n = res_size as usize;
                    u.decompressed[d..d + n].copy_from_slice(&u.file_data[s..s + n]);
                }
            }
        }

        // The payload's TLS directory (DD[9]) arrives blanked: Crackproof strips
        // the struct and re-installs TLS itself when it maps the module. Prefer
        // recovering the real one from the stub's plaintext `.rdata` — dropping
        // DD[9] leaves `_tls_index` unwritten, so every `thread_local` access
        // resolves through TLS slot 0 (another module's block, or NULL). Only if
        // the stub can't supply it do we clear the entry, which at least stops
        // the loader writing through a NULL `AddressOfIndex`.
        //
        // Old builds have no TLS directory at all (DD[9] already 0), so this is
        // a no-op for them. Restricted to the old, `/FIXED` layout: the caller
        // zeroes BaseReloc/DllCharacteristics below, so the restored absolute
        // VAs stay valid without relocations. The new-layout companion case is
        // handled by `job::restore_tls_from_stub`.
        let tls_dd_off = pe_off2.wrapping_add(136 + 9 * 8);
        let tls_rva = get_u32(&u.decompressed, tls_dd_off);
        if tls_rva != 0 && (tls_rva as usize + 40) <= u.decompressed.len() {
            let tls_all_zero = u.decompressed[tls_rva as usize..tls_rva as usize + 40]
                .iter()
                .all(|&b| b == 0);
            if tls_all_zero {
                let image_base = get_u64(&u.decompressed, pe_off2.wrapping_add(48));
                if new_layout || !u.restore_pe64_tls_from_stub(pe_off, tls_rva, image_base) {
                    write_u32(&mut u.decompressed, tls_dd_off, 0);
                    write_u32(&mut u.decompressed, tls_dd_off.wrapping_add(4), 0);
                }
            }
        }

        // If the COR20 (CLR) directory points at a zero-cb header, clear it so
        // the loader treats the image as native instead of handing off to
        // mscoree._CorExeMain (which crashes on the empty header). Skipped when
        // the new-layout managed restore above repopulated a real COR20 header.
        let cor20_dd_off = pe_off2.wrapping_add(0xF8);
        let cor20_rva = get_u32(&u.decompressed, cor20_dd_off);
        if !restored_clr
            && cor20_rva != 0
            && (cor20_rva as usize + 4) <= u.decompressed.len()
            && get_u32(&u.decompressed, cor20_rva) == 0
        {
            write_u32(&mut u.decompressed, cor20_dd_off, 0);
            write_u32(&mut u.decompressed, cor20_dd_off.wrapping_add(4), 0);
        }

        // Old-layout CrackProof binaries are /FIXED: the shell discards the
        // relocation table and clears DllCharacteristics, so the loader needs no
        // relocations (exe_pe+0x5E / +0xB0). The new-layout (external-companion)
        // modules are *not* /FIXED — they keep a real DllCharacteristics
        // (ASLR/high-entropy) and a valid BaseReloc table (DD[5]); zeroing those
        // produces a DLL that the loader can only place at its preferred base,
        // and any rebase leaves every pointer — including the restored TLS
        // directory — unrelocated and the module crashes. So preserve both for
        // the new layout.
        //
        // The same applies to a *DLL* on the old layout: EXEs load at their
        // preferred base, but a DLL is almost always rebased, so stripping its
        // BaseReloc/DllCharacteristics makes it unloadable. The PE32 pipeline
        // already gates this on IMAGE_FILE_DLL (see run_pe32); this is the
        // PE32+ counterpart of that fix. EXEs keep the original /FIXED zeroing.
        let is_dll = (get_u16(&u.decompressed, pe_off2.wrapping_add(22)) & 0x2000) != 0;
        if !new_layout && !is_dll {
            write_u16(&mut u.decompressed, pe_off2.wrapping_add(0x5E), 0);
            write_u32(&mut u.decompressed, pe_off2.wrapping_add(0xB0), 0);
            write_u32(&mut u.decompressed, pe_off2.wrapping_add(0xB4), 0);
        } else if !new_layout {
            // Old-layout DLL: keep whatever BaseReloc the header restore
            // produced and make sure DYNAMIC_BASE is set (same as run_pe32).
            let mut dll_chars = get_u16(&u.decompressed, pe_off2.wrapping_add(0x5E));
            if dll_chars == 0 {
                dll_chars = 0x0040; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            }
            write_u16(
                &mut u.decompressed,
                pe_off2.wrapping_add(0x5E),
                dll_chars as u32,
            );
        }

        Ok(u.decompressed)
    }

    /// Validate the new-layout (marker-less) file-decryptor choice by
    /// trial-decompression, same approach as [`Self::pe32_file_lfsr_validates`].
    ///
    /// The marker-less discovery picks the file LFSR by *distance* (the LFSR
    /// whose fileCS pointer sits just past `info[3]`), not by content. A
    /// coincidental LFSR-shaped block at a shorter distance would decode to a
    /// wrong `ops2` translate and silently garble every section block — raw
    /// blocks never hit `DecompressFailed`, so the failure would ship as a
    /// plausible but wrong image. Replay the first *compressed* block's full
    /// transform (raw copy, AES, translate, decompress) on a snapshot and
    /// require decompression to succeed; restore the region afterwards.
    ///
    /// `walk4_slot` holds the compressedInfo table pointer; entries are read
    /// with the non-mutating `trial_decrypt5_u32` (the position-keyed cipher
    /// has no cross-byte state, so trial reads equal the real pass's
    /// in-place decrypts). Returns `true` when no compressed block exists
    /// (nothing to validate against).
    fn new_layout_file_ops_validate(&mut self, walk4_slot: u32, ops: &[Op], rebase: u32) -> bool {
        let mut walk4 = get_u32(&self.decompressed, walk4_slot);
        for _ in 0..4096 {
            if walk4 as usize + 16 > self.decompressed.len() {
                return false;
            }
            let src = trial_decrypt5_u32(&self.decompressed, walk4);
            let len = trial_decrypt5_u32(&self.decompressed, walk4.wrapping_add(4));
            let dst = trial_decrypt5_u32(&self.decompressed, walk4.wrapping_add(8));
            let plain_len = trial_decrypt5_u32(&self.decompressed, walk4.wrapping_add(12));
            if len == 0 {
                return true; // terminator: no compressed block to validate against
            }
            if len != plain_len {
                let cs = src.wrapping_add(rebase) as usize;
                let dd = dst as usize;
                let ll = len as usize;
                let touch = len.max(plain_len) as usize;
                if dd < 0x1000
                    || cs.checked_add(ll).is_none_or(|e| e > self.file_data.len())
                    || dd
                        .checked_add(touch)
                        .is_none_or(|e| e > self.decompressed.len())
                {
                    return false;
                }
                let snap: Vec<u8> = self.decompressed[dd..dd + touch].to_vec();
                self.decompressed[dd..dd + ll].copy_from_slice(&self.file_data[cs..cs + ll]);
                self.aes_decrypt(dst, len, self.key_offsets[2]);
                for k in 0..len {
                    let idx = (dst + k) as usize;
                    self.decompressed[idx] = super::bytecode::apply(ops, self.decompressed[idx]);
                }
                let ok = primitives::decompress(
                    &mut self.decompressed,
                    dst,
                    dst,
                    self.key_offsets[0],
                    len,
                    plain_len,
                );
                self.decompressed[dd..dd + touch].copy_from_slice(&snap);
                return ok;
            }
            walk4 = walk4.wrapping_add(16);
        }
        true
    }

    /// Validate a candidate PE32 file-decryptor LFSR block by trial-decompression.
    ///
    /// `file_dec_addr` is the absolute address of the candidate bytecode block;
    /// `ci_slot` is the absolute address of the compressedInfo pointer slot
    /// (`eighth_start + off_compressed_info`). Decodes the candidate's `file_ops`
    /// (the per-byte translate applied to every data block before Huffman
    /// decompression), then replays the first *compressed* data block's full
    /// transform — raw copy, AES, translate, decompress — on a snapshot and
    /// reports whether decompression succeeded. The correct fileLFSR yields a
    /// translate that lets every block decompress; a coincidental valid-opcode
    /// block decodes to a bogus translate that makes decompression fail.
    ///
    /// Non-destructive: the 96-byte LFSR block and the touched destination
    /// region are snapshotted and restored before returning.
    fn pe32_file_lfsr_validates(&mut self, file_dec_addr: u32, ci_slot: u32) -> bool {
        let da = file_dec_addr as usize;
        if da + 96 > self.decompressed.len() {
            return false;
        }
        // Decode file_ops transiently (decrypt_data6 mutates 96 bytes in place).
        let lfsr_snap: Vec<u8> = self.decompressed[da..da + 96].to_vec();
        self.decrypt_data6(file_dec_addr);
        let ops = generate(&self.decompressed, file_dec_addr);
        self.decompressed[da..da + 96].copy_from_slice(&lfsr_snap);
        let ops = match ops {
            Some(o) => o,
            None => return false,
        };

        let cdo = (!get_u32(self.file_data, 0x1080)).wrapping_add(0x1000);
        let table = get_u32(&self.decompressed, ci_slot);
        if table == 0 || table as usize + 16 > self.decompressed.len() {
            return false;
        }
        // Walk the compressedInfo table (entries read via the non-mutating
        // trial decrypt) to the first compressed block, then test it.
        let mut entry = table;
        for _ in 0..256 {
            if entry as usize + 16 > self.decompressed.len() {
                return false;
            }
            let src2 = trial_decrypt5_u32(&self.decompressed, entry);
            let s_sz2 = trial_decrypt5_u32(&self.decompressed, entry.wrapping_add(4));
            let dst2 = trial_decrypt5_u32(&self.decompressed, entry.wrapping_add(8));
            let d_sz2 = trial_decrypt5_u32(&self.decompressed, entry.wrapping_add(12));
            if s_sz2 == 0 {
                return false; // terminator: no compressed block to validate against
            }
            if s_sz2 != d_sz2 {
                let file_src = src2.wrapping_add(cdo) as usize;
                let dd = dst2 as usize;
                let n = s_sz2 as usize;
                let dlen = self.decompressed.len();
                // The trial transform writes `s_sz2` bytes starting at dd
                // (copy + AES + translate) before decompress reads them, so
                // the snapshot/restore must cover max(s_sz2, d_sz2) — restoring
                // only d_sz2 leaves [dd+d_sz2, dd+s_sz2) permanently corrupted
                // for the wrong-candidate case (s_sz2 > d_sz2), and every
                // later candidate is then validated against a polluted buffer.
                let touch = (s_sz2.max(d_sz2)) as usize;
                if dst2 < 0x1000
                    || file_src
                        .checked_add(n)
                        .is_none_or(|e| e > self.file_data.len())
                    || dd.checked_add(touch).is_none_or(|e| e > dlen)
                {
                    return false;
                }
                let dst_snap: Vec<u8> = self.decompressed[dd..dd + touch].to_vec();
                self.decompressed[dd..dd + n]
                    .copy_from_slice(&self.file_data[file_src..file_src + n]);
                self.aes_decrypt(dst2, s_sz2, self.key_offsets[2]);
                for k in 0..s_sz2 {
                    let idx = (dst2 + k) as usize;
                    self.decompressed[idx] = super::bytecode::apply(&ops, self.decompressed[idx]);
                }
                let ok = primitives::decompress(
                    &mut self.decompressed,
                    dst2,
                    dst2,
                    self.key_offsets[0],
                    s_sz2,
                    d_sz2,
                );
                self.decompressed[dd..dd + touch].copy_from_slice(&dst_snap);
                return ok;
            }
            entry = entry.wrapping_add(16);
        }
        false
    }

    /// PE32+ counterpart of [`Self::restore_pe32_tls_from_stub`]: recover the
    /// genuine 40-byte `IMAGE_TLS_DIRECTORY64` and its raw-data template from the
    /// loader stub, which keeps `.rdata` in plaintext at the same RVAs.
    ///
    /// Only meaningful for the old (single-file, `/FIXED`) layout, where the
    /// caller goes on to zero `DllCharacteristics` and `BaseReloc` — the image
    /// then loads at `image_base`, so the struct's absolute VAs are already
    /// correct and need no relocations. The external-companion layout keeps its
    /// relocations and is handled separately by `job::restore_tls_from_stub`,
    /// which also synthesizes the four DIR64 fixups.
    ///
    /// Returns `false` without touching the image if the stub cannot supply a
    /// plausible directory, so the caller can fall back to clearing DD[9].
    fn restore_pe64_tls_from_stub(
        &mut self,
        pe_off: u32,
        tls_dir_rva: u32,
        image_base: u64,
    ) -> bool {
        let src = match prot_rva_to_off(self.file_data, pe_off, tls_dir_rva) {
            Some(o) => o as usize,
            None => return false,
        };
        if src.checked_add(40).is_none_or(|e| e > self.file_data.len()) {
            return false;
        }
        let field = |i: u32| get_u64(self.file_data, (src as u32).wrapping_add(i));
        let (start_va, end_va, idx_va, cb_va) = (field(0), field(8), field(16), field(24));

        let img_len = self.decompressed.len() as u64;
        let in_image = |va: u64| va > image_base && (va - image_base) < img_len;
        if !in_image(start_va) || !in_image(idx_va) || !in_image(cb_va) {
            return false;
        }
        if end_va < start_va || (end_va - start_va) > 0x10_0000 {
            return false;
        }

        // Template first: bail before touching the struct so a failure leaves the
        // caller's all-zero directory intact.
        let tpl_len = (end_va - start_va) as usize;
        if tpl_len > 0 {
            let tpl_rva = (start_va - image_base) as u32;
            let ts = match prot_rva_to_off(self.file_data, pe_off, tpl_rva) {
                Some(o) => o as usize,
                None => return false,
            };
            let td = tpl_rva as usize;
            if ts
                .checked_add(tpl_len)
                .is_none_or(|e| e > self.file_data.len())
                || td
                    .checked_add(tpl_len)
                    .is_none_or(|e| e > self.decompressed.len())
            {
                return false;
            }
            self.decompressed[td..td + tpl_len].copy_from_slice(&self.file_data[ts..ts + tpl_len]);
        }

        let d = tls_dir_rva as usize;
        self.decompressed[d..d + 40].copy_from_slice(&self.file_data[src..src + 40]);
        true
    }

    /// Restore the genuine `IMAGE_TLS_DIRECTORY32` — and the raw-data template
    /// it points at — from the loader stub.
    ///
    /// Crackproof zeroes the TLS directory struct inside the encrypted payload
    /// and re-installs TLS itself when it maps the module, so a statically
    /// unpacked image reaches the ordinary Windows loader with a blank struct.
    /// Synthesizing a placeholder (empty template, index/callbacks aimed at
    /// scratch) makes the image *load*, but it is not equivalent to the
    /// original: the module's initialized thread-local bytes are never copied,
    /// `_tls_index` is written somewhere the code never reads, and the TLS
    /// callback array — which is where the CRT runs `__dyn_tls_init` — is empty.
    /// Every `thread_local` access then hits a garbage slot (the same class of
    /// `0xC0000005` documented for the companion-DLL path in `job.rs`).
    ///
    /// The stub keeps the module's original `.rdata` and `.tls` in plaintext, so
    /// both the 24-byte struct and its template are copied back byte-for-byte at
    /// their RVAs. EXE images are emitted without base relocations and therefore
    /// load at `image_base`, so the struct's absolute VAs stay correct as-is;
    /// DLLs keep the original relocation table, which already covered these four
    /// fields before packing.
    ///
    /// Returns `false` without touching the image when the stub cannot supply a
    /// plausible directory, so the caller can fall back to the placeholder.
    fn restore_pe32_tls_from_stub(
        &mut self,
        pe_off: u32,
        tls_dir_rva: u32,
        image_base: u32,
    ) -> bool {
        let src = match prot_rva_to_off(self.file_data, pe_off, tls_dir_rva) {
            Some(o) => o as usize,
            None => return false,
        };
        if src.checked_add(24).is_none_or(|e| e > self.file_data.len()) {
            return false;
        }
        let field = |i: u32| get_u32(self.file_data, (src as u32).wrapping_add(i));
        let (start_va, end_va, idx_va, cb_va) = (field(0), field(4), field(8), field(12));

        // Sanity-check before trusting it: a stub whose `.rdata` is not plaintext
        // at this RVA yields noise, and installing noise is worse than the
        // placeholder. All three pointers must land inside the image at its
        // preferred base, and the template must be a sane, non-inverted range.
        let img_len = self.decompressed.len() as u64;
        let in_image = |va: u32| va > image_base && ((va - image_base) as u64) < img_len;
        if !in_image(start_va) || !in_image(idx_va) || !in_image(cb_va) {
            return false;
        }
        if end_va < start_va || (end_va - start_va) as u64 > 0x10_0000 {
            return false;
        }

        // Template first: a failure here must leave the struct untouched so the
        // caller's fallback still sees an all-zero directory.
        let tpl_len = (end_va - start_va) as usize;
        if tpl_len > 0 {
            let tpl_rva = start_va - image_base;
            let ts = match prot_rva_to_off(self.file_data, pe_off, tpl_rva) {
                Some(o) => o as usize,
                None => return false,
            };
            let td = tpl_rva as usize;
            if ts
                .checked_add(tpl_len)
                .is_none_or(|e| e > self.file_data.len())
                || td
                    .checked_add(tpl_len)
                    .is_none_or(|e| e > self.decompressed.len())
            {
                return false;
            }
            self.decompressed[td..td + tpl_len].copy_from_slice(&self.file_data[ts..ts + tpl_len]);
        }

        let d = tls_dir_rva as usize;
        self.decompressed[d..d + 24].copy_from_slice(&self.file_data[src..src + 24]);
        true
    }

    /// PE32 (32-bit) unpack pipeline. The shared Stage 1/2 setup (info decrypt,
    /// payload decrypt, raw copy, header restore) has already run in `run()`
    /// before dispatch; this takes over from "Locating shell offsets".
    fn run_pe32(&mut self, pe_off: u32, verbose: bool) -> Result<Vec<u8>, UnpackError> {
        let info = self.info;
        let info3 = info[3];

        // advance_key: replays the packer's per-iteration key walk.
        let advance_key = |mut key: u32, iterations: u32| -> u32 {
            for m in 0..iterations {
                let bound = (m + 1).wrapping_mul(25) << 2;
                let mut n: u32 = 1;
                while n <= bound {
                    key = key.wrapping_add(n);
                    n += 1;
                }
            }
            key
        };

        // ---- Locate tbl in shell ----
        let tbl = primitives::find_tbl_pe32(&self.decompressed, &info)
            .ok_or(UnpackError::Pe32TblNotFound)?;
        if verbose {
            println!("[3/9] Locating config layout (PE32)...");
            println!("  tbl = 0x{:X}", tbl);
        }

        // ---- PE header restore ----
        let val_bc = get_u32(&self.decompressed, tbl.wrapping_add(0xBC));
        let val_c8 = get_u32(&self.decompressed, tbl.wrapping_add(0xC8));
        let val_cc = get_u32(&self.decompressed, tbl.wrapping_add(0xCC));
        write_u32(&mut self.decompressed, pe_off.wrapping_add(0x80), val_bc);
        write_u32(&mut self.decompressed, pe_off.wrapping_add(0x88), val_c8);
        write_u32(&mut self.decompressed, pe_off.wrapping_add(0x8C), val_cc);
        write_u32(&mut self.decompressed, pe_off.wrapping_add(0xB0), 0);
        write_u32(&mut self.decompressed, pe_off.wrapping_add(0xB4), 0);

        // ---- Header-independent checksum inputs ----
        let first_stage_cs = self.calculate_checksum(tbl.wrapping_add(0xA8));
        let second_stage_key = get_u32(&self.decompressed, tbl.wrapping_add(0x40));

        // ---- Stage 3: SecondStage ----
        //
        // ss_key = headerChecksum ^ firstStageCS ^ secondStageKey, where the
        // header checksum (a XOR of crc32(region)^size over the sub-regions at
        // tbl+0x58) is taken over the *original* pre-pack PE header. For EXEs the
        // import/resource restore above reconstructs that header exactly. Native
        // DLLs additionally carry a packer-added BaseReloc data-directory entry
        // (dir 5) that was absent from the checksummed original, so the header
        // checksum only matches once that entry is treated as zero. EXEs have no
        // dir-5 entry, so zeroing it is a no-op for them.
        //
        // Rather than branch on EXE-vs-DLL, try the header as-is and, on failure,
        // with the BaseReloc entry zeroed; keep whichever ss_key decrypts a
        // SecondStage whose ThirdStage (off,size) pair lands inside the image.
        // This uses the same shift/key trial-and-validate the later stages
        // already use, and keeps EXE output byte-identical (the as-is variant
        // wins first).
        let ss_pair = tbl.wrapping_add(0x98);
        let ss = get_u32(&self.decompressed, ss_pair);
        let ss_size = get_u32(&self.decompressed, ss_pair.wrapping_add(4));
        let ss_shift = ss_size.wrapping_sub(0xBC0);
        // Back up the SecondStage ciphertext so a failed trial can be retried.
        let ss_lo = ss as usize;
        let ss_hi = ss_lo.wrapping_add(ss_size as usize);
        if ss_hi < ss_lo || ss_hi > self.decompressed.len() {
            return Err(UnpackError::Corrupt);
        }
        let ss_ct: Vec<u8> = self.decompressed[ss_lo..ss_hi].to_vec();
        // PE32 data dir 5 (BaseReloc) = optional_header(pe+24) + 0x60 + 5*8 = pe+0xA0.
        let reloc_dir = pe_off.wrapping_add(0xA0);
        let len = self.decompressed.len() as u64;
        let pair_off = 0xB8Cu32.wrapping_add(ss_shift);
        let mut found = false;
        // Holds the winning variant's header checksum; the later stages
        // (Forth/Fifth/Seven/Eighth) reuse it as a key component.
        let mut header_checksum: u32 = 0;
        for zero_reloc in [false, true] {
            if zero_reloc {
                write_u32(&mut self.decompressed, reloc_dir, 0);
                write_u32(&mut self.decompressed, reloc_dir.wrapping_add(4), 0);
            }
            let mut hcs_addr = tbl.wrapping_add(0x58);
            header_checksum = 0;
            while get_u32(&self.decompressed, hcs_addr.wrapping_add(4)) != 0 {
                header_checksum ^= self.calculate_checksum(hcs_addr);
                hcs_addr = hcs_addr.wrapping_add(8);
            }
            let ss_key = header_checksum ^ first_stage_cs ^ second_stage_key;
            self.decompressed[ss_lo..ss_hi].copy_from_slice(&ss_ct);
            self.decrypt_data3(ss_pair, ss_key, 21);
            // Validate: the ThirdStage (off,size) pair must reference the image.
            let pair = ss.wrapping_add(pair_off);
            let off = get_u32(&self.decompressed, pair) as u64;
            let sz = get_u32(&self.decompressed, pair.wrapping_add(4)) as u64;
            if off > 0x1000 && off < len && sz >= 4 && off.saturating_add(sz) <= len {
                found = true;
                break;
            }
        }
        if !found {
            return Err(UnpackError::Corrupt);
        }
        if verbose {
            println!(
                "  ss = 0x{:08X}, size = 0x{:X}, shift = 0x{:X}",
                ss, ss_size, ss_shift
            );
        }

        // ---- PE32 fixed offsets ----
        let third_key_off = 0x968u32.wrapping_add(ss_shift);
        let forth_key_off = 0x964u32.wrapping_add(ss_shift);
        let cs_base_off = 0x96Cu32.wrapping_add(ss_shift);
        let dp_base_off = 0xA9Cu32.wrapping_add(ss_shift);

        // ---- Stage 4: ThirdStage (brute-force the rotate shift) ----
        let third_pair_off = 0xB8Cu32.wrapping_add(ss_shift);
        let key = get_u32(&self.decompressed, ss.wrapping_add(third_key_off));
        let pair_addr = ss.wrapping_add(third_pair_off);
        let ts_addr = get_u32(&self.decompressed, pair_addr);
        let ts_size_raw = get_u32(&self.decompressed, pair_addr.wrapping_add(4));
        let backup: Vec<u8> =
            self.decompressed[ts_addr as usize..(ts_addr + ts_size_raw) as usize].to_vec();
        let mut info_table: Option<u32> = None;
        let mut keys_addr: u32 = 0;
        let mut ts: u32 = 0;
        for &shift in &[19u32, 21, 17, 23, 15, 25, 13, 11] {
            self.decompressed[ts_addr as usize..(ts_addr + ts_size_raw) as usize]
                .copy_from_slice(&backup);
            write_u32(&mut self.decompressed, pair_addr, ts_addr);
            write_u32(
                &mut self.decompressed,
                pair_addr.wrapping_add(4),
                ts_size_raw,
            );
            self.decrypt_data3(pair_addr, key, shift);
            let mut off = 0u32;
            while off + 32 < ts_size_raw {
                let t0 = get_u32(&self.decompressed, ts_addr.wrapping_add(off));
                if t0 == 1 || t0 == 0x11 {
                    let t1 = get_u32(&self.decompressed, ts_addr.wrapping_add(off + 16));
                    if t1 == 2 {
                        let addr0 = get_u32(&self.decompressed, ts_addr.wrapping_add(off + 4));
                        if 0x1000 < addr0 && (addr0 as usize) < self.decompressed.len() {
                            let it = ts_addr.wrapping_add(off);
                            info_table = Some(it);
                            keys_addr = it.wrapping_sub(0x58);
                            ts = ts_addr;
                            break;
                        }
                    }
                }
                off = off.wrapping_add(4);
            }
            if info_table.is_some() {
                break;
            }
        }
        let info_table = info_table.ok_or(UnpackError::Pe32ThirdStageFailed)?;
        if verbose {
            println!("[4/9] Decrypting stages (PE32)...");
            println!(
                "  thirdStage start = 0x{:X}, infoTable = 0x{:X}",
                ts, info_table
            );
        }

        // ---- Process infoTable ----
        let mut it_addr = info_table;
        for _ in 0..2 {
            let tval = get_u32(&self.decompressed, it_addr);
            if tval == 1 || tval == 0x11 {
                self.decrypt_data4(it_addr.wrapping_add(4));
            } else if tval == 2 {
                let mut copy_addr = get_u32(&self.decompressed, it_addr.wrapping_add(4));
                loop {
                    self.decrypt_data5(copy_addr, 16);
                    let s_a = get_u32(&self.decompressed, copy_addr);
                    let s_sz = get_u32(&self.decompressed, copy_addr.wrapping_add(4));
                    let d_a = get_u32(&self.decompressed, copy_addr.wrapping_add(8));
                    let d_sz = get_u32(&self.decompressed, copy_addr.wrapping_add(12));
                    copy_addr = copy_addr.wrapping_add(16);
                    if s_sz == 0 {
                        break;
                    }
                    if s_a != 0 && d_a != 0 && d_sz == s_sz {
                        let sa = s_a as usize;
                        let da = d_a as usize;
                        let n = s_sz as usize;
                        self.decompressed.copy_within(sa..sa + n, da);
                    }
                }
            }
            it_addr = it_addr.wrapping_add(16);
        }

        // ---- keyOffsets ----
        let mut ka = keys_addr;
        for k in 0..2usize {
            let mut ka2 = ka;
            for l in 0..2usize {
                self.decrypt_data4(ka2);
                self.key_offsets[k * 2 + l] = get_u32(&self.decompressed, ka2);
                ka2 = ka2.wrapping_add(8);
            }
            ka = ka.wrapping_add(32);
        }

        // ---- Checksum addresses ----
        let second_stage_cs_addr = tbl.wrapping_add(0xB0);
        let forth_stage_cs_addr = ss.wrapping_add(cs_base_off);
        let fifth_stage_cs_addr = ss.wrapping_add(cs_base_off).wrapping_add(0x08);
        let seven_stage_cs_addr = ss.wrapping_add(cs_base_off).wrapping_add(0x10);

        // ---- ForthStage ----
        let second_stage_cs = self.calculate_checksum(second_stage_cs_addr);
        let forth_stage_key = advance_key(
            get_u32(&self.decompressed, ss.wrapping_add(forth_key_off)),
            4,
        );
        let dp_base = ss.wrapping_add(dp_base_off);
        let forth_addr = dp_base.wrapping_add(0x40);
        let fk = header_checksum ^ second_stage_cs ^ forth_stage_key;
        if !self.decrypt_and_decompress_data(forth_addr, fk, None) {
            return Err(UnpackError::DecompressFailed);
        }

        // ---- FifthStage ----
        let fifth_addr = dp_base.wrapping_add(0x50);
        let forth_cs = self.calculate_checksum(forth_stage_cs_addr);
        let forth_region_off = get_u32(&self.decompressed, forth_stage_cs_addr);
        let forth_region_sz = get_u32(&self.decompressed, forth_stage_cs_addr.wrapping_add(4));
        let fifth_key = get_u32(
            &self.decompressed,
            forth_region_off
                .wrapping_add(forth_region_sz)
                .wrapping_sub(4),
        );
        let fk5 = header_checksum ^ forth_cs ^ fifth_key;
        if !self.decrypt_and_decompress_data(fifth_addr, fk5, None) {
            return Err(UnpackError::DecompressFailed);
        }

        // ---- SevenStage ----
        let seven_addr = dp_base.wrapping_add(0x70);
        let seven_dsz = get_u32(&self.decompressed, seven_addr.wrapping_add(12));
        let fifth_cs = self.calculate_checksum(fifth_stage_cs_addr);
        let cs1_addr = get_u32(
            &self.decompressed,
            ss.wrapping_add(cs_base_off).wrapping_add(0x08),
        );
        let cs1_size = get_u32(
            &self.decompressed,
            ss.wrapping_add(cs_base_off)
                .wrapping_add(0x08)
                .wrapping_add(4),
        );
        let seven_key = !get_u32(
            &self.decompressed,
            cs1_addr.wrapping_add(cs1_size).wrapping_sub(0x10),
        );
        let fk7 = header_checksum ^ fifth_cs ^ seven_key;
        if !self.decrypt_and_decompress_data(seven_addr, fk7, None) {
            return Err(UnpackError::DecompressFailed);
        }

        // ---- EighthStage ----
        let seven_start_actual = get_u32(&self.decompressed, seven_addr);
        if verbose {
            println!("[5/9] Decrypting eighthStage (PE32)...");
            println!(
                "  sevenStart = 0x{:X}, sevenDsz = 0x{:X}",
                seven_start_actual, seven_dsz
            );
        }
        // Locate the customDecryptor LFSR block (scan backward from middle, then
        // forward as fallback).
        let scan_start = seven_dsz / 2;
        let custom_dec_off = primitives::find_lfsr_block(
            &self.decompressed,
            seven_start_actual,
            seven_dsz,
            scan_start,
            true,
        )
        .or_else(|| {
            primitives::find_lfsr_block(&self.decompressed, seven_start_actual, seven_dsz, 0, false)
        })
        .ok_or(UnpackError::Pe32CustomDecryptorNotFound)?;
        let custom_dec_addr = seven_start_actual.wrapping_add(custom_dec_off);
        self.decrypt_data6(custom_dec_addr);
        let custom_ops = generate(&self.decompressed, custom_dec_addr)
            .ok_or(UnpackError::Pe32BytecodeGenFailed)?;

        let seven_cs = self.calculate_checksum(seven_stage_cs_addr);
        let eighth_addr = dp_base.wrapping_add(0xC0);
        let eighth_dsz = get_u32(&self.decompressed, eighth_addr.wrapping_add(12));
        let eighth_src = get_u32(&self.decompressed, eighth_addr);
        let eighth_ssz = get_u32(&self.decompressed, eighth_addr.wrapping_add(4));
        let eighth_backup: Vec<u8> =
            self.decompressed[eighth_src as usize..(eighth_src + eighth_ssz) as usize].to_vec();
        let eighth_pair_bak: Vec<u8> =
            self.decompressed[eighth_addr as usize..(eighth_addr + 16) as usize].to_vec();
        let data_len = self.decompressed.len() as u32;

        // Build the eighthStageKey candidate list (offsets relative to
        // sevenStart) using gap heuristics + scan.
        let mut candidates: Vec<u32> = Vec::new();
        let push_cand = |c: &mut Vec<u32>, off: u32| {
            if !c.contains(&off) {
                c.push(off);
            }
        };
        for &end_gap in &[0xD0u32, 0xC0, 0xE0, 0xB0, 0xA0, 0xF0, 0x100] {
            if end_gap <= seven_dsz {
                let off = seven_dsz - end_gap;
                if off < seven_dsz {
                    let val = get_u32(&self.decompressed, seven_start_actual.wrapping_add(off));
                    if val != 0 && val != 0xCCCC_CCCC {
                        push_cand(&mut candidates, off);
                    }
                }
            }
        }
        for &gap in &[
            0x70u32, 0xD0, 0x28, 0x50, 0x48, 0x30, 0x40, 0x58, 0x60, 0x20, 0x38, 0x80, 0x90, 0xA0,
            0xB0,
        ] {
            if gap <= custom_dec_off {
                let off = custom_dec_off - gap;
                if off + 4 <= seven_dsz && !candidates.contains(&off) {
                    let val = get_u32(&self.decompressed, seven_start_actual.wrapping_add(off));
                    if val != 0 && val != 0xCCCC_CCCC {
                        push_cand(&mut candidates, off);
                    }
                }
            }
        }
        let scan_lo = custom_dec_off.saturating_sub(0x100);
        let mut off = scan_lo;
        while off < custom_dec_off {
            if !candidates.contains(&off) {
                let val = get_u32(&self.decompressed, seven_start_actual.wrapping_add(off));
                let all_printable = (0..4u32).all(|i| {
                    let b = (val >> (i * 8)) & 0xFF;
                    (32..127).contains(&b)
                });
                if val != 0 && val != 0xCCCC_CCCC && !all_printable {
                    push_cand(&mut candidates, off);
                }
            }
            off = off.wrapping_add(4);
        }

        let k1 = self.key_offsets[1];
        let k3 = self.key_offsets[3];
        let mut eighth_ok = false;
        for ek_off in candidates {
            self.decompressed[eighth_src as usize..(eighth_src + eighth_ssz) as usize]
                .copy_from_slice(&eighth_backup);
            self.decompressed[eighth_addr as usize..(eighth_addr + 16) as usize]
                .copy_from_slice(&eighth_pair_bak);
            let raw = get_u32(&self.decompressed, seven_start_actual.wrapping_add(ek_off));
            let test_key = advance_key(raw, 3);
            let fk8 = header_checksum ^ fifth_cs ^ seven_cs ^ test_key;
            let result = primitives::decrypt_and_decompress_data(
                &mut self.decompressed,
                eighth_addr,
                fk8,
                k1,
                k3,
                Some(&custom_ops),
            );
            if result {
                let est = get_u32(&self.decompressed, eighth_addr);
                if 0x1000 < est && est < data_len {
                    eighth_ok = true;
                    break;
                }
            }
        }
        if !eighth_ok {
            return Err(UnpackError::Pe32EighthKeyNotFound);
        }
        let eighth_start = get_u32(&self.decompressed, eighth_addr);
        if verbose {
            println!(
                "  eighthStart = 0x{:08X}, dsz = 0x{:X}",
                eighth_start, eighth_dsz
            );
        }

        // ---- Final processing offsets (anchored on the eighthStage config cluster) ----
        //
        // The eighthStage holds a config cluster — importTable, fileCS,
        // compressedInfo, zeroList — at fixed offsets from a cluster base
        // (base+0x18 / +0x30 / +0x40 / +0x48) with the fileLFSR at +0x4B4.
        // Classic builds stamp a 0x00007679 dword at that base; native DLLs and
        // some older PE32 EXEs (ss_size=0xBE8) omit the stamp.
        // Locate the cluster by stamp when present (validated by fileCS at
        // base+0x30 pointing past info[3]); otherwise fall back to finding the
        // fileCS slot by shape — (addr, size) with addr just past info[3] and a
        // small 16-aligned size — and back-derive base = fileCS_off - 0x30.
        // Hardcoded eighthStart-relative constants remain as a last-resort
        // fallback for builds where neither discovery path fires.
        let marker = {
            let mut m: Option<u32> = None;
            let hi = eighth_dsz.saturating_sub(0x4C);
            let mut o = 0u32;
            while o < hi {
                if get_u32(&self.decompressed, eighth_start.wrapping_add(o)) == 0x7679 {
                    let fc = get_u32(&self.decompressed, eighth_start.wrapping_add(o + 0x30));
                    if fc > info3 && (fc as usize) < self.decompressed.len() {
                        m = Some(o);
                        break;
                    }
                }
                o = o.wrapping_add(4);
            }
            if m.is_none() {
                // fileCS-shaped slot: addr in (info3, info3+0x2000], size in
                // 0x10..=0x200 and 16-aligned. Prefer the candidate whose addr
                // is closest to (but past) info3 — matches every observed
                // build (one PE32 EXE family dist ~0x1C0, another ~0x1A0).
                let mut best: Option<(u32 /*dist*/, u32 /*off*/)> = None;
                let mut o = 0u32;
                let dlen = self.decompressed.len() as u32;
                while o + 8 <= eighth_dsz.saturating_sub(0x4B4u32.saturating_sub(0x30)) {
                    let fc = get_u32(&self.decompressed, eighth_start.wrapping_add(o));
                    let sz = get_u32(&self.decompressed, eighth_start.wrapping_add(o + 4));
                    if fc > info3
                        && fc <= info3.wrapping_add(0x2000)
                        && fc < dlen
                        && (0x10..=0x200).contains(&sz)
                        && (sz & 0xF) == 0
                    {
                        // Cluster base must leave room for the +0x4B4 LFSR slot
                        // (even if the exact LFSR is later adjusted by scan).
                        if o >= 0x30 {
                            let base = o - 0x30;
                            if base.wrapping_add(0x4C) <= eighth_dsz {
                                let dist = fc - info3;
                                match best {
                                    None => best = Some((dist, base)),
                                    Some((bd, _)) if dist < bd => best = Some((dist, base)),
                                    _ => {}
                                }
                            }
                        }
                    }
                    o = o.wrapping_add(4);
                }
                if let Some((dist, base)) = best {
                    if verbose {
                        println!(
                            "  pe32 cluster via fileCS (no 0x7679): base=+0x{:X} dist_info3=0x{:X}",
                            base, dist
                        );
                    }
                    m = Some(base);
                }
            }
            m
        };
        let (off_import_table, off_file_cs, off_compressed_info, off_zero_list, off_file_lfsr) =
            match marker {
                Some(m) => (m + 0x18, m + 0x30, m + 0x40, m + 0x48, m + 0x4B4),
                None => (
                    0x3C50u32.wrapping_add(ss_shift),
                    0x3C68u32.wrapping_add(ss_shift),
                    0x3C78u32.wrapping_add(ss_shift),
                    0x3C80u32.wrapping_add(ss_shift),
                    0x40ECu32.wrapping_add(ss_shift),
                ),
            };

        // ---- File checksums (permanent decrypt) ----
        let file_cs_addr_ptr = eighth_start.wrapping_add(off_file_cs);
        let mut file_cs_addr = get_u32(&self.decompressed, file_cs_addr_ptr);
        let file_cs_size = get_u32(&self.decompressed, file_cs_addr_ptr.wrapping_add(4));
        if file_cs_size > 0 {
            let file_cs_end = file_cs_addr.wrapping_add(file_cs_size);
            while file_cs_addr < file_cs_end {
                self.decrypt_data5(file_cs_addr, 16);
                file_cs_addr = file_cs_addr.wrapping_add(16);
            }
        } else {
            while get_u32(&self.decompressed, file_cs_addr.wrapping_add(4)) != 0 {
                self.decrypt_data5(file_cs_addr, 16);
                file_cs_addr = file_cs_addr.wrapping_add(16);
            }
        }

        // ---- File decryptor LFSR ----
        //
        // When the marker-relative off_file_lfsr is in range, try that slot
        // first (exact). If it is not a valid LFSR block, trial-and-validate
        // candidates from off_zero_list forward — required for older PE32 EXEs
        // without the 0x7679 stamp where the expected slot is empty and a loose
        // decoded[0]+0xC3 nearest-hit picks the wrong decryptor. Fall back to
        // the legacy loose scan only if no candidate trial-decompresses. Native
        // DLLs have a smaller eighthStage where off_file_lfsr lands out of range
        // and use the same trial-validate scan from just past the cluster (else
        // branch).
        let lfsr_off = if off_file_lfsr.wrapping_add(96) <= eighth_dsz {
            let mut lfsr_off = off_file_lfsr;
            let exact = primitives::find_lfsr_block(
                &self.decompressed,
                eighth_start,
                eighth_dsz,
                off_file_lfsr,
                false,
            );
            if exact != Some(off_file_lfsr) {
                // Prefer trial-and-validate (same as the DLL branch): a loose
                // decoded[0]+0xC3 scan can land on coincidental LFSR-shaped
                // blocks that decode to a wrong file_ops and scramble every
                // compressed block. Observed on older PE32 EXEs without the
                // 0x7679 cluster stamp: the expected slot is empty and the
                // nearest loose hit is not the real decryptor.
                let ci_slot = eighth_start.wrapping_add(off_compressed_info);
                let mut scan = off_zero_list;
                let mut chosen: Option<u32> = None;
                let mut considered = 0u32;
                while let Some(cand) = primitives::find_lfsr_block(
                    &self.decompressed,
                    eighth_start,
                    eighth_dsz,
                    scan,
                    false,
                ) {
                    considered = considered.wrapping_add(1);
                    if self.pe32_file_lfsr_validates(eighth_start.wrapping_add(cand), ci_slot) {
                        chosen = Some(cand);
                        break;
                    }
                    scan = cand + 1;
                }
                if let Some(c) = chosen {
                    if verbose {
                        println!(
                            "  pe32 fileLFSR via trial-validate: +0x{:X} (expected +0x{:X}, considered {})",
                            c, off_file_lfsr, considered
                        );
                    }
                    lfsr_off = c;
                } else {
                    // No candidate trial-decompresses: fail loudly. The old
                    // "legacy loose scan" picked the nearest LFSR-shaped block
                    // by offset distance without any validation — that is
                    // exactly how a wrong file_ops got applied to every data
                    // block (uncompressed blocks never hit DecompressFailed),
                    // producing a plausible but fully wrong image (the PE32
                    // .text scramble root cause). Trial-and-validate or error.
                    return Err(UnpackError::Pe32FileLfsrNotFound);
                }
            }
            lfsr_off
        } else {
            // Native DLL: the marker-relative off_file_lfsr (EXE-tuned, marker +
            // 0x4B4) overshoots the smaller DLL eighthStage, so the exact slot is
            // unavailable. A plain forward scan returns the FIRST valid-opcode
            // block, but the DLL eighthStage contains coincidental valid-opcode
            // blocks that decode to trivial programs (e.g. a constant byte add)
            // ahead of the real file decryptor. A wrong file_ops corrupts the
            // per-block translate (applied before decompression), so every data
            // block fails to decompress. Enumerate every candidate forward and
            // keep the first whose decoded file_ops actually decompresses the
            // first compressed data block — trial-and-validate, same idea as the
            // D1/D2 fixes. Non-DLL (EXE) builds never reach this branch.
            let ci_slot = eighth_start.wrapping_add(off_compressed_info);
            let mut scan = off_zero_list.wrapping_add(8);
            let mut chosen: Option<u32> = None;
            while let Some(cand) = primitives::find_lfsr_block(
                &self.decompressed,
                eighth_start,
                eighth_dsz,
                scan,
                false,
            ) {
                if self.pe32_file_lfsr_validates(eighth_start.wrapping_add(cand), ci_slot) {
                    chosen = Some(cand);
                    break;
                }
                scan = cand + 1;
            }
            chosen.ok_or(UnpackError::Pe32FileLfsrNotFound)?
        };
        let file_dec_addr = eighth_start.wrapping_add(lfsr_off);
        self.decrypt_data6(file_dec_addr);
        let file_ops = generate(&self.decompressed, file_dec_addr)
            .ok_or(UnpackError::Pe32BytecodeGenFailed)?;

        // ---- PE32 metadata: EP and data dirs from info[3] ----
        let test_val = get_u32(&self.decompressed, info3.wrapping_add(0x10));
        let metadata_ep: u32;
        let mut metadata_dirs = [0u8; 128];
        if test_val > 0x10000 {
            // Layout B
            let s = info3.wrapping_add(0x10) as usize;
            let backup_meta = self.decompressed[s..s + 0x290].to_vec();
            self.decrypt_data5(info3.wrapping_add(0x10), 0x290);
            metadata_ep = get_u32(&self.decompressed, info3.wrapping_add(0x20));
            let d = info3.wrapping_add(0x30) as usize;
            metadata_dirs.copy_from_slice(&self.decompressed[d..d + 128]);
            self.decompressed[s..s + 0x290].copy_from_slice(&backup_meta);
        } else {
            // Layout A
            let s = info3.wrapping_add(0x40) as usize;
            let backup_meta = self.decompressed[s..s + 144].to_vec();
            self.decrypt_data5(info3.wrapping_add(0x40), 144);
            metadata_ep = get_u32(&self.decompressed, info3.wrapping_add(0x40));
            let d = info3.wrapping_add(0x50) as usize;
            metadata_dirs.copy_from_slice(&self.decompressed[d..d + 128]);
            self.decompressed[s..s + 144].copy_from_slice(&backup_meta);
        }

        // ---- Zero-out list (runs BEFORE decompression) ----
        let zero_list_addr = eighth_start.wrapping_add(off_zero_list);
        let mut zero_ptr = get_u32(&self.decompressed, zero_list_addr);
        loop {
            self.decrypt_data5(zero_ptr, 16);
            let src3 = get_u32(&self.decompressed, zero_ptr);
            let s_sz3 = get_u32(&self.decompressed, zero_ptr.wrapping_add(4));
            zero_ptr = zero_ptr.wrapping_add(16);
            if s_sz3 == 0 {
                break;
            }
            if src3.wrapping_add(s_sz3) as usize > self.decompressed.len() {
                break;
            }
            for b in &mut self.decompressed[src3 as usize..(src3 + s_sz3) as usize] {
                *b = 0;
            }
        }

        // ---- File data decompression ----
        if verbose {
            println!("[6/9] Loading and decompressing file data (PE32)...");
        }
        let compress_data_offset = (!get_u32(self.file_data, 0x1080)).wrapping_add(0x1000);
        let compressed_info_addr = eighth_start.wrapping_add(off_compressed_info);
        let mut compressed_info = get_u32(&self.decompressed, compressed_info_addr);
        // Pass 1 (sequential): position-keyed descriptor chain (decrypt_data5),
        // terminated by a zero source-size record.
        struct Blk {
            src: u32,
            ssz: u32,
            dst: u32,
            dsz: u32,
        }
        let mut blocks: Vec<Blk> = Vec::new();
        loop {
            self.decrypt_data5(compressed_info, 16);
            let src2 = get_u32(&self.decompressed, compressed_info);
            let s_sz2 = get_u32(&self.decompressed, compressed_info.wrapping_add(4));
            let dst2 = get_u32(&self.decompressed, compressed_info.wrapping_add(8));
            let d_sz2 = get_u32(&self.decompressed, compressed_info.wrapping_add(12));
            compressed_info = compressed_info.wrapping_add(16);
            if s_sz2 == 0 {
                break;
            }
            blocks.push(Blk {
                src: src2,
                ssz: s_sz2,
                dst: dst2,
                dsz: d_sz2,
            });
        }
        // Pass 2: independent per-block work over disjoint dst spans (see
        // `parallel_for` for how the spans are carved safely).
        {
            let lut = OpsLut::new(&file_ops);
            let clean = &self.file_data;
            let ko = self.key_offsets;
            let ks_snap = primitives::aes_schedule_snapshot(&self.decompressed, ko[2])
                .ok_or(UnpackError::Corrupt)?;
            let tab_snap = primitives::huffman_table_snapshot(&self.decompressed, ko[0])
                .ok_or(UnpackError::DecompressFailed)?;
            let spans: Vec<(usize, usize)> = blocks
                .iter()
                .map(|b| {
                    let s = b.dst as usize;
                    (s, s + b.ssz.max(b.dsz) as usize)
                })
                .collect();
            let do_block = |i: usize, base: usize, span: &mut [u8]| -> Result<(), UnpackError> {
                let b = &blocks[i];
                let file_src = b.src.wrapping_add(compress_data_offset) as usize;
                let rel = b.dst as usize - base;
                let n = b.ssz as usize;
                span[rel..rel + n].copy_from_slice(&clean[file_src..file_src + n]);
                primitives::aes_decrypt_ks(&ks_snap, span, rel as u32, b.ssz);
                lut.map_region(span, rel, n);
                if b.ssz != b.dsz {
                    // decompress reports corruption (after partial writes) via
                    // its bool; surface it instead of shipping a garbage block.
                    if !primitives::decompress_tbl(
                        &tab_snap, span, rel as u32, rel as u32, b.ssz, b.dsz,
                    ) {
                        return Err(UnpackError::DecompressFailed);
                    }
                }
                Ok(())
            };
            super::parallel::parallel_for(&mut self.decompressed, &spans, 1, do_block)?;
        }

        // ---- Section fixup ----
        self.decompressed[..0x1000].copy_from_slice(&self.file_data[..0x1000]);
        let opt_hdr_size = get_u16(self.file_data, pe_off.wrapping_add(20)) as u32;
        let sec_hdr_table = pe_off.wrapping_add(24).wrapping_add(opt_hdr_size);
        let export_va = get_u32(
            self.file_data,
            pe_off
                .wrapping_add(24)
                .wrapping_add(opt_hdr_size)
                .wrapping_sub(128),
        );
        let export_size = get_u32(
            self.file_data,
            pe_off
                .wrapping_add(24)
                .wrapping_add(opt_hdr_size)
                .wrapping_sub(124),
        );
        let mut export_file_off: u32 = 0;
        let mut text_off: u32 = 0;
        let mut text_size: u32 = 0;
        // Walk by NumberOfSections (PE has no zero-VS sentinel; a real
        // VirtualSize==0 section would truncate these fixups early), stopping
        // at the all-zero padding in case NumberOfSections is overstated.
        let num_sections = get_u16(self.file_data, pe_off.wrapping_add(6)) as u32;
        for i in 0..num_sections.min(96) {
            let sec_hdr = sec_hdr_table.wrapping_add(i.wrapping_mul(40));
            if self.file_data[sec_hdr as usize..sec_hdr as usize + 8]
                .iter()
                .all(|&b| b == 0)
            {
                break;
            }
            let va = get_u32(self.file_data, sec_hdr.wrapping_add(12));
            let sz = get_u32(self.file_data, sec_hdr.wrapping_add(8));
            let f_off = get_u32(self.file_data, sec_hdr.wrapping_add(20));
            let name = section_name(self.file_data, sec_hdr);
            if name.starts_with(".text") {
                text_size = sz;
                text_off = va;
            }
            if export_size != 0
                && export_va >= va
                && export_va.wrapping_add(export_size) <= va.wrapping_add(sz)
            {
                export_file_off = export_va.wrapping_sub(va).wrapping_add(f_off);
            }
            write_u32(&mut self.decompressed, sec_hdr.wrapping_add(16), sz);
            write_u32(&mut self.decompressed, sec_hdr.wrapping_add(20), va);
            if name.starts_with(".idata") {
                write_u32(
                    &mut self.decompressed,
                    sec_hdr.wrapping_add(36),
                    0xC000_0040,
                );
            }
        }
        if export_size != 0 && export_file_off != 0 {
            let d = export_va as usize;
            let s = export_file_off as usize;
            let n = export_size as usize;
            self.decompressed[d..d + n].copy_from_slice(&self.file_data[s..s + n]);
        }

        // ---- .text decrypt with decrypt_data8 (PE32 auto-detected formula) ----
        // `select_dd8_formula_pe32` returns None when `.text` was not packer-dd8-
        // encrypted (native DLLs leave it plaintext); applying dd8 there would
        // scramble valid code, so skip it entirely in that case.
        if text_size > 0 && text_off > 0 {
            if let Some(big) =
                primitives::select_dd8_formula_pe32(&self.decompressed, text_off, text_size)
            {
                if verbose {
                    println!(
                        "[7/9] Decrypting .text (PE32 dd8, formula={})...",
                        if big { "0x8000*(page+1)" } else { "page+1" }
                    );
                }
                let num_pages = text_size / 0x1000;
                for page in 0..num_pages {
                    let pk = if big {
                        0x8000u32.wrapping_mul(page.wrapping_add(1))
                    } else {
                        page.wrapping_add(1)
                    };
                    let pa = text_off.wrapping_add(page.wrapping_mul(0x1000));
                    let mut k = pk;
                    let rk = k.rotate_right(15);
                    k = rk;
                    for bi in 1..256u32 {
                        let rk = k.rotate_right(15);
                        let ri = rk.wrapping_add(bi);
                        k = ri.wrapping_add(bi);
                        let tidx =
                            pa.wrapping_add(bi.wrapping_mul(16)).wrapping_add(ri & 0xF) as usize;
                        self.decompressed[tidx] ^= k as u8;
                    }
                }
            } else if verbose {
                println!("[7/9] Skipping .text dd8 (already plaintext)...");
            }
        }

        // ---- Fix data directories (PE32: data dirs at pe+0x78) ----
        let exe_pe = get_u32(&self.decompressed, 60);
        for i in 0..128u32 {
            self.decompressed[(exe_pe + 0x78 + i) as usize] = metadata_dirs[i as usize];
        }
        // DLL-aware reloc / DllCharacteristics handling. An EXE's packer rebuilds
        // the relocation table and clears DllCharacteristics, so the loader needs
        // no relocations. A DLL, by contrast, is almost always mapped at a
        // non-preferred base, so it MUST keep its base-relocation directory
        // (restored above from metadata_dirs) and a valid DllCharacteristics
        // (DYNAMIC_BASE) — zeroing them leaves the DLL unrelocatable and its
        // imports pinned to the packer stub, so it fails to load (which looks
        // like a missing/broken export table).
        let is_dll = (get_u16(&self.decompressed, exe_pe.wrapping_add(22)) & 0x2000) != 0;
        if !is_dll {
            // EXE: clear BaseReloc (index 5 = pe+0xA0) and DllCharacteristics (pe+0x5E).
            write_u32(&mut self.decompressed, exe_pe.wrapping_add(0xA0), 0);
            write_u32(&mut self.decompressed, exe_pe.wrapping_add(0xA4), 0);
            write_u16(&mut self.decompressed, exe_pe.wrapping_add(0x5E), 0);
        } else {
            // DLL: keep the BaseReloc dir from metadata; ensure DYNAMIC_BASE.
            let mut dll_chars = get_u16(&self.decompressed, exe_pe.wrapping_add(0x5E));
            if dll_chars == 0 {
                dll_chars = 0x0040; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            }
            write_u16(
                &mut self.decompressed,
                exe_pe.wrapping_add(0x5E),
                dll_chars as u32,
            );
        }

        // ---- TLS directory reconstruction (PE32: index 9 = pe+0xC0) ----
        let tls_dir_rva = get_u32(&self.decompressed, exe_pe.wrapping_add(0xC0));
        let tls_dir_sz = get_u32(&self.decompressed, exe_pe.wrapping_add(0xC4));
        if tls_dir_rva > 0
            && tls_dir_sz >= 24
            && (tls_dir_rva as usize + 24) <= self.decompressed.len()
        {
            let all_zero = (0..6u32)
                .all(|i| get_u32(&self.decompressed, tls_dir_rva.wrapping_add(i * 4)) == 0);
            if all_zero {
                let image_base = get_u32(&self.decompressed, exe_pe.wrapping_add(52));
                // Prefer the module's real TLS directory, which survives in the
                // loader stub's plaintext `.rdata`/`.tls`. Only when the stub
                // cannot supply one does a placeholder get synthesized: it keeps
                // the image loadable, but drops the initialized TLS template,
                // `_tls_index` and the TLS callback array, so any module that
                // actually uses `thread_local` faults once it runs.
                if !self.restore_pe32_tls_from_stub(pe_off, tls_dir_rva, image_base) {
                    let mut tls_sec_va: u32 = 0;
                    let mut data_sec_va: u32 = 0;
                    let mut data_sec_sz: u32 = 0;
                    let sh = exe_pe
                        .wrapping_add(24)
                        .wrapping_add(get_u16(&self.decompressed, exe_pe.wrapping_add(20)) as u32);
                    let ns = get_u16(&self.decompressed, exe_pe.wrapping_add(6)) as u32;
                    for i in 0..ns {
                        let s = sh.wrapping_add(i * 40);
                        let nm = get_string_to_null(&self.decompressed, s);
                        let va = get_u32(&self.decompressed, s.wrapping_add(12));
                        let sz = get_u32(&self.decompressed, s.wrapping_add(16));
                        if nm.starts_with(".tls") {
                            tls_sec_va = va;
                        }
                        if nm.starts_with(".data") {
                            data_sec_va = va;
                            data_sec_sz = sz;
                        }
                    }
                    if tls_sec_va > 0 && data_sec_va > 0 {
                        let start_raw = image_base.wrapping_add(tls_sec_va);
                        let end_raw = start_raw;
                        let idx_addr = image_base
                            .wrapping_add(data_sec_va)
                            .wrapping_add(data_sec_sz)
                            .wrapping_sub(16);
                        let cb_addr = image_base
                            .wrapping_add(data_sec_va)
                            .wrapping_add(data_sec_sz)
                            .wrapping_sub(8);
                        let scratch = (data_sec_va + data_sec_sz - 16) as usize;
                        for b in &mut self.decompressed[scratch..scratch + 16] {
                            *b = 0;
                        }
                        write_u32(&mut self.decompressed, tls_dir_rva, start_raw);
                        write_u32(&mut self.decompressed, tls_dir_rva.wrapping_add(4), end_raw);
                        write_u32(
                            &mut self.decompressed,
                            tls_dir_rva.wrapping_add(8),
                            idx_addr,
                        );
                        write_u32(
                            &mut self.decompressed,
                            tls_dir_rva.wrapping_add(12),
                            cb_addr,
                        );
                        write_u32(&mut self.decompressed, tls_dir_rva.wrapping_add(16), 0);
                        write_u32(
                            &mut self.decompressed,
                            tls_dir_rva.wrapping_add(20),
                            0x30_0000,
                        );
                    } else {
                        write_u32(&mut self.decompressed, exe_pe.wrapping_add(0xC0), 0);
                        write_u32(&mut self.decompressed, exe_pe.wrapping_add(0xC4), 0);
                    }
                }
            }
        }

        // ---- Import table (PE32, 4-byte thunks) ----
        if verbose {
            println!("[8/9] Decrypting import strings (PE32)...");
        }
        let import_table_addr = eighth_start.wrapping_add(off_import_table);
        let mut import_table_ptr = get_u32(&self.decompressed, import_table_addr);
        let mut idt_size = get_u32(&self.decompressed, import_table_addr.wrapping_add(4));

        let metadata_import_rva = get_u32(&metadata_dirs, 8);
        let metadata_import_size = get_u32(&metadata_dirs, 12);
        let dlen = self.decompressed.len() as u32;

        let mut eighth_import_valid = false;
        if 0 < import_table_ptr && import_table_ptr < dlen && 0 < idt_size && idt_size < 0x10000 {
            let test_name = if import_table_ptr + 20 <= dlen {
                get_u32(&self.decompressed, import_table_ptr.wrapping_add(12))
            } else {
                0
            };
            let test_ilt = if import_table_ptr + 4 <= dlen {
                get_u32(&self.decompressed, import_table_ptr)
            } else {
                0
            };
            if 0x1000 < test_name && test_name < dlen && 0x1000 < test_ilt && test_ilt < dlen {
                eighth_import_valid = true;
            }
        }
        let mut metadata_import_valid = false;
        if 0x1000 < metadata_import_rva && metadata_import_rva < dlen.wrapping_sub(20) {
            let test_name2 = get_u32(&self.decompressed, metadata_import_rva.wrapping_add(12));
            let test_ilt2 = get_u32(&self.decompressed, metadata_import_rva);
            if 0x1000 < test_name2 && test_name2 < dlen && 0x1000 < test_ilt2 && test_ilt2 < dlen {
                metadata_import_valid = true;
            }
        }
        if metadata_import_valid
            && (!eighth_import_valid || metadata_import_rva != import_table_ptr)
        {
            import_table_ptr = metadata_import_rva;
            idt_size = metadata_import_size;
        }

        if 0 < import_table_ptr && import_table_ptr < dlen && 0 < idt_size && idt_size < 0x10000 {
            let mut idt_pos = import_table_ptr;
            let idt_end = import_table_ptr.wrapping_add(idt_size);
            while idt_pos.wrapping_add(20) <= idt_end {
                let ilt_rva = get_u32(&self.decompressed, idt_pos);
                let name_rva = get_u32(&self.decompressed, idt_pos.wrapping_add(12));
                let iat_rva = get_u32(&self.decompressed, idt_pos.wrapping_add(16));
                if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
                    break;
                }
                if 0 < name_rva && name_rva < dlen {
                    self.decrypt_data7(name_rva, name_rva as u8);
                }
                let thunk_base = if 0 < ilt_rva && ilt_rva < dlen {
                    ilt_rva
                } else {
                    iat_rva
                };
                if 0 < thunk_base && thunk_base < dlen.wrapping_sub(4) {
                    let mut thunk_pos = thunk_base;
                    while thunk_pos.wrapping_add(4) <= dlen {
                        let thunk_val = get_u32(&self.decompressed, thunk_pos);
                        if thunk_val == 0 {
                            break;
                        }
                        if thunk_val & 0x8000_0000 == 0 && thunk_val.wrapping_add(2) < dlen {
                            self.decrypt_data7(thunk_val.wrapping_add(2), thunk_val as u8);
                            write_u16(&mut self.decompressed, thunk_val, 0);
                        }
                        thunk_pos = thunk_pos.wrapping_add(4);
                    }
                }
                idt_pos = idt_pos.wrapping_add(20);
            }
        }

        // Update PE header: Import directory (index 1 = pe+0x80), clear IAT
        // directory (index 12 = pe+0xD8).
        write_u32(
            &mut self.decompressed,
            exe_pe.wrapping_add(0x80),
            import_table_ptr,
        );
        write_u32(&mut self.decompressed, exe_pe.wrapping_add(0x84), idt_size);
        write_u32(&mut self.decompressed, exe_pe.wrapping_add(0xD8), 0);
        write_u32(&mut self.decompressed, exe_pe.wrapping_add(0xDC), 0);

        // ---- EP (from metadata) ----
        if metadata_ep > 0 {
            write_u32(&mut self.decompressed, exe_pe.wrapping_add(40), metadata_ep);
        } else {
            let real_ep = get_u32(self.file_data, pe_off.wrapping_add(40));
            write_u32(&mut self.decompressed, exe_pe.wrapping_add(40), real_ep);
        }

        // ---- Output transforms ----
        if verbose {
            println!("[9/9] Rebuilding PE file layout (PE32)...");
        }
        let mut out = std::mem::take(&mut self.decompressed);
        // kmiat import relocation is an EXE-only fixup: it discards the original
        // import directory in favour of the loader-written IAT stub. A DLL keeps
        // its real import table (restored above from metadata), so skip kmiat for
        // DLLs (`!is_dll` guard).
        let is_dll = (get_u16(&out, pe_off.wrapping_add(22)) & 0x2000) != 0;
        if !is_dll && !primitives::pe32_imports_already_match_idata_layout(&mut out, pe_off) {
            primitives::move_pe32_imports_to_kmiat(&mut out, pe_off);
        }
        let compact =
            primitives::compact_memory_image_to_pe(&out, pe_off).ok_or(UnpackError::Corrupt)?;
        Ok(compact)
    }
}
