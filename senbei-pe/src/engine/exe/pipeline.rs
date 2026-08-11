use senbei_crypto::bytecode::{Op, OpsLut, generate};
use senbei_crypto::primitives;
use senbei_crypto::primitives::*;

use super::super::error::*;
use super::super::layout::{self, *};

mod pe32;

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
    const HEADER_LEN: usize = 4128;
    if input.len() < HEADER_LEN {
        return Err(UnpackError::InputTooShort {
            actual: input.len(),
            required: HEADER_LEN,
        });
    }
    // The pipeline chases offsets read out of the decrypted image; on a
    // truncated/garbled-but-detected file those run out of bounds. Trap any
    // such panic and report it as corrupt input so the library never unwinds
    // into the caller (same role as the DLL path's explicit bounds checks).
    // `input` is read-only for the entire unpack (the payload is decrypted into a
    // separate `decompressed` buffer), so the unpacker borrows it directly — no
    // owned copy is made here. catch_unwind uses AssertUnwindSafe, so a borrowing
    // (non-'static) closure is fine.
    super::super::catch_unpack(move || Unpacker::run(input, verbose))
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
    fn decrypt_and_decompress_data(
        &mut self,
        pos: u32,
        key: u32,
        custom: Option<&[Op]>,
    ) -> Result<(), DecompressionFailure> {
        primitives::decrypt_and_decompress_data_detailed(
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
        if !super::super::is_supported_magic(u.info[1]) {
            return Err(UnpackError::HeaderMagicMismatch { found: u.info[1] });
        }

        let pe_off = get_u32(u.file_data, 60);
        if (pe_off as usize)
            .checked_add(84)
            .is_none_or(|end| end > u.file_data.len())
        {
            return Err(UnpackError::InvalidPeOffset {
                offset: i64::from(pe_off),
                input_len: u.file_data.len(),
            });
        }
        let size_of_image = get_u32(u.file_data, pe_off.wrapping_add(80));
        if size_of_image == 0 || size_of_image as u64 > super::super::MAX_IMAGE_SIZE {
            return Err(UnpackError::InvalidImageSize {
                size: i64::from(size_of_image),
                max: super::super::MAX_IMAGE_SIZE,
            });
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

        // Layouts shift the anchor-relative fields by either zero or eight
        // bytes. The nearby version-like word is not stable across all build
        // families, so validate the stage1 (RVA, length) descriptor itself.
        let descriptor_is_valid = |extra: u32| -> bool {
            let pos = anchor.wrapping_add(120 + extra);
            let Some(end) = (pos as usize).checked_add(8) else {
                return false;
            };
            if end > u.decompressed.len() {
                return false;
            }
            let base = get_u32(&u.decompressed, pos);
            let length = get_u32(&u.decompressed, pos.wrapping_add(4));
            base >= u.info[3]
                && length >= 16
                && (base as usize)
                    .checked_add(length as usize)
                    .is_some_and(|stage_end| stage_end <= u.decompressed.len())
        };
        let anchor_extra = [0u32, 8]
            .into_iter()
            .find(|&extra| descriptor_is_valid(extra))
            .ok_or(UnpackError::Stage1DescriptorNotFound { anchor })?;

        if verbose {
            println!("  anchor = 0x{anchor:08X}");
            println!("  anchor layout offset = +0x{anchor_extra:X}");
        }

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
        let stage1_descriptor = [
            get_u32(&u.decompressed, tgt),
            get_u32(&u.decompressed, tgt.wrapping_add(4)),
        ];
        u.decrypt_data3(tgt, xor_acc ^ chk1 ^ v, 21);
        let stage1 = get_u32(&u.decompressed, tgt);
        let stage1_len = get_u32(&u.decompressed, tgt.wrapping_add(4));
        if verbose {
            println!("[3/9] Locating config layout...");
            println!("  stage1 = 0x{:08X}", stage1);
            println!("  stage1_len = 0x{stage1_len:08X}");
            println!(
                "  stage1 descriptor = [0x{:08X}, 0x{:08X}]",
                stage1_descriptor[0], stage1_descriptor[1]
            );
            println!("  stage1 key = xor 0x{xor_acc:08X} ^ chk 0x{chk1:08X} ^ val 0x{v:08X}");
        }

        // Field offsets inside stage1 vary between Crackproof versions. Locate
        // stage2 (the only 16-byte entry where dword[0]==dword[2], dword[1] is the
        // large encrypted size and dword[3] is a smaller decompressed size), then
        // derive every other field as fixed offsets from there. Observed
        // stage2_off: 3632 (older EXE builds), 3616 (another old-layout build),
        // 3624 (managed-assembly builds).
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
            println!("  stage2_off = 0x{stage2_off:04X}");
            println!("  checksum table = stage1+0x{chk_src_start:04X}");
            println!("  stage2 key = 0x{key2:08X}");
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
        if verbose {
            println!("  operation table = stage2+0x{table_start:04X}");
            println!("  head/walk = +0x{head_off:04X}/+0x{walk2_off:04X}");
            for index in 0..2u32 {
                let entry = stage2.wrapping_add(head_off + index * 16);
                println!(
                    "  operation[{index}] = [0x{:08X}, 0x{:08X}, 0x{:08X}, 0x{:08X}]",
                    get_u32(&u.decompressed, entry),
                    get_u32(&u.decompressed, entry.wrapping_add(4)),
                    get_u32(&u.decompressed, entry.wrapping_add(8)),
                    get_u32(&u.decompressed, entry.wrapping_add(12)),
                );
            }
        }

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
        if verbose {
            println!(
                "  key offsets = [0x{:08X}, 0x{:08X}, 0x{:08X}, 0x{:08X}]",
                u.key_offsets[0], u.key_offsets[1], u.key_offsets[2], u.key_offsets[3]
            );
        }

        let chk2 = u.calculate_checksum(anchor.wrapping_add(48 + anchor_extra));
        let accum_at = stage1.wrapping_add(chk_src_start.wrapping_sub(16));
        let accum_seed = get_u32(&u.decompressed, accum_at);
        let mut running_accum = accum_seed;
        let mut accum_candidates = vec![(0u32, accum_seed)];
        for l in 0..8u32 {
            let bound = (l + 1).wrapping_mul(25) << 2;
            let mut i: u32 = 1;
            while i <= bound {
                running_accum = running_accum.wrapping_add(i);
                i = i.wrapping_add(1);
            }
            accum_candidates.push((l + 1, running_accum));
        }
        let accum = accum_candidates[4].1;

        let at1 = stage1.wrapping_add(stage2_off.wrapping_add(88));
        let stage3_field = get_u32(&u.decompressed, at1);
        let stage3_slen = get_u32(&u.decompressed, at1.wrapping_add(4));
        let stage3_dest = get_u32(&u.decompressed, at1.wrapping_add(8));
        let stage3_dlen = get_u32(&u.decompressed, at1.wrapping_add(12));
        if verbose {
            println!("[5/9] Decrypting stages 3-5...");
            println!("  stage3  = 0x{:08X}", stage3_field);
            println!(
                "  stage3 descriptor = [0x{stage3_field:08X}, 0x{stage3_slen:08X}, 0x{stage3_dest:08X}, 0x{stage3_dlen:08X}]"
            );
            println!("  stage3 key = xor 0x{xor_acc:08X} ^ chk 0x{chk2:08X} ^ val 0x{accum:08X}");
            println!("  stage3 accum seed = 0x{accum_seed:08X}");
        }
        let stage3_key = xor_acc ^ chk2 ^ accum;
        let stage3_source_end = (stage3_field as usize)
            .checked_add(stage3_slen as usize)
            .filter(|&end| end <= u.decompressed.len())
            .ok_or(UnpackError::BufferRangeOutOfBounds {
                operation: BufferOperation::Read,
                offset: stage3_field as usize,
                size: stage3_slen as usize,
                buffer_len: u.decompressed.len(),
            })?;
        let stage3_dest_end = (stage3_dest as usize)
            .checked_add(stage3_dlen as usize)
            .filter(|&end| end <= u.decompressed.len())
            .ok_or(UnpackError::BufferRangeOutOfBounds {
                operation: BufferOperation::CopyDestination,
                offset: stage3_dest as usize,
                size: stage3_dlen as usize,
                buffer_len: u.decompressed.len(),
            })?;
        const MAX_STAGE3_TRIAL_BYTES: usize = 16 * 1024 * 1024;
        let trial_size = (stage3_slen as usize).checked_add(stage3_dlen as usize);
        let stage3_backups = trial_size
            .filter(|&size| size <= MAX_STAGE3_TRIAL_BYTES)
            .map(|_| {
                (
                    u.decompressed[stage3_field as usize..stage3_source_end].to_vec(),
                    u.decompressed[stage3_dest as usize..stage3_dest_end].to_vec(),
                )
            });
        let default_result = u.decrypt_and_decompress_data(at1, stage3_key, None);
        if let Err(reason) = default_result {
            let Some((source_backup, dest_backup)) = stage3_backups else {
                return Err(UnpackError::StageDecompressionFailed {
                    stage: DecompressionStage::ExeStage3,
                    reason,
                });
            };
            let restore_stage3 = |data: &mut [u8]| {
                data[stage3_field as usize..stage3_source_end].copy_from_slice(&source_backup);
                data[stage3_dest as usize..stage3_dest_end].copy_from_slice(&dest_backup);
            };
            let mut selected = None;
            for (rounds, candidate_accum) in &accum_candidates {
                if *rounds == 4 {
                    continue;
                }
                restore_stage3(&mut u.decompressed);
                let candidate_key = xor_acc ^ chk2 ^ candidate_accum;
                let result = u.decrypt_and_decompress_data(at1, candidate_key, None);
                if result.is_ok()
                    && find_v4_offset(&u.decompressed, stage3_field, stage3_dlen).is_some()
                {
                    selected = Some(*rounds);
                    break;
                }
            }
            if let Some(rounds) = selected {
                if verbose {
                    println!("  selected stage3 accumulator rounds = {rounds}");
                }
            } else {
                restore_stage3(&mut u.decompressed);
                return Err(UnpackError::StageDecompressionFailed {
                    stage: DecompressionStage::ExeStage3,
                    reason,
                });
            }
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
        if let Err(reason) = u.decrypt_and_decompress_data(at2, xor_acc ^ chk3 ^ v4_val, None) {
            return Err(UnpackError::StageDecompressionFailed {
                stage: DecompressionStage::ExeStage3Secondary,
                reason,
            });
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
        if let Err(reason) = u.decrypt_and_decompress_data(at3, xor_acc ^ chk4 ^ v5_val, None) {
            return Err(UnpackError::StageDecompressionFailed {
                stage: DecompressionStage::ExeStage4,
                reason,
            });
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
                return Err(UnpackError::BytecodeGenerationFailed(
                    BytecodeStage::ExeStage4,
                ));
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
        if let Err(reason) =
            u.decrypt_and_decompress_data(at4, xor_acc ^ chk4 ^ chk5 ^ accum2, Some(&ops1))
        {
            return Err(UnpackError::StageDecompressionFailed {
                stage: DecompressionStage::ExeStage5,
                reason,
            });
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
            let slots = layout::discover_eighth_slots(
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
                return Err(UnpackError::BytecodeGenerationFailed(
                    BytecodeStage::ExeStage5,
                ));
            }
        };
        // The new layout picked its file decryptor by distance (no marker, no
        // content check). Prove the choice before shipping it: a wrong pick
        // would garble every section block, and raw blocks would carry that
        // garbling into the output without any error (see the validator).
        let rebase = (!get_u32(u.file_data, 4224)).wrapping_add(4096);
        if new_layout && !u.new_layout_file_ops_validate(walk4_slot, &ops2, rebase) {
            return Err(UnpackError::FileDecryptorValidationFailed);
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
                .ok_or(UnpackError::InvalidAesKeySchedule { offset: ko[2] })?;
            let tab_snap = primitives::huffman_table_snapshot(&u.decompressed, ko[0])
                .ok_or(UnpackError::InvalidHuffmanTable { offset: ko[0] })?;
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
                        return Err(UnpackError::SectionDecompressionFailed {
                            pipeline: SectionPipeline::ExePe32Plus,
                            block: i,
                        });
                    }
                }
                Ok(())
            };
            super::super::parallel::parallel_for(&mut u.decompressed, &spans, 1, do_block)?;
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
        let mut walk5 = get_u32(&u.decompressed, at7);
        if !new_layout {
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
                None => layout::select_dd8_shift(&u.decompressed, text_va, text_size, u.info[3]),
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
            write_u32(&mut u.decompressed, pe_off2.wrapping_add(40), ep);
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
                        layout::select_dd8_shift(&u.decompressed, text_va, text_size, u.info[3])
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
    /// raw blocks never enter the decompressor, so the failure would ship as a
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
                    self.decompressed[idx] =
                        senbei_crypto::bytecode::apply(ops, self.decompressed[idx]);
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
                    self.decompressed[idx] =
                        senbei_crypto::bytecode::apply(&ops, self.decompressed[idx]);
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
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn short_input_reports_actual_and_required_lengths() {
        let error = unpack(&[0; 4096]).expect_err("header must be rejected");
        assert_eq!(
            error,
            UnpackError::InputTooShort {
                actual: 4096,
                required: 4128,
            }
        );
    }

    #[test]
    fn structured_errors_include_stage_and_block_context() {
        let stage = UnpackError::StageDecompressionFailed {
            stage: DecompressionStage::ExeStage4,
            reason: DecompressionFailure::NoProgress,
        };
        assert_eq!(
            stage.to_string(),
            "EXE stage4 decompression failed: Huffman symbol consumed no input and produced no output"
        );

        let block = UnpackError::SectionDecompressionFailed {
            pipeline: SectionPipeline::ExePe32,
            block: 7,
        };
        assert_eq!(
            block.to_string(),
            "PE32 EXE section block 7 decompression failed"
        );
    }
}
