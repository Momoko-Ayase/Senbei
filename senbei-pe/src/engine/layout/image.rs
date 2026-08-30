//! PE import reconstruction and memory-image compaction.

use senbei_crypto::primitives::{get_u16, get_u32, write_u16, write_u32};

use super::super::MAX_IMAGE_SIZE;

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
pub fn pe32_imports_already_match_idata_layout(data: &mut [u8], pe_header: u32) -> bool {
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
pub fn move_pe32_imports_to_kmiat(data: &mut Vec<u8>, pe_header: u32) {
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
    if kmiat_end > MAX_IMAGE_SIZE {
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
/// [`MAX_IMAGE_SIZE`]: the final allocation is sized from header-derived
/// section data, and an uncapped `vec![0; n]` from a corrupt header would abort
/// the process (which `catch_unpack` cannot trap).
pub fn compact_memory_image_to_pe(data: &[u8], pe_header: u32) -> Option<Vec<u8>> {
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
            if raw_cursor > MAX_IMAGE_SIZE {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Review regression: a zero last-section VA (corrupt section table) must
    /// bail instead of building .kmiat at RVA 0 — the old code zeroed
    /// `[0, 0x7000)`, wiping the DOS/PE headers, and returned the broken image
    /// as a success. A near-2 GiB VA must likewise refuse to grow the image
    /// past [`MAX_IMAGE_SIZE`].
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
