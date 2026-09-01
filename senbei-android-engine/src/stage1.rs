use std::path::Path;

use goblin::elf::{Elf, header::EM_AARCH64};

use crate::error::{Error, Result, invalid};

pub(crate) const SHT_LOUSER: u32 = 0x8000_0000;
pub const DEFAULT_CIPHER_CONSTANT: u32 = 0xbf20_165d;
pub const DEFAULT_OUTER_SIZE: usize = 0x23c;

pub(crate) fn looks_protected(data: &[u8]) -> bool {
    let Ok(elf) = Elf::parse(data) else {
        return false;
    };
    if elf.header.e_machine != EM_AARCH64
        || elf
            .section_headers
            .iter()
            .filter(|section| section.sh_type == SHT_LOUSER)
            .count()
            != 1
    {
        return false;
    }
    [
        ".dynsym",
        ".dynstr",
        ".gnu.hash",
        ".gnu.version",
        ".gnu.version_r",
    ]
    .into_iter()
    .all(|wanted| {
        elf.section_headers.iter().any(|section| {
            elf.shdr_strtab
                .get_at(section.sh_name)
                .is_some_and(|name| name == wanted)
        })
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Stage1Header {
    pub key: u32,
    pub reserved: u32,
    pub payload_offset: u32,
    pub payload_size: u32,
    pub payload_key: u32,
    pub entry_offset: u32,
    pub protect_size: u32,
    pub size_copy: u32,
}

#[derive(Debug)]
pub(crate) struct Stage1Result {
    pub section_index: usize,
    pub section_offset: usize,
    pub section_size: usize,
    pub header_offset: usize,
    pub payload_file_offset: usize,
    pub remaining_file_offset: usize,
    pub remaining_size: usize,
    pub header: Stage1Header,
    pub plaintext: Vec<u8>,
}

pub(crate) fn inspect(
    data: &[u8],
    path: &Path,
    outer_size: usize,
    cipher_constant: u32,
) -> Result<Stage1Result> {
    let elf = Elf::parse(data).map_err(|source| Error::Elf {
        path: path.to_path_buf(),
        source,
    })?;
    if elf.header.e_machine != EM_AARCH64 {
        return invalid(format!(
            "expected AArch64 ELF (machine 0x{EM_AARCH64:X}), got 0x{:X}",
            elf.header.e_machine
        ));
    }
    let matches = elf
        .section_headers
        .iter()
        .enumerate()
        .filter(|(_, section)| section.sh_type == SHT_LOUSER)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return invalid(format!(
            "expected exactly one SHT_LOUSER section, found {}",
            matches.len()
        ));
    }
    let (section_index, section) = matches[0];
    let section_offset = usize::try_from(section.sh_offset)
        .map_err(|_| Error::Invalid("SHT_LOUSER offset exceeds usize".to_owned()))?;
    let section_size = usize::try_from(section.sh_size)
        .map_err(|_| Error::Invalid("SHT_LOUSER size exceeds usize".to_owned()))?;
    let section_end = section_offset
        .checked_add(section_size)
        .ok_or_else(|| Error::Invalid("SHT_LOUSER range overflows usize".to_owned()))?;
    if section_end > data.len() {
        return invalid("SHT_LOUSER range extends beyond the input file");
    }
    let header_relative = outer_size;
    if outer_size
        .checked_add(0x1000)
        .is_none_or(|end| end > section_size)
    {
        return invalid("Stage 1 outer header leaves no complete parameter area");
    }
    let header_offset = section_offset
        .checked_add(header_relative)
        .ok_or_else(|| Error::Invalid("Stage 1 header offset overflow".to_owned()))?;
    let header_raw = bytes(data, header_offset, 0x1000)?;
    let header = decrypt_header(header_raw, cipher_constant)?;
    if header.reserved != 0 {
        return invalid(format!(
            "Stage 1 header reserved word is nonzero: 0x{:x}",
            header.reserved
        ));
    }
    if header.size_copy != header.payload_size {
        return invalid(format!(
            "Stage 1 payload size copy 0x{:x} != size 0x{:x}",
            header.size_copy, header.payload_size
        ));
    }
    let private_size = section_size - outer_size;
    let payload_offset = usize::try_from(header.payload_offset)
        .map_err(|_| Error::Invalid("Stage 1 payload offset exceeds usize".to_owned()))?;
    let payload_size = usize::try_from(header.payload_size)
        .map_err(|_| Error::Invalid("Stage 1 payload size exceeds usize".to_owned()))?;
    let payload_end = payload_offset
        .checked_add(payload_size)
        .ok_or_else(|| Error::Invalid("Stage 1 payload range overflow".to_owned()))?;
    if payload_offset < 0x20 || payload_end > private_size {
        return invalid(format!(
            "Stage 1 payload range 0x{payload_offset:x}..0x{payload_end:x} exceeds private size 0x{private_size:x}"
        ));
    }
    if payload_size == 0 || payload_size % 4 != 0 {
        return invalid(format!(
            "Stage 1 payload size must be nonzero and word aligned: 0x{payload_size:x}"
        ));
    }
    let entry_offset = usize::try_from(header.entry_offset)
        .map_err(|_| Error::Invalid("Stage 1 entry offset exceeds usize".to_owned()))?;
    if entry_offset >= payload_size {
        return invalid("Stage 1 entry offset is outside the payload");
    }
    let protect_size = usize::try_from(header.protect_size)
        .map_err(|_| Error::Invalid("Stage 1 protect size exceeds usize".to_owned()))?;
    if protect_size > payload_size {
        return invalid("Stage 1 mprotect length exceeds the payload");
    }
    let payload_file_offset = header_offset
        .checked_add(payload_offset)
        .ok_or_else(|| Error::Invalid("Stage 1 payload file offset overflow".to_owned()))?;
    let encrypted = bytes(data, payload_file_offset, payload_size)?;
    let plaintext = decrypt_words(encrypted, header.payload_key, cipher_constant)?;
    let aligned_payload_end = (payload_end + 3) & !3;
    let remaining_relative = aligned_payload_end;
    if remaining_relative > private_size {
        return invalid("aligned Stage 2 cursor exceeds SHT_LOUSER");
    }
    let remaining_file_offset = section_offset
        .checked_add(outer_size)
        .and_then(|value| value.checked_add(remaining_relative))
        .ok_or_else(|| Error::Invalid("Stage 2 stream offset overflow".to_owned()))?;
    Ok(Stage1Result {
        section_index,
        section_offset,
        section_size,
        header_offset,
        payload_file_offset,
        remaining_file_offset,
        remaining_size: private_size - remaining_relative,
        header,
        plaintext,
    })
}

fn decrypt_header(raw: &[u8], constant: u32) -> Result<Stage1Header> {
    let key = read_u32(raw, 0)?;
    let mut decoded = decrypt_words(&raw[..0x20], key, constant)?;
    decoded[..4].copy_from_slice(&key.to_le_bytes());
    Ok(Stage1Header {
        key,
        reserved: read_u32(&decoded, 4)?,
        payload_offset: read_u32(&decoded, 8)?,
        payload_size: read_u32(&decoded, 12)?,
        payload_key: read_u32(&decoded, 16)?,
        entry_offset: read_u32(&decoded, 20)?,
        protect_size: read_u32(&decoded, 24)?,
        size_copy: read_u32(&decoded, 28)?,
    })
}

fn decrypt_words(ciphertext: &[u8], key: u32, constant: u32) -> Result<Vec<u8>> {
    if ciphertext.len() % 4 != 0 {
        return invalid("Stage 1 word cipher input is not 4-byte aligned");
    }
    let mut plaintext = ciphertext.to_vec();
    for (index, chunk) in plaintext.chunks_exact_mut(4).enumerate() {
        let index = u32::try_from(index)
            .map_err(|_| Error::Invalid("Stage 1 word index exceeds u32".to_owned()))?;
        let mut word = u32::from_le_bytes(
            chunk
                .try_into()
                .map_err(|_| Error::Invalid("Stage 1 word has an invalid size".to_owned()))?,
        );
        word = word.wrapping_add(index.wrapping_add(3).wrapping_mul(key));
        word ^= constant.wrapping_mul(index.wrapping_add(1));
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(plaintext)
}

fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::Invalid("byte range overflow".to_owned()))?;
    data.get(offset..end).ok_or_else(|| {
        Error::Invalid(format!(
            "byte range 0x{offset:x}..0x{end:x} is outside the input"
        ))
    })
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = bytes(data, offset, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        Error::Invalid("invalid u32 byte range".to_owned())
    })?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage1_word_transform_round_trips() {
        let key = 0x1234_5678;
        let constant = DEFAULT_CIPHER_CONSTANT;
        let plain = [0x1122_3344_u32, 0xaabb_ccdd, 0x0102_0304];
        let mut cipher = Vec::new();
        for (index, value) in plain.into_iter().enumerate() {
            let index = index as u32;
            let word = (value ^ constant.wrapping_mul(index + 1))
                .wrapping_sub((index + 3).wrapping_mul(key));
            cipher.extend_from_slice(&word.to_le_bytes());
        }
        let decoded = decrypt_words(&cipher, key, constant).unwrap();
        let expected = plain
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(decoded, expected);
    }
}
