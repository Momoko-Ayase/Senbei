//! Basic PE format parsing and address mapping.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("input is not a PE image")]
    Invalid,
    #[error("PE range is outside the input")]
    OutOfBounds,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headers {
    pub pe_offset: usize,
    pub is_pe32_plus: bool,
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_rva: u32,
    pub sections_offset: usize,
    pub sections: u16,
}

pub fn parse(data: &[u8]) -> Result<Headers> {
    if data.get(0..2) != Some(b"MZ") {
        return Err(Error::Invalid);
    }
    let pe_offset = read_u32(data, 0x3c)? as usize;
    if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return Err(Error::Invalid);
    }
    let sections = read_u16(data, pe_offset + 6)?;
    let optional_size = read_u16(data, pe_offset + 20)? as usize;
    let optional = pe_offset.checked_add(24).ok_or(Error::OutOfBounds)?;
    let magic = read_u16(data, optional)?;
    let is_pe32_plus = magic == 0x20b;
    if !is_pe32_plus && magic != 0x10b {
        return Err(Error::Invalid);
    }
    let entry_rva = read_u32(data, optional + 16)?;
    let image_base = if is_pe32_plus {
        read_u64(data, optional + 24)?
    } else {
        read_u32(data, optional + 28)? as u64
    };
    let size_of_image = read_u32(data, optional + 56)?;
    let sections_offset = optional
        .checked_add(optional_size)
        .ok_or(Error::OutOfBounds)?;
    let table_size = usize::from(sections)
        .checked_mul(40)
        .ok_or(Error::OutOfBounds)?;
    data.get(sections_offset..sections_offset + table_size)
        .ok_or(Error::OutOfBounds)?;
    Ok(Headers {
        pe_offset,
        is_pe32_plus,
        image_base,
        size_of_image,
        entry_rva,
        sections_offset,
        sections,
    })
}

pub fn sections(data: &[u8], headers: Headers) -> Result<Vec<Section>> {
    (0..headers.sections)
        .map(|index| {
            let offset = headers
                .sections_offset
                .checked_add(usize::from(index) * 40)
                .ok_or(Error::OutOfBounds)?;
            Ok(Section {
                virtual_size: read_u32(data, offset + 8)?,
                virtual_address: read_u32(data, offset + 12)?,
                raw_size: read_u32(data, offset + 16)?,
                raw_offset: read_u32(data, offset + 20)?,
                characteristics: read_u32(data, offset + 36)?,
            })
        })
        .collect()
}

/// Read one PE data-directory entry as `(RVA, size)`.
pub fn data_directory(data: &[u8], headers: Headers, index: u16) -> Result<(u32, u32)> {
    let directory_base = headers
        .pe_offset
        .checked_add(24)
        .and_then(|offset| offset.checked_add(if headers.is_pe32_plus { 112 } else { 96 }))
        .ok_or(Error::OutOfBounds)?;
    let offset = directory_base
        .checked_add(
            usize::from(index)
                .checked_mul(8)
                .ok_or(Error::OutOfBounds)?,
        )
        .ok_or(Error::OutOfBounds)?;
    Ok((read_u32(data, offset)?, read_u32(data, offset + 4)?))
}

/// Return the COFF characteristics bit field.
pub fn characteristics(data: &[u8], headers: Headers) -> Result<u16> {
    read_u16(
        data,
        headers
            .pe_offset
            .checked_add(22)
            .ok_or(Error::OutOfBounds)?,
    )
}

pub fn rva_to_offset(data: &[u8], headers: Headers, rva: u32) -> Result<usize> {
    if rva < headers.sections_offset as u32 {
        return Ok(rva as usize);
    }
    for section in sections(data, headers)? {
        let span = section.virtual_size.max(section.raw_size);
        if rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span) {
            let offset = section
                .raw_offset
                .checked_add(rva - section.virtual_address)
                .ok_or(Error::OutOfBounds)? as usize;
            if offset < data.len() {
                return Ok(offset);
            }
        }
    }
    Err(Error::OutOfBounds)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or(Error::OutOfBounds)?
        .try_into()
        .map_err(|_| Error::OutOfBounds)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or(Error::OutOfBounds)?
        .try_into()
        .map_err(|_| Error::OutOfBounds)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or(Error::OutOfBounds)?
        .try_into()
        .map_err(|_| Error::OutOfBounds)?;
    Ok(u64::from_le_bytes(bytes))
}
