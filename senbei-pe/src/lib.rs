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

/// Map a complete RVA range backed by file bytes in the headers or one section.
/// Unlike a virtual mapping, this rejects a section's zero-filled tail.
pub fn rva_range(
    data: &[u8],
    headers: Headers,
    rva: u32,
    size: u32,
) -> Result<std::ops::Range<usize>> {
    let header_size = read_u32(data, headers.pe_offset + 24 + 60)?;
    let offset = if rva < header_size && size <= header_size - rva {
        rva
    } else {
        sections(data, headers)?
            .into_iter()
            .find_map(|section| {
                let delta = rva.checked_sub(section.virtual_address)?;
                if delta >= section.raw_size || size > section.raw_size - delta {
                    return None;
                }
                section.raw_offset.checked_add(delta)
            })
            .ok_or(Error::OutOfBounds)?
    } as usize;
    let end = offset
        .checked_add(size as usize)
        .ok_or(Error::OutOfBounds)?;
    data.get(offset..end).ok_or(Error::OutOfBounds)?;
    Ok(offset..end)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rva_ranges_require_file_backing_for_every_byte() {
        let mut data = [0u8; 0x400];
        let headers = Headers {
            pe_offset: 0x40,
            is_pe32_plus: false,
            image_base: 0,
            size_of_image: 0x2000,
            entry_rva: 0x1000,
            sections_offset: 0x100,
            sections: 1,
        };
        for (offset, value) in [
            (0x94, 0x200u32),
            (0x108, 0x100),
            (0x10c, 0x1000),
            (0x110, 0x80),
            (0x114, 0x200),
        ] {
            data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(rva_range(&data, headers, 0x1000, 0x80), Ok(0x200..0x280));
        assert_eq!(rva_range(&data, headers, 0x100, 0x100), Ok(0x100..0x200));
        for (rva, size) in [(0x1070, 0x20), (0x1080, 1), (0x1f0, 0x20), (u32::MAX, 4)] {
            assert_eq!(
                rva_range(&data, headers, rva, size),
                Err(Error::OutOfBounds)
            );
        }
    }
}
