use crate::error::{Error, Result, invalid};

pub(crate) const SHT_NOBITS: u32 = 8;
pub(crate) const SHT_LOUSER: u32 = 0x8000_0000;
pub(crate) const SHF_ALLOC: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoadSegment {
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SectionHeader {
    pub name: u32,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub alignment: u64,
    pub entry_size: u64,
}

impl SectionHeader {
    pub const SIZE: usize = 0x40;

    fn parse(data: &[u8], offset: usize) -> Result<Self> {
        Ok(Self {
            name: read_u32(data, offset)?,
            section_type: read_u32(data, offset + 4)?,
            flags: read_u64(data, offset + 8)?,
            address: read_u64(data, offset + 0x10)?,
            offset: read_u64(data, offset + 0x18)?,
            size: read_u64(data, offset + 0x20)?,
            link: read_u32(data, offset + 0x28)?,
            info: read_u32(data, offset + 0x2c)?,
            alignment: read_u64(data, offset + 0x30)?,
            entry_size: read_u64(data, offset + 0x38)?,
        })
    }

    pub fn encode(self) -> [u8; Self::SIZE] {
        let mut output = [0_u8; Self::SIZE];
        output[0..4].copy_from_slice(&self.name.to_le_bytes());
        output[4..8].copy_from_slice(&self.section_type.to_le_bytes());
        output[8..0x10].copy_from_slice(&self.flags.to_le_bytes());
        output[0x10..0x18].copy_from_slice(&self.address.to_le_bytes());
        output[0x18..0x20].copy_from_slice(&self.offset.to_le_bytes());
        output[0x20..0x28].copy_from_slice(&self.size.to_le_bytes());
        output[0x28..0x2c].copy_from_slice(&self.link.to_le_bytes());
        output[0x2c..0x30].copy_from_slice(&self.info.to_le_bytes());
        output[0x30..0x38].copy_from_slice(&self.alignment.to_le_bytes());
        output[0x38..0x40].copy_from_slice(&self.entry_size.to_le_bytes());
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ElfLayout {
    pub entrypoint: u64,
    pub program_headers: Vec<LoadSegment>,
    pub section_headers: Vec<SectionHeader>,
    pub section_name_index: usize,
    pub private_section_index: usize,
}

impl ElfLayout {
    pub fn parse(data: &[u8], require_private: bool) -> Result<Self> {
        let ident = slice(data, 0, 6)?;
        if ident[..4] != *b"\x7fELF" || ident[4] != 2 || ident[5] != 1 {
            return invalid("input is not a little-endian ELF64 file");
        }
        if read_u16(data, 0x12)? != 0xb7 {
            return invalid("input is not an AArch64 ELF");
        }
        let entrypoint = read_u64(data, 0x18)?;
        let program_header_offset = usize_from_u64(read_u64(data, 0x20)?, "program header offset")?;
        let section_header_offset = usize_from_u64(read_u64(data, 0x28)?, "section header offset")?;
        let program_header_size = usize::from(read_u16(data, 0x36)?);
        let program_header_count = usize::from(read_u16(data, 0x38)?);
        let section_header_size = usize::from(read_u16(data, 0x3a)?);
        let section_header_count = usize::from(read_u16(data, 0x3c)?);
        let section_name_index = usize::from(read_u16(data, 0x3e)?);
        if program_header_size != 0x38 || section_header_size != SectionHeader::SIZE {
            return invalid("unexpected ELF program/section header size");
        }

        let mut program_headers = Vec::new();
        for index in 0..program_header_count {
            let offset = checked_index(program_header_offset, index, program_header_size)?;
            if read_u32(data, offset)? != 1 {
                continue;
            }
            let segment = LoadSegment {
                flags: read_u32(data, offset + 4)?,
                offset: read_u64(data, offset + 8)?,
                virtual_address: read_u64(data, offset + 0x10)?,
                file_size: read_u64(data, offset + 0x20)?,
                memory_size: read_u64(data, offset + 0x28)?,
            };
            let file_end = segment
                .offset
                .checked_add(segment.file_size)
                .ok_or_else(|| Error::Invalid(format!("PT_LOAD {index} file range overflow")))?;
            if file_end > data.len() as u64 {
                return invalid(format!("PT_LOAD {index} exceeds input file"));
            }
            program_headers.push(segment);
        }
        if program_headers.is_empty() {
            return invalid("input ELF contains no PT_LOAD segments");
        }

        let mut section_headers = Vec::with_capacity(section_header_count);
        for index in 0..section_header_count {
            let offset = checked_index(section_header_offset, index, section_header_size)?;
            section_headers.push(SectionHeader::parse(data, offset)?);
        }
        if section_name_index >= section_headers.len() {
            return invalid("ELF section-name index is out of range");
        }
        let private = section_headers
            .iter()
            .enumerate()
            .filter_map(|(index, section)| (section.section_type == SHT_LOUSER).then_some(index))
            .collect::<Vec<_>>();
        let private_section_index = match private.as_slice() {
            [index] => *index,
            [] if !require_private => usize::MAX,
            _ => {
                return invalid(format!(
                    "expected {} SHT_LOUSER section, found {}",
                    if require_private {
                        "one"
                    } else {
                        "at most one"
                    },
                    private.len()
                ));
            }
        };
        Ok(Self {
            entrypoint,
            program_headers,
            section_headers,
            section_name_index,
            private_section_index,
        })
    }

    pub fn private_section(&self) -> Result<SectionHeader> {
        self.section_headers
            .get(self.private_section_index)
            .copied()
            .ok_or_else(|| Error::Invalid("ELF has no private section".to_owned()))
    }

    pub fn load_end(&self) -> Result<u64> {
        self.program_headers
            .iter()
            .map(|segment| {
                segment
                    .virtual_address
                    .checked_add(segment.memory_size)
                    .ok_or_else(|| Error::Invalid("PT_LOAD memory end overflow".to_owned()))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .ok_or_else(|| Error::Invalid("ELF has no PT_LOAD memory range".to_owned()))
    }

    pub fn file_load_end(&self) -> Result<u64> {
        self.program_headers
            .iter()
            .map(|segment| {
                segment
                    .offset
                    .checked_add(segment.file_size)
                    .ok_or_else(|| Error::Invalid("PT_LOAD file end overflow".to_owned()))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .ok_or_else(|| Error::Invalid("ELF has no PT_LOAD file range".to_owned()))
    }

    pub fn section_names(&self, data: &[u8]) -> Result<Vec<String>> {
        let table = self.section_headers[self.section_name_index];
        let strings = slice_u64(data, table.offset, table.size)?;
        self.section_headers
            .iter()
            .map(|section| {
                let offset = section.name as usize;
                if offset >= strings.len() {
                    return Ok(String::new());
                }
                let end = strings[offset..]
                    .iter()
                    .position(|&byte| byte == 0)
                    .map_or(strings.len(), |length| offset + length);
                Ok(String::from_utf8_lossy(&strings[offset..end]).into_owned())
            })
            .collect()
    }

    pub fn file_offset_to_virtual_address(&self, offset: u64, size: u64) -> Result<u64> {
        let end = offset
            .checked_add(size)
            .ok_or_else(|| Error::Invalid("file range overflow".to_owned()))?;
        for segment in &self.program_headers {
            let segment_end = segment
                .offset
                .checked_add(segment.file_size)
                .ok_or_else(|| Error::Invalid("PT_LOAD file range overflow".to_owned()))?;
            if segment.offset <= offset && end <= segment_end {
                return segment
                    .virtual_address
                    .checked_add(offset - segment.offset)
                    .ok_or_else(|| Error::Invalid("virtual address overflow".to_owned()));
            }
        }
        invalid(format!(
            "file range 0x{offset:x}..0x{end:x} is not in PT_LOAD"
        ))
    }
}

pub(crate) fn slice(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::Invalid("byte range overflow".to_owned()))?;
    data.get(offset..end).ok_or_else(|| {
        Error::Invalid(format!(
            "byte range 0x{offset:x}..0x{end:x} is out of bounds"
        ))
    })
}

pub(crate) fn slice_u64(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    slice(
        data,
        usize_from_u64(offset, "file offset")?,
        usize_from_u64(size, "file size")?,
    )
}

pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = slice(data, offset, 2)?
        .try_into()
        .map_err(|_| Error::Invalid("invalid u16 range".to_owned()))?;
    Ok(u16::from_le_bytes(bytes))
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = slice(data, offset, 4)?
        .try_into()
        .map_err(|_| Error::Invalid("invalid u32 range".to_owned()))?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes: [u8; 8] = slice(data, offset, 8)?
        .try_into()
        .map_err(|_| Error::Invalid("invalid u64 range".to_owned()))?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn read_i64(data: &[u8], offset: usize) -> Result<i64> {
    let bytes: [u8; 8] = slice(data, offset, 8)?
        .try_into()
        .map_err(|_| Error::Invalid("invalid i64 range".to_owned()))?;
    Ok(i64::from_le_bytes(bytes))
}

pub(crate) fn usize_from_u64(value: u64, field: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::Invalid(format!("{field} 0x{value:x} exceeds usize")))
}

pub(crate) fn checked_index(base: usize, index: usize, stride: usize) -> Result<usize> {
    index
        .checked_mul(stride)
        .and_then(|value| base.checked_add(value))
        .ok_or_else(|| Error::Invalid("table index overflow".to_owned()))
}

pub(crate) fn align_up(value: u64, alignment: u64) -> Result<u64> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return invalid(format!("invalid alignment {alignment}"));
    }
    value
        .checked_add(alignment - 1)
        .map(|aligned| aligned & !(alignment - 1))
        .ok_or_else(|| Error::Invalid("alignment overflow".to_owned()))
}
