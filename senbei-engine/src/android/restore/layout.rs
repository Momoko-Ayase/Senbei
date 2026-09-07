use super::error::{Error, Result, invalid};

pub(crate) const SHT_NOBITS: u32 = 8;
pub(crate) const SHT_STRTAB: u32 = 3;
pub(crate) const SHT_LOUSER: u32 = 0x8000_0000;
pub(crate) const SHF_ALLOC: u64 = 2;
const PT_LOAD: u32 = 1;
pub(crate) const PF_R: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoadSegment {
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: u32,
    pub alignment: u64,
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
    pub program_header_offset: usize,
    pub program_header_size: usize,
    pub program_header_count: usize,
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
            if read_u32(data, offset)? != PT_LOAD {
                continue;
            }
            let segment = LoadSegment {
                flags: read_u32(data, offset + 4)?,
                offset: read_u64(data, offset + 8)?,
                virtual_address: read_u64(data, offset + 0x10)?,
                file_size: read_u64(data, offset + 0x20)?,
                memory_size: read_u64(data, offset + 0x28)?,
                alignment: read_u64(data, offset + 0x30)?,
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
        let layout = Self {
            entrypoint,
            program_header_offset,
            program_header_size,
            program_header_count,
            program_headers,
            section_headers,
            section_name_index,
            private_section_index,
        };
        // Section roles are resolved from the ELF's own string table. Validate
        // it at the format boundary so callers cannot silently continue with
        // fabricated or lossy section names.
        layout.section_names(data)?;
        Ok(layout)
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

    pub fn load_alignment(&self) -> Result<u64> {
        let alignment = self
            .program_headers
            .iter()
            .map(|segment| segment.alignment)
            .max()
            .ok_or_else(|| Error::Invalid("ELF has no PT_LOAD alignment".to_owned()))?;
        if alignment == 0 || !alignment.is_power_of_two() {
            return invalid(format!("invalid PT_LOAD alignment 0x{alignment:x}"));
        }
        Ok(alignment)
    }

    pub fn append_load_segment(&self, output: &mut [u8], segment: LoadSegment) -> Result<Self> {
        if self.program_header_size != 0x38 {
            return invalid("unexpected ELF program header size");
        }
        if segment.file_size == 0 {
            return invalid("new PT_LOAD has no file contents");
        }
        if segment.memory_size < segment.file_size {
            return invalid("new PT_LOAD memory size is smaller than file size");
        }
        if segment.alignment == 0 || !segment.alignment.is_power_of_two() {
            return invalid(format!(
                "invalid new PT_LOAD alignment 0x{:x}",
                segment.alignment
            ));
        }
        if segment.offset % segment.alignment != segment.virtual_address % segment.alignment {
            return invalid("new PT_LOAD offset and address are misaligned");
        }
        let segment_file_end = segment
            .offset
            .checked_add(segment.file_size)
            .ok_or_else(|| Error::Invalid("new PT_LOAD file range overflow".to_owned()))?;
        let segment_memory_end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or_else(|| Error::Invalid("new PT_LOAD memory range overflow".to_owned()))?;
        if segment_file_end > output.len() as u64 {
            return invalid("new PT_LOAD exceeds output mapping");
        }
        for existing in &self.program_headers {
            let existing_file_end = existing
                .offset
                .checked_add(existing.file_size)
                .ok_or_else(|| Error::Invalid("PT_LOAD file range overflow".to_owned()))?;
            if segment.offset < existing_file_end && existing.offset < segment_file_end {
                return invalid("new PT_LOAD overlaps an existing file range");
            }
            let existing_memory_end = existing
                .virtual_address
                .checked_add(existing.memory_size)
                .ok_or_else(|| Error::Invalid("PT_LOAD memory range overflow".to_owned()))?;
            if segment.virtual_address < existing_memory_end
                && existing.virtual_address < segment_memory_end
            {
                return invalid("new PT_LOAD overlaps an existing memory range");
            }
        }
        let new_count = self
            .program_header_count
            .checked_add(1)
            .ok_or_else(|| Error::Invalid("program header count overflow".to_owned()))?;
        let new_count_u16 = u16::try_from(new_count)
            .map_err(|_| Error::Invalid("program header count exceeds u16".to_owned()))?;
        let header_offset = checked_index(
            self.program_header_offset,
            self.program_header_count,
            self.program_header_size,
        )?;
        let header_end = header_offset
            .checked_add(self.program_header_size)
            .ok_or_else(|| Error::Invalid("new program header range overflow".to_owned()))?;
        slice(output, header_offset, self.program_header_size)?;
        let first_file_section = self
            .section_headers
            .iter()
            .filter(|section| section.section_type != SHT_NOBITS && section.size != 0)
            .map(|section| section.offset)
            .min();
        if first_file_section.is_some_and(|offset| header_end as u64 > offset) {
            return invalid("no space for an additional program header");
        }

        let mut header = [0_u8; 0x38];
        header[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
        header[4..8].copy_from_slice(&segment.flags.to_le_bytes());
        header[8..0x10].copy_from_slice(&segment.offset.to_le_bytes());
        header[0x10..0x18].copy_from_slice(&segment.virtual_address.to_le_bytes());
        header[0x18..0x20].copy_from_slice(&segment.virtual_address.to_le_bytes());
        header[0x20..0x28].copy_from_slice(&segment.file_size.to_le_bytes());
        header[0x28..0x30].copy_from_slice(&segment.memory_size.to_le_bytes());
        header[0x30..0x38].copy_from_slice(&segment.alignment.to_le_bytes());
        output
            .get_mut(header_offset..header_end)
            .ok_or_else(|| Error::Invalid("new program header exceeds output".to_owned()))?
            .copy_from_slice(&header);
        output
            .get_mut(0x38..0x3a)
            .ok_or_else(|| Error::Invalid("ELF header is truncated".to_owned()))?
            .copy_from_slice(&new_count_u16.to_le_bytes());

        let mut updated = self.clone();
        updated.program_header_count = new_count;
        updated.program_headers.push(segment);
        Ok(updated)
    }

    /// Resolve every section's name from the ELF `shstrtab` section.
    ///
    /// The returned names are source data, not role labels supplied by the
    /// caller. Any malformed string-table reference is an input error.
    pub fn section_names(&self, data: &[u8]) -> Result<Vec<String>> {
        let table = self
            .section_headers
            .get(self.section_name_index)
            .copied()
            .ok_or_else(|| Error::Invalid("ELF section-name index is out of range".to_owned()))?;
        if table.section_type != SHT_STRTAB {
            return invalid(format!(
                "ELF section-name table has unexpected type 0x{:x}",
                table.section_type
            ));
        }
        let strings = slice_u64(data, table.offset, table.size)?;
        if strings.is_empty() || strings[0] != 0 {
            return invalid("ELF section-name table does not start with NUL");
        }
        if strings.last().copied() != Some(0) {
            return invalid("ELF section-name table is not NUL terminated");
        }
        self.section_headers
            .iter()
            .enumerate()
            .map(|(index, section)| {
                let offset = section.name as usize;
                if offset >= strings.len() {
                    return invalid(format!(
                        "ELF section {index} name offset 0x{offset:x} exceeds section-name table"
                    ));
                }
                let end = strings[offset..]
                    .iter()
                    .position(|&byte| byte == 0)
                    .map(|length| offset + length)
                    .ok_or_else(|| {
                        Error::Invalid(format!(
                            "ELF section {index} name at 0x{offset:x} is unterminated"
                        ))
                    })?;
                let name = std::str::from_utf8(&strings[offset..end]).map_err(|error| {
                    Error::Invalid(format!(
                        "ELF section {index} name at 0x{offset:x} is not UTF-8: {error}"
                    ))
                })?;
                if index == 0 && section.name != 0 {
                    return invalid("ELF null section has a nonzero name offset");
                }
                Ok(name.to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(name_index: u32) -> ElfLayout {
        ElfLayout {
            entrypoint: 0,
            program_header_offset: 0,
            program_header_size: 0x38,
            program_header_count: 0,
            program_headers: Vec::new(),
            section_headers: vec![
                SectionHeader {
                    name: 0,
                    section_type: 0,
                    flags: 0,
                    address: 0,
                    offset: 0,
                    size: 0,
                    link: 0,
                    info: 0,
                    alignment: 0,
                    entry_size: 0,
                },
                SectionHeader {
                    name: name_index,
                    section_type: 1,
                    flags: 0,
                    address: 0,
                    offset: 0,
                    size: 0,
                    link: 0,
                    info: 0,
                    alignment: 0,
                    entry_size: 0,
                },
                SectionHeader {
                    name: 1,
                    section_type: SHT_STRTAB,
                    flags: 0,
                    address: 0,
                    offset: 0,
                    size: 8,
                    link: 0,
                    info: 0,
                    alignment: 1,
                    entry_size: 0,
                },
            ],
            section_name_index: 2,
            private_section_index: usize::MAX,
        }
    }

    #[test]
    fn section_names_resolve_from_elf_string_table() {
        let names = layout(1)
            .section_names(b"\0text\0\0\0")
            .expect("valid names");
        assert_eq!(names, ["", "text", "text"]);
    }

    #[test]
    fn section_names_reject_out_of_range_name_offsets() {
        let error = layout(8)
            .section_names(b"\0text\0\0\0")
            .expect_err("invalid offset");
        assert!(error.to_string().contains("exceeds section-name table"));
    }

    #[test]
    fn section_names_reject_invalid_utf8() {
        let mut elf_layout = layout(1);
        elf_layout.section_headers[1].name = 1;
        let error = elf_layout
            .section_names(b"\0\xff\0\0\0\0\0\0")
            .expect_err("invalid UTF-8");
        assert!(error.to_string().contains("is not UTF-8"));
    }

    #[test]
    fn section_names_reject_non_string_table() {
        let mut elf_layout = layout(1);
        elf_layout.section_headers[2].section_type = 1;
        let error = elf_layout
            .section_names(b"\0text\0\0\0")
            .expect_err("wrong section type");
        assert!(error.to_string().contains("unexpected type"));
    }

    #[test]
    fn section_names_reject_unterminated_table() {
        let elf_layout = layout(1);
        let error = elf_layout
            .section_names(b"\0text\0\x01\x01")
            .expect_err("unterminated table");
        assert!(error.to_string().contains("not NUL terminated"));
    }

    #[test]
    fn append_load_segment_updates_program_headers() {
        let elf_layout = ElfLayout {
            entrypoint: 0,
            program_header_offset: 0,
            program_header_size: 0x38,
            program_header_count: 0,
            program_headers: Vec::new(),
            section_headers: Vec::new(),
            section_name_index: 0,
            private_section_index: usize::MAX,
        };
        let mut output = vec![0_u8; 0x2000];
        let updated = elf_layout
            .append_load_segment(
                &mut output,
                LoadSegment {
                    offset: 0x1000,
                    virtual_address: 0x2000,
                    file_size: 0x20,
                    memory_size: 0x20,
                    flags: PF_R,
                    alignment: 0x1000,
                },
            )
            .expect("append segment");
        assert_eq!(updated.program_header_count, 1);
        assert_eq!(updated.program_headers[0].virtual_address, 0x2000);
        assert_eq!(&output[0..4], &PT_LOAD.to_le_bytes());
        assert_eq!(&output[0x38..0x3a], &1_u16.to_le_bytes());
    }

    #[test]
    fn append_load_segment_rejects_program_header_overlap() {
        let mut elf_layout = ElfLayout {
            entrypoint: 0,
            program_header_offset: 0,
            program_header_size: 0x38,
            program_header_count: 0,
            program_headers: Vec::new(),
            section_headers: Vec::new(),
            section_name_index: 0,
            private_section_index: usize::MAX,
        };
        elf_layout.section_headers.push(SectionHeader {
            name: 0,
            section_type: 1,
            flags: 0,
            address: 0,
            offset: 0x20,
            size: 1,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        });
        let mut output = vec![0_u8; 0x100];
        let error = elf_layout
            .append_load_segment(
                &mut output,
                LoadSegment {
                    offset: 0x80,
                    virtual_address: 0x1080,
                    file_size: 0x20,
                    memory_size: 0x20,
                    flags: PF_R,
                    alignment: 0x1000,
                },
            )
            .expect_err("overlapping program header");
        assert!(error.to_string().contains("additional program header"));
    }
}
