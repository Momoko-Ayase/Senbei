//! Basic ELF format parsing shared by the unpacking engine.

use goblin::elf::{Elf, header::EM_AARCH64, program_header::PT_LOAD};
use thiserror::Error;

pub mod hash;
pub mod layout;

pub use hash::{build_gnu_hash, build_sysv_hash};
pub use layout::{
    ElfLayout, LoadSegment, PF_R, SHF_ALLOC, SHT_LOUSER, SHT_NOBITS, SectionHeader, align_up,
    checked_index, read_i64, read_u16, read_u32, read_u64, slice, slice_u64, usize_from_u64,
};

/// ELF machine identifier for AArch64.
pub const AARCH64_MACHINE: u16 = EM_AARCH64;

/// Dynamic sections required by the restored AArch64 loader image.
pub const DYNAMIC_SECTION_NAMES: [&str; 8] = [
    ".dynsym",
    ".gnu.version",
    ".gnu.version_r",
    ".gnu.hash",
    ".dynstr",
    ".rela.dyn",
    ".rela.plt",
    ".dynamic",
];

/// Dynamic sections needed to identify a protected image before extraction.
pub const PROBE_SECTION_NAMES: [&str; 5] = [
    ".dynsym",
    ".dynstr",
    ".gnu.hash",
    ".gnu.version",
    ".gnu.version_r",
];

/// ELF64 dynamic table record sizes.
pub const ELF64_SYMBOL_SIZE: usize = 0x18;
pub const ELF64_RELA_SIZE: usize = 0x18;

/// AArch64 relocation kinds used by the dynamic linker.
pub const R_AARCH64_ABS64: u32 = 0x101;
pub const R_AARCH64_GLOB_DAT: u32 = 0x401;
pub const R_AARCH64_JUMP_SLOT: u32 = 0x402;
pub const R_AARCH64_RELATIVE: u32 = 0x403;
pub const VER_NDX_GLOBAL: u16 = 1;

/// ELF dynamic-table tag identifiers used by restored images.
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_STRSZ: u64 = 10;
pub const DT_JMPREL: u64 = 23;
pub const DT_GNU_HASH: u64 = 0x6fff_fef5;
pub const DT_VERSYM: u64 = 0x6fff_fff0;
pub const DT_RELACOUNT: u64 = 0x6fff_fff9;
pub const DT_VERNEED: u64 = 0x6fff_fffe;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ELF parse failed: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("input is not an ELF64 little-endian image")]
    NotElf64,
    #[error("input is not an AArch64 image")]
    NotAarch64,
    #[error("invalid ELF layout: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Parse an ELF64 little-endian image.
pub fn parse(data: &[u8]) -> Result<Elf<'_>> {
    let elf = Elf::parse(data)?;
    if elf.header.e_ident[4] != 2 || elf.header.e_ident[5] != 1 {
        return Err(Error::NotElf64);
    }
    Ok(elf)
}

/// Return true when `data` starts with a valid AArch64 ELF64 image.
pub fn is_aarch64(data: &[u8]) -> bool {
    parse(data)
        .map(|elf| elf.header.e_machine == EM_AARCH64)
        .unwrap_or(false)
}

/// Return whether a short prefix identifies an ELF64 little-endian AArch64
/// image. This is intentionally a prefix-only check for filesystem scanners;
/// callers that need structural guarantees must use [`parse`].
#[must_use]
pub fn is_aarch64_prefix(data: &[u8]) -> bool {
    data.get(0..6) == Some(b"\x7fELF\x02\x01")
        && data
            .get(18..20)
            .is_some_and(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) == EM_AARCH64)
}

/// Return the maximum file end among PT_LOAD segments.
pub fn load_file_end(data: &[u8]) -> Result<u64> {
    let elf = parse(data)?;
    Ok(elf
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == PT_LOAD)
        .map(|ph| ph.p_offset.saturating_add(ph.p_filesz))
        .max()
        .unwrap_or(0))
}

pub(crate) fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(matches!(parse(b"not elf"), Err(Error::Parse(_))));
    }
}
