//! Basic ELF format parsing shared by the unpacking engine.

use goblin::elf::{Elf, header::EM_AARCH64, program_header::PT_LOAD};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ELF parse failed: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("input is not an ELF64 little-endian image")]
    NotElf64,
    #[error("input is not an AArch64 image")]
    NotAarch64,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(matches!(parse(b"not elf"), Err(Error::Parse(_))));
    }
}
