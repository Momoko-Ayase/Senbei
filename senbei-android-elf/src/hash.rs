use crate::error::{Error, Result, invalid};

#[must_use]
pub(crate) fn elf_hash(name: &[u8]) -> u32 {
    let mut value = 0_u32;
    for &byte in name {
        value = value.wrapping_shl(4).wrapping_add(u32::from(byte));
        let high = value & 0xf000_0000;
        if high != 0 {
            value ^= high >> 24;
            value &= !high;
        }
    }
    value
}

#[must_use]
pub(crate) fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381_u32, |value, &byte| {
        value.wrapping_mul(33).wrapping_add(u32::from(byte))
    })
}

pub(crate) fn build_sysv_hash(names: &[Vec<u8>]) -> Result<Vec<u8>> {
    if names.len() < 2 {
        return invalid("dynamic symbol table is unexpectedly empty");
    }
    let bucket_count = names.len();
    let symbol_count = names.len();
    let mut buckets = vec![0_u32; bucket_count];
    let mut chains = vec![0_u32; symbol_count];
    for (symbol_index, name) in names.iter().enumerate().skip(1) {
        let bucket_index = elf_hash(name) as usize % bucket_count;
        let symbol_index32 = u32::try_from(symbol_index)
            .map_err(|_| Error::Invalid("dynamic symbol index exceeds u32".to_owned()))?;
        if buckets[bucket_index] == 0 {
            buckets[bucket_index] = symbol_index32;
            continue;
        }
        let mut chain_index = buckets[bucket_index] as usize;
        while chains[chain_index] != 0 {
            chain_index = chains[chain_index] as usize;
        }
        chains[chain_index] = symbol_index32;
    }
    let mut output = Vec::with_capacity((2 + bucket_count + symbol_count) * 4);
    output.extend_from_slice(
        &u32::try_from(bucket_count)
            .map_err(|_| Error::Invalid("SysV bucket count exceeds u32".to_owned()))?
            .to_le_bytes(),
    );
    output.extend_from_slice(
        &u32::try_from(symbol_count)
            .map_err(|_| Error::Invalid("SysV symbol count exceeds u32".to_owned()))?
            .to_le_bytes(),
    );
    for value in buckets.into_iter().chain(chains) {
        output.extend_from_slice(&value.to_le_bytes());
    }
    Ok(output)
}

pub(crate) fn build_gnu_hash(names: &[Vec<u8>]) -> Result<Vec<u8>> {
    let hashes = names
        .iter()
        .skip(1)
        .map(|name| gnu_hash(name))
        .collect::<Vec<_>>();
    if hashes.is_empty() {
        return invalid("GNU hash requires at least one dynamic symbol");
    }
    let bloom_shift = 5_u32;
    let mut bloom_word = 0_u64;
    for &value in &hashes {
        bloom_word |= 1_u64 << (value & 63);
        bloom_word |= 1_u64 << ((value >> bloom_shift) & 63);
    }
    let mut chains = hashes
        .into_iter()
        .map(|value| value & !1)
        .collect::<Vec<_>>();
    let last = chains
        .last_mut()
        .ok_or_else(|| Error::Invalid("GNU hash chain is empty".to_owned()))?;
    *last |= 1;
    let mut output = Vec::with_capacity(28 + chains.len() * 4);
    for value in [1_u32, 1, 1, bloom_shift] {
        output.extend_from_slice(&value.to_le_bytes());
    }
    output.extend_from_slice(&bloom_word.to_le_bytes());
    output.extend_from_slice(&1_u32.to_le_bytes());
    for value in chains {
        output.extend_from_slice(&value.to_le_bytes());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_elf_hash_is_stable() {
        assert_eq!(elf_hash(b"printf"), 0x0779_05a6);
        assert_eq!(gnu_hash(b"printf"), 0x156b_2bb8);
    }
}
