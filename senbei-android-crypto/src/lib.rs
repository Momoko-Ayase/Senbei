//! Cryptographic and compression primitives used by the Android protector.

use aes::Aes256;
use aes::cipher::{Block, BlockDecrypt, KeyInit};

const RECORD_SIZE: usize = 0x5c;

/// Errors raised while parsing or decoding protector containers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
}

type Result<T> = std::result::Result<T, Error>;

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(message.into()))
}

fn range(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::Invalid("byte range overflow".to_owned()))?;
    data.get(offset..end).ok_or_else(|| {
        Error::Invalid(format!(
            "byte range 0x{offset:x}..0x{end:x} is out of bounds"
        ))
    })
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = range(data, offset, 2)?
        .try_into()
        .map_err(|_| Error::Invalid("invalid u16 range".to_owned()))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = range(data, offset, 4)?
        .try_into()
        .map_err(|_| Error::Invalid("invalid u32 range".to_owned()))?;
    Ok(u32::from_le_bytes(bytes))
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| Error::Invalid("zero alignment".to_owned()))?;
    value
        .checked_add(mask)
        .map(|v| v & !mask)
        .ok_or_else(|| Error::Invalid("alignment overflow".to_owned()))
}

/// Multiply by the fixed element used by the native GF(2^32) transform.
#[must_use]
pub fn gf32_mul_fixed(mut value: u32) -> u32 {
    let mut multiplier = 0x9451_1dd2_u32;
    let mut result = 0_u32;
    while multiplier != 0 {
        if multiplier & 1 != 0 {
            result ^= value;
        }
        let carry = value >> 31;
        value = value.wrapping_shl(1);
        if carry != 0 {
            value ^= 0x5793_57eb;
        }
        multiplier >>= 1;
    }
    result
}

fn mix_columns(block: [u8; 16]) -> [u8; 16] {
    const fn xtime(value: u8) -> u8 {
        (value << 1) ^ if value & 0x80 != 0 { 0x1b } else { 0 }
    }

    let mut output = [0_u8; 16];
    for offset in (0..16).step_by(4) {
        let [a, b, c, d] = block[offset..offset + 4] else {
            unreachable!("fixed four-byte AES column")
        };
        output[offset] = xtime(a) ^ (xtime(b) ^ b) ^ c ^ d;
        output[offset + 1] = a ^ xtime(b) ^ (xtime(c) ^ c) ^ d;
        output[offset + 2] = a ^ b ^ xtime(c) ^ (xtime(d) ^ d);
        output[offset + 3] = (xtime(a) ^ a) ^ b ^ c ^ xtime(d);
    }
    output
}

/// Static configuration recovered from module `0x9B`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module9bConfig {
    pub header_seed: u32,
    pub container_seed: u32,
    pub aes_key: [u8; 32],
    pub skip_aes: bool,
    pub schedule_offset: usize,
}

impl Module9bConfig {
    /// Parse the unique AES-256 decryption schedule and adjacent configuration.
    pub fn parse(image: &[u8]) -> Result<Self> {
        const MARKER: [u8; 4] = [0x00, 0x01, 0x0e, 0x00];
        let mut matches = image
            .windows(MARKER.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == MARKER).then_some(offset));
        let schedule_offset = matches
            .next()
            .ok_or_else(|| Error::Invalid("cannot locate the 0x9B AES-256 schedule".to_owned()))?;
        if schedule_offset < 8 || matches.next().is_some() {
            return invalid("cannot uniquely locate the 0x9B AES-256 schedule");
        }

        let header_seed = read_u32(image, schedule_offset - 8)?;
        let schedule_size = read_u32(image, schedule_offset - 4)?;
        if schedule_size != 0xf4 {
            return invalid(format!(
                "unexpected 0x9B AES schedule size 0x{schedule_size:x}"
            ));
        }
        let bits = read_u16(image, schedule_offset)?;
        let rounds = read_u16(image, schedule_offset + 2)?;
        if (bits, rounds) != (0x100, 14) {
            return invalid(format!(
                "unexpected AES schedule header 0x{bits:x}/{rounds}"
            ));
        }

        let schedule = range(image, schedule_offset + 4, 15 * 16)?;
        let mut round_keys = [[0_u8; 16]; 15];
        for (round, output) in round_keys.iter_mut().enumerate() {
            let source = &schedule[round * 16..round * 16 + 16];
            for word in 0..4 {
                let start = word * 4;
                for byte in 0..4 {
                    output[start + byte] = source[start + 3 - byte];
                }
            }
        }
        let mut aes_key = [0_u8; 32];
        aes_key[..16].copy_from_slice(&round_keys[14]);
        aes_key[16..].copy_from_slice(&mix_columns(round_keys[13]));

        let container_seed_offset = schedule_offset
            .checked_add(0x100)
            .ok_or_else(|| Error::Invalid("container seed offset overflow".to_owned()))?;
        let skip_aes_offset = schedule_offset
            .checked_add(0x240)
            .ok_or_else(|| Error::Invalid("skip-AES offset overflow".to_owned()))?;
        let skip_aes = *image.get(skip_aes_offset).ok_or_else(|| {
            Error::Invalid("0x9B static configuration exceeds its image".to_owned())
        })? != 0;

        Ok(Self {
            header_seed,
            container_seed: read_u32(image, container_seed_offset)?,
            aes_key,
            skip_aes,
            schedule_offset,
        })
    }
}

/// Decrypted header at the start of direct-data object `0x9D`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedDescriptor {
    pub command_id: u32,
    pub flags: u32,
    pub outer_offset: u32,
    pub outer_expected_size: u32,
    pub auxiliary_offset: u32,
    pub auxiliary_expected_size: u32,
}

impl ProtectedDescriptor {
    /// Decrypt the `0x5c`-byte descriptor with the module header seed.
    pub fn decrypt(data: &[u8], seed: u32) -> Result<Self> {
        if data.len() < RECORD_SIZE {
            return invalid("0x9D descriptor is truncated");
        }
        let base0 = seed.wrapping_add(0xd3e8_7144).wrapping_mul(seed);
        let base1 = base0.wrapping_add(seed.wrapping_mul(0x0bd9_418d));
        let mut words = [0_u32; RECORD_SIZE / 4];
        for (index, word) in words.iter_mut().enumerate() {
            let cipher = read_u32(data, index * 4)?;
            let subtractor = base0.wrapping_shl(if index & 1 != 0 { 4 } else { 0 });
            *word = cipher.wrapping_sub(subtractor)
                ^ base1.wrapping_shr((seed.wrapping_add((index as u32).wrapping_mul(4))) & 7);
        }
        if words[6..].iter().any(|&word| word != 0) {
            return invalid("unexpected nonzero reserved words in the 0x9D descriptor");
        }
        let descriptor = Self {
            command_id: words[0],
            flags: words[1],
            outer_offset: words[2],
            outer_expected_size: words[3],
            auxiliary_offset: words[4],
            auxiliary_expected_size: words[5],
        };
        if descriptor.command_id != 0x9d || descriptor.outer_offset as usize != RECORD_SIZE {
            return invalid("unexpected decrypted 0x9D descriptor");
        }
        Ok(descriptor)
    }
}

/// One encrypted segment in a decoded `0x9D` container header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedSegment {
    pub offset: u32,
    pub size: u32,
}

/// Parsed primary or auxiliary `0x9D` container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHeader {
    pub start: usize,
    pub output_size: u32,
    pub skip_aes: bool,
    pub tree: Vec<u8>,
    pub segments: Vec<EncodedSegment>,
}

impl ContainerHeader {
    /// Parse and decrypt a container header, Huffman tree, and segment table.
    pub fn parse(data: &[u8], start: usize, seed: u32) -> Result<Self> {
        range(data, start, 12)?;
        let seed_square = seed.wrapping_mul(seed);
        let state = seed_square.wrapping_shr(17) ^ seed_square.wrapping_shl(11);
        let raw0 = read_u32(data, start)?;
        let raw1 = read_u32(data, start + 4)?;
        let raw2 = read_u32(data, start + 8)?;
        let output_size = 0xa21d_fb3a_u32
            .wrapping_shl(state & 7)
            .wrapping_add(state.wrapping_mul(0xf87b_337c))
            .wrapping_add(gf32_mul_fixed(raw0));
        let flag_word = gf32_mul_fixed(raw1)
            ^ state
                .wrapping_add(0xbd19_c63c)
                .wrapping_add(0x416e_2af2_u32.wrapping_shr(state & 0x0d));
        let segment_count = (flag_word & 0xff) as usize;
        let skip_aes = (flag_word >> 8) & 0xff == 1;
        let tree_size = 0x643a_3a3b_u32
            .wrapping_shl(state & 0x0b)
            .wrapping_sub(state ^ 0x3b2b_f538)
            .wrapping_add(gf32_mul_fixed(raw2)) as usize;
        if segment_count == 0 || tree_size > 0x1b00 {
            return invalid(format!(
                "invalid container fields: segments={segment_count}, tree=0x{tree_size:x}"
            ));
        }

        let tree_start = start
            .checked_add(12)
            .ok_or_else(|| Error::Invalid("tree offset overflow".to_owned()))?;
        let mut tree = range(data, tree_start, tree_size)?.to_vec();
        for offset in (0..tree_size & !3).step_by(4) {
            let value = read_u32(&tree, offset)?;
            tree[offset..offset + 4].copy_from_slice(&gf32_mul_fixed(value).to_le_bytes());
        }
        let tree_state = state.wrapping_add(0xf1cb_5b81).wrapping_mul(state);
        let tree_delta = tree_state.wrapping_sub(0x23b3_2203_u32.wrapping_mul(state));
        for (index, byte) in tree.iter_mut().enumerate() {
            let shift = u32::try_from(index & 0x1b)
                .map_err(|_| Error::Invalid("tree shift conversion failed".to_owned()))?;
            let left = gf32_mul_fixed(tree_state.wrapping_shl(shift));
            let right = tree_delta.wrapping_shr((index & 0x17) as u32);
            let adjustment = left.wrapping_sub(right).wrapping_shr((index & 0x1f) as u32);
            *byte = byte.wrapping_add(adjustment as u8);
        }

        let table_start = start
            .checked_add(align_up(12 + tree_size, 4)?)
            .ok_or_else(|| Error::Invalid("segment table offset overflow".to_owned()))?;
        let table_size = segment_count
            .checked_mul(8)
            .ok_or_else(|| Error::Invalid("segment table size overflow".to_owned()))?;
        let mut table = range(data, table_start, table_size)?.to_vec();
        let table_state = state.wrapping_add(0xb31f_451c).wrapping_mul(state);
        let table_xor = table_state.wrapping_shl(3);
        let table_add = table_state.wrapping_sub(0x822f_e82d_u32.wrapping_mul(state));
        for offset in (0..table_size).step_by(4) {
            let value = read_u32(&table, offset)?;
            let decoded = gf32_mul_fixed(value ^ table_xor)
                .wrapping_add(table_add.wrapping_shr(((offset & 7) + 5) as u32));
            table[offset..offset + 4].copy_from_slice(&decoded.to_le_bytes());
        }
        let mut segments = Vec::with_capacity(segment_count);
        for index in 0..segment_count {
            let offset = read_u32(&table, index * 8)?;
            let size = read_u32(&table, index * 8 + 4)?;
            let absolute = start
                .checked_add(offset as usize)
                .and_then(|value| value.checked_add(size as usize));
            if size == 0 || absolute.is_none_or(|end| end > data.len()) {
                return invalid(format!("container segment {index} lies outside 0x9D"));
            }
            segments.push(EncodedSegment { offset, size });
        }
        Ok(Self {
            start,
            output_size,
            skip_aes,
            tree,
            segments,
        })
    }

    /// End offset of the furthest encrypted segment.
    pub fn encoded_end(&self) -> Result<usize> {
        self.segments
            .iter()
            .map(|segment| {
                self.start
                    .checked_add(segment.offset as usize)
                    .and_then(|value| value.checked_add(segment.size as usize))
                    .ok_or_else(|| Error::Invalid("encoded segment end overflow".to_owned()))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .ok_or_else(|| Error::Invalid("container has no encoded segments".to_owned()))
    }
}

/// Decoder for the protector's Huffman/LZ writer streams.
#[derive(Debug, Clone)]
pub struct HuffmanLzDecoder {
    tree: Vec<u8>,
    lookup_symbols: Vec<u16>,
    lookup_bits: Vec<u8>,
}

impl HuffmanLzDecoder {
    /// Build the full 16-bit prefix lookup used by the static decoder.
    pub fn new(tree: &[u8]) -> Result<Self> {
        if tree.len() < 256 * 3 || tree.len() % 3 != 0 {
            return invalid(format!("invalid Huffman tree size 0x{:x}", tree.len()));
        }
        let mut result = Self {
            tree: tree.to_vec(),
            lookup_symbols: vec![0; 0x1_0000],
            lookup_bits: vec![0; 0x1_0000],
        };
        for word in 0..0x1_0000_u32 {
            let (symbol, bits) = result.decode_symbol(word)?;
            if bits <= 16 {
                result.lookup_symbols[word as usize] = symbol;
                result.lookup_bits[word as usize] = bits;
            }
        }
        Ok(result)
    }

    fn entry(&self, index: usize) -> Result<(u16, bool, u8)> {
        let offset = index
            .checked_mul(3)
            .ok_or_else(|| Error::Invalid("Huffman node offset overflow".to_owned()))?;
        let bytes = range(&self.tree, offset, 3)?;
        let raw = u16::from(bytes[0]) | (u16::from(bytes[1]) << 8);
        Ok((raw & 0x7fff, raw & 0x8000 != 0, bytes[2]))
    }

    fn decode_symbol(&self, word: u32) -> Result<(u16, u8)> {
        let (mut value, leaf, extra) = self.entry((word & 0xff) as usize)?;
        if leaf {
            if extra == 0 {
                return invalid("zero-width Huffman leaf");
            }
            return Ok((value, extra));
        }
        let mut bits = extra
            .checked_add(1)
            .ok_or_else(|| Error::Invalid("Huffman bit count overflow".to_owned()))?;
        let mut mask = 1_u32.wrapping_shl(u32::from(extra));
        loop {
            let branch = usize::from(word & mask != 0);
            let (next, is_leaf, _) = self.entry(usize::from(value) + branch)?;
            value = next;
            if is_leaf {
                return Ok((value, bits));
            }
            mask = mask.wrapping_shl(1);
            bits = bits
                .checked_add(1)
                .ok_or_else(|| Error::Invalid("Huffman bit count overflow".to_owned()))?;
            if bits > 31 {
                return invalid("Huffman code exceeds the native 32-bit window");
            }
        }
    }

    /// Decode one compressed writer payload to its exact expected size.
    pub fn decode(&self, source: &[u8], output_size: usize) -> Result<Vec<u8>> {
        let mut output = vec![0_u8; output_size];
        let mut source_pos = 0_usize;
        let mut bit_buffer = 0_u64;
        let mut available = 0_u8;
        let mut consumed_bits = 0_usize;
        let mut output_pos = 0_usize;
        let mut prefix = 0_usize;

        while output_pos < output_size {
            while available < 24 && source_pos < source.len() {
                bit_buffer |= u64::from(source[source_pos]) << available;
                source_pos += 1;
                available += 8;
            }
            let key = (bit_buffer & 0xffff) as usize;
            let mut bits = self.lookup_bits[key];
            let symbol = if bits != 0 {
                self.lookup_symbols[key]
            } else {
                let mut value_offset = ((bit_buffer & 0xff) as usize) * 3;
                let mut node = range(&self.tree, value_offset, 3)?;
                let mut raw = u16::from(node[0]) | (u16::from(node[1]) << 8);
                if raw & 0x8000 != 0 {
                    bits = node[2];
                    raw & 0x7fff
                } else {
                    let extra = node[2];
                    bits = extra + 1;
                    let mut mask = 1_u64 << extra;
                    loop {
                        let branch = usize::from(bit_buffer & mask != 0);
                        let index = usize::from(raw & 0x7fff) + branch;
                        value_offset = index
                            .checked_mul(3)
                            .ok_or_else(|| Error::Invalid("Huffman node overflow".to_owned()))?;
                        node = range(&self.tree, value_offset, 3)?;
                        raw = u16::from(node[0]) | (u16::from(node[1]) << 8);
                        if raw & 0x8000 != 0 {
                            break raw & 0x7fff;
                        }
                        mask <<= 1;
                        bits += 1;
                    }
                }
            };
            if bits == 0 || bits > available {
                return invalid("compressed stream ends inside a Huffman code");
            }
            bit_buffer >>= bits;
            available -= bits;
            consumed_bits = consumed_bits
                .checked_add(usize::from(bits))
                .ok_or_else(|| Error::Invalid("consumed bit count overflow".to_owned()))?;

            let kind = symbol & 0x300;
            let value = usize::from(symbol & 0xff);
            match kind {
                0 => {
                    output[output_pos] = value as u8;
                    output_pos += 1;
                }
                0x100 => {
                    if prefix > 0xff {
                        return invalid("compressed prefix exceeds 16 bits");
                    }
                    prefix = if prefix == 0 {
                        value
                    } else {
                        value | (prefix << 8)
                    };
                }
                0x200 => {
                    if prefix == 0 {
                        prefix = 1;
                    }
                    let count = value
                        .checked_mul(prefix)
                        .ok_or_else(|| Error::Invalid("repeat count overflow".to_owned()))?;
                    if !matches!(value, 1 | 2 | 4)
                        || value > output_pos
                        || output_pos
                            .checked_add(count)
                            .is_none_or(|end| end > output_size)
                    {
                        return invalid("invalid compressed repeated-pattern command");
                    }
                    let pattern = output[output_pos - value..output_pos].to_vec();
                    for chunk in output[output_pos..output_pos + count].chunks_exact_mut(value) {
                        chunk.copy_from_slice(&pattern);
                    }
                    output_pos += count;
                    prefix = 0;
                }
                0x300 => {
                    let length = value;
                    let distance = prefix.checked_add(length).ok_or_else(|| {
                        Error::Invalid("back-reference distance overflow".to_owned())
                    })?;
                    if distance > output_pos
                        || output_pos
                            .checked_add(length)
                            .is_none_or(|end| end > output_size)
                    {
                        return invalid("invalid compressed back-reference");
                    }
                    let source_start = output_pos - distance;
                    output.copy_within(source_start..source_start + length, output_pos);
                    output_pos += length;
                    prefix = 0;
                }
                _ => unreachable!("masked Huffman symbol kind"),
            }
        }
        if consumed_bits.div_ceil(8) != source.len() {
            return invalid(format!(
                "compressed input consumption mismatch: used=0x{:x}, size=0x{:x}",
                consumed_bits.div_ceil(8),
                source.len()
            ));
        }
        Ok(output)
    }
}

/// Apply the native word transform and optional AES-256-CBC decryption.
pub fn transform_segment(
    data: &[u8],
    seed: u32,
    aes_key: &[u8; 32],
    decrypt_aes: bool,
) -> Result<Vec<u8>> {
    let mut transformed = data.to_vec();
    let mut state = seed;
    let mut left = 0xe34e_ac63_u32;
    let mut right = 0x07b4_8238_u32;
    for (index, chunk) in transformed.chunks_exact_mut(4).enumerate() {
        let index32 = u32::try_from(index)
            .map_err(|_| Error::Invalid("segment word index exceeds u32".to_owned()))?;
        left = state
            .wrapping_add(0x72f6_fcbe)
            .wrapping_add(left.wrapping_add(0x4f8b_1bca).wrapping_mul(left))
            .wrapping_shr(index32.wrapping_mul(index32) & 0x0f);
        right = state
            .wrapping_sub(0x71b6_a98d)
            .wrapping_add(right.wrapping_sub(0x1605_a81c).wrapping_mul(right))
            .wrapping_shl(index32 & 7);
        state = left ^ right;
        let bytes: [u8; 4] = chunk
            .try_into()
            .map_err(|_| Error::Invalid("invalid transformed word".to_owned()))?;
        let mut value = u32::from_le_bytes(bytes);
        value = value.wrapping_add(0xb43b_9baf_u32.wrapping_mul(index32 & 0x0d));
        value ^= 0xaf57_f7fb_u32.wrapping_mul(index32 & 3);
        value = value.wrapping_sub(state) ^ state;
        chunk.copy_from_slice(&value.to_le_bytes());
    }

    if decrypt_aes {
        let cipher = Aes256::new_from_slice(aes_key)
            .map_err(|_| Error::Invalid("invalid AES-256 key length".to_owned()))?;
        let aligned_size = transformed.len() & !0x0f;
        let mut previous = [0_u8; 16];
        for chunk in transformed[..aligned_size].chunks_exact_mut(16) {
            let mut ciphertext = [0_u8; 16];
            ciphertext.copy_from_slice(chunk);
            cipher.decrypt_block(Block::<Aes256>::from_mut_slice(chunk));
            for (byte, prior) in chunk.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            previous = ciphertext;
        }
    }
    Ok(transformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_mix_columns_matches_fips_example() {
        let input = [
            0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6,
            0xc6, 0xc6,
        ];
        assert_eq!(
            mix_columns(input),
            [
                0x8e, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6,
                0xc6, 0xc6,
            ]
        );
    }

    #[test]
    fn descriptor_rejects_truncated_input() {
        assert!(ProtectedDescriptor::decrypt(&[0_u8; 16], 1).is_err());
    }
}
