use senbei_android_crypto::gf32_mul_fixed;

use crate::error::{Error, Result, invalid};

pub(crate) const RECORD_SIZE: usize = 0x5c;
pub(crate) const DIRECT_FLAG: u32 = 2;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Record {
    pub index: usize,
    pub command_id: u32,
    pub flags: u32,
    pub image_offset: u32,
    pub image_size: u32,
    pub metadata_offset: u32,
    pub metadata_size: u32,
    pub id_copy: u32,
    pub entry_offset: u32,
    pub init_offset: u32,
}

impl Record {
    pub(crate) fn direct(self) -> bool {
        self.flags & DIRECT_FLAG != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamHeader {
    pub encrypted_words: [u32; 2],
    pub decrypted_words: [u32; 2],
    pub record_state: u32,
}

pub(crate) fn parse_record_stream(
    stream: &[u8],
    stream_id: u32,
) -> Result<(StreamHeader, Vec<Record>, usize)> {
    if stream.len() < 8 {
        return invalid(format!(
            "stream 0x{stream_id:02X} is shorter than its 8-byte header"
        ));
    }
    let cipher0 = read_u32(stream, 0)?;
    let cipher1 = read_u32(stream, 4)?;
    let key = stream_id.wrapping_mul(0x9d32_3cd7);
    let shift = stream_id & 7;
    let base = (key >> shift)
        .wrapping_add(0x5e72_7d74)
        .wrapping_add(key.wrapping_shl(stream_id & 0xb))
        .wrapping_add(0xf71e_3005);
    let plain0 =
        gf32_mul_fixed(cipher0.wrapping_add(0xcbf0_c1d8)) ^ 0xeb_e81dba_u32.wrapping_add(base);
    let plain1 = gf32_mul_fixed(cipher1.wrapping_add(cipher0))
        ^ 0xeb_e81dba_u32.wrapping_mul(5).wrapping_add(base);
    let header = StreamHeader {
        encrypted_words: [cipher0, cipher1],
        decrypted_words: [plain0, plain1],
        record_state: plain1.wrapping_add(base),
    };

    let mut records = Vec::new();
    let mut first_payload = stream.len();
    for index in 0..256_usize {
        let start =
            8_usize
                .checked_add(index.checked_mul(RECORD_SIZE).ok_or_else(|| {
                    Error::Invalid("record descriptor offset overflow".to_owned())
                })?)
                .ok_or_else(|| Error::Invalid("record descriptor offset overflow".to_owned()))?;
        let end = start
            .checked_add(RECORD_SIZE)
            .ok_or_else(|| Error::Invalid("record descriptor end overflow".to_owned()))?;
        if end > stream.len() {
            return invalid(format!(
                "stream 0x{stream_id:02X} descriptor table is truncated at record {index}"
            ));
        }
        let record = decrypt_record(&stream[start..end], index, header.record_state)?;
        if record.id_copy != 0 && record.command_id != record.id_copy {
            return invalid(format!(
                "stream 0x{stream_id:02X} record {index} command/id mismatch: 0x{:X} != 0x{:X}",
                record.command_id, record.id_copy
            ));
        }
        for (offset, size) in [
            (record.image_offset, record.image_size),
            (record.metadata_offset, record.metadata_size),
        ] {
            if offset != 0 && size != 0 {
                let offset = usize::try_from(offset).map_err(|_| {
                    Error::Invalid(format!(
                        "stream 0x{stream_id:02X} record {index} payload offset exceeds usize"
                    ))
                })?;
                if offset >= stream.len() {
                    return invalid(format!(
                        "stream 0x{stream_id:02X} record {index} payload offset 0x{offset:x} exceeds stream 0x{:x}",
                        stream.len()
                    ));
                }
                first_payload = first_payload.min(offset);
            }
        }
        records.push(record);
        if end == first_payload {
            return Ok((header, records, first_payload));
        }
        if end > first_payload {
            return invalid(format!(
                "stream 0x{stream_id:02X} descriptor table crosses first payload at 0x{first_payload:x}"
            ));
        }
    }
    invalid(format!(
        "stream 0x{stream_id:02X} has no descriptor boundary in 256 records"
    ))
}

fn decrypt_record(raw: &[u8], index: usize, state: u32) -> Result<Record> {
    if raw.len() != RECORD_SIZE {
        return invalid(format!(
            "record {index} has size 0x{:x}, expected 0x{RECORD_SIZE:x}",
            raw.len()
        ));
    }
    let product = state.wrapping_add(0x96f6_0b71).wrapping_mul(state);
    let index_mask = product.wrapping_shl(((index + 1) & 3) as u32);
    let mix = state.wrapping_mul(0x06a5_5bcc).wrapping_add(product);
    let mut accumulator = 0x7993_4cf6_u32;
    let mut feedback = 0xf02f_7685_u32;
    let mut words = [0_u32; RECORD_SIZE / 4];
    for (word_index, chunk) in raw.chunks_exact(4).enumerate() {
        feedback = feedback.wrapping_mul(feedback);
        let cipher = u32::from_le_bytes(
            chunk
                .try_into()
                .map_err(|_| Error::Invalid("record word has an invalid size".to_owned()))?,
        );
        let mut value = gf32_mul_fixed(cipher ^ (feedback >> 3)) ^ index_mask;
        value = value.wrapping_add(accumulator).wrapping_add(state);
        value = value.wrapping_sub(mix >> ((word_index * 4 + 3) & 5));
        words[word_index] = value;
        accumulator = accumulator.wrapping_add(0xe64d_33d8);
        feedback = cipher;
    }
    Ok(Record {
        index,
        command_id: words[0],
        flags: words[1],
        image_offset: words[2],
        image_size: words[3],
        metadata_offset: words[4],
        metadata_size: words[5],
        id_copy: words[6],
        entry_offset: words[7],
        init_offset: words[8],
    })
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data.get(offset..offset + 4).ok_or_else(|| {
        Error::Invalid(format!("record header range 0x{offset:x} is out of bounds"))
    })?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        Error::Invalid("invalid record u32 range".to_owned())
    })?))
}
