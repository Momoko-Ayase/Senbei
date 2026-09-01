//! Static restoration of protected IL2CPP v31 method tokens.

use serde::Serialize;

/// Seed embedded in the current `libil2cpp` module `0x0C`.
pub const DEFAULT_METHOD_TOKEN_SEED: u32 = 0xa6fa_e968;

const MAGIC: u32 = 0xfab1_1baf;
const SUPPORTED_VERSION: u32 = 31;
const HDR_METHODS: usize = 0x30;
const HDR_TYPES: usize = 0xa0;
const HDR_IMAGES: usize = 0xa8;
const METHOD_STRIDE: usize = 0x24;
const METHOD_TOKEN_OFFSET: usize = 0x18;
const TYPE_STRIDE: usize = 0x58;
const TYPE_METHOD_START_OFFSET: usize = 0x24;
const TYPE_METHOD_COUNT_OFFSET: usize = 0x40;
const IMAGE_STRIDE: usize = 0x28;
const IMAGE_TYPE_START_OFFSET: usize = 0x08;
const IMAGE_TYPE_COUNT_OFFSET: usize = 0x0c;
const METHOD_TOKEN_TABLE: u32 = 0x0600_0000;

/// Summary of one metadata restoration pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub version: u32,
    pub seed: String,
    pub encryption_status: String,
    pub images: usize,
    pub images_with_methods: usize,
    pub types: usize,
    pub methods: usize,
    pub visited_methods: usize,
    pub already_correct_before: usize,
    pub correct_after: usize,
    pub changed_tokens: usize,
    pub transformed_images: usize,
}

/// Per-image constraints recovered from the encrypted MethodDef RID
/// permutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageKeyDiscovery {
    pub image: usize,
    pub method_count: u32,
    pub modulus: u32,
    pub clean: bool,
    pub seed_residues: Vec<u32>,
}

/// Result of statically testing the known five-round permutation against a
/// metadata file without assuming a seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SeedDiscoveryReport {
    pub version: u32,
    pub images: Vec<ImageKeyDiscovery>,
    pub seed_candidates: Vec<u32>,
}

/// Metadata parsing or validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("not an IL2CPP global-metadata.dat")]
    NotMetadata,
    #[error("unsupported metadata version {0}")]
    UnsupportedVersion(u32),
    #[error("malformed metadata: {0}")]
    Malformed(String),
    #[error("method-token restoration failed: {0}")]
    Validation(String),
}

type Result<T> = std::result::Result<T, Error>;

fn malformed<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Malformed(message.into()))
}

fn validation<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Validation(message.into()))
}

fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::Malformed("byte range overflow".to_owned()))?;
    data.get(offset..end).ok_or_else(|| {
        Error::Malformed(format!(
            "byte range 0x{offset:x}..0x{end:x} is out of bounds"
        ))
    })
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let value: [u8; 2] = bytes(data, offset, 2)?
        .try_into()
        .map_err(|_| Error::Malformed("invalid u16 range".to_owned()))?;
    Ok(u16::from_le_bytes(value))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let value: [u8; 4] = bytes(data, offset, 4)?
        .try_into()
        .map_err(|_| Error::Malformed("invalid u32 range".to_owned()))?;
    Ok(u32::from_le_bytes(value))
}

fn read_i32(data: &[u8], offset: usize) -> Result<i32> {
    let value: [u8; 4] = bytes(data, offset, 4)?
        .try_into()
        .map_err(|_| Error::Malformed("invalid i32 range".to_owned()))?;
    Ok(i32::from_le_bytes(value))
}

fn table(data: &[u8], header_offset: usize) -> Result<(usize, usize)> {
    let offset = read_u32(data, header_offset)? as usize;
    let size = read_u32(data, header_offset + 4)? as usize;
    bytes(data, offset, size)?;
    Ok((offset, size))
}

#[inline]
fn inverse_round(mut value: u32, count: u32, key: u32) -> u32 {
    let mirror = count.wrapping_mul(2).wrapping_sub(1);
    if value & 1 != 0 {
        value = mirror.wrapping_sub(value);
    }
    value >>= 1;
    if value >= count {
        value = mirror.wrapping_sub(value);
    }
    let value = value.wrapping_sub(key);
    if value > count {
        value.wrapping_add(count)
    } else {
        value
    }
}

fn decrypt_rid(rid: u32, low: u32, high: u32, seed: u32) -> Result<u32> {
    let count = high
        .checked_add(1)
        .and_then(|value| value.checked_sub(low))
        .ok_or_else(|| Error::Validation("invalid image RID interval".to_owned()))?;
    if count < 2 {
        return validation("RID inverse permutation requires at least two entries");
    }
    let half = count / 2;
    if half == 0 {
        return validation("RID inverse permutation has a zero divisor");
    }
    let key = seed % half + count / 4;
    let mut value = rid
        .checked_sub(low)
        .ok_or_else(|| Error::Validation("encrypted RID lies below image minimum".to_owned()))?;
    for _ in 0..5 {
        value = inverse_round(value, count, key);
    }
    value
        .checked_add(low)
        .ok_or_else(|| Error::Validation("restored RID overflow".to_owned()))
}

/// Restore MethodDef RID values exactly as module `0x0C` does.
///
/// The operation is idempotent for tooling purposes: an image whose tokens are
/// already canonical is detected and left untouched instead of applying the
/// native inverse permutation a second time.
pub fn restore_method_tokens(data: &[u8], seed: u32) -> Result<(Vec<u8>, Report)> {
    if read_u32(data, 0).ok() != Some(MAGIC) {
        return Err(Error::NotMetadata);
    }
    let version = read_u32(data, 4)?;
    if version != SUPPORTED_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }

    let (method_offset, method_size) = table(data, HDR_METHODS)?;
    let (type_offset, type_size) = table(data, HDR_TYPES)?;
    let (image_offset, image_size) = table(data, HDR_IMAGES)?;
    if method_size % METHOD_STRIDE != 0
        || type_size % TYPE_STRIDE != 0
        || image_size % IMAGE_STRIDE != 0
    {
        return malformed("v31 table size is not divisible by its entry stride");
    }
    let method_count = method_size / METHOD_STRIDE;
    let type_count = type_size / TYPE_STRIDE;
    let image_count = image_size / IMAGE_STRIDE;
    let mut owners = vec![u32::MAX; method_count];
    let mut output = data.to_vec();
    let mut images_with_methods = 0_usize;
    let mut visited_methods = 0_usize;
    let mut already_correct_before = 0_usize;
    let mut correct_after = 0_usize;
    let mut changed_tokens = 0_usize;
    let mut transformed_images = 0_usize;

    for image_index in 0..image_count {
        let image_base = image_offset + image_index * IMAGE_STRIDE;
        let type_start = read_i32(data, image_base + IMAGE_TYPE_START_OFFSET)?;
        let type_start = usize::try_from(type_start)
            .map_err(|_| Error::Malformed(format!("image {image_index} has negative typeStart")))?;
        let type_entries = read_u32(data, image_base + IMAGE_TYPE_COUNT_OFFSET)? as usize;
        let type_end = type_start
            .checked_add(type_entries)
            .ok_or_else(|| Error::Malformed("image type range overflow".to_owned()))?;
        if type_end > type_count {
            return malformed(format!("image {image_index} type range exceeds the table"));
        }

        let mut methods = Vec::new();
        for type_index in type_start..type_end {
            let type_base = type_offset + type_index * TYPE_STRIDE;
            let method_entries = read_u16(data, type_base + TYPE_METHOD_COUNT_OFFSET)? as usize;
            if method_entries == 0 {
                continue;
            }
            let method_start = read_i32(data, type_base + TYPE_METHOD_START_OFFSET)?;
            let method_start = usize::try_from(method_start).map_err(|_| {
                Error::Malformed(format!(
                    "type {type_index} has methods but negative methodStart"
                ))
            })?;
            let method_end = method_start
                .checked_add(method_entries)
                .ok_or_else(|| Error::Malformed("type method range overflow".to_owned()))?;
            if method_end > method_count {
                return malformed(format!("type {type_index} method range exceeds the table"));
            }
            for (method_index, owner) in owners
                .iter_mut()
                .enumerate()
                .take(method_end)
                .skip(method_start)
            {
                if *owner != u32::MAX {
                    return malformed(format!("method {method_index} belongs to multiple images"));
                }
                *owner = u32::try_from(image_index)
                    .map_err(|_| Error::Malformed("image index exceeds u32".to_owned()))?;
                methods.push(method_index);
            }
        }
        if methods.is_empty() {
            continue;
        }
        images_with_methods += 1;
        visited_methods += methods.len();
        let method_base = *methods
            .iter()
            .min()
            .ok_or_else(|| Error::Malformed("nonempty image lost its method minimum".to_owned()))?;
        let method_last = *methods
            .iter()
            .max()
            .ok_or_else(|| Error::Malformed("nonempty image lost its method maximum".to_owned()))?;
        if method_last - method_base + 1 != methods.len() {
            return malformed(format!(
                "image {image_index} method block is not contiguous"
            ));
        }

        let mut tokens = Vec::with_capacity(methods.len());
        let mut image_already_clean = true;
        for &method_index in &methods {
            let token_offset = method_offset + method_index * METHOD_STRIDE + METHOD_TOKEN_OFFSET;
            let token = read_u32(data, token_offset)?;
            if token & 0xff00_0000 != METHOD_TOKEN_TABLE {
                return malformed(format!(
                    "method {method_index} has non-MethodDef token 0x{token:08x}"
                ));
            }
            let expected = u32::try_from(method_index - method_base + 1)
                .map_err(|_| Error::Validation("local method RID exceeds u32".to_owned()))?;
            let rid = token & 0x00ff_ffff;
            if rid == expected {
                already_correct_before += 1;
            } else {
                image_already_clean = false;
            }
            tokens.push((method_index, token_offset, token, expected));
        }

        if image_already_clean {
            correct_after += tokens.len();
            continue;
        }
        transformed_images += 1;
        let low = tokens
            .iter()
            .map(|(_, _, token, _)| token & 0x00ff_ffff)
            .min()
            .ok_or_else(|| Error::Validation("image has no MethodDef RID".to_owned()))?;
        let high = tokens
            .iter()
            .map(|(_, _, token, _)| token & 0x00ff_ffff)
            .max()
            .ok_or_else(|| Error::Validation("image has no MethodDef RID".to_owned()))?;
        if high <= 1 {
            return validation(format!(
                "image {image_index} is noncanonical but native R > 1 gate would skip it"
            ));
        }
        let interval = high - low + 1;
        if interval as usize != tokens.len() {
            return validation(format!(
                "image {image_index} RID interval {low}..={high} is not a permutation"
            ));
        }
        for (method_index, token_offset, token, expected) in tokens {
            let restored_rid = decrypt_rid(token & 0x00ff_ffff, low, high, seed)?;
            if restored_rid != expected {
                return validation(format!(
                    "method {method_index} restored RID {restored_rid} != expected {expected}"
                ));
            }
            let restored_token = METHOD_TOKEN_TABLE | restored_rid;
            if restored_token != token {
                output[token_offset..token_offset + 4]
                    .copy_from_slice(&restored_token.to_le_bytes());
                changed_tokens += 1;
            }
            correct_after += 1;
        }
    }

    if owners.contains(&u32::MAX) {
        return malformed("one or more method definitions are not owned by an image");
    }
    if visited_methods != method_count || correct_after != method_count {
        return validation(format!(
            "method coverage mismatch: visited={visited_methods}, correct={correct_after}, total={method_count}"
        ));
    }

    Ok((
        output,
        Report {
            version,
            seed: format!("0x{seed:08X}"),
            encryption_status: if changed_tokens == 0 {
                "clean".to_owned()
            } else {
                "encrypted".to_owned()
            },
            images: image_count,
            images_with_methods,
            types: type_count,
            methods: method_count,
            visited_methods,
            already_correct_before,
            correct_after,
            changed_tokens,
            transformed_images,
        },
    ))
}

/// Discover seeds compatible with the known v31 five-round RID permutation.
///
/// This is diagnostic and does not modify metadata. It enumerates the only
/// possible per-image key residues and intersects them over the 32-bit seed
/// domain. An empty candidate list means that the sample changed the
/// permutation itself rather than merely embedding a different seed.
pub fn discover_method_token_seeds(data: &[u8]) -> Result<SeedDiscoveryReport> {
    if read_u32(data, 0).ok() != Some(MAGIC) {
        return Err(Error::NotMetadata);
    }
    let version = read_u32(data, 4)?;
    if version != SUPPORTED_VERSION {
        return Ok(SeedDiscoveryReport {
            version,
            images: Vec::new(),
            seed_candidates: Vec::new(),
        });
    }
    let (method_offset, method_size) = table(data, HDR_METHODS)?;
    let (type_offset, type_size) = table(data, HDR_TYPES)?;
    let (image_offset, image_size) = table(data, HDR_IMAGES)?;
    if method_size % METHOD_STRIDE != 0
        || type_size % TYPE_STRIDE != 0
        || image_size % IMAGE_STRIDE != 0
    {
        return malformed("v31 table size is not divisible by its entry stride");
    }
    let method_count = method_size / METHOD_STRIDE;
    let type_count = type_size / TYPE_STRIDE;
    let image_count = image_size / IMAGE_STRIDE;
    let mut reports = Vec::with_capacity(image_count);
    for image_index in 0..image_count {
        let image_base = image_offset + image_index * IMAGE_STRIDE;
        let type_start = usize::try_from(read_i32(data, image_base + IMAGE_TYPE_START_OFFSET)?)
            .map_err(|_| Error::Malformed(format!("image {image_index} has negative typeStart")))?;
        let type_entries = read_u32(data, image_base + IMAGE_TYPE_COUNT_OFFSET)? as usize;
        let type_end = type_start
            .checked_add(type_entries)
            .ok_or_else(|| Error::Malformed("image type range overflow".to_owned()))?;
        if type_end > type_count {
            return malformed(format!("image {image_index} type range exceeds the table"));
        }
        let mut methods = Vec::new();
        for type_index in type_start..type_end {
            let type_base = type_offset + type_index * TYPE_STRIDE;
            let method_entries = read_u16(data, type_base + TYPE_METHOD_COUNT_OFFSET)? as usize;
            if method_entries == 0 {
                continue;
            }
            let method_start =
                usize::try_from(read_i32(data, type_base + TYPE_METHOD_START_OFFSET)?).map_err(
                    |_| Error::Malformed(format!("type {type_index} has negative methodStart")),
                )?;
            let method_end = method_start
                .checked_add(method_entries)
                .ok_or_else(|| Error::Malformed("type method range overflow".to_owned()))?;
            if method_end > method_count {
                return malformed(format!("type {type_index} method range exceeds the table"));
            }
            methods.extend(method_start..method_end);
        }
        if methods.is_empty() {
            reports.push(ImageKeyDiscovery {
                image: image_index,
                method_count: 0,
                modulus: 0,
                clean: true,
                seed_residues: Vec::new(),
            });
            continue;
        }
        let method_base = *methods
            .iter()
            .min()
            .ok_or_else(|| Error::Malformed("image method minimum is missing".to_owned()))?;
        let method_last = *methods
            .iter()
            .max()
            .ok_or_else(|| Error::Malformed("image method maximum is missing".to_owned()))?;
        if method_last - method_base + 1 != methods.len() {
            return validation(format!(
                "image {image_index} method block is not contiguous"
            ));
        }
        let mut values = Vec::with_capacity(methods.len());
        let mut clean = true;
        for method_index in methods {
            let token = read_u32(
                data,
                method_offset + method_index * METHOD_STRIDE + METHOD_TOKEN_OFFSET,
            )?;
            if token & 0xff00_0000 != METHOD_TOKEN_TABLE {
                return validation(format!(
                    "method {method_index} has non-MethodDef token 0x{token:08x}"
                ));
            }
            let expected = u32::try_from(method_index - method_base + 1)
                .map_err(|_| Error::Validation("local method RID exceeds u32".to_owned()))?;
            let rid = token & 0x00ff_ffff;
            clean &= rid == expected;
            values.push((rid, expected));
        }
        let count = u32::try_from(values.len())
            .map_err(|_| Error::Validation("image method count exceeds u32".to_owned()))?;
        if clean {
            reports.push(ImageKeyDiscovery {
                image: image_index,
                method_count: count,
                modulus: count / 2,
                clean,
                seed_residues: Vec::new(),
            });
            continue;
        }
        let low = values
            .iter()
            .map(|(rid, _)| *rid)
            .min()
            .ok_or_else(|| Error::Validation("image has no encrypted RID".to_owned()))?;
        let high = values
            .iter()
            .map(|(rid, _)| *rid)
            .max()
            .ok_or_else(|| Error::Validation("image has no encrypted RID".to_owned()))?;
        if high - low + 1 != count || count < 2 {
            return validation(format!(
                "image {image_index} RID interval is not a permutation"
            ));
        }
        let half = count / 2;
        let quarter = count / 4;
        let mut residues = Vec::new();
        for key_delta in 0..half {
            let key = quarter + key_delta;
            let valid = values
                .iter()
                .all(|(rid, expected)| decrypt_rid_with_key(*rid, low, high, key) == *expected);
            if valid {
                residues.push(key_delta);
            }
        }
        reports.push(ImageKeyDiscovery {
            image: image_index,
            method_count: count,
            modulus: half,
            clean,
            seed_residues: residues,
        });
    }

    let constraints = reports
        .iter()
        .filter(|report| !report.clean)
        .collect::<Vec<_>>();
    let mut seeds = Vec::new();
    if let Some(anchor) = constraints.iter().max_by_key(|report| report.modulus) {
        for &residue in &anchor.seed_residues {
            let mut candidate = u64::from(residue);
            let modulus = u64::from(anchor.modulus);
            while candidate <= u64::from(u32::MAX) {
                let valid = constraints.iter().all(|report| {
                    report.modulus != 0
                        && !report.seed_residues.is_empty()
                        && report
                            .seed_residues
                            .iter()
                            .any(|&value| candidate % u64::from(report.modulus) == u64::from(value))
                });
                if valid {
                    seeds.push(candidate as u32);
                }
                candidate = candidate.saturating_add(modulus);
            }
        }
    }
    seeds.sort_unstable();
    seeds.dedup();
    Ok(SeedDiscoveryReport {
        version,
        images: reports,
        seed_candidates: seeds,
    })
}

fn decrypt_rid_with_key(rid: u32, low: u32, high: u32, key: u32) -> u32 {
    let count = high - low + 1;
    let mut value = rid - low;
    for _ in 0..5 {
        value = inverse_round(value, count, key);
    }
    value + low
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn encrypted_rid(expected: u32, count: u32, seed: u32) -> u32 {
        (1..=count)
            .find(|&candidate| decrypt_rid(candidate, 1, count, seed) == Ok(expected))
            .expect("inverse permutation must be bijective")
    }

    fn build(tokens: &[u32]) -> (Vec<u8>, usize) {
        let header_size = 0x100;
        let images = header_size;
        let types = images + IMAGE_STRIDE;
        let methods = types + 2 * TYPE_STRIDE;
        let mut data = vec![0_u8; methods + tokens.len() * METHOD_STRIDE];
        put_u32(&mut data, 0, MAGIC);
        put_u32(&mut data, 4, SUPPORTED_VERSION);
        put_u32(&mut data, HDR_METHODS, methods as u32);
        put_u32(
            &mut data,
            HDR_METHODS + 4,
            (tokens.len() * METHOD_STRIDE) as u32,
        );
        put_u32(&mut data, HDR_TYPES, types as u32);
        put_u32(&mut data, HDR_TYPES + 4, (2 * TYPE_STRIDE) as u32);
        put_u32(&mut data, HDR_IMAGES, images as u32);
        put_u32(&mut data, HDR_IMAGES + 4, IMAGE_STRIDE as u32);
        put_u32(&mut data, images + IMAGE_TYPE_START_OFFSET, 0);
        put_u32(&mut data, images + IMAGE_TYPE_COUNT_OFFSET, 2);
        // Deliberately traverse the high method indices first.
        put_u32(&mut data, types + TYPE_METHOD_START_OFFSET, 4);
        put_u16(&mut data, types + TYPE_METHOD_COUNT_OFFSET, 3);
        put_u32(&mut data, types + TYPE_STRIDE + TYPE_METHOD_START_OFFSET, 0);
        put_u16(&mut data, types + TYPE_STRIDE + TYPE_METHOD_COUNT_OFFSET, 4);
        for (index, &token) in tokens.iter().enumerate() {
            put_u32(
                &mut data,
                methods + index * METHOD_STRIDE + METHOD_TOKEN_OFFSET,
                token,
            );
        }
        (data, methods)
    }

    #[test]
    fn restores_five_round_permutation_by_physical_method_index() {
        let tokens = (1..=7)
            .map(|expected| {
                METHOD_TOKEN_TABLE | encrypted_rid(expected, 7, DEFAULT_METHOD_TOKEN_SEED)
            })
            .collect::<Vec<_>>();
        let (data, methods) = build(&tokens);
        let (restored, report) =
            restore_method_tokens(&data, DEFAULT_METHOD_TOKEN_SEED).expect("restore");
        assert_eq!(report.encryption_status, "encrypted");
        assert!(report.changed_tokens > 0);
        assert_eq!(report.correct_after, 7);
        for index in 0..7 {
            assert_eq!(
                read_u32(
                    &restored,
                    methods + index * METHOD_STRIDE + METHOD_TOKEN_OFFSET
                )
                .expect("token"),
                METHOD_TOKEN_TABLE | (index as u32 + 1)
            );
        }
    }

    #[test]
    fn clean_metadata_is_idempotent() {
        let tokens = (1..=7)
            .map(|rid| METHOD_TOKEN_TABLE | rid)
            .collect::<Vec<_>>();
        let (data, _) = build(&tokens);
        let (restored, report) =
            restore_method_tokens(&data, DEFAULT_METHOD_TOKEN_SEED).expect("restore");
        assert_eq!(report.encryption_status, "clean");
        assert_eq!(report.changed_tokens, 0);
        assert_eq!(restored, data);
    }

    #[test]
    fn encrypted_metadata_rejects_the_wrong_seed() {
        let tokens = (1..=7)
            .map(|expected| {
                METHOD_TOKEN_TABLE | encrypted_rid(expected, 7, DEFAULT_METHOD_TOKEN_SEED)
            })
            .collect::<Vec<_>>();
        let (data, _) = build(&tokens);
        let wrong_seed = DEFAULT_METHOD_TOKEN_SEED.wrapping_add(1);

        assert!(matches!(
            restore_method_tokens(&data, wrong_seed),
            Err(Error::Validation(_))
        ));
    }
}
