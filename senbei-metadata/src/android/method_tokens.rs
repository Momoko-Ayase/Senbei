//! Static restoration of protected IL2CPP method tokens for verified layouts.

use serde::Serialize;

use crate::common::MAGIC;

/// Seed embedded in the current `libil2cpp` module `0x0C`.
pub const DEFAULT_METHOD_TOKEN_SEED: u32 = 0xa6fa_e968;

const SUPPORTED_V29: u32 = 29;
const SUPPORTED_V31: u32 = 31;
const HDR_METHODS: usize = 0x30;
const HDR_TYPES: usize = 0xa0;
const HDR_IMAGES: usize = 0xa8;
const TYPE_STRIDE: usize = 0x58;
const TYPE_METHOD_START_OFFSET: usize = 0x24;
const TYPE_METHOD_COUNT_OFFSET: usize = 0x40;
const IMAGE_STRIDE: usize = 0x28;
const IMAGE_TYPE_START_OFFSET: usize = 0x08;
const IMAGE_TYPE_COUNT_OFFSET: usize = 0x0c;
const METHOD_TOKEN_TABLE: u32 = 0x0600_0000;

// The aliases keep the v31 synthetic fixtures readable; production paths use
// the version-specific layout returned by `layout_for_version`.
#[cfg(test)]
const METHOD_STRIDE: usize = 0x24;
#[cfg(test)]
const METHOD_TOKEN_OFFSET: usize = 0x18;

#[derive(Clone, Copy)]
struct Layout {
    method_stride: usize,
    method_token_offset: usize,
}

fn layout_for_version(version: u32) -> Option<Layout> {
    match version {
        SUPPORTED_V29 => Some(Layout {
            method_stride: 0x20,
            method_token_offset: 0x14,
        }),
        SUPPORTED_V31 => Some(Layout {
            method_stride: 0x24,
            method_token_offset: 0x18,
        }),
        _ => None,
    }
}

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
    if version == 39 {
        return restore_v39(data, seed);
    }
    let Some(layout) = layout_for_version(version) else {
        return Err(Error::UnsupportedVersion(version));
    };

    let (method_offset, method_size) = table(data, HDR_METHODS)?;
    let (type_offset, type_size) = table(data, HDR_TYPES)?;
    let (image_offset, image_size) = table(data, HDR_IMAGES)?;
    if method_size % layout.method_stride != 0
        || type_size % TYPE_STRIDE != 0
        || image_size % IMAGE_STRIDE != 0
    {
        return malformed("method/type/image table size is not divisible by its entry stride");
    }
    let method_count = method_size / layout.method_stride;
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
            let token_offset =
                method_offset + method_index * layout.method_stride + layout.method_token_offset;
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

/// Discover seeds compatible with the known five-round RID permutation.
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
    if version == 39 {
        return discover_v39(data);
    }
    let Some(layout) = layout_for_version(version) else {
        return Ok(SeedDiscoveryReport {
            version,
            images: Vec::new(),
            seed_candidates: Vec::new(),
        });
    };
    let (method_offset, method_size) = table(data, HDR_METHODS)?;
    let (type_offset, type_size) = table(data, HDR_TYPES)?;
    let (image_offset, image_size) = table(data, HDR_IMAGES)?;
    if method_size % layout.method_stride != 0
        || type_size % TYPE_STRIDE != 0
        || image_size % IMAGE_STRIDE != 0
    {
        return malformed("method/type/image table size is not divisible by its entry stride");
    }
    let method_count = method_size / layout.method_stride;
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
                method_offset + method_index * layout.method_stride + layout.method_token_offset,
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

const V39_METHODS: usize = 5;
const V39_PARAMETERS: usize = 10;
const V39_GENERIC_CONTAINERS: usize = 14;
const V39_INTERFACE_OFFSETS: usize = 18;
const V39_TYPES: usize = 19;
const V39_IMAGES: usize = 20;

#[derive(Debug, Clone, Copy)]
struct V39Layout {
    method_offset: usize,
    method_count: usize,
    method_stride: usize,
    method_token_offset: usize,
    type_definition_index_width: usize,
    type_offset: usize,
    type_count: usize,
    type_stride: usize,
    type_method_start_offset: usize,
    type_method_count_offset: usize,
    image_offset: usize,
    image_count: usize,
    image_stride: usize,
}

fn v39_section(data: &[u8], index: usize) -> Result<(usize, usize, usize)> {
    let header = 8_usize
        .checked_add(
            index
                .checked_mul(12)
                .ok_or_else(|| Error::Malformed("v39 section header offset overflow".to_owned()))?,
        )
        .ok_or_else(|| Error::Malformed("v39 section header offset overflow".to_owned()))?;
    let offset = read_u32(data, header)? as usize;
    let size = read_u32(data, header + 4)? as usize;
    let count = read_u32(data, header + 8)? as usize;
    bytes(data, offset, size)?;
    Ok((offset, size, count))
}

fn v39_index_width(count: usize) -> usize {
    if count <= u8::MAX as usize {
        1
    } else if count <= u16::MAX as usize {
        2
    } else {
        4
    }
}

fn read_v39_index(data: &[u8], offset: usize, width: usize) -> Result<usize> {
    match width {
        1 => Ok(bytes(data, offset, 1)?[0] as usize),
        2 => Ok(read_u16(data, offset)? as usize),
        4 => Ok(read_u32(data, offset)? as usize),
        _ => malformed("v39 index has an unsupported width"),
    }
}

fn parse_v39(data: &[u8]) -> Result<V39Layout> {
    let (method_offset, method_size, method_count) = v39_section(data, V39_METHODS)?;
    let (_, parameter_size, parameter_count) = v39_section(data, V39_PARAMETERS)?;
    let (_, _, generic_count) = v39_section(data, V39_GENERIC_CONTAINERS)?;
    let (_interface_offset, interface_size, interface_count) =
        v39_section(data, V39_INTERFACE_OFFSETS)?;
    let (type_offset, type_size, type_count) = v39_section(data, V39_TYPES)?;
    let (image_offset, image_size, image_count) = v39_section(data, V39_IMAGES)?;
    let parameter_index_width = v39_index_width(parameter_count);
    let generic_container_index_width = v39_index_width(generic_count);
    let type_definition_index_width = v39_index_width(type_count);
    let type_index_width = if interface_count == 0 {
        4
    } else {
        let element_size = interface_size
            .checked_div(interface_count)
            .ok_or_else(|| Error::Malformed("v39 interface-offset size is invalid".to_owned()))?;
        element_size
            .checked_sub(4)
            .filter(|width| matches!(width, 1 | 2 | 4))
            .ok_or_else(|| Error::Malformed("v39 type-index width is invalid".to_owned()))?
    };
    let method_stride = 20_usize
        .checked_add(type_definition_index_width)
        .and_then(|size| size.checked_add(type_index_width))
        .and_then(|size| size.checked_add(parameter_index_width))
        .and_then(|size| size.checked_add(generic_container_index_width))
        .ok_or_else(|| Error::Malformed("v39 method stride overflow".to_owned()))?;
    let type_stride = 68_usize
        .checked_add(
            type_index_width
                .checked_mul(3)
                .ok_or_else(|| Error::Malformed("v39 type stride overflow".to_owned()))?,
        )
        .and_then(|size| size.checked_add(generic_container_index_width))
        .ok_or_else(|| Error::Malformed("v39 type stride overflow".to_owned()))?;
    let image_stride = 32_usize
        .checked_add(
            type_definition_index_width
                .checked_mul(2)
                .ok_or_else(|| Error::Malformed("v39 image stride overflow".to_owned()))?,
        )
        .ok_or_else(|| Error::Malformed("v39 image stride overflow".to_owned()))?;
    if method_count.checked_mul(method_stride) != Some(method_size)
        || type_count.checked_mul(type_stride) != Some(type_size)
        || image_count.checked_mul(image_stride) != Some(image_size)
        || parameter_count == 0 && parameter_size != 0
    {
        return malformed("v39 table size does not match its compact entry layout");
    }
    let type_method_start_offset = 16_usize
        .checked_add(
            type_index_width
                .checked_mul(3)
                .ok_or_else(|| Error::Malformed("v39 type method offset overflow".to_owned()))?,
        )
        .and_then(|offset| offset.checked_add(generic_container_index_width))
        .ok_or_else(|| Error::Malformed("v39 type method offset overflow".to_owned()))?;
    let type_method_count_offset = type_method_start_offset
        .checked_add(7 * 4)
        .ok_or_else(|| Error::Malformed("v39 type method count offset overflow".to_owned()))?;
    let method_token_offset = 4_usize
        .checked_add(type_definition_index_width)
        .and_then(|offset| offset.checked_add(type_index_width))
        .and_then(|offset| offset.checked_add(4))
        .and_then(|offset| offset.checked_add(parameter_index_width))
        .and_then(|offset| offset.checked_add(generic_container_index_width))
        .ok_or_else(|| Error::Malformed("v39 method token offset overflow".to_owned()))?;
    if method_token_offset
        .checked_add(4)
        .is_none_or(|end| end > method_stride)
        || type_method_count_offset
            .checked_add(2)
            .is_none_or(|end| end > type_stride)
    {
        return malformed("v39 compact layout fields exceed their records");
    }
    // Touch the section base so malformed headers fail before any output copy.
    Ok(V39Layout {
        method_offset,
        method_count,
        method_stride,
        method_token_offset,
        type_definition_index_width,
        type_offset,
        type_count,
        type_stride,
        type_method_start_offset,
        type_method_count_offset,
        image_offset,
        image_count,
        image_stride,
    })
}

fn v39_image_methods(data: &[u8], layout: V39Layout, image: usize) -> Result<Vec<usize>> {
    let image_base = layout
        .image_offset
        .checked_add(
            image
                .checked_mul(layout.image_stride)
                .ok_or_else(|| Error::Malformed("v39 image offset overflow".to_owned()))?,
        )
        .ok_or_else(|| Error::Malformed("v39 image offset overflow".to_owned()))?;
    let type_start = read_v39_index(data, image_base + 8, layout.type_definition_index_width)?;
    let type_count = read_u32(data, image_base + 8 + layout.type_definition_index_width)? as usize;
    let type_end = type_start
        .checked_add(type_count)
        .ok_or_else(|| Error::Malformed("v39 image type range overflow".to_owned()))?;
    if type_end > layout.type_count {
        return malformed("v39 image type range exceeds the type table");
    }
    let mut methods = Vec::new();
    for type_index in type_start..type_end {
        let type_base = layout
            .type_offset
            .checked_add(
                type_index
                    .checked_mul(layout.type_stride)
                    .ok_or_else(|| Error::Malformed("v39 type offset overflow".to_owned()))?,
            )
            .ok_or_else(|| Error::Malformed("v39 type offset overflow".to_owned()))?;
        let method_start = read_u32(data, type_base + layout.type_method_start_offset)?;
        let method_count = read_u16(data, type_base + layout.type_method_count_offset)? as usize;
        if method_start == u32::MAX || method_count == 0 {
            continue;
        }
        let method_start = method_start as usize;
        let method_end = method_start
            .checked_add(method_count)
            .ok_or_else(|| Error::Malformed("v39 type method range overflow".to_owned()))?;
        if method_end > layout.method_count {
            return malformed("v39 type method range exceeds the method table");
        }
        methods.extend(method_start..method_end);
    }
    Ok(methods)
}

#[allow(clippy::too_many_arguments)]
fn v39_report(
    layout: V39Layout,
    changed_tokens: usize,
    images_with_methods: usize,
    visited_methods: usize,
    already_correct_before: usize,
    correct_after: usize,
    transformed_images: usize,
    seed: u32,
) -> Report {
    Report {
        version: 39,
        seed: format!("0x{seed:08X}"),
        encryption_status: if changed_tokens == 0 {
            "clean".to_owned()
        } else {
            "encrypted".to_owned()
        },
        images: layout.image_count,
        images_with_methods,
        types: layout.type_count,
        methods: layout.method_count,
        visited_methods,
        already_correct_before,
        correct_after,
        changed_tokens,
        transformed_images,
    }
}

fn restore_v39(data: &[u8], seed: u32) -> Result<(Vec<u8>, Report)> {
    let layout = parse_v39(data)?;
    let mut owners = vec![u32::MAX; layout.method_count];
    let mut output = data.to_vec();
    let mut images_with_methods = 0;
    let mut visited_methods = 0;
    let mut already_correct_before = 0;
    let mut correct_after = 0;
    let mut changed_tokens = 0;
    let mut transformed_images = 0;
    for image in 0..layout.image_count {
        let methods = v39_image_methods(data, layout, image)?;
        if methods.is_empty() {
            continue;
        }
        images_with_methods += 1;
        visited_methods += methods.len();
        let method_base = *methods.iter().min().ok_or_else(|| {
            Error::Malformed("v39 nonempty image lost its method minimum".to_owned())
        })?;
        let method_last = *methods.iter().max().ok_or_else(|| {
            Error::Malformed("v39 nonempty image lost its method maximum".to_owned())
        })?;
        if method_last - method_base + 1 != methods.len() {
            return validation(format!("v39 image {image} method block is not contiguous"));
        }
        for &method in &methods {
            if owners[method] != u32::MAX {
                return malformed(format!("v39 method {method} belongs to multiple images"));
            }
            owners[method] = image as u32;
        }
        let mut tokens = Vec::with_capacity(methods.len());
        let mut clean = true;
        for method in methods {
            let offset =
                layout.method_offset + method * layout.method_stride + layout.method_token_offset;
            let token = read_u32(data, offset)?;
            if token & 0xff00_0000 != METHOD_TOKEN_TABLE {
                return malformed(format!("v39 method {method} has a non-MethodDef token"));
            }
            let expected = (method - method_base + 1) as u32;
            let rid = token & 0x00ff_ffff;
            if rid == expected {
                already_correct_before += 1;
            } else {
                clean = false;
            }
            tokens.push((offset, token, expected));
        }
        if clean {
            correct_after += tokens.len();
            continue;
        }
        transformed_images += 1;
        let low = tokens
            .iter()
            .map(|(_, token, _)| token & 0x00ff_ffff)
            .min()
            .unwrap();
        let high = tokens
            .iter()
            .map(|(_, token, _)| token & 0x00ff_ffff)
            .max()
            .unwrap();
        if high - low + 1 != tokens.len() as u32 {
            return validation(format!(
                "v39 image {image} RID interval is not a permutation"
            ));
        }
        for (offset, token, expected) in tokens {
            let restored = decrypt_rid(token & 0x00ff_ffff, low, high, seed)?;
            if restored != expected {
                return validation(format!(
                    "v39 restored RID {restored} != expected {expected}"
                ));
            }
            let restored_token = METHOD_TOKEN_TABLE | restored;
            if restored_token != token {
                output[offset..offset + 4].copy_from_slice(&restored_token.to_le_bytes());
                changed_tokens += 1;
            }
            correct_after += 1;
        }
    }
    if owners.contains(&u32::MAX) {
        return malformed("v39 method definitions are not all owned by an image");
    }
    if visited_methods != layout.method_count || correct_after != layout.method_count {
        return validation(format!(
            "v39 method coverage mismatch: visited={visited_methods}, correct={correct_after}, total={}",
            layout.method_count
        ));
    }
    Ok((
        output,
        v39_report(
            layout,
            changed_tokens,
            images_with_methods,
            visited_methods,
            already_correct_before,
            correct_after,
            transformed_images,
            seed,
        ),
    ))
}

fn discover_v39(data: &[u8]) -> Result<SeedDiscoveryReport> {
    let layout = parse_v39(data)?;
    let mut reports = Vec::with_capacity(layout.image_count);
    for image in 0..layout.image_count {
        let methods = v39_image_methods(data, layout, image)?;
        if methods.is_empty() {
            reports.push(ImageKeyDiscovery {
                image,
                method_count: 0,
                modulus: 0,
                clean: true,
                seed_residues: Vec::new(),
            });
            continue;
        }
        let base = *methods.iter().min().unwrap();
        let last = *methods.iter().max().unwrap();
        if last - base + 1 != methods.len() {
            return validation(format!("v39 image {image} method block is not contiguous"));
        }
        let values = methods
            .iter()
            .map(|&method| {
                let offset = layout.method_offset
                    + method * layout.method_stride
                    + layout.method_token_offset;
                let token = read_u32(data, offset)?;
                if token & 0xff00_0000 != METHOD_TOKEN_TABLE {
                    return malformed(format!("v39 method {method} has a non-MethodDef token"));
                }
                Ok((token & 0x00ff_ffff, (method - base + 1) as u32))
            })
            .collect::<Result<Vec<_>>>()?;
        let count = u32::try_from(values.len())
            .map_err(|_| Error::Validation("v39 image method count exceeds u32".to_owned()))?;
        let clean = values.iter().all(|(rid, expected)| rid == expected);
        if clean {
            reports.push(ImageKeyDiscovery {
                image,
                method_count: count,
                modulus: count / 2,
                clean: true,
                seed_residues: Vec::new(),
            });
            continue;
        }
        let low = values.iter().map(|(rid, _)| *rid).min().unwrap();
        let high = values.iter().map(|(rid, _)| *rid).max().unwrap();
        if high - low + 1 != count || count < 2 {
            return validation(format!(
                "v39 image {image} RID interval is not a permutation"
            ));
        }
        let half = count / 2;
        let quarter = count / 4;
        let mut residues = Vec::new();
        for residue in 0..half {
            let key = quarter + residue;
            if values
                .iter()
                .all(|(rid, expected)| decrypt_rid_with_key(*rid, low, high, key) == *expected)
            {
                residues.push(residue);
            }
        }
        reports.push(ImageKeyDiscovery {
            image,
            method_count: count,
            modulus: half,
            clean: false,
            seed_residues: residues,
        });
    }
    let constraints = reports
        .iter()
        .filter(|image| !image.clean)
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();
    if let Some(anchor) = constraints.iter().max_by_key(|image| image.modulus) {
        // Returning every 32-bit seed is not representable for tiny synthetic
        // images (for example, a two-entry image has billions of candidates).
        // The caller still tries the known default seed and validates it fully.
        if anchor.modulus < 1024 {
            return Ok(SeedDiscoveryReport {
                version: 39,
                images: reports,
                seed_candidates: candidates,
            });
        }
        for &residue in &anchor.seed_residues {
            let modulus = u64::from(anchor.modulus);
            let mut candidate = u64::from(residue);
            while candidate <= u64::from(u32::MAX) {
                if constraints.iter().all(|image| {
                    image.modulus != 0
                        && image
                            .seed_residues
                            .iter()
                            .any(|value| candidate % u64::from(image.modulus) == u64::from(*value))
                }) {
                    candidates.push(candidate as u32);
                }
                candidate = candidate.saturating_add(modulus);
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    Ok(SeedDiscoveryReport {
        version: 39,
        images: reports,
        seed_candidates: candidates,
    })
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
        put_u32(&mut data, 4, SUPPORTED_V31);
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
    fn restores_v29_method_tokens_with_legacy_method_layout() {
        let method_stride = 0x20;
        let method_token_offset = 0x14;
        let hdr = 0x100usize;
        let images = hdr;
        let types = images + IMAGE_STRIDE;
        let methods = types + 2 * TYPE_STRIDE;
        let mut data = vec![0_u8; methods + 7 * method_stride];
        put_u32(&mut data, 0, MAGIC);
        put_u32(&mut data, 4, SUPPORTED_V29);
        put_u32(&mut data, HDR_METHODS, methods as u32);
        put_u32(&mut data, HDR_METHODS + 4, (7 * method_stride) as u32);
        put_u32(&mut data, HDR_TYPES, types as u32);
        put_u32(&mut data, HDR_TYPES + 4, (2 * TYPE_STRIDE) as u32);
        put_u32(&mut data, HDR_IMAGES, images as u32);
        put_u32(&mut data, HDR_IMAGES + 4, IMAGE_STRIDE as u32);
        put_u32(&mut data, images + IMAGE_TYPE_START_OFFSET, 0);
        put_u32(&mut data, images + IMAGE_TYPE_COUNT_OFFSET, 2);
        put_u32(&mut data, types + TYPE_METHOD_START_OFFSET, 0);
        put_u16(&mut data, types + TYPE_METHOD_COUNT_OFFSET, 3);
        put_u32(&mut data, types + TYPE_STRIDE + TYPE_METHOD_START_OFFSET, 3);
        put_u16(&mut data, types + TYPE_STRIDE + TYPE_METHOD_COUNT_OFFSET, 4);
        for expected in 1..=7 {
            let encrypted = encrypted_rid(expected, 7, DEFAULT_METHOD_TOKEN_SEED);
            put_u32(
                &mut data,
                methods + (expected as usize - 1) * method_stride + method_token_offset,
                METHOD_TOKEN_TABLE | encrypted,
            );
        }
        let (restored, report) =
            restore_method_tokens(&data, DEFAULT_METHOD_TOKEN_SEED).expect("v29 restore");
        assert_eq!(report.version, SUPPORTED_V29);
        assert_eq!(report.changed_tokens, 7);
        for expected in 1..=7 {
            let offset = methods + (expected as usize - 1) * method_stride + method_token_offset;
            assert_eq!(
                read_u32(&restored, offset).unwrap(),
                METHOD_TOKEN_TABLE | expected
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

    #[test]
    fn restores_compact_v39_method_tokens_without_touching_other_fields() {
        let method_stride = 25;
        let type_stride = 75;
        let image_stride = 34;
        let method_offset = 0x400;
        let type_offset = 0x600;
        let image_offset = 0x700;
        let method_count = 7_u32;
        let mut data = vec![0_u8; image_offset + image_stride];
        put_u32(&mut data, 0, MAGIC);
        put_u32(&mut data, 4, 39);
        let section = |data: &mut [u8], index: usize, offset: usize, size: usize, count: usize| {
            let header = 8 + index * 12;
            put_u32(data, header, offset as u32);
            put_u32(data, header + 4, size as u32);
            put_u32(data, header + 8, count as u32);
        };
        section(
            &mut data,
            V39_METHODS,
            method_offset,
            method_stride * method_count as usize,
            method_count as usize,
        );
        section(&mut data, V39_PARAMETERS, 0x300, 1, 1);
        section(&mut data, V39_GENERIC_CONTAINERS, 0x320, 1, 1);
        section(&mut data, V39_INTERFACE_OFFSETS, 0x340, 6, 1);
        section(&mut data, V39_TYPES, type_offset, type_stride, 1);
        section(&mut data, V39_IMAGES, image_offset, image_stride, 1);
        data.resize(image_offset + image_stride, 0);
        // Compact v39 type definition: firstMethod at offset 23, methodCount at 51.
        put_u32(&mut data, type_offset + 23, 0);
        put_u16(&mut data, type_offset + 51, method_count as u16);
        // Compact v39 image definition: firstTypeIndex (one byte) and typeCount.
        data[image_offset + 8] = 0;
        put_u32(&mut data, image_offset + 9, 1);
        for expected in 1..=method_count {
            let token = METHOD_TOKEN_TABLE
                | encrypted_rid(expected, method_count, DEFAULT_METHOD_TOKEN_SEED);
            put_u32(
                &mut data,
                method_offset + (expected as usize - 1) * method_stride + 13,
                token,
            );
        }
        let (out, report) =
            restore_method_tokens(&data, DEFAULT_METHOD_TOKEN_SEED).expect("v39 restore");
        assert_eq!(report.version, 39);
        assert_eq!(report.changed_tokens, method_count as usize);
        for expected in 1..=method_count {
            let offset = method_offset + (expected as usize - 1) * method_stride + 13;
            assert_eq!(
                read_u32(&out, offset).unwrap(),
                METHOD_TOKEN_TABLE | expected
            );
        }
        let discovery = discover_method_token_seeds(&data).expect("v39 discovery");
        assert_eq!(discovery.version, 39);
        assert!(discovery.seed_candidates.is_empty());
    }
}
