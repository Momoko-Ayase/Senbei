//! Restoration of IL2CPP v24.1 `Il2CppMethodDefinition.methodIndex` values.
//!
//! CrackProof's v24.1 Android module rewrites the global method-index permutation
//! at runtime. The transform parameters are carried by the decoded module `0x0C`,
//! so the restore derives them from that module instead of hard-coding a
//! game-specific table.

use serde::Serialize;

use crate::common::MAGIC;

const RAW_VERSION_24: u32 = 24;
const HDR_METHODS: usize = 0x30;
const V24_1_METHOD_STRIDE: usize = 0x34;
const V24_1_METHOD_INDEX_OFFSET: usize = 0x14;
const V24_1_SELECTOR: u32 = 1;
const EXCEPTION_COUNT: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MethodIndexReport {
    pub version: u32,
    pub methods: usize,
    pub active_methods: usize,
    pub changed_indices: usize,
    pub exception_count: usize,
    pub seed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MethodIndexError {
    #[error("not an IL2CPP global-metadata.dat")]
    NotMetadata,
    #[error("unsupported metadata version {0}")]
    UnsupportedVersion(u32),
    #[error("malformed v24.1 metadata: {0}")]
    Malformed(String),
    #[error("v24.1 method-index profile was not found in module 0x0C")]
    ProfileNotFound,
    #[error("multiple v24.1 method-index profiles matched module 0x0C")]
    AmbiguousProfile,
    #[error("v24.1 method-index restoration failed validation: {0}")]
    Validation(String),
}

type Result<T> = std::result::Result<T, MethodIndexError>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Profile {
    seed: u32,
    exception_values: [u32; EXCEPTION_COUNT],
}

fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| MethodIndexError::Malformed("byte range overflow".to_owned()))?;
    data.get(offset..end).ok_or_else(|| {
        MethodIndexError::Malformed(format!(
            "byte range 0x{offset:x}..0x{end:x} is out of bounds"
        ))
    })
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let value: [u8; 4] = bytes(data, offset, 4)?
        .try_into()
        .map_err(|_| MethodIndexError::Malformed("invalid u32 range".to_owned()))?;
    Ok(u32::from_le_bytes(value))
}

fn read_i32(data: &[u8], offset: usize) -> Result<i32> {
    let value: [u8; 4] = bytes(data, offset, 4)?
        .try_into()
        .map_err(|_| MethodIndexError::Malformed("invalid i32 range".to_owned()))?;
    Ok(i32::from_le_bytes(value))
}

fn write_i32(data: &mut [u8], offset: usize, value: i32) -> Result<()> {
    let destination = data.get_mut(offset..offset + 4).ok_or_else(|| {
        MethodIndexError::Malformed("method-index write is out of bounds".to_owned())
    })?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn method_table(data: &[u8]) -> Result<(usize, usize)> {
    if read_u32(data, 0)? != MAGIC {
        return Err(MethodIndexError::NotMetadata);
    }
    let version = read_u32(data, 4)?;
    if version != RAW_VERSION_24 {
        return Err(MethodIndexError::UnsupportedVersion(version));
    }
    let offset = read_u32(data, HDR_METHODS)? as usize;
    let size = read_u32(data, HDR_METHODS + 4)? as usize;
    bytes(data, offset, size)?;
    if !size.is_multiple_of(V24_1_METHOD_STRIDE) {
        return Err(MethodIndexError::Malformed(format!(
            "method table size 0x{size:x} is not divisible by v24.1 stride 0x{V24_1_METHOD_STRIDE:x}"
        )));
    }
    Ok((offset, size / V24_1_METHOD_STRIDE))
}

fn method_indices(data: &[u8]) -> Result<(usize, Vec<Option<u32>>)> {
    let (offset, count) = method_table(data)?;
    let mut indices = Vec::with_capacity(count);
    for method in 0..count {
        let value = read_i32(
            data,
            offset + method * V24_1_METHOD_STRIDE + V24_1_METHOD_INDEX_OFFSET,
        )?;
        indices.push((value >= 0).then_some(value as u32));
    }
    Ok((offset, indices))
}

fn is_complete_permutation(indices: &[Option<u32>]) -> bool {
    let active_count = indices.iter().filter(|value| value.is_some()).count();
    if active_count == 0 || active_count > u32::MAX as usize {
        return false;
    }
    let mut seen = vec![false; active_count];
    for value in indices.iter().flatten().copied() {
        let Ok(index) = usize::try_from(value) else {
            return false;
        };
        if index >= active_count || seen[index] {
            return false;
        }
        seen[index] = true;
    }
    seen.into_iter().all(|value| value)
}

fn permutation_key(seed: u32, count: u32) -> Result<u32> {
    if count < 2 {
        return Err(MethodIndexError::Validation(
            "method-index permutation requires at least two active methods".to_owned(),
        ));
    }
    if count > u32::MAX / 2 {
        return Err(MethodIndexError::Validation(
            "active method count is too large for the permutation mirror".to_owned(),
        ));
    }
    let half = count / 2;
    if half == 0 {
        return Err(MethodIndexError::Validation(
            "method-index permutation has a zero divisor".to_owned(),
        ));
    }
    Ok(seed % half + count / 4)
}

fn permutation_round(mut value: u32, count: u32, key: u32) -> u32 {
    let mirror = count * 2 - 1;
    if value & 1 != 0 {
        value = mirror - value;
    }
    value >>= 1;
    if value >= count {
        value = mirror - value;
    }
    let adjusted = i64::from(value) - i64::from(key);
    if adjusted < 0 {
        (adjusted + i64::from(count)) as u32
    } else {
        adjusted as u32
    }
}

fn transform_index(mut value: u32, count: u32, seed: u32) -> Result<u32> {
    let key = permutation_key(seed, count)?;
    for _ in 0..5 {
        value = permutation_round(value, count, key);
    }
    Ok(value)
}

fn transformed_values(indices: &[Option<u32>], seed: u32) -> Result<Vec<Option<u32>>> {
    let active_count = indices.iter().filter(|value| value.is_some()).count();
    let count = u32::try_from(active_count)
        .map_err(|_| MethodIndexError::Validation("active method count exceeds u32".to_owned()))?;
    indices
        .iter()
        .map(|value| {
            value
                .map(|value| transform_index(value, count, seed))
                .transpose()
        })
        .collect()
}

fn missing_values(indices: &[Option<u32>]) -> Option<Vec<u32>> {
    let active_count = indices.iter().filter(|value| value.is_some()).count();
    let mut seen = vec![false; active_count];
    for value in indices.iter().flatten().copied() {
        let index = usize::try_from(value).ok()?;
        if index >= active_count {
            return None;
        }
        seen[index] = true;
    }
    Some(
        seen.into_iter()
            .enumerate()
            .filter_map(|(index, present)| (!present).then_some(index as u32))
            .collect(),
    )
}

fn find_exception_table(
    module: &[u8],
    count: u32,
    missing: &[u32],
) -> Option<[u32; EXCEPTION_COUNT]> {
    if missing.len() != EXCEPTION_COUNT || count == 0 {
        return None;
    }
    let mut wanted = vec![false; count as usize];
    for &value in missing {
        let slot = wanted.get_mut(value as usize)?;
        *slot = true;
    }
    let table_bytes = EXCEPTION_COUNT * 4;
    for offset in (8..=module.len().checked_sub(table_bytes)?).step_by(4) {
        if read_u32(module, offset - 8).ok()? != V24_1_SELECTOR
            || read_u32(module, offset - 4).ok()? != count - 1
        {
            continue;
        }
        let mut values = [0_u32; EXCEPTION_COUNT];
        let mut seen = vec![false; count as usize];
        let mut matches = true;
        for (index, slot) in values.iter_mut().enumerate() {
            let value = read_u32(module, offset + index * 4).ok()?;
            let Some(is_wanted) = wanted.get(value as usize) else {
                matches = false;
                break;
            };
            if !*is_wanted || seen[value as usize] {
                matches = false;
                break;
            }
            seen[value as usize] = true;
            *slot = value;
        }
        if matches {
            return Some(values);
        }
    }
    None
}

fn profile_candidates(module: &[u8], indices: &[Option<u32>]) -> Result<Vec<Profile>> {
    let active_count = indices.iter().filter(|value| value.is_some()).count();
    let count = u32::try_from(active_count)
        .map_err(|_| MethodIndexError::Validation("active method count exceeds u32".to_owned()))?;
    if count <= EXCEPTION_COUNT as u32 {
        return Err(MethodIndexError::Validation(format!(
            "active method count {count} is too small for the v24.1 exception table"
        )));
    }

    let mut profiles = Vec::new();
    for offset in (0..module.len().saturating_sub(8)).step_by(4) {
        let Ok(version) = read_u32(module, offset + 4) else {
            continue;
        };
        if version != RAW_VERSION_24 {
            continue;
        }
        let seed = read_u32(module, offset)?;
        let transformed = transformed_values(indices, seed)?;
        let Some(missing) = missing_values(&transformed) else {
            continue;
        };
        let Some(exception_values) = find_exception_table(module, count, &missing) else {
            continue;
        };
        let mut candidate = transformed;
        let mut exception = exception_values.iter().copied();
        for value in candidate.iter_mut().flatten() {
            if let Some(replacement) = exception.next() {
                *value = replacement;
            } else {
                break;
            }
        }
        if exception.next().is_none() && is_complete_permutation(&candidate) {
            profiles.push(Profile {
                seed,
                exception_values,
            });
        }
    }
    profiles.sort_by_key(|profile| profile.seed);
    profiles.dedup();
    Ok(profiles)
}

/// Restore the v24.1 `methodIndex` permutation using the decoded CrackProof
/// module `0x0C` that accompanied the protected library.
///
/// The profile is accepted only when the module supplies a seed plus a
/// 256-entry exception table that turns the restored non-negative indices into
/// the exact permutation `0..active_method_count`. This makes a wrong module or
/// incompatible v24 sub-layout fail without mutating the metadata.
pub fn restore_method_indices_v24_1(
    data: &[u8],
    module_0c: &[u8],
) -> Result<(Vec<u8>, MethodIndexReport)> {
    let (method_offset, indices) = method_indices(data)?;
    let active_count = indices.iter().filter(|value| value.is_some()).count();
    if is_complete_permutation(&indices) {
        return Ok((
            data.to_vec(),
            MethodIndexReport {
                version: RAW_VERSION_24,
                methods: indices.len(),
                active_methods: active_count,
                changed_indices: 0,
                exception_count: 0,
                seed: "clean".to_owned(),
            },
        ));
    }

    let profiles = profile_candidates(module_0c, &indices)?;
    let profile = match profiles.as_slice() {
        [] => return Err(MethodIndexError::ProfileNotFound),
        [profile] => profile,
        _ => return Err(MethodIndexError::AmbiguousProfile),
    };

    let mut restored = transformed_values(&indices, profile.seed)?;
    let mut exception = profile.exception_values.iter().copied();
    for value in restored.iter_mut().flatten() {
        if let Some(replacement) = exception.next() {
            *value = replacement;
        } else {
            break;
        }
    }
    if exception.next().is_some() {
        return Err(MethodIndexError::Validation(
            "metadata has fewer active methods than the exception table".to_owned(),
        ));
    }
    if !is_complete_permutation(&restored) {
        return Err(MethodIndexError::Validation(
            "restored methodIndex values are not a complete permutation".to_owned(),
        ));
    }

    let mut output = data.to_vec();
    let mut changed_indices = 0_usize;
    for (method, value) in restored.iter().enumerate() {
        let Some(value) = value else {
            continue;
        };
        let offset = method_offset + method * V24_1_METHOD_STRIDE + V24_1_METHOD_INDEX_OFFSET;
        let old = read_i32(data, offset)?;
        let new = i32::try_from(*value).map_err(|_| {
            MethodIndexError::Validation("restored methodIndex exceeds i32".to_owned())
        })?;
        if old != new {
            write_i32(&mut output, offset, new)?;
            changed_indices += 1;
        }
    }

    Ok((
        output,
        MethodIndexReport {
            version: RAW_VERSION_24,
            methods: indices.len(),
            active_methods: active_count,
            changed_indices,
            exception_count: EXCEPTION_COUNT,
            seed: format!("0x{:08X}", profile.seed),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inverse_map(count: u32, seed: u32) -> Vec<u32> {
        let mut inverse = vec![u32::MAX; count as usize];
        for value in 0..count {
            let transformed = transform_index(value, count, seed).unwrap();
            inverse[transformed as usize] = value;
        }
        assert!(inverse.iter().all(|value| *value != u32::MAX));
        inverse
    }

    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let active_count = 512_u32;
        let seed = 0x7770_0dcc;
        let inverse = inverse_map(active_count, seed);
        let header_size = 0x100usize;
        let method_size = active_count as usize * V24_1_METHOD_STRIDE;
        let mut metadata = vec![0_u8; header_size + method_size];
        metadata[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        metadata[4..8].copy_from_slice(&RAW_VERSION_24.to_le_bytes());
        metadata[HDR_METHODS..HDR_METHODS + 4].copy_from_slice(&(header_size as u32).to_le_bytes());
        metadata[HDR_METHODS + 4..HDR_METHODS + 8]
            .copy_from_slice(&(method_size as u32).to_le_bytes());

        // Before the exception patch the first half duplicates the second half,
        // leaving 0..255 missing. The module's 256-entry table fills exactly
        // those first active methods after the five-round transform.
        for method in 0..active_count as usize {
            let transformed = 256 + (method % 256) as u32;
            let protected = inverse[transformed as usize];
            let offset = header_size + method * V24_1_METHOD_STRIDE + V24_1_METHOD_INDEX_OFFSET;
            metadata[offset..offset + 4].copy_from_slice(&(protected as i32).to_le_bytes());
        }

        let mut module = vec![0_u8; 0x1000];
        module[0x100..0x104].copy_from_slice(&seed.to_le_bytes());
        module[0x104..0x108].copy_from_slice(&RAW_VERSION_24.to_le_bytes());
        module[0x3f8..0x3fc].copy_from_slice(&V24_1_SELECTOR.to_le_bytes());
        module[0x3fc..0x400].copy_from_slice(&(active_count - 1).to_le_bytes());
        for value in 0..EXCEPTION_COUNT as u32 {
            let offset = 0x400 + value as usize * 4;
            module[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        (metadata, module)
    }

    #[test]
    fn restores_v24_1_method_index_permutation() {
        let (metadata, module) = fixture();
        let (restored, report) = restore_method_indices_v24_1(&metadata, &module).unwrap();
        assert_eq!(report.active_methods, 512);
        assert_eq!(report.exception_count, 256);
        assert_eq!(report.seed, "0x77700DCC");
        let (offset, indices) = method_indices(&restored).unwrap();
        assert_eq!(offset, 0x100);
        assert!(is_complete_permutation(&indices));
        for (method, value) in indices.into_iter().enumerate() {
            assert_eq!(value, Some(method as u32));
        }
    }

    #[test]
    fn clean_v24_1_metadata_is_idempotent() {
        let (metadata, module) = fixture();
        let (restored, _) = restore_method_indices_v24_1(&metadata, &module).unwrap();
        let (again, report) = restore_method_indices_v24_1(&restored, &module).unwrap();
        assert_eq!(again, restored);
        assert_eq!(report.changed_indices, 0);
        assert_eq!(report.seed, "clean");
    }

    #[test]
    fn rejects_unrelated_module() {
        let (metadata, _) = fixture();
        let error = restore_method_indices_v24_1(&metadata, &[0_u8; 0x1000]).unwrap_err();
        assert_eq!(error, MethodIndexError::ProfileNotFound);
    }
}
