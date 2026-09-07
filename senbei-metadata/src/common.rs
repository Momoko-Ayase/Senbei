//! Shared IL2CPP metadata header primitives.

/// IL2CPP global-metadata sanity magic.
pub(crate) const MAGIC: u32 = 0xFAB1_1BAF;

/// Cheap check used by both platform scanners before opening a full metadata
/// file.
#[must_use]
pub fn is_metadata(data: &[u8]) -> bool {
    data.get(0..4)
        .is_some_and(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == MAGIC)
}
