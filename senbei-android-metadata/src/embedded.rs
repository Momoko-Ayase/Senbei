//! Extraction of the embedded-metadata packaging variant.
//!
//! Some protected il2cpp builds ship no `global-metadata.dat` in the app's
//! assets at all. Instead a slim metadata blob (an older header format with
//! custom record layouts) is embedded in the protected library's data section
//! and wrapped in a per-word XOR layer: a 0x100-byte header whose 64 words each
//! carry their own key, followed by exactly 256 segments with one u32 key each
//! at irregular boundaries. At runtime the protector's il2cpp-side modules
//! regenerate the keys and unwrap the blob in place; the keys are stored
//! nowhere in the image.
//!
//! For the one observed build using this variant the full keystream was
//! recovered from a ciphertext/plaintext pair and is embedded in
//! [`crate::keystream`]. Extraction is therefore content-gated: the wrapped
//! header's first plaintext words are known constants, so a restored image that
//! does not contain them (every other build) is skipped cheaply and nothing is
//! written.
//!
//! The unwrapped blob stores its patched sanity/version fields byte-swapped;
//! they are rewritten to the standard il2cpp metadata magic and version so the
//! output is a well-formed `global-metadata.dat`.

use crate::keystream::{HEADER_KEYS, SEGMENTS};

/// Standard il2cpp metadata sanity magic written over the patched header.
const STANDARD_MAGIC: u32 = 0xfab1_1baf;
/// Standard header version matching the blob's record layout.
const STANDARD_VERSION: u32 = 24;

/// Plaintext of the first two wrapped header words (the byte-swapped patched
/// sanity/version pair). Also the probe pattern: a restored image contains the
/// embedded blob iff `word[0] ^ HEADER_KEYS[0]` and `word[1] ^ HEADER_KEYS[1]`
/// equal these constants at some 4-aligned offset.
const PROBE_WORDS: [u32; 2] = [0x9732_ca38, 0xbac4_374f];

/// Size of the wrapped blob: the last segment's end offset.
pub fn embedded_metadata_size() -> usize {
    SEGMENTS[SEGMENTS.len() - 1].0 as usize
}

/// Locate and unwrap the embedded metadata blob in a restored library image.
///
/// Returns a standalone, well-formed `global-metadata.dat`, or `None` when the
/// image carries no blob wrapped with the known keystream.
pub fn extract_embedded_metadata(image: &[u8]) -> Option<Vec<u8>> {
    let total = embedded_metadata_size();
    let offset = find_wrapped_header(image)?;
    let blob = image.get(offset..offset.checked_add(total)?)?;

    let mut out = blob.to_vec();
    for (i, &key) in HEADER_KEYS.iter().enumerate() {
        xor_word(&mut out, 4 * i, key);
    }
    let mut pos = 0x100_usize;
    for &(end, key) in &SEGMENTS {
        let end = end as usize;
        let mut o = pos;
        while o + 4 <= end {
            xor_word(&mut out, o, key);
            o += 4;
        }
        pos = end;
    }
    out[0..4].copy_from_slice(&STANDARD_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&STANDARD_VERSION.to_le_bytes());
    Some(out)
}

/// Scan `image` for the wrapped header probe pattern (4-aligned).
fn find_wrapped_header(image: &[u8]) -> Option<usize> {
    let mut off = 0;
    while off + 8 <= image.len() {
        let word = u32::from_le_bytes(image[off..off + 4].try_into().ok()?);
        if word ^ HEADER_KEYS[0] == PROBE_WORDS[0] {
            let next = u32::from_le_bytes(image[off + 4..off + 8].try_into().ok()?);
            if next ^ HEADER_KEYS[1] == PROBE_WORDS[1] {
                return Some(off);
            }
        }
        off += 4;
    }
    None
}

fn xor_word(data: &mut [u8], offset: usize, key: u32) {
    let word = u32::from_le_bytes(data[offset..offset + 4].try_into().expect("word in bounds"));
    data[offset..offset + 4].copy_from_slice(&(word ^ key).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a synthetic blob with the keystream, then unwrap it back.
    #[test]
    fn roundtrip_wrapped_blob() {
        let total = embedded_metadata_size();
        let mut image = vec![0_u8; total + 0x40];
        // Plaintext blob: standard probe words, then a ramp.
        image[0..4].copy_from_slice(&PROBE_WORDS[0].to_le_bytes());
        image[4..8].copy_from_slice(&PROBE_WORDS[1].to_le_bytes());
        for o in (8..total).step_by(4) {
            let v = (o as u32).wrapping_mul(0x9e37_79b1);
            image[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        // Wrap with the keystream.
        for (i, &key) in HEADER_KEYS.iter().enumerate() {
            xor_word(&mut image, 4 * i, key);
        }
        let mut pos = 0x100_usize;
        for &(end, key) in &SEGMENTS {
            let mut o = pos;
            while o + 4 <= end as usize {
                xor_word(&mut image, o, key);
                o += 4;
            }
            pos = end as usize;
        }

        let out = extract_embedded_metadata(&image).expect("blob found");
        assert_eq!(out.len(), total);
        // Header rewritten to the standard magic/version…
        assert_eq!(&out[0..4], &STANDARD_MAGIC.to_le_bytes());
        assert_eq!(&out[4..8], &STANDARD_VERSION.to_le_bytes());
        // …and the body round-trips.
        for o in (8..total).step_by(4) {
            let v = (o as u32).wrapping_mul(0x9e37_79b1);
            assert_eq!(&out[o..o + 4], &v.to_le_bytes(), "word at {o:#x}");
        }
    }

    #[test]
    fn no_blob_in_plain_data() {
        let image = vec![0xAB_u8; 0x1000];
        assert!(extract_embedded_metadata(&image).is_none());
    }
}
