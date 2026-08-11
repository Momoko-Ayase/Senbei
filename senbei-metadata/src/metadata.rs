//! il2cpp `global-metadata.dat` de-obfuscation.
//!
//! Crackproof's `-GMD` option obfuscates the **method-token** field of every
//! `Il2CppMethodDefinition` in `global-metadata.dat`. il2cpp resolves a method's
//! compiled function/invoker by indexing the per-module
//! `Il2CppCodeGenModule.methodPointers` / `invokerIndices` tables — which are
//! sized to the module's *compiled* method count — by `(token_row - 1)`. That
//! only works when each module's method tokens are the **contiguous** range
//! `1..=methodPointerCount`. `-GMD` replaces them with sparse, original-metadata-style
//! tokens (e.g. mscorlib rows reach ~55k for only ~14k compiled methods) and the
//! running game's Crackproof loader remaps them back at load time.
//!
//! A statically-unpacked il2cpp game assembly run without Crackproof reads the
//! tokens raw, so `(token_row - 1)` runs off the end of those tables — an
//! out-of-bounds read that crashes deep in il2cpp init (first hit:
//! `System.Array`'s interface method setup). See the project notes for the full
//! trace.
//!
//! This module reverses the obfuscation purely from the metadata's own
//! structure. Methods are laid out grouped by type, and types grouped by image
//! (module), so a method's correct token row is simply its position within its
//! module's method range. We re-derive that range from the images/types tables
//! and rewrite each method token to `0x06000000 | (local_index + 1)`.
//!
//! Only method tokens are touched: field tokens are already contiguous and type
//! tokens resolve correctly. The transform is a no-op on an unobfuscated
//! metadata (its tokens already equal `local_index + 1`), so it is safe to run on
//! any il2cpp game — `remapped == 0` then reports that nothing changed.

/// il2cpp `global-metadata.dat` sanity magic (`Il2CppGlobalMetadataHeader.sanity`).
const MAGIC: u32 = 0xFAB1_1BAF;

/// Metadata format version this de-obfuscator understands. The struct strides
/// and header field offsets below are specific to it; other versions are left
/// untouched rather than risk corrupting a layout we have not verified.
/// (Observed on real games shipping version 31 / Unity 2022.3.)
const SUPPORTED_VERSION: u32 = 31;

// --- Il2CppGlobalMetadataHeader field byte-offsets (each is an i32 offset/size
//     pair). Shared layout across recent versions. ---
const HDR_METHODS: usize = 0x30; // methodsOffset / methodsSize
const HDR_TYPES: usize = 0xA0; // typeDefinitionsOffset / size
const HDR_IMAGES: usize = 0xA8; // imagesOffset / size

// --- version-31 struct strides and field offsets ---
const METHOD_STRIDE: usize = 0x24; // sizeof(Il2CppMethodDefinition)
const METHOD_TOKEN_OFF: usize = 0x18; // .token (u32)
const TYPE_STRIDE: usize = 0x58; // sizeof(Il2CppTypeDefinition)
const TYPE_METHOD_START_OFF: usize = 0x24; // .methodStart (i32)
const TYPE_METHOD_COUNT_OFF: usize = 0x40; // .method_count (u16)
const IMAGE_STRIDE: usize = 0x28; // sizeof(Il2CppImageDefinition)
const IMAGE_TYPE_START_OFF: usize = 0x08; // .typeStart (i32)
const IMAGE_TYPE_COUNT_OFF: usize = 0x0C; // .typeCount (u32)

/// `IMAGE_CODE_GEN_MODULE` method-definition token table id (`0x06 << 24`).
const METHOD_TOKEN_TABLE: u32 = 0x0600_0000;
/// `Il2Cpp*Index` "no value" sentinel (`kTypeIndexInvalid` etc.).
const NO_METHODS: u32 = 0xFFFF_FFFF;

/// Outcome of a successful [`deobfuscate`] pass.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    pub version: u32,
    /// Total `Il2CppMethodDefinition` entries.
    pub methods: usize,
    /// Number of method tokens actually rewritten (0 ⇒ the input was already
    /// de-obfuscated, i.e. not `-GMD`-protected).
    pub remapped: usize,
    /// Number of modules (images) that own at least one method.
    pub modules: usize,
}

/// Why [`deobfuscate`] declined to process the input. None of these mutate the
/// input; the caller leaves the file untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Missing the il2cpp metadata sanity magic — not a `global-metadata.dat`.
    NotMetadata,
    /// Recognised metadata, but an unhandled format version.
    UnsupportedVersion(u32),
    /// Magic/version matched but the table layout is inconsistent with the
    /// supported version (truncated, mis-sized, or overlapping ranges).
    Malformed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotMetadata => write!(f, "not an il2cpp global-metadata.dat"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported metadata version {v}"),
            Error::Malformed => write!(f, "malformed metadata for version {SUPPORTED_VERSION}"),
        }
    }
}
impl std::error::Error for Error {}

/// Cheap check for the il2cpp metadata sanity magic, for scanning prefixes.
pub fn is_metadata(data: &[u8]) -> bool {
    rd_u32(data, 0) == Some(MAGIC)
}

/// De-obfuscate the method tokens in an il2cpp `global-metadata.dat`.
///
/// On success returns the (possibly-rewritten) file bytes and a [`Report`]. The
/// transform is idempotent: a metadata that is already de-obfuscated comes back
/// byte-identical with `report.remapped == 0`.
pub fn deobfuscate(data: &[u8]) -> Result<(Vec<u8>, Report), Error> {
    if rd_u32(data, 0) != Some(MAGIC) {
        return Err(Error::NotMetadata);
    }
    let version = rd_u32(data, 4).ok_or(Error::Malformed)?;
    if version != SUPPORTED_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }

    let (m_off, m_size) = table(data, HDR_METHODS)?;
    let (t_off, t_size) = table(data, HDR_TYPES)?;
    let (i_off, i_size) = table(data, HDR_IMAGES)?;

    // The strides must divide their tables exactly and the tables must lie
    // within the file: a mismatch means our version-31 layout is wrong for this
    // file, so bail without touching it rather than scribble at bad offsets.
    if m_size % METHOD_STRIDE != 0 || t_size % TYPE_STRIDE != 0 || i_size % IMAGE_STRIDE != 0 {
        return Err(Error::Malformed);
    }
    let method_count = m_size / METHOD_STRIDE;
    let type_count = t_size / TYPE_STRIDE;
    let image_count = i_size / IMAGE_STRIDE;
    if !fits(data, m_off, m_size) || !fits(data, t_off, t_size) || !fits(data, i_off, i_size) {
        return Err(Error::Malformed);
    }

    // Map every method to its owning module and record each module's first
    // (lowest) method index. A method's correct token row is its 1-based offset
    // from that first index (methods are contiguous & grouped per module).
    let mut module_of = vec![u32::MAX; method_count];
    let mut module_first = vec![u32::MAX; image_count];
    for (img, first_slot) in module_first.iter_mut().enumerate() {
        let ib = i_off + img * IMAGE_STRIDE;
        let type_start = rd_u32(data, ib + IMAGE_TYPE_START_OFF).ok_or(Error::Malformed)?;
        let type_cnt = rd_u32(data, ib + IMAGE_TYPE_COUNT_OFF).ok_or(Error::Malformed)?;
        let mut first = u32::MAX;
        for t in type_start..type_start.saturating_add(type_cnt) {
            if t as usize >= type_count {
                return Err(Error::Malformed);
            }
            let tb = t_off + (t as usize) * TYPE_STRIDE;
            let ms = rd_u32(data, tb + TYPE_METHOD_START_OFF).ok_or(Error::Malformed)?;
            let mc = rd_u16(data, tb + TYPE_METHOD_COUNT_OFF).ok_or(Error::Malformed)? as u32;
            if ms == NO_METHODS || mc == 0 {
                continue;
            }
            first = first.min(ms);
            for m in ms..ms.saturating_add(mc) {
                let mi = m as usize;
                if mi >= method_count {
                    return Err(Error::Malformed);
                }
                if module_of[mi] != u32::MAX {
                    return Err(Error::Malformed); // a method in two modules — layout is wrong
                }
                module_of[mi] = img as u32;
            }
        }
        *first_slot = first;
    }

    // Rewrite each owned method's token to `0x06000000 | (local_index + 1)`.
    // Any method NOT owned by an image would keep its original (obfuscated)
    // token — a silent partial remap that still crashes il2cpp at runtime, so
    // treat it as a malformed layout instead of shipping it.
    let mut out = data.to_vec();
    let mut remapped = 0usize;
    for (mi, &img) in module_of.iter().enumerate() {
        if img == u32::MAX {
            return Err(Error::Malformed); // method outside every image's range
        }
        let first = module_first[img as usize];
        let local = (mi as u32) - first; // mi >= first by construction
        let new_tok = METHOD_TOKEN_TABLE | ((local + 1) & 0x00FF_FFFF);
        let off = m_off + mi * METHOD_STRIDE + METHOD_TOKEN_OFF;
        // `fits` above guarantees this 4-byte write is in bounds.
        if out[off..off + 4] != new_tok.to_le_bytes() {
            out[off..off + 4].copy_from_slice(&new_tok.to_le_bytes());
            remapped += 1;
        }
    }

    let modules = module_first.iter().filter(|&&f| f != u32::MAX).count();
    Ok((
        out,
        Report {
            version,
            methods: method_count,
            remapped,
            modules,
        },
    ))
}

/// Read the (offset, size) i32 pair of a metadata table from the header.
fn table(data: &[u8], hdr_off: usize) -> Result<(usize, usize), Error> {
    let off = rd_u32(data, hdr_off).ok_or(Error::Malformed)? as usize;
    let size = rd_u32(data, hdr_off + 4).ok_or(Error::Malformed)? as usize;
    Ok((off, size))
}

/// True if `[off, off+len)` lies within `data`.
fn fits(data: &[u8], off: usize, len: usize) -> bool {
    off.checked_add(len).is_some_and(|end| end <= data.len())
}

fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    let s = b.get(o..o + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u16(b: &[u8], o: usize) -> Option<u16> {
    let s = b.get(o..o + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal but structurally valid v31 metadata with two modules:
    //   image 0: 1 type, 2 methods (global 0,1)
    //   image 1: 1 type, 3 methods (global 2,3,4)
    // Method tokens are seeded with *obfuscated* (sparse) values; the correct
    // de-obfuscated tokens are per-module 1-based: [1,2] and [1,2,3].
    struct Built {
        bytes: Vec<u8>,
        m_off: usize,
    }
    fn build(method_tokens: &[u32]) -> Built {
        // Layout: [header 0x100][images][types][methods]
        let hdr = 0x100usize;
        let images = hdr;
        let i_count = 2;
        let i_size = i_count * IMAGE_STRIDE;
        let types = images + i_size;
        let t_count = 2;
        let t_size = t_count * TYPE_STRIDE;
        let methods = types + t_size;
        let m_count = method_tokens.len();
        let m_size = m_count * METHOD_STRIDE;
        let total = methods + m_size;
        let mut b = vec![0u8; total];

        let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let put16 = |b: &mut [u8], o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());

        put32(&mut b, 0, MAGIC);
        put32(&mut b, 4, SUPPORTED_VERSION);
        put32(&mut b, HDR_METHODS, methods as u32);
        put32(&mut b, HDR_METHODS + 4, m_size as u32);
        put32(&mut b, HDR_TYPES, types as u32);
        put32(&mut b, HDR_TYPES + 4, t_size as u32);
        put32(&mut b, HDR_IMAGES, images as u32);
        put32(&mut b, HDR_IMAGES + 4, i_size as u32);

        // image 0: typeStart=0 typeCount=1 ; image 1: typeStart=1 typeCount=1
        put32(&mut b, images + IMAGE_TYPE_START_OFF, 0);
        put32(&mut b, images + IMAGE_TYPE_COUNT_OFF, 1);
        put32(&mut b, images + IMAGE_STRIDE + IMAGE_TYPE_START_OFF, 1);
        put32(&mut b, images + IMAGE_STRIDE + IMAGE_TYPE_COUNT_OFF, 1);
        // type 0: methodStart=0 count=2 ; type 1: methodStart=2 count=3
        put32(&mut b, types + TYPE_METHOD_START_OFF, 0);
        put16(&mut b, types + TYPE_METHOD_COUNT_OFF, 2);
        put32(&mut b, types + TYPE_STRIDE + TYPE_METHOD_START_OFF, 2);
        put16(&mut b, types + TYPE_STRIDE + TYPE_METHOD_COUNT_OFF, 3);
        // method tokens
        for (i, &tok) in method_tokens.iter().enumerate() {
            put32(&mut b, methods + i * METHOD_STRIDE + METHOD_TOKEN_OFF, tok);
        }
        Built {
            bytes: b,
            m_off: methods,
        }
    }
    fn tok(b: &[u8], m_off: usize, i: usize) -> u32 {
        rd_u32(b, m_off + i * METHOD_STRIDE + METHOD_TOKEN_OFF).unwrap()
    }

    #[test]
    fn remaps_obfuscated_method_tokens_per_module() {
        // Obfuscated sparse tokens (rows way past each module's method count).
        let built = build(&[
            0x0600_D49F,
            0x0600_FFFF,
            0x0600_1234,
            0x0600_ABCD,
            0x0600_5555,
        ]);
        let (out, r) = deobfuscate(&built.bytes).expect("ok");
        assert_eq!(r.version, 31);
        assert_eq!(r.methods, 5);
        assert_eq!(r.modules, 2);
        assert_eq!(r.remapped, 5);
        // module 0 (methods 0,1) -> rows 1,2 ; module 1 (methods 2,3,4) -> rows 1,2,3
        assert_eq!(tok(&out, built.m_off, 0), 0x0600_0001);
        assert_eq!(tok(&out, built.m_off, 1), 0x0600_0002);
        assert_eq!(tok(&out, built.m_off, 2), 0x0600_0001);
        assert_eq!(tok(&out, built.m_off, 3), 0x0600_0002);
        assert_eq!(tok(&out, built.m_off, 4), 0x0600_0003);
    }

    #[test]
    fn idempotent_on_clean_metadata() {
        // Already de-obfuscated: per-module contiguous rows.
        let clean = [
            0x0600_0001,
            0x0600_0002,
            0x0600_0001,
            0x0600_0002,
            0x0600_0003,
        ];
        let built = build(&clean);
        let (out, r) = deobfuscate(&built.bytes).expect("ok");
        assert_eq!(r.remapped, 0, "no rewrites on already-clean metadata");
        assert_eq!(out, built.bytes, "byte-identical output");
    }

    #[test]
    fn rejects_non_metadata() {
        assert_eq!(
            deobfuscate(b"not metadata at all....").unwrap_err(),
            Error::NotMetadata
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut built = build(&[
            0x0600_0001,
            0x0600_0002,
            0x0600_0001,
            0x0600_0002,
            0x0600_0003,
        ]);
        built.bytes[4..8].copy_from_slice(&29u32.to_le_bytes());
        assert_eq!(
            deobfuscate(&built.bytes).unwrap_err(),
            Error::UnsupportedVersion(29)
        );
    }
}
