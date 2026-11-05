//! Known il2cpp metadata byte layouts and format identification.
//!
//! This module owns the byte-level facts used by the restoration algorithms:
//! header field offsets, record strides and field offsets. Parsing, validation
//! and recovery stay in the sibling modules; nothing here opens an input or
//! decides that a restore will succeed.
//!
//! [`identify`] is intentionally a raw-version check. A `global-metadata.dat`
//! can carry a version whose record layout is not known, and version 24 does
//! not by itself identify the context-dependent v24.1 method-index layout. The
//! returned [`Capabilities`] list the entry points implemented for a version;
//! they are not a protection verdict, and an attempted restore may still
//! reject the input. Identification reads only the 8-byte header, so a
//! [`LayoutStatus::Known`] result states that a layout definition exists for
//! that raw version — never that this particular input validated against it.

use serde::Serialize;

/// il2cpp `global-metadata.dat` sanity magic.
pub(crate) const MAGIC: u32 = 0xFAB1_1BAF;

/// Fixed header fields shared by the layouts in this module. Table entries are
/// little-endian `i32` (offset, size) pairs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderLayout {
    pub magic: usize,
    pub version: usize,
    pub methods: usize,
    pub types: usize,
    pub images: usize,
}

pub(crate) const HEADER: HeaderLayout = HeaderLayout {
    magic: 0x00,
    version: 0x04,
    methods: 0x30,
    types: 0xA0,
    images: 0xA8,
};

/// `Il2CppMethodDefinition` record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MethodRecord {
    pub stride: usize,
    pub token: usize,
}

/// `Il2CppTypeDefinition` record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TypeRecord {
    pub stride: usize,
    pub method_start: usize,
    pub method_count: usize,
}

/// `Il2CppImageDefinition` record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ImageRecord {
    pub stride: usize,
    pub type_start: usize,
    pub type_count: usize,
}

/// Fixed record layout shared by the non-compact metadata versions.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FixedLayout {
    pub method: MethodRecord,
    pub types: TypeRecord,
    pub images: ImageRecord,
}

pub(crate) const V29: FixedLayout = FixedLayout {
    method: MethodRecord {
        stride: 0x20,
        token: 0x14,
    },
    types: TypeRecord {
        stride: 0x58,
        method_start: 0x24,
        method_count: 0x40,
    },
    images: ImageRecord {
        stride: 0x28,
        type_start: 0x08,
        type_count: 0x0C,
    },
};

pub(crate) const V31: FixedLayout = FixedLayout {
    method: MethodRecord {
        stride: 0x24,
        token: 0x18,
    },
    types: V29.types,
    images: V29.images,
};

/// The context-validated v24.1 `Il2CppMethodDefinition.methodIndex` record.
///
/// This layout is applied only after the accompanying decoded module 0x0C has
/// supplied and validated a profile; the raw version 24 tag is not enough.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MethodIndexRecord {
    pub stride: usize,
    pub index: usize,
}

pub(crate) const V24_1_METHOD_INDEX: MethodIndexRecord = MethodIndexRecord {
    stride: 0x34,
    index: 0x14,
};

/// Version 39 uses a compact section directory instead of the fixed header
/// table pairs. Each directory record is (offset, size, count). The record
/// layout is the known observed definition derived from the compact index
/// widths, not a fixed-stride one; it is validated per input by the parser.
pub(crate) mod v39 {
    /// First section record in the compact header.
    pub(crate) const SECTION_HEADER_BASE: usize = 0x08;
    /// Byte stride of one section record.
    pub(crate) const SECTION_HEADER_STRIDE: usize = 0x0C;

    /// Section indices used by method-token restoration.
    pub(crate) const SECTION_METHODS: usize = 5;
    pub(crate) const SECTION_PARAMETERS: usize = 10;
    pub(crate) const SECTION_GENERIC_CONTAINERS: usize = 14;
    pub(crate) const SECTION_INTERFACE_OFFSETS: usize = 18;
    pub(crate) const SECTION_TYPES: usize = 19;
    pub(crate) const SECTION_IMAGES: usize = 20;

    /// Widths of the compact indices stored inside v39 records.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Widths {
        pub type_definition: usize,
        pub type_index: usize,
        pub parameter: usize,
        pub generic_container: usize,
    }

    /// Record strides and field offsets derived from [`Widths`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Records {
        pub method_stride: usize,
        pub method_token_offset: usize,
        pub type_stride: usize,
        pub type_method_start_offset: usize,
        pub type_method_count_offset: usize,
        pub image_stride: usize,
    }

    /// Compact index width for a table of `count` entries.
    pub(crate) fn index_width(count: usize) -> usize {
        if count <= u8::MAX as usize {
            1
        } else if count <= u16::MAX as usize {
            2
        } else {
            4
        }
    }

    /// Width of the type index stored in interface-offset records. An absent
    /// interface table keeps the full-width form.
    pub(crate) fn type_index_width(interface_size: usize, interface_count: usize) -> Option<usize> {
        if interface_count == 0 {
            return Some(4);
        }
        interface_size
            .checked_div(interface_count)?
            .checked_sub(4)
            .filter(|width| matches!(width, 1 | 2 | 4))
    }

    impl Records {
        /// Derive the record layout for one set of compact index widths.
        ///
        /// The constants are the fixed portions of the observed records; the
        /// compact index fields follow them in the order used by the v39
        /// parser.
        pub(crate) fn from_widths(widths: Widths) -> Option<Self> {
            let method_stride = 20_usize
                .checked_add(widths.type_definition)?
                .checked_add(widths.type_index)?
                .checked_add(widths.parameter)?
                .checked_add(widths.generic_container)?;
            let type_stride = 68_usize
                .checked_add(widths.type_index.checked_mul(3)?)?
                .checked_add(widths.generic_container)?;
            let image_stride = 32_usize.checked_add(widths.type_definition.checked_mul(2)?)?;
            let type_method_start_offset = 16_usize
                .checked_add(widths.type_index.checked_mul(3)?)?
                .checked_add(widths.generic_container)?;
            let type_method_count_offset = type_method_start_offset.checked_add(7 * 4)?;
            let method_token_offset = 4_usize
                .checked_add(widths.type_definition)?
                .checked_add(widths.type_index)?
                .checked_add(4)?
                .checked_add(widths.parameter)?
                .checked_add(widths.generic_container)?;
            Some(Self {
                method_stride,
                method_token_offset,
                type_stride,
                type_method_start_offset,
                type_method_count_offset,
                image_stride,
            })
        }
    }
}

/// Raw metadata format version reported by the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataVersion {
    V24,
    V29,
    V31,
    V39,
    Unknown(u32),
}

impl MetadataVersion {
    /// Classify a raw header version. Unknown versions keep their numeric value.
    #[must_use]
    pub const fn from_raw(version: u32) -> Self {
        match version {
            24 => Self::V24,
            29 => Self::V29,
            31 => Self::V31,
            39 => Self::V39,
            other => Self::Unknown(other),
        }
    }

    /// Numeric header value for this version.
    #[must_use]
    pub const fn raw(self) -> u32 {
        match self {
            Self::V24 => 24,
            Self::V29 => 29,
            Self::V31 => 31,
            Self::V39 => 39,
            Self::Unknown(version) => version,
        }
    }

    /// How much the raw version alone establishes about the record layout.
    #[must_use]
    pub const fn layout_status(self) -> LayoutStatus {
        match self {
            Self::V24 => LayoutStatus::ContextRequired,
            Self::V29 | Self::V31 | Self::V39 => LayoutStatus::Known,
            Self::Unknown(_) => LayoutStatus::Unverified,
        }
    }

    /// Restoration entry points implemented for this version.
    #[must_use]
    pub const fn capabilities(self) -> Capabilities {
        match self {
            Self::V24 => Capabilities {
                seeded_method_tokens: false,
                structural_method_tokens: false,
                method_index_restore: true,
                method_index_requires_context: true,
            },
            Self::V29 => Capabilities {
                seeded_method_tokens: true,
                structural_method_tokens: false,
                method_index_restore: false,
                method_index_requires_context: false,
            },
            Self::V31 => Capabilities {
                seeded_method_tokens: true,
                structural_method_tokens: true,
                method_index_restore: false,
                method_index_requires_context: false,
            },
            Self::V39 => Capabilities {
                seeded_method_tokens: true,
                structural_method_tokens: false,
                method_index_restore: false,
                method_index_requires_context: false,
            },
            Self::Unknown(_) => Capabilities::NONE,
        }
    }
}

/// How much the raw version alone establishes about the record layout.
///
/// This describes the layout definition and the restoration entry points for
/// a version — not whether any particular input validated. Identification
/// reads only the 8-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutStatus {
    /// A known layout definition exists for this raw version. The input body
    /// has not been validated; the transform still checks its tables.
    Known,
    /// Version 24 records are applied only after context validation; the
    /// version tag does not establish the v24.1 layout.
    ContextRequired,
    /// No record layout is asserted for this version.
    Unverified,
}

/// Restoration entry points implemented for an identified version.
///
/// A capability means the crate has an entry point that can attempt the
/// transform. It does not mean the input is protected, that the input uses
/// that transform, or that the attempt will validate and produce output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// Seeded five-round `Il2CppMethodDefinition.token` restoration.
    pub seeded_method_tokens: bool,
    /// Structural per-image method-token remap.
    pub structural_method_tokens: bool,
    /// v24.1 `methodIndex` permutation restoration.
    pub method_index_restore: bool,
    /// When [`Self::method_index_restore`] is set, the per-application decoded
    /// module 0x0C must be supplied and validated before the layout is used.
    pub method_index_requires_context: bool,
}

impl Capabilities {
    /// No restoration entry point is implemented for the version.
    pub const NONE: Self = Self {
        seeded_method_tokens: false,
        structural_method_tokens: false,
        method_index_restore: false,
        method_index_requires_context: false,
    };
}

/// Raw version and layout/capability facts for one metadata header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MetadataIdentity {
    /// Numeric header version, including versions with no known layout.
    pub raw_version: u32,
    pub version: MetadataVersion,
    pub layout: LayoutStatus,
    pub capabilities: Capabilities,
}

impl MetadataIdentity {
    /// Build the identity for a raw version.
    #[must_use]
    pub const fn new(version: MetadataVersion) -> Self {
        Self {
            raw_version: version.raw(),
            version,
            layout: version.layout_status(),
            capabilities: version.capabilities(),
        }
    }
}

/// Identify a raw il2cpp metadata header.
///
/// Returns `None` when the magic or the complete 8-byte header is absent. The
/// check deliberately reads only the header: a body truncated after the header
/// still identifies, and every restore entry point validates the tables it
/// needs. This reports a layout/magic match, not a protection or obfuscation
/// verdict.
#[must_use]
pub fn identify(data: &[u8]) -> Option<MetadataIdentity> {
    let magic: [u8; 4] = data.get(HEADER.magic..HEADER.magic + 4)?.try_into().ok()?;
    if u32::from_le_bytes(magic) != MAGIC {
        return None;
    }
    let version: [u8; 4] = data
        .get(HEADER.version..HEADER.version + 4)?
        .try_into()
        .ok()?;
    Some(MetadataIdentity::new(MetadataVersion::from_raw(
        u32::from_le_bytes(version),
    )))
}

/// Record layout used by the seeded and structural token transforms.
pub(crate) fn fixed_layout(version: u32) -> Option<FixedLayout> {
    match MetadataVersion::from_raw(version) {
        MetadataVersion::V29 => Some(V29),
        MetadataVersion::V31 => Some(V31),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u32) -> Vec<u8> {
        let mut data = MAGIC.to_le_bytes().to_vec();
        data.extend_from_slice(&version.to_le_bytes());
        data
    }

    #[test]
    fn identifies_each_known_raw_version() {
        for (raw, version) in [
            (24, MetadataVersion::V24),
            (29, MetadataVersion::V29),
            (31, MetadataVersion::V31),
            (39, MetadataVersion::V39),
        ] {
            let identity = identify(&header(raw)).expect("metadata header");
            assert_eq!(identity.version, version);
            assert_eq!(identity.version.raw(), raw);
        }
    }

    #[test]
    fn v24_is_context_required_and_not_claimed_as_v24_1() {
        let identity = identify(&header(24)).expect("metadata header");
        assert_eq!(identity.layout, LayoutStatus::ContextRequired);
        assert!(identity.capabilities.method_index_restore);
        assert!(identity.capabilities.method_index_requires_context);
        assert!(!identity.capabilities.seeded_method_tokens);
        assert!(!identity.capabilities.structural_method_tokens);
    }

    #[test]
    fn known_versions_expose_their_entry_points() {
        let v29 = identify(&header(29)).expect("metadata header");
        assert_eq!(v29.layout, LayoutStatus::Known);
        assert!(v29.capabilities.seeded_method_tokens);
        assert!(!v29.capabilities.structural_method_tokens);

        let v31 = identify(&header(31)).expect("metadata header");
        assert_eq!(v31.layout, LayoutStatus::Known);
        assert!(v31.capabilities.seeded_method_tokens);
        assert!(v31.capabilities.structural_method_tokens);

        let v39 = identify(&header(39)).expect("metadata header");
        assert_eq!(v39.layout, LayoutStatus::Known);
        assert!(v39.capabilities.seeded_method_tokens);
        assert!(!v39.capabilities.structural_method_tokens);
    }

    #[test]
    fn unknown_versions_assert_no_layout_or_capability() {
        let identity = identify(&header(30)).expect("metadata header");
        assert_eq!(identity.version, MetadataVersion::Unknown(30));
        assert_eq!(identity.layout, LayoutStatus::Unverified);
        assert_eq!(identity.capabilities, Capabilities::NONE);
    }

    #[test]
    fn rejects_non_metadata_and_incomplete_headers() {
        assert!(identify(b"").is_none());
        assert!(identify(b"not metadata at all....").is_none());
        // Magic only, and magic plus a partial version, are not identified.
        assert!(identify(&MAGIC.to_le_bytes()).is_none());
        assert!(identify(&header(31)[..7]).is_none());
        assert!(crate::common::is_metadata(&header(31)[..4]));
    }

    #[test]
    fn known_layout_values_are_kept_explicit() {
        assert_eq!(
            (HEADER.methods, HEADER.types, HEADER.images),
            (0x30, 0xA0, 0xA8)
        );
        assert_eq!(
            (V29.method.stride, V29.method.token),
            (0x20, 0x14),
            "v29 method record"
        );
        assert_eq!(
            (V31.method.stride, V31.method.token),
            (0x24, 0x18),
            "v31 method record"
        );
        assert_eq!(
            (V24_1_METHOD_INDEX.stride, V24_1_METHOD_INDEX.index),
            (0x34, 0x14),
            "context-validated v24.1 method-index record"
        );
        assert_eq!(V29.types.stride, 0x58);
        assert_eq!(V29.types.method_start, 0x24);
        assert_eq!(V29.types.method_count, 0x40);
        assert_eq!(V29.images.stride, 0x28);
        assert_eq!(V29.images.type_start, 0x08);
        assert_eq!(V29.images.type_count, 0x0C);
    }

    #[test]
    fn v39_compact_layout_matches_observed_records() {
        let records = v39::Records::from_widths(v39::Widths {
            type_definition: 1,
            type_index: 2,
            parameter: 1,
            generic_container: 1,
        })
        .expect("record layout");
        assert_eq!(
            (records.method_stride, records.method_token_offset),
            (25, 13)
        );
        assert_eq!(records.type_stride, 75);
        assert_eq!(
            (
                records.type_method_start_offset,
                records.type_method_count_offset
            ),
            (23, 51)
        );
        assert_eq!(records.image_stride, 34);
    }

    #[test]
    fn v39_index_width_tracks_table_counts() {
        assert_eq!(v39::index_width(0), 1);
        assert_eq!(v39::index_width(u8::MAX as usize), 1);
        assert_eq!(v39::index_width(u8::MAX as usize + 1), 2);
        assert_eq!(v39::index_width(u16::MAX as usize), 2);
        assert_eq!(v39::index_width(u16::MAX as usize + 1), 4);
        assert_eq!(v39::type_index_width(0, 0), Some(4));
        assert_eq!(v39::type_index_width(6, 1), Some(2));
    }

    #[test]
    fn a_known_layout_does_not_mean_the_input_validated() {
        // The header alone identifies as known-layout v31 and advertises the
        // structural transform, but the table bounds are missing, so the
        // transform still rejects the input. `Known` is a layout definition,
        // not an input-validation result.
        let data = header(31);
        let identity = identify(&data).expect("metadata header");
        assert_eq!(identity.layout, LayoutStatus::Known);
        assert!(identity.capabilities.structural_method_tokens);
        assert_eq!(
            crate::deobfuscate(&data).unwrap_err(),
            crate::Error::Malformed
        );
    }

    #[test]
    fn identification_needs_only_the_eight_byte_header() {
        // A header with no tables still identifies; every transform then
        // reports its own structural error instead of a version error.
        for version in [24, 29, 31, 39] {
            assert!(identify(&header(version)).is_some(), "v{version} header");
        }
    }

    #[test]
    fn unknown_version_is_not_reported_as_unsupported_by_identification() {
        // Identification is descriptive: an unknown version is carried through
        // as `Unknown(n)` with no capabilities, rather than collapsing into a
        // restore error or a layout claim.
        let identity = identify(&header(27)).expect("metadata header");
        assert_eq!(identity.version, MetadataVersion::Unknown(27));
        assert_eq!(identity.raw_version, 27);
        assert_eq!(identity.layout, LayoutStatus::Unverified);
        assert_eq!(identity.capabilities, Capabilities::NONE);
        assert_eq!(
            crate::deobfuscate(&header(27)).unwrap_err(),
            crate::Error::UnsupportedVersion(27)
        );
    }

    #[test]
    fn truncated_table_body_still_preserves_unsupported_input_behavior() {
        // Build a real v31 header whose method table claims bytes that the
        // truncated input does not contain. Identification succeeds; the
        // structural transform rejects it as malformed, as before.
        let mut data = header(31);
        data.resize(0x100, 0);
        data[HEADER.methods..HEADER.methods + 4].copy_from_slice(&0x200_u32.to_le_bytes());
        data[HEADER.methods + 4..HEADER.methods + 8].copy_from_slice(&0x24_u32.to_le_bytes());
        let identity = identify(&data).expect("metadata header");
        assert_eq!(identity.version, MetadataVersion::V31);
        assert!(identity.capabilities.structural_method_tokens);
        assert_eq!(
            crate::deobfuscate(&data).unwrap_err(),
            crate::Error::Malformed
        );
    }

    #[test]
    fn serde_shape_is_stable_for_reporting() {
        let identity = identify(&header(24)).expect("metadata header");
        let json = serde_json::to_value(identity).expect("serialize");
        assert_eq!(json["raw_version"], 24);
        assert_eq!(json["version"], "v24");
        assert_eq!(json["layout"], "context_required");
        assert_eq!(json["capabilities"]["method_index_restore"], true);
        assert_eq!(json["capabilities"]["method_index_requires_context"], true);
        assert_eq!(json["capabilities"]["seeded_method_tokens"], false);

        // A known layout definition serializes as "known", never "verified":
        // identification does not validate the input body.
        let known = identify(&header(31)).expect("metadata header");
        let json = serde_json::to_value(known).expect("serialize");
        assert_eq!(json["layout"], "known");
        assert_eq!(json["raw_version"], 31);

        let unknown = identify(&header(30)).expect("metadata header");
        let json = serde_json::to_value(unknown).expect("serialize");
        assert_eq!(json["version"]["unknown"], 30);
        assert_eq!(json["layout"], "unverified");
    }

    #[test]
    fn truncated_metadata_keeps_the_old_unsupported_or_malformed_behavior() {
        let v24 = header(24);
        assert!(matches!(
            crate::android::restore_method_indices_v24_1(&v24, &[]),
            Err(crate::android::MethodIndexError::Malformed(_))
        ));

        let v29 = header(29);
        assert!(matches!(
            crate::android::restore_method_tokens(&v29, 0),
            Err(crate::android::Error::Malformed(_))
        ));

        let v31 = header(31);
        assert!(matches!(
            crate::android::restore_method_tokens(&v31, 0),
            Err(crate::android::Error::Malformed(_))
        ));

        let v39 = header(39);
        assert!(matches!(
            crate::android::discover_method_token_seeds(&v39),
            Err(crate::android::Error::Malformed(_))
        ));
    }
}
