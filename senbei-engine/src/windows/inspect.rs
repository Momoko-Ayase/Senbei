//! Rich, read-only Windows research inspection.
//!
//! [`inspect_research`](super::inspect_research) answers a narrower question
//! than recovery: what does the input itself say? It parses the PE container
//! (headers, sections, directories, file regions), decodes the protected header
//! table when one is present, and — within a small, fixed scratch budget —
//! decodes the declared payload prefix to look for real shell structures.
//!
//! What it never does: allocate `SizeOfImage`, run a recovery stage, execute
//! the input, or report a protection build/version. A recovery is the only
//! place where later-stage facts become observable; this module reports only
//! what a bounded probe can see, and names the stage where a fact was not
//! available instead of guessing.
//!
//! Every offset is labelled with the address space it belongs to:
//! [`AddressSpace::FileOffset`] (protected input bytes),
//! [`AddressSpace::DecodedPayloadOffset`] (offset relative to the decoded
//! payload base `info[3]`), and [`AddressSpace::WorkingImageRva`] (RVA of the
//! image the pipeline builds). The scratch image this module decodes is exactly
//! such a working-image fragment, so payload offsets and RVAs coincide only
//! when the probe base is `info[3]`.

use serde::Serialize;

use senbei_crypto::primitives;
use senbei_pe::{Headers, Section};

use super::layout;
use super::research::AddressSpace;
use crate::profile::TargetFormat;
use crate::windows::{Kind, MAGIC_KONN};

/// Upper bound for the PE section and directory lists. A real image is far
/// below this; a corrupt header cannot make inspection allocate or scan
/// without bound.
const MAX_SECTIONS: u16 = 96;
/// Upper bound for the data directories walked from `NumberOfRvaAndSizes`.
const MAX_DIRECTORIES: u32 = 16;
/// Upper bound for reported file regions (gaps + overlay).
const MAX_REGIONS: usize = 64;
/// Upper bound for reported issues, so a malformed header cannot grow output
/// without bound.
pub const DEFAULT_MAX_ISSUES: usize = 64;
/// Default scratch budget for prefix decoding (2 MiB).
pub const DEFAULT_PREFIX_SCRATCH_BYTES: u64 = 2 * 1024 * 1024;
/// Default candidate cap for shell discovery.
pub const DEFAULT_MAX_CANDIDATES: usize = 32;
/// Work limits for [`inspect_research_with_limits`]. The defaults are what
/// [`inspect_research`] uses; tests and fuzzing can lower them to prove the
/// bounds.
///
/// The trace budget is not here: the pure inspector never emits trace events.
/// Use [`with_research_trace_limited`](super::with_research_trace_limited) to
/// bound a recovery trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectionLimits {
    pub prefix_scratch_bytes: u64,
    pub max_candidates: usize,
    pub max_issues: usize,
}

impl Default for InspectionLimits {
    fn default() -> Self {
        Self {
            prefix_scratch_bytes: DEFAULT_PREFIX_SCRATCH_BYTES,
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_issues: DEFAULT_MAX_ISSUES,
        }
    }
}

/// Severity of an inspection issue. Inspection issues explain a partial or
/// unavailable finding; they are not recovery errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionSeverity {
    Info,
    Warning,
    /// The fact exists but needs a stage this bounded probe does not run.
    Unavailable,
}

/// One partial-finding explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectionIssue {
    pub severity: InspectionSeverity,
    /// Short area tag: "pe", "protection", "payload", "probe", "discovery".
    pub area: &'static str,
    pub message: String,
}

/// Work actually done by one inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectionWork {
    pub prefix_scratch_limit: u64,
    pub prefix_bytes_decoded: u64,
    pub candidates_considered: u32,
    /// True when a limit (not the input) stopped a probe from going further.
    pub budget_limited: bool,
}

/// Complete result of one research inspection. Always returned, even for
/// garbage; malformed inputs keep whatever parsed and explain the rest in
/// [`issues`](Self::issues).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsInspection {
    pub input_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeInspection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection: Option<ProtectionInspection>,
    pub issues: Vec<InspectionIssue>,
    pub work: InspectionWork,
}

/// COFF header field a named flag came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagField {
    CoffCharacteristics,
    DllCharacteristics,
}

/// A set bit with its documented name. These are *declarations* in the header,
/// not guarantees about runtime behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NamedFlag {
    pub field: FlagField,
    pub bit: u16,
    pub name: &'static str,
}

/// Section permission bits from `IMAGE_SCN_MEM_*` / `IMAGE_SCN_CNT_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SectionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub code: bool,
    pub initialized_data: bool,
    pub uninitialized_data: bool,
}

/// How much of a section's declared raw range the file actually backs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionBacking {
    /// The full declared raw range is inside the input.
    FileBacked,
    /// Part of the raw range is inside the input.
    RawTruncated { available: u64 },
    /// The section declares no file bytes (BSS-like).
    VirtualOnly,
}

/// One observed section-table anomaly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionAnomaly {
    pub kind: SectionAnomalyKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionAnomalyKind {
    /// Raw range starts before the end of the PE headers.
    RawOverlapsHeaders,
    /// Raw range runs past the end of the file.
    RawPastEof,
    /// Virtual range overlaps another section's virtual range.
    VirtualOverlap,
    /// Raw range overlaps another section's raw range.
    RawOverlap,
    /// Virtual size is zero but raw size is not.
    ZeroVirtualSize,
    /// Entry point lies inside the section's virtual range.
    EntryPointInside,
}

/// One section-table entry as declared, plus what the file backs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionInspection {
    pub index: u16,
    /// Section name, trailing NULs stripped. Not guaranteed ASCII.
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    /// `raw_offset + raw_size` as computed, even when it overflows 32 bits.
    pub raw_end: u64,
    pub raw_in_bounds: bool,
    /// Original `IMAGE_SECTION_HEADER.Characteristics`. The permission booleans
    /// are derived views; discardable/shared/cache bits exist only here.
    pub characteristics: u32,
    pub permissions: SectionPermissions,
    pub backing: SectionBacking,
    pub anomalies: Vec<SectionAnomaly>,
}

/// How a declared data directory maps into the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryMapping {
    /// Directory entry is (0, 0): not published.
    Zero,
    /// The range lies wholly in the PE headers.
    HeaderBacked,
    /// The range lies wholly in file bytes outside any section (the
    /// certificate table is the only such directory).
    FileBacked,
    /// The range lies wholly in one section's file-backed bytes.
    SectionBacked { section: u16 },
    /// Only `backed` bytes of `size` are file-backed.
    PartiallyBacked { backed: u64 },
    /// Nothing maps into the input.
    Unmapped,
}

/// One declared data directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectoryInspection {
    pub index: u16,
    pub name: &'static str,
    /// RVA, or file offset for the certificate directory (index 4).
    pub address: u32,
    pub address_space: AddressSpace,
    pub size: u32,
    /// File offset when the declared range is file-backed from its start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<u64>,
    pub mapping: DirectoryMapping,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// A byte range of the file not covered by any section's declared raw range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRegionKind {
    /// Between the end of the PE headers and the first section's raw start.
    HeadersToFirstSection,
    /// Between two sections' raw ranges.
    BetweenSections,
    /// After the last section's raw range.
    Overlay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FileRegion {
    pub offset: u64,
    pub length: u64,
    pub kind: FileRegionKind,
}

/// Everything parsed from the PE headers of either the input or a restored
/// image. Fields are optional so a truncated header still reports what parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeInspection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<TargetFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<Kind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_base: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_rva: Option<u32>,
    /// File offset backing the entry point, when a section maps it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_file_offset: Option<u64>,
    /// True when the entry point RVA maps to file bytes; false when it is in a
    /// zero-filled tail or unmapped; absent when no entry point was parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_of_image: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_of_headers: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_alignment: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_alignment: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub characteristics: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dll_characteristics: Option<u16>,
    pub named_flags: Vec<NamedFlag>,
    pub sections: Vec<SectionInspection>,
    pub directories: Vec<DirectoryInspection>,
    pub unsectioned: Vec<FileRegion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<FileRegion>,
    /// Header-level parse explanation when parsing stopped early.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_issue: Option<String>,
}

/// Decoded header word with the source file position it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderWordSemantic {
    Key,
    Magic,
    PayloadSource,
    DestinationRva,
    TotalLength,
    EndMarker,
}

/// One of the eight protection header words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderWord {
    pub index: u8,
    /// Absolute byte offset in the protected input of the *raw* cell this word
    /// was extracted from (`0x1000 + index * 4`). It identifies where the
    /// scalar was read, not what the value means.
    pub source_file_offset: u64,
    pub raw_word: u32,
    /// Decoded word (the key-table formula's output).
    pub decoded_word: u32,
    /// Semantic name only where the pipeline actually uses the word that way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<HeaderWordSemantic>,
}

/// One in-bounds check on the declared payload region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayloadCheck {
    pub name: &'static str,
    pub start: u64,
    pub length: u64,
    pub end: u64,
    pub limit: u64,
    pub in_bounds: bool,
    pub overflow: bool,
}

/// The payload the header declares. Values are the decoded header words,
/// expressed in the space the pipeline uses: `source_file_offset` is a file
/// offset, `destination_rva` and `size_of_image` are working-image RVAs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeclaredPayload {
    /// `info[4] + 0x1000`, the first protected byte of the payload.
    pub source_file_offset: u64,
    pub destination_rva: u32,
    /// `info[6] - info[3] + 0x2000`: the prefix the key-table cipher covers.
    pub prefix_length: u64,
    /// `info[5]`: declared total payload length.
    pub total_length: u64,
    /// Header-declared `SizeOfImage` of the protected file.
    pub size_of_image: u64,
    pub checks: Vec<PayloadCheck>,
}

/// Outcome of a bounded probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// A required stage or input region was missing; no probe was possible.
    Unavailable,
    /// A work limit stopped the probe before it could decide.
    BudgetLimited,
    /// The probe ran but produced no structurally valid result.
    Failed,
    /// The probe produced a validated structural result.
    Decoded,
}

/// Bounded scratch-only decoding of the declared payload prefix.
///
/// `requested_length`/`decoded_length` are the whole scratch span: the decoded
/// prefix plus the raw tail copied verbatim after it. `prefix_bytes` and
/// `tail_bytes` split that span, so a reader never has to infer how much was
/// actually cipher-decoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrefixProbe {
    pub status: ProbeOutcome,
    /// `prefix_bytes + tail_bytes`: the scratch span the probe used.
    pub requested_length: u64,
    pub decoded_length: u64,
    /// Bytes actually run through the prefix cipher
    /// (`info[6] - info[3] + 0x2000`), or the intended prefix on an
    /// `Unavailable`/`BudgetLimited` outcome. On those outcomes it is a
    /// declaration, not work done: read `decoded_length` for what happened.
    pub prefix_bytes: u64,
    /// Raw payload tail available after the prefix, clamped to the input.
    /// These bytes are copied only when the probe status is `Decoded`; on a
    /// blocked or budget-limited probe this is a planned span, not work done.
    pub tail_bytes: u64,
    pub limit_bytes: u64,
    /// First decoded words at the payload destination (working-image RVA).
    pub first_words: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

/// Kind of structure a shell candidate represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellCandidateKind {
    /// PE32 compact/standard shell table (`find_tbl_pe32_candidates` shape).
    Pe32ShellTable,
    /// PE32+ anchor descriptor scan (anchor-relative stage1 descriptor).
    Pe32PlusAnchor,
}

/// How far a candidate was validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// A value was read from the input and reported; not structural.
    Observed,
    /// The shape matches, but the stage that would confirm it was not run.
    StructuralCandidate,
    /// A bounded trial produced a structurally valid result.
    TrialValidated,
    /// A bounded trial rejected the candidate.
    Rejected,
}

/// One named field of a shell candidate. `space` is present only when the
/// value is an offset; plain scalars (sizes, flags) carry `None` so a number
/// is never mislabelled as an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateField {
    pub name: &'static str,
    pub value: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<AddressSpace>,
}

/// One discovered shell structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShellCandidate {
    pub kind: ShellCandidateKind,
    pub status: CandidateStatus,
    /// Offset in the decoded payload scratch (relative to the probe base).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_offset: Option<u64>,
    /// Working-image RVA of the candidate, when the scratch is RVA-addressed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_rva: Option<u32>,
    /// File offset in the protected input when the structure lives there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_file_offset: Option<u64>,
    pub fields: Vec<CandidateField>,
    pub reason: &'static str,
}

/// Result of bounded shell discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveryReport {
    pub status: ProbeOutcome,
    pub candidates: Vec<ShellCandidate>,
    /// Word positions the structural scan examined. This is scan effort, not a
    /// candidate count; use `candidates.len()` for how many structures were
    /// reported.
    pub positions_scanned: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

/// Protection-header facts and bounded probe results for one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtectionInspection {
    /// Decoded `info[1]`.
    pub magic: Option<u32>,
    pub magic_recognized: bool,
    pub header_words: Vec<HeaderWord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<DeclaredPayload>,
    pub probe: PrefixProbe,
    pub discovery: DiscoveryReport,
}

// ---------------------------------------------------------------------------
// Inspection entry points
// ---------------------------------------------------------------------------

pub(super) fn inspect(input: &[u8], limits: &InspectionLimits) -> WindowsInspection {
    let mut issues = IssueList::new(limits.max_issues);
    let pe = inspect_pe(input, &mut issues);
    let protection = inspect_protection(input, limits, &mut issues);
    let (prefix_bytes_decoded, candidates_considered, budget_limited) = work_from(&protection);
    WindowsInspection {
        input_len: input.len() as u64,
        pe,
        protection,
        issues: issues.into_vec(),
        work: InspectionWork {
            prefix_scratch_limit: limits.prefix_scratch_bytes,
            prefix_bytes_decoded,
            candidates_considered,
            budget_limited,
        },
    }
}

fn work_from(protection: &Option<ProtectionInspection>) -> (u64, u32, bool) {
    let Some(protection) = protection else {
        return (0, 0, false);
    };
    let budget_limited = protection.probe.status == ProbeOutcome::BudgetLimited
        || protection.discovery.status == ProbeOutcome::BudgetLimited;
    (
        // Actual cipher-decoded bytes, excluding the verbatim raw tail. A
        // failed/budget-limited probe decoded nothing.
        if protection.probe.status == ProbeOutcome::Decoded {
            protection.probe.prefix_bytes
        } else {
            0
        },
        u32::try_from(protection.discovery.candidates.len()).unwrap_or(u32::MAX),
        budget_limited,
    )
}

struct IssueList {
    issues: Vec<InspectionIssue>,
    limit: usize,
}

impl IssueList {
    fn new(limit: usize) -> Self {
        Self {
            issues: Vec::new(),
            limit,
        }
    }

    fn push(
        &mut self,
        severity: InspectionSeverity,
        area: &'static str,
        message: impl Into<String>,
    ) {
        if self.issues.len() < self.limit {
            self.issues.push(InspectionIssue {
                severity,
                area,
                message: message.into(),
            });
        }
    }

    fn into_vec(self) -> Vec<InspectionIssue> {
        self.issues
    }
}

// ---------------------------------------------------------------------------
// PE header inspection
// ---------------------------------------------------------------------------

const DIRECTORY_NAMES: [&str; 16] = [
    "export",
    "import",
    "resource",
    "exception",
    "certificate",
    "base_relocation",
    "debug",
    "architecture",
    "global_pointer",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr_runtime",
    "reserved",
];

fn inspect_pe(input: &[u8], issues: &mut IssueList) -> Option<PeInspection> {
    let headers = match senbei_pe::parse(input) {
        Ok(headers) => Some(headers),
        Err(error) => {
            issues.push(
                InspectionSeverity::Warning,
                "pe",
                format!("PE headers did not parse: {error}"),
            );
            None
        }
    };
    let headers = headers?;
    let sections = senbei_pe::sections(input, headers).unwrap_or_default();
    let typed = TypedHeader::read(input, &headers);
    let mut pe = PeInspection {
        pe_offset: Some(headers.pe_offset as u64),
        machine: typed.machine,
        format: Some(if headers.is_pe32_plus {
            TargetFormat::Pe32Plus
        } else {
            TargetFormat::Pe32
        }),
        kind: typed.kind,
        image_base: Some(headers.image_base),
        entry_point_rva: Some(headers.entry_rva),
        entry_point_file_offset: None,
        entry_point_available: None,
        size_of_image: Some(headers.size_of_image),
        size_of_headers: typed.size_of_headers,
        section_alignment: typed.section_alignment,
        file_alignment: typed.file_alignment,
        characteristics: typed.characteristics,
        dll_characteristics: typed.dll_characteristics,
        named_flags: typed.named_flags,
        sections: Vec::new(),
        directories: Vec::new(),
        unsectioned: Vec::new(),
        overlay: None,
        parse_issue: None,
    };

    let entry = resolve_entry(input, &headers);
    pe.entry_point_file_offset = entry.0;
    pe.entry_point_available = Some(entry.1);

    let size_of_headers = typed.size_of_headers.unwrap_or(0);
    let section_anomalies =
        section_anomalies(&sections, headers.entry_rva, input.len(), size_of_headers);
    for (index, section) in sections.iter().enumerate().take(MAX_SECTIONS as usize) {
        pe.sections.push(inspect_section(
            index as u16,
            section,
            section_name(input, &headers, index as u16),
            input.len(),
            &section_anomalies[index],
        ));
    }
    if sections.len() > MAX_SECTIONS as usize {
        issues.push(
            InspectionSeverity::Warning,
            "pe",
            format!(
                "{} sections declared; only the first {} are reported",
                sections.len(),
                MAX_SECTIONS
            ),
        );
    }

    pe.directories = inspect_directories(input, &headers, &sections);
    let (unsectioned, overlay) = file_regions(input.len(), &sections, &headers);
    pe.unsectioned = unsectioned;
    pe.overlay = overlay;

    if typed.machine.is_none() {
        pe.parse_issue = Some("COFF machine field is outside the input".to_owned());
    }
    Some(pe)
}

/// `(file_offset, is_file_backed)` for the entry point, when one exists.
fn resolve_entry(input: &[u8], headers: &Headers) -> (Option<u64>, bool) {
    if headers.entry_rva == 0 {
        return (None, false);
    }
    let sections = senbei_pe::sections(input, *headers).unwrap_or_default();
    for section in &sections {
        let delta = headers.entry_rva.wrapping_sub(section.virtual_address);
        let span = section.virtual_size.max(section.raw_size);
        if headers.entry_rva >= section.virtual_address && delta < span {
            if delta < section.raw_size {
                let offset = section.raw_offset as u64 + delta as u64;
                if offset < input.len() as u64 {
                    return (Some(offset), true);
                }
            }
            return (None, false);
        }
    }
    if headers.entry_rva < headers.sections_offset as u32 {
        let offset = headers.entry_rva as u64;
        if offset < input.len() as u64 {
            return (Some(offset), true);
        }
    }
    (None, false)
}

struct TypedHeader {
    machine: Option<u16>,
    kind: Option<Kind>,
    size_of_headers: Option<u32>,
    section_alignment: Option<u32>,
    file_alignment: Option<u32>,
    characteristics: Option<u16>,
    dll_characteristics: Option<u16>,
    named_flags: Vec<NamedFlag>,
}

impl TypedHeader {
    fn read(input: &[u8], headers: &Headers) -> Self {
        let pe = headers.pe_offset;
        let machine = read_u16(input, pe + 4);
        let characteristics = read_u16(input, pe + 22);
        let optional = pe + 24;
        // These four fields sit at the same optional-header offsets in PE32
        // and PE32+; only ImageBase and the directory base differ.
        let size_of_headers = read_u32(input, optional + 60);
        let section_alignment = read_u32(input, optional + 32);
        let file_alignment = read_u32(input, optional + 36);
        let dll_characteristics = read_u16(input, optional + 70);
        let mut named_flags = Vec::new();
        if let Some(chars) = characteristics {
            for (bit, name) in COFF_FLAGS {
                if chars & bit != 0 {
                    named_flags.push(NamedFlag {
                        field: FlagField::CoffCharacteristics,
                        bit,
                        name,
                    });
                }
            }
        }
        if let Some(chars) = dll_characteristics {
            for (bit, name) in DLL_FLAGS {
                if chars & bit != 0 {
                    named_flags.push(NamedFlag {
                        field: FlagField::DllCharacteristics,
                        bit,
                        name,
                    });
                }
            }
        }
        let kind = match (characteristics, clr_directory_rva(input, headers)) {
            (Some(chars), Some(clr)) => {
                let is_dll = chars & 0x2000 != 0;
                Some(match (is_dll, clr != 0) {
                    (false, false) => Kind::NativeExe,
                    (false, true) => Kind::ManagedExe,
                    (true, false) => Kind::NativeDll,
                    (true, true) => Kind::ManagedDll,
                })
            }
            _ => None,
        };
        Self {
            machine,
            kind,
            size_of_headers,
            section_alignment,
            file_alignment,
            characteristics,
            dll_characteristics,
            named_flags,
        }
    }
}

const COFF_FLAGS: [(u16, &str); 11] = [
    (0x0001, "relocations_stripped"),
    (0x0002, "executable_image"),
    (0x0004, "line_numbers_stripped"),
    (0x0008, "local_symbols_stripped"),
    (0x0010, "large_address_aware"),
    (0x0020, "32bit_machine"),
    (0x0100, "debug_stripped"),
    (0x0200, "removable_run_from_swap"),
    (0x1000, "system"),
    (0x2000, "dll"),
    (0x4000, "unmanaged_code_only"),
];

const DLL_FLAGS: [(u16, &str); 9] = [
    (0x0020, "high_entropy_va"),
    (0x0040, "dynamic_base_aslr_declared"),
    (0x0080, "force_integrity"),
    (0x0100, "nx_compat_declared"),
    (0x0200, "no_isolation"),
    (0x0400, "no_seh"),
    (0x0800, "no_bind"),
    (0x1000, "app_container"),
    (0x4000, "guard_cf_declared"),
];

fn clr_directory_rva(input: &[u8], headers: &Headers) -> Option<u32> {
    senbei_pe::data_directory(input, *headers, 14)
        .ok()
        .map(|(rva, _)| rva)
}

fn inspect_section(
    index: u16,
    section: &Section,
    name: String,
    input_len: usize,
    anomalies: &[SectionAnomaly],
) -> SectionInspection {
    let raw_end = section.raw_offset as u64 + section.raw_size as u64;
    let raw_in_bounds = raw_end <= input_len as u64;
    let available = (input_len as u64).saturating_sub(section.raw_offset as u64);
    let backing = if section.raw_size == 0 {
        SectionBacking::VirtualOnly
    } else if raw_in_bounds {
        SectionBacking::FileBacked
    } else {
        SectionBacking::RawTruncated {
            available: available.min(section.raw_size as u64),
        }
    };
    SectionInspection {
        index,
        name,
        virtual_address: section.virtual_address,
        virtual_size: section.virtual_size,
        raw_offset: section.raw_offset,
        raw_size: section.raw_size,
        raw_end,
        raw_in_bounds,
        characteristics: section.characteristics,
        permissions: SectionPermissions {
            read: section.characteristics & 0x4000_0000 != 0,
            write: section.characteristics & 0x8000_0000 != 0,
            execute: section.characteristics & 0x2000_0000 != 0,
            code: section.characteristics & 0x0000_0020 != 0,
            initialized_data: section.characteristics & 0x0000_0040 != 0,
            uninitialized_data: section.characteristics & 0x0000_0080 != 0,
        },
        backing,
        anomalies: anomalies.to_vec(),
    }
}

/// Section names are exactly 8 bytes and may fill the field (no NUL).
fn section_name(input: &[u8], headers: &Headers, index: u16) -> String {
    let Some(offset) = headers.sections_offset.checked_add(usize::from(index) * 40) else {
        return String::new();
    };
    let Some(field) = input.get(offset..offset + 8) else {
        return String::new();
    };
    let end = field.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Anomalies for at most [`MAX_SECTIONS`] sections. The cap is applied before
/// any pairwise work, so a crafted header declaring 65535 overlapping sections
/// cannot drive quadratic time or per-section allocation.
fn section_anomalies(
    sections: &[Section],
    entry_rva: u32,
    input_len: usize,
    size_of_headers: u32,
) -> Vec<Vec<SectionAnomaly>> {
    let sections = &sections[..sections.len().min(MAX_SECTIONS as usize)];
    let mut result = vec![Vec::new(); sections.len()];
    if sections.is_empty() {
        return result;
    }
    for (index, section) in sections.iter().enumerate() {
        let raw_end = section.raw_offset as u64 + section.raw_size as u64;
        let virt_end =
            section.virtual_address as u64 + section.virtual_size.max(section.raw_size) as u64;
        let mut anomalies = Vec::new();
        if section.raw_size != 0
            && size_of_headers != 0
            && (section.raw_offset as u64) < u64::from(size_of_headers)
        {
            anomalies.push(SectionAnomaly {
                kind: SectionAnomalyKind::RawOverlapsHeaders,
                detail: format!(
                    "raw range starts at 0x{:X}, inside the declared headers (0x{size_of_headers:X})",
                    section.raw_offset
                ),
            });
        }
        if raw_end > input_len as u64 && section.raw_size != 0 {
            anomalies.push(SectionAnomaly {
                kind: SectionAnomalyKind::RawPastEof,
                detail: format!("raw range ends at 0x{raw_end:X}, input is 0x{input_len:X} bytes"),
            });
        }
        if section.virtual_size == 0 && section.raw_size != 0 {
            anomalies.push(SectionAnomaly {
                kind: SectionAnomalyKind::ZeroVirtualSize,
                detail: "virtual size is zero while raw size is not".to_owned(),
            });
        }
        let entry_in =
            entry_rva != 0 && entry_rva >= section.virtual_address && (entry_rva as u64) < virt_end;
        if entry_in {
            anomalies.push(SectionAnomaly {
                kind: SectionAnomalyKind::EntryPointInside,
                detail: format!("entry point 0x{entry_rva:X} lies in this section"),
            });
        }
        for other in &sections[index + 1..] {
            let other_virt_end =
                other.virtual_address as u64 + other.virtual_size.max(other.raw_size) as u64;
            let virt_overlap = (section.virtual_address as u64) < other_virt_end
                && (other.virtual_address as u64) < virt_end
                && section.virtual_size != 0
                && other.virtual_size != 0;
            if virt_overlap {
                anomalies.push(SectionAnomaly {
                    kind: SectionAnomalyKind::VirtualOverlap,
                    detail: format!(
                        "virtual range overlaps section at RVA 0x{:X}",
                        other.virtual_address
                    ),
                });
            }
            let other_raw_end = other.raw_offset as u64 + other.raw_size as u64;
            if section.raw_size != 0
                && other.raw_size != 0
                && (section.raw_offset as u64) < other_raw_end
                && (other.raw_offset as u64) < raw_end
            {
                anomalies.push(SectionAnomaly {
                    kind: SectionAnomalyKind::RawOverlap,
                    detail: format!(
                        "raw range overlaps section at file offset 0x{:X}",
                        other.raw_offset
                    ),
                });
            }
        }
        result[index] = anomalies;
    }
    result
}

fn inspect_directories(
    input: &[u8],
    headers: &Headers,
    sections: &[Section],
) -> Vec<DirectoryInspection> {
    let count = directory_count(input, headers).min(MAX_DIRECTORIES).min(16);
    let mut result = Vec::new();
    for index in 0..count {
        let Ok((address, size)) = senbei_pe::data_directory(input, *headers, index as u16) else {
            break;
        };
        let name = DIRECTORY_NAMES[index as usize];
        let address_space = if index == 4 {
            AddressSpace::FileOffset
        } else {
            AddressSpace::WorkingImageRva
        };
        if address == 0 || size == 0 {
            result.push(DirectoryInspection {
                index: index as u16,
                name,
                address,
                address_space,
                size,
                file_offset: None,
                mapping: DirectoryMapping::Zero,
                note: None,
            });
            continue;
        }
        let (file_offset, mapping) = if index == 4 {
            // The certificate table is a file offset, not an RVA, and it is
            // not inside any section — report plain file backing rather than
            // inventing a section index.
            let end = address as u64 + size as u64;
            if end <= input.len() as u64 {
                (Some(address as u64), DirectoryMapping::FileBacked)
            } else {
                (
                    Some(address as u64),
                    DirectoryMapping::PartiallyBacked {
                        backed: (input.len() as u64).saturating_sub(address as u64),
                    },
                )
            }
        } else {
            map_directory(input, headers, sections, address, size)
        };
        let note = if index == 4 {
            Some("certificate directory uses a file offset, not an RVA")
        } else {
            None
        };
        result.push(DirectoryInspection {
            index: index as u16,
            name,
            address,
            address_space,
            size,
            file_offset,
            mapping,
            note,
        });
    }
    result
}

fn directory_count(input: &[u8], headers: &Headers) -> u32 {
    let optional = headers.pe_offset + 24;
    let offset = if headers.is_pe32_plus {
        optional + 108
    } else {
        optional + 92
    };
    read_u32(input, offset).unwrap_or(0)
}

fn map_directory(
    input: &[u8],
    headers: &Headers,
    sections: &[Section],
    rva: u32,
    size: u32,
) -> (Option<u64>, DirectoryMapping) {
    // Headers extend to the declared `SizeOfHeaders`, not merely to the end of
    // the section table: a directory placed in the reserved header padding is
    // header-backed too.
    let size_of_headers = read_u32(input, headers.pe_offset + 24 + 60)
        .filter(|&size| size != 0)
        .unwrap_or(headers.sections_offset as u32);
    if rva < size_of_headers {
        let end = rva as u64 + size as u64;
        if end <= input.len() as u64 {
            return (Some(rva as u64), DirectoryMapping::HeaderBacked);
        }
        return (
            None,
            DirectoryMapping::PartiallyBacked {
                backed: (input.len() as u64).saturating_sub(rva as u64),
            },
        );
    }
    for (index, section) in sections.iter().enumerate() {
        let delta = rva.wrapping_sub(section.virtual_address);
        if rva < section.virtual_address {
            continue;
        }
        let span = section.virtual_size.max(section.raw_size);
        if delta >= span {
            continue;
        }
        if delta < section.raw_size {
            let offset = section.raw_offset as u64 + delta as u64;
            let raw_left = (section.raw_size - delta) as u64;
            if size as u64 <= raw_left && offset + size as u64 <= input.len() as u64 {
                return (
                    Some(offset),
                    DirectoryMapping::SectionBacked {
                        section: index as u16,
                    },
                );
            }
            return (
                Some(offset),
                DirectoryMapping::PartiallyBacked {
                    backed: raw_left.min((input.len() as u64).saturating_sub(offset)),
                },
            );
        }
        return (None, DirectoryMapping::Unmapped);
    }
    (None, DirectoryMapping::Unmapped)
}

fn file_regions(
    input_len: usize,
    sections: &[Section],
    headers: &Headers,
) -> (Vec<FileRegion>, Option<FileRegion>) {
    let file_len = input_len as u64;
    let section_table_end = headers.sections_offset as u64 + sections.len() as u64 * 40;
    // A declared `SizeOfHeaders` is the reserve the loader zero-fills; the
    // section table end is the conservative minimum. Use the smaller so a
    // bogus SizeOfHeaders cannot hide a gap.
    let header_end = section_table_end.min(file_len);
    let mut raws: Vec<(u64, u64)> = sections
        .iter()
        .filter(|section| section.raw_size != 0 && (section.raw_offset as u64) < file_len)
        .map(|section| {
            (
                section.raw_offset as u64,
                (section.raw_offset as u64 + section.raw_size as u64).min(file_len),
            )
        })
        .collect();
    raws.sort_unstable();
    let first_start = raws.first().map_or(file_len, |(start, _)| *start);
    let mut regions: Vec<FileRegion> = Vec::new();
    let push = |offset: u64, end: u64, kind: FileRegionKind, regions: &mut Vec<FileRegion>| {
        if offset < end && regions.len() < MAX_REGIONS {
            regions.push(FileRegion {
                offset,
                length: end - offset,
                kind,
            });
        }
    };
    if header_end < first_start {
        push(
            header_end,
            first_start,
            FileRegionKind::HeadersToFirstSection,
            &mut regions,
        );
    }
    let mut cursor = first_start;
    for (start, end) in &raws {
        if *start > cursor {
            push(
                cursor,
                *start,
                FileRegionKind::BetweenSections,
                &mut regions,
            );
        }
        cursor = cursor.max(*end);
    }
    let overlay = (cursor < file_len).then(|| FileRegion {
        offset: cursor,
        length: file_len - cursor,
        kind: FileRegionKind::Overlay,
    });
    (regions, overlay)
}

// ---------------------------------------------------------------------------
// Small bounded readers
// ---------------------------------------------------------------------------

fn read_u16(input: &[u8], offset: usize) -> Option<u16> {
    let bytes = input.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(input: &[u8], offset: usize) -> Option<u32> {
    let bytes = input.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

// ---------------------------------------------------------------------------
// Protection header inspection
// ---------------------------------------------------------------------------

/// The protected header table occupies `[0x1000, 0x1020)`.
const HEADER_TABLE_OFFSET: usize = 0x1000;
const HEADER_TABLE_LEN: usize = 32;

fn inspect_protection(
    input: &[u8],
    limits: &InspectionLimits,
    issues: &mut IssueList,
) -> Option<ProtectionInspection> {
    let words = header_words(input)?;
    let info: [u32; 8] = std::array::from_fn(|index| words[index].decoded);
    let magic = Some(info[1]);
    let magic_recognized = info[1] == MAGIC_KONN;

    let mut header_words_out: Vec<HeaderWord> = Vec::with_capacity(8);
    for (index, word) in words.iter().enumerate() {
        header_words_out.push(HeaderWord {
            index: index as u8,
            source_file_offset: (HEADER_TABLE_OFFSET + index * 4) as u64,
            raw_word: word.raw,
            decoded_word: word.decoded,
            semantic: header_semantic(index),
        });
    }

    if !magic_recognized {
        issues.push(
            InspectionSeverity::Info,
            "protection",
            format!(
                "header table decoded but info[1] is 0x{:08X}, not the supported magic",
                info[1]
            ),
        );
    }

    let payload = declared_payload(input, &info);
    // A probe only makes sense for the protected layout this pipeline knows.
    // An unrelated file can carry a coherent-looking word table by accident;
    // reporting its raw/decoded words is fine, running the pipeline's
    // discovery over it is not.
    let (probe, scratch) = if magic_recognized {
        decode_prefix_probe(input, &info, payload.as_ref(), limits, issues)
    } else {
        (
            PrefixProbe {
                status: ProbeOutcome::Unavailable,
                requested_length: 0,
                decoded_length: 0,
                prefix_bytes: 0,
                tail_bytes: 0,
                limit_bytes: limits.prefix_scratch_bytes,
                first_words: Vec::new(),
                reason: Some("header magic is not a supported protection header"),
            },
            None,
        )
    };
    let discovery = discover_shell(input, payload.as_ref(), &probe, scratch.as_deref(), limits);

    Some(ProtectionInspection {
        magic,
        magic_recognized,
        header_words: header_words_out,
        payload,
        probe,
        discovery,
    })
}

struct Word {
    raw: u32,
    decoded: u32,
}

/// Decode the eight header words with the same recurrence `decrypt_data1`
/// uses, pairing each decoded word with its raw source cell so the report
/// cannot show an inconsistent raw/decoded pair.
fn header_words(input: &[u8]) -> Option<[Word; 8]> {
    if input.len() < HEADER_TABLE_OFFSET + HEADER_TABLE_LEN {
        return None;
    }
    let mut info = [0u32; 8];
    primitives::decrypt_data1(input, &mut info);
    Some(std::array::from_fn(|index| {
        let raw = primitives::get_u32(input, (HEADER_TABLE_OFFSET + index * 4) as u32);
        Word {
            raw,
            decoded: info[index],
        }
    }))
}

fn header_semantic(index: usize) -> Option<HeaderWordSemantic> {
    match index {
        0 => Some(HeaderWordSemantic::Key),
        1 => Some(HeaderWordSemantic::Magic),
        3 => Some(HeaderWordSemantic::DestinationRva),
        4 => Some(HeaderWordSemantic::PayloadSource),
        5 => Some(HeaderWordSemantic::TotalLength),
        6 => Some(HeaderWordSemantic::EndMarker),
        // info[2] and info[7] are not used semantically by the pipeline.
        _ => None,
    }
}

fn declared_payload(input: &[u8], info: &[u32; 8]) -> Option<DeclaredPayload> {
    // Read SizeOfImage from the parsed PE, never from a raw e_lfanew: a
    // crafted offset must not drive a read here.
    let headers = senbei_pe::parse(input).ok()?;
    let size_of_image = headers.size_of_image;
    let destination = info[3];
    let total = info[5];
    let prefix_word = info[6].wrapping_sub(info[3]);
    let prefix_length = prefix_word as u64 + 0x2000;
    let source = info[4] as u64 + 0x1000;
    let mut checks = Vec::new();
    checks.push(payload_check(
        "declared_prefix",
        destination as u64,
        prefix_length,
        size_of_image as u64,
    ));
    checks.push(payload_check(
        "source_prefix",
        source,
        prefix_length,
        input.len() as u64,
    ));
    checks.push(payload_check(
        "declared_payload",
        destination as u64,
        total as u64,
        size_of_image as u64,
    ));
    let raw_tail_start = source.saturating_add(prefix_length);
    let remaining = u64::from(total).saturating_sub(prefix_length);
    checks.push(payload_check(
        "source_raw_tail",
        raw_tail_start,
        remaining,
        input.len() as u64,
    ));
    Some(DeclaredPayload {
        source_file_offset: source,
        destination_rva: destination,
        prefix_length,
        total_length: total as u64,
        size_of_image: size_of_image as u64,
        checks,
    })
}

fn payload_check(name: &'static str, start: u64, length: u64, limit: u64) -> PayloadCheck {
    let overflow = start.checked_add(length).is_none();
    let end = start.saturating_add(length);
    PayloadCheck {
        name,
        start,
        length,
        end,
        limit,
        in_bounds: !overflow && end <= limit,
        overflow,
    }
}

// ---------------------------------------------------------------------------
// Bounded prefix probe
// ---------------------------------------------------------------------------

/// Decode the declared payload prefix into scratch (never `SizeOfImage`) and
/// report the first words. Larger values (stage tables) need the rest of the
/// pipeline, so a successful decode here is reported as `Decoded`, not as
/// recovery.
/// Decode the declared payload prefix once into scratch (never `SizeOfImage`)
/// and report the first words. The scratch is returned privately so discovery
/// can reuse it instead of decoding a second time; it is never part of the
/// public report.
///
/// The budget counts the whole allocation (prefix plus the raw tail actually
/// present in the input), and the required source end is the prefix end or the
/// real tail end, whichever the input can actually supply.
fn decode_prefix_probe(
    input: &[u8],
    info: &[u32; 8],
    payload: Option<&DeclaredPayload>,
    limits: &InspectionLimits,
    issues: &mut IssueList,
) -> (PrefixProbe, Option<Vec<u8>>) {
    let limit_bytes = limits.prefix_scratch_bytes;
    let unavailable = |requested_length: u64, reason: &'static str| {
        (
            PrefixProbe {
                status: ProbeOutcome::Unavailable,
                requested_length,
                decoded_length: 0,
                prefix_bytes: requested_length,
                tail_bytes: 0,
                limit_bytes,
                first_words: Vec::new(),
                reason: Some(reason),
            },
            None,
        )
    };
    let Some(payload) = payload else {
        return unavailable(0, "declared payload words could not be read");
    };
    if !info_header_plausible(info) {
        return unavailable(0, "header words are not a coherent payload descriptor");
    }
    let prefix = payload.prefix_length;
    let source = payload.source_file_offset;
    let Some(prefix_end) = source.checked_add(prefix) else {
        return unavailable(prefix, "payload descriptor overflows a file offset");
    };
    if prefix_end > input.len() as u64 {
        return unavailable(prefix, "input does not contain the declared payload prefix");
    }
    // Raw tail: whatever real payload bytes follow the prefix and are inside
    // the input. A file that ends exactly at the prefix is valid.
    let tail = payload
        .total_length
        .saturating_sub(prefix)
        .min((input.len() as u64).saturating_sub(prefix_end));
    let allocation = prefix.saturating_add(tail);
    if prefix > limit_bytes || allocation > limit_bytes {
        issues.push(
            InspectionSeverity::Info,
            "probe",
            format!(
                "prefix probe needs 0x{allocation:X} bytes (prefix 0x{prefix:X}, tail 0x{tail:X}), above the 0x{limit_bytes:X} scratch cap"
            ),
        );
        return (
            PrefixProbe {
                status: ProbeOutcome::BudgetLimited,
                requested_length: allocation,
                decoded_length: 0,
                prefix_bytes: prefix,
                tail_bytes: tail,
                limit_bytes,
                first_words: Vec::new(),
                reason: Some("declared prefix plus tail exceeds the scratch budget"),
            },
            None,
        );
    }
    if !prefix.is_multiple_of(4) {
        return unavailable(prefix, "declared prefix length is not word-aligned");
    }
    let Ok(prefix_len) = usize::try_from(prefix) else {
        return unavailable(prefix, "declared prefix length is too large");
    };
    let Ok(tail_len) = usize::try_from(tail) else {
        return unavailable(prefix, "declared raw tail is too large");
    };
    let Ok(source_u32) = u32::try_from(source) else {
        return unavailable(prefix, "payload source is outside the 32-bit address space");
    };
    let mut scratch = vec![0u8; prefix_len + tail_len];
    primitives::decode_payload_prefix(
        input,
        source_u32,
        &mut scratch,
        0,
        info[0],
        u32::try_from(prefix).expect("prefix was checked against a 2 MiB cap"),
    );
    if tail_len > 0 {
        let start = usize::try_from(prefix_end).expect("prefix end fits usize");
        scratch[prefix_len..prefix_len + tail_len].copy_from_slice(&input[start..start + tail_len]);
    }
    let first_words = (0..4.min(scratch.len() / 4))
        .map(|index| primitives::get_u32(&scratch, (index * 4) as u32))
        .collect();
    issues.push(
        InspectionSeverity::Info,
        "probe",
        "prefix decoded in scratch; later stages still require a full recovery",
    );
    (
        PrefixProbe {
            status: ProbeOutcome::Decoded,
            requested_length: allocation,
            decoded_length: allocation,
            prefix_bytes: prefix,
            tail_bytes: tail,
            limit_bytes,
            first_words,
            reason: Some("bounded prefix only; not a recovered image"),
        },
        Some(scratch),
    )
}

fn info_header_plausible(info: &[u32; 8]) -> bool {
    let end = info[6];
    let base = info[3];
    let total = info[5];
    end > base
        && total > end.wrapping_sub(base)
        && total as u64 <= senbei_crypto::MAX_IMAGE_SIZE
        && base != 0
}

// ---------------------------------------------------------------------------
// Bounded shell discovery
// ---------------------------------------------------------------------------

fn discover_shell(
    input: &[u8],
    payload: Option<&DeclaredPayload>,
    probe: &PrefixProbe,
    scratch: Option<&[u8]>,
    limits: &InspectionLimits,
) -> DiscoveryReport {
    if probe.status != ProbeOutcome::Decoded {
        return DiscoveryReport {
            status: match probe.status {
                ProbeOutcome::Unavailable => ProbeOutcome::Unavailable,
                ProbeOutcome::BudgetLimited => ProbeOutcome::BudgetLimited,
                _ => ProbeOutcome::Unavailable,
            },
            candidates: Vec::new(),
            positions_scanned: 0,
            reason: Some("shell discovery needs a decoded payload prefix"),
        };
    }
    let (Some(info), Some(payload), Some(scratch)) = (header_info(input), payload, scratch) else {
        return DiscoveryReport {
            status: ProbeOutcome::Unavailable,
            candidates: Vec::new(),
            positions_scanned: 0,
            reason: Some("protection header or decoded prefix is unavailable"),
        };
    };
    // Use the PE format the parser accepted rather than re-reading e_lfanew;
    // a crafted e_lfanew must not select a discovery path here.
    let Some(pe) = senbei_pe::parse(input).ok() else {
        return DiscoveryReport {
            status: ProbeOutcome::Unavailable,
            candidates: Vec::new(),
            positions_scanned: 0,
            reason: Some("PE headers did not parse"),
        };
    };
    if pe.is_pe32_plus {
        discover_pe32_plus_anchor(info, payload, scratch, limits)
    } else {
        discover_pe32_table(info, payload, scratch, limits)
    }
}

fn header_info(input: &[u8]) -> Option<[u32; 8]> {
    if input.len() < HEADER_TABLE_OFFSET + HEADER_TABLE_LEN {
        return None;
    }
    let mut info = [0u32; 8];
    primitives::decrypt_data1(input, &mut info);
    Some(info)
}

/// PE32 shell table discovery, run against the decoded scratch with
/// `info[3]` as the buffer origin.
///
/// `find_tbl_pe32_candidates_at` takes the origin explicitly, so `info[3]` and
/// `info[6]` stay absolute and only the in-buffer bounds check shifts. A
/// candidate at scratch offset `candidate` is working-image RVA
/// `info[3] + candidate` and protected-file offset
/// `info[4] + 0x1000 + candidate`.
fn discover_pe32_table(
    info: [u32; 8],
    payload: &DeclaredPayload,
    scratch: &[u8],
    limits: &InspectionLimits,
) -> DiscoveryReport {
    let base = info[3];
    // The declared working image may be larger than the decoded prefix. Pass
    // its size so a candidate whose fields validate against the declared image
    // is still reported; its stage bytes are then known to be undecoded.
    let window_len = payload.size_of_image.saturating_sub(base as u64);
    // The locator owns the scan loop, so it reports the real number of word
    // positions examined; that count is scan effort, not a candidate count.
    let (candidates, positions_scanned) =
        layout::find_tbl_pe32_candidates_counted(scratch, &info, base, window_len);
    let mut out = Vec::new();
    let mut budget_limited = false;
    for candidate in candidates {
        if out.len() >= limits.max_candidates {
            budget_limited = true;
            break;
        }
        let u = candidate as usize;
        let Some(table) = scratch.get(u..u + 0xD0) else {
            continue;
        };
        let compact = primitives::get_u32(table, 0x78) == info[6];
        let (header_field, stage_field) = if compact {
            (0x50u32, 0x88u32)
        } else {
            (0x58, 0x98)
        };
        let header = primitives::get_u32(table, header_field);
        let header_size = primitives::get_u32(table, header_field + 4);
        let stage_descriptor = primitives::get_u32(table, stage_field);
        let stage_descriptor_size = primitives::get_u32(table, stage_field + 4);
        let checksum_start = primitives::get_u32(table, stage_field + 0x10);
        let checksum_size = primitives::get_u32(table, stage_field + 0x14);
        let mut fields = vec![
            CandidateField {
                name: "compact_layout",
                value: u32::from(compact),
                space: None,
            },
            CandidateField {
                name: "header_start",
                value: header,
                space: Some(AddressSpace::WorkingImageRva),
            },
            CandidateField {
                name: "header_size",
                value: header_size,
                space: None,
            },
            CandidateField {
                name: "stage_descriptor_start",
                value: stage_descriptor,
                space: Some(AddressSpace::WorkingImageRva),
            },
            CandidateField {
                name: "stage_descriptor_size",
                value: stage_descriptor_size,
                space: None,
            },
            CandidateField {
                name: "checksum_start",
                value: checksum_start,
                space: Some(AddressSpace::WorkingImageRva),
            },
            CandidateField {
                name: "checksum_size",
                value: checksum_size,
                space: None,
            },
            CandidateField {
                name: "second_stage_key",
                value: primitives::get_u32(table, 0x40),
                space: None,
            },
        ];
        // The descriptor stores an absolute working-image RVA; the scratch
        // starts at `info[3]`, so subtract the base before the bounds check.
        let stage_in_scratch = stage_descriptor
            .checked_sub(info[3])
            .and_then(|relative| (relative as usize).checked_add(4))
            .is_some_and(|end| end <= scratch.len());
        if !stage_in_scratch {
            fields.push(CandidateField {
                name: "stage_beyond_prefix",
                value: 1,
                space: None,
            });
        }
        let source_offset = payload.source_file_offset.saturating_add(candidate as u64);
        let status = if header > 0
            && header_size > 0
            && header
                .checked_add(header_size)
                .is_some_and(|end| end <= 0x1000)
            && checksum_size >= 4
        {
            CandidateStatus::StructuralCandidate
        } else {
            CandidateStatus::Rejected
        };
        let reason = match (status, stage_in_scratch) {
            (CandidateStatus::StructuralCandidate, true) => {
                "shell table shape matches the declared image; second-stage decryption requires recovery"
            }
            (CandidateStatus::StructuralCandidate, false) => {
                "shell table fields match the declared image; stage bytes are beyond the bounded prefix"
            }
            _ => "shell table shape does not satisfy the header/stage ranges",
        };
        out.push(ShellCandidate {
            kind: ShellCandidateKind::Pe32ShellTable,
            status,
            payload_offset: Some(candidate as u64),
            image_rva: Some(base.wrapping_add(candidate)),
            source_file_offset: Some(source_offset),
            fields,
            reason,
        });
    }
    let status = if budget_limited {
        ProbeOutcome::BudgetLimited
    } else if out.is_empty() {
        ProbeOutcome::Failed
    } else {
        ProbeOutcome::Decoded
    };
    let reason = match status {
        ProbeOutcome::Decoded => "candidates reported without stage validation",
        ProbeOutcome::Failed => "no shell table shape in the decoded payload window",
        ProbeOutcome::BudgetLimited => "candidate list reached the configured cap",
        ProbeOutcome::Unavailable => "shell discovery unavailable",
    };
    DiscoveryReport {
        status,
        candidates: out,
        positions_scanned,
        reason: Some(reason),
    }
}

/// PE32+ anchor discovery: scan `info[6]+0x1000 .. info[6]+0x8000` for the
/// anchor field (dword == `info[3]`, followed by a near, 0x200-aligned value
/// below `info[6]`), and report the anchor-relative stage1 descriptor when it
/// validates. Uses the same rebased scratch as the PE32 probe.
fn discover_pe32_plus_anchor(
    info: [u32; 8],
    payload: &DeclaredPayload,
    scratch: &[u8],
    _limits: &InspectionLimits,
) -> DiscoveryReport {
    let base = info[3];
    let rebased_info6 = info[6].wrapping_sub(base);
    let mut probe = rebased_info6.wrapping_add(0x1000);
    let probe_end = rebased_info6.wrapping_add(0x8000);
    let mut anchor = None;
    let mut positions_scanned = 0u32;
    while probe + 12 <= probe_end && (probe as usize + 12) <= scratch.len() {
        positions_scanned = positions_scanned.saturating_add(1);
        if primitives::get_u32(scratch, probe) == base {
            // The scratch starts at `info[3]`, but the layout stores absolute
            // RVAs, so the nearby end marker is compared after adding the base
            // back. `probe` itself is a scratch offset; the report adds the
            // base when it names an image RVA.
            let v8 = primitives::get_u32(scratch, probe + 8);
            if v8 >= base {
                let delta = info[6].wrapping_sub(v8);
                if v8 < info[6] && delta <= 0x1000 && delta.is_multiple_of(0x200) {
                    anchor = Some(probe);
                    break;
                }
            }
        }
        probe = probe.wrapping_add(4);
    }
    let Some(anchor) = anchor else {
        return DiscoveryReport {
            status: ProbeOutcome::Failed,
            candidates: Vec::new(),
            positions_scanned,
            reason: Some("no anchor field in the decoded payload window"),
        };
    };
    let descriptor = [0u32, 8].into_iter().find_map(|extra| {
        let pos = anchor.wrapping_add(120 + extra);
        let end = (pos as usize).checked_add(8)?;
        if end > scratch.len() {
            return None;
        }
        let start = primitives::get_u32(scratch, pos);
        let length = primitives::get_u32(scratch, pos + 4);
        // Descriptor values are absolute RVAs; the scratch starts at `info[3]`,
        // so the in-probe bounds check subtracts the base.
        let start_rel = start.checked_sub(base)?;
        let valid = length >= 16
            && (start_rel as usize)
                .checked_add(length as usize)
                .is_some_and(|end| end <= scratch.len());
        valid.then_some((extra, start, length))
    });
    let mut fields = vec![CandidateField {
        name: "anchor_payload_offset",
        value: anchor,
        space: Some(AddressSpace::DecodedPayloadOffset),
    }];
    if let Some((extra, start, length)) = descriptor {
        fields.push(CandidateField {
            name: "stage1_layout_extra",
            value: extra,
            space: None,
        });
        fields.push(CandidateField {
            name: "stage1_start",
            value: start,
            space: Some(AddressSpace::WorkingImageRva),
        });
        fields.push(CandidateField {
            name: "stage1_length",
            value: length,
            space: None,
        });
    }
    let status = if descriptor.is_some() {
        CandidateStatus::StructuralCandidate
    } else {
        CandidateStatus::Observed
    };
    let source_offset = payload.source_file_offset.saturating_add(anchor as u64);
    DiscoveryReport {
        status: ProbeOutcome::Decoded,
        candidates: vec![ShellCandidate {
            kind: ShellCandidateKind::Pe32PlusAnchor,
            status,
            payload_offset: Some(anchor as u64),
            image_rva: Some(base.wrapping_add(anchor)),
            source_file_offset: Some(source_offset),
            fields,
            reason: if descriptor.is_some() {
                "anchor and stage1 descriptor validate; full stage decryption requires recovery"
            } else {
                "anchor field found; stage1 descriptor needs recovery to validate"
            },
        }],
        positions_scanned,
        reason: Some("bounded anchor probe only"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PE_OFF: usize = 0x80;
    const OPT_SIZE: usize = 0xE0;
    const SECTION_TABLE: usize = PE_OFF + 24 + OPT_SIZE;
    const SIZE_OF_IMAGE: u32 = 0x40_4000;

    /// Minimal PE32 with `sections` entries, no protection table. Everything
    /// after the header is caller-controlled.
    fn pe32(file_len: usize, sections: &[(&str, u32, u32, u32, u32, u32)]) -> Vec<u8> {
        let mut data = vec![0u8; file_len];
        let needed = SECTION_TABLE + sections.len() * 40;
        if data.len() < needed {
            data.resize(needed, 0);
        }
        data[..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
        data[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
        data[PE_OFF + 4..PE_OFF + 6].copy_from_slice(&0x14C_u16.to_le_bytes());
        data[PE_OFF + 6..PE_OFF + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        data[PE_OFF + 20..PE_OFF + 22].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
        data[PE_OFF + 22..PE_OFF + 24].copy_from_slice(&0x0102_u16.to_le_bytes());
        let opt = PE_OFF + 24;
        data[opt..opt + 2].copy_from_slice(&0x10B_u16.to_le_bytes());
        data[opt + 16..opt + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[opt + 28..opt + 32].copy_from_slice(&0x400000_u32.to_le_bytes());
        data[opt + 32..opt + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        data[opt + 36..opt + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        data[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
        data[opt + 60..opt + 64].copy_from_slice(&0x400_u32.to_le_bytes());
        data[opt + 70..opt + 72].copy_from_slice(&0_u16.to_le_bytes());
        data[opt + 92..opt + 96].copy_from_slice(&16_u32.to_le_bytes());
        for (index, (name, vsize, va, raw_size, raw_off, characteristics)) in
            sections.iter().enumerate()
        {
            let at = SECTION_TABLE + index * 40;
            let field = name.as_bytes();
            let take = field.len().min(8);
            data[at..at + take].copy_from_slice(&field[..take]);
            data[at + 8..at + 12].copy_from_slice(&vsize.to_le_bytes());
            data[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
            data[at + 16..at + 20].copy_from_slice(&raw_size.to_le_bytes());
            data[at + 20..at + 24].copy_from_slice(&raw_off.to_le_bytes());
            data[at + 36..at + 40].copy_from_slice(&characteristics.to_le_bytes());
        }
        data
    }

    fn sample_sections() -> [(&'static str, u32, u32, u32, u32, u32); 1] {
        [(".text", 0x1000, 0x1000, 0x200, 0x400, 0x6000_0020)]
    }

    #[test]
    fn pe_reports_headers_sections_and_entry_backing() {
        let data = pe32(0x800, &sample_sections());
        let out = inspect(&data, &InspectionLimits::default());
        let pe = out.pe.expect("PE must parse");
        assert_eq!(pe.machine, Some(0x14C));
        assert_eq!(pe.format, Some(TargetFormat::Pe32));
        assert_eq!(pe.kind, Some(Kind::NativeExe));
        assert_eq!(pe.image_base, Some(0x40_0000));
        assert_eq!(pe.entry_point_rva, Some(0x1000));
        assert_eq!(pe.entry_point_file_offset, Some(0x400));
        assert_eq!(pe.entry_point_available, Some(true));
        assert_eq!(pe.size_of_image, Some(SIZE_OF_IMAGE));
        assert_eq!(pe.size_of_headers, Some(0x400));
        assert_eq!(pe.section_alignment, Some(0x1000));
        assert_eq!(pe.file_alignment, Some(0x200));
        assert_eq!(pe.sections.len(), 1);
        let text = &pe.sections[0];
        assert_eq!(text.name, ".text");
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.raw_offset, 0x400);
        assert_eq!(text.raw_end, 0x600);
        assert!(text.raw_in_bounds);
        assert_eq!(text.backing, SectionBacking::FileBacked);
        assert_eq!(text.characteristics, 0x6000_0020);
        assert!(text.permissions.read && text.permissions.execute && text.permissions.code);
        assert!(!text.permissions.write);
        assert_eq!(
            pe.named_flags
                .iter()
                .map(|flag| flag.name)
                .collect::<Vec<_>>(),
            ["executable_image", "debug_stripped"]
        );
        assert!(
            pe.directories
                .iter()
                .all(|dir| dir.mapping == DirectoryMapping::Zero)
        );
    }

    #[test]
    fn directory_mappings_report_real_backing() {
        let mut data = pe32(0x1000, &sample_sections());
        let opt = PE_OFF + 24;
        let dd = opt + 96;
        // Certificate table (index 4) is a file offset outside any section.
        data[dd + 4 * 8..dd + 4 * 8 + 4].copy_from_slice(&0x900u32.to_le_bytes());
        data[dd + 4 * 8 + 4..dd + 4 * 8 + 8].copy_from_slice(&0x40u32.to_le_bytes());
        // Import (index 1) inside the declared header area but past the
        // section table end (0x400 headers are declared).
        data[dd + 8..dd + 12].copy_from_slice(&0x300u32.to_le_bytes());
        data[dd + 12..dd + 16].copy_from_slice(&0x20u32.to_le_bytes());
        let pe = inspect(&data, &InspectionLimits::default()).pe.unwrap();
        let cert = &pe.directories[4];
        assert_eq!(cert.address_space, AddressSpace::FileOffset);
        assert_eq!(cert.mapping, DirectoryMapping::FileBacked);
        assert_eq!(cert.file_offset, Some(0x900));
        let import = &pe.directories[1];
        assert_eq!(import.mapping, DirectoryMapping::HeaderBacked);
        assert_eq!(import.file_offset, Some(0x300));
    }

    #[test]
    fn raw_section_overlapping_headers_is_reported() {
        // Declared headers end at 0x400; a section raw range starting at
        // 0x300 overlaps them.
        let sections = [(".data", 0x1000, 0x1000, 0x200, 0x300, 0xC000_0040)];
        let data = pe32(0x800, &sections);
        let pe = inspect(&data, &InspectionLimits::default()).pe.unwrap();
        assert!(
            pe.sections[0]
                .anomalies
                .iter()
                .any(|anomaly| anomaly.kind == SectionAnomalyKind::RawOverlapsHeaders)
        );
    }

    #[test]
    fn raw_section_characteristics_survive_the_permission_view() {
        // 0x0200_0040 = MEM_DISCARDABLE | CNT_INITIALIZED_DATA, neither of
        // which the permission booleans represent.
        let sections = [(".data", 0x1000, 0x1000, 0x200, 0x400, 0x0200_0040)];
        let data = pe32(0x800, &sections);
        let pe = inspect(&data, &InspectionLimits::default()).pe.unwrap();
        assert_eq!(pe.sections[0].characteristics, 0x0200_0040);
        assert!(pe.sections[0].permissions.initialized_data);
        assert!(!pe.sections[0].permissions.execute);
    }

    #[test]
    fn named_dll_flags_are_declarations() {
        let mut data = pe32(0x800, &sample_sections());
        let opt = PE_OFF + 24;
        data[opt + 70..opt + 72].copy_from_slice(&0x0140_u16.to_le_bytes());
        let out = inspect(&data, &InspectionLimits::default());
        let pe = out.pe.unwrap();
        let flags: Vec<&str> = pe.named_flags.iter().map(|flag| flag.name).collect();
        assert!(flags.contains(&"dynamic_base_aslr_declared"));
        assert!(flags.contains(&"nx_compat_declared"));
        assert_eq!(pe.dll_characteristics, Some(0x0140));
    }

    #[test]
    fn positions_scanned_is_real_scan_effort_not_a_candidate_count() {
        // PE32: the locator scans a bounded 4-byte-stepped window, so the count
        // is in the thousands even though only two candidates exist.
        let data = protected(0x3000, 0x4000);
        let protection = inspect(&data, &InspectionLimits::default())
            .protection
            .unwrap();
        let positions = protection.discovery.positions_scanned;
        assert!(positions > 8, "PE32 scan positions = {positions}");
        assert!(
            positions as usize >= protection.discovery.candidates.len(),
            "scan effort cannot be below the reported candidates"
        );

        // PE32+: the same field counts anchor-scan dwords.
        let prefix = 0x3000usize;
        let mut plain = vec![0u8; prefix];
        let anchor = 0x2100usize;
        primitives::write_u32(&mut plain, anchor as u32, 0x20_0000);
        primitives::write_u32(&mut plain, anchor as u32 + 8, 0x20_0C00);
        primitives::write_u32(&mut plain, (anchor + 120) as u32, 0x20_2000);
        primitives::write_u32(&mut plain, (anchor + 124) as u32, 0x40);
        let data = protected_pe64(prefix, &plain);
        let protection = inspect(&data, &InspectionLimits::default())
            .protection
            .unwrap();
        // Scan starts at (info[6]-info[3])+0x1000 = 0x2000; the anchor at 0x2100
        // is the 65th word examined (0x100/4 + 1), and the loop stops there.
        assert_eq!(protection.discovery.positions_scanned, 0x41);
        assert_eq!(protection.discovery.candidates.len(), 1);
    }

    #[test]
    fn declared_section_count_is_capped_before_pairwise_work() {
        // 65535 sections all claiming the same virtual and raw range: the
        // uncapped pairwise sweep would do ~2.1e9 comparisons. The cap must
        // apply before any pair processing.
        let count = u16::MAX;
        let mut data = pe32(0x400, &[]);
        data[PE_OFF + 6..PE_OFF + 8].copy_from_slice(&count.to_le_bytes());
        let table = SECTION_TABLE;
        let needed = table + count as usize * 40;
        data.resize(needed, 0);
        for index in 0..count as usize {
            let at = table + index * 40;
            data[at..at + 5].copy_from_slice(b".text");
            data[at + 8..at + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            data[at + 12..at + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            data[at + 16..at + 20].copy_from_slice(&0x1000u32.to_le_bytes());
            data[at + 20..at + 24].copy_from_slice(&0x400u32.to_le_bytes());
            data[at + 36..at + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        }
        let out = inspect(&data, &InspectionLimits::default());
        let pe = out.pe.expect("headers parse");
        assert_eq!(pe.sections.len(), MAX_SECTIONS as usize);
        assert!(
            out.issues
                .iter()
                .any(|issue| issue.message.contains("sections declared")),
            "truncation must be stated, not silent"
        );
    }

    #[test]
    fn section_anomalies_name_real_problems() {
        let mut data = pe32(0x600, &sample_sections());
        // Entry point lies in the zero-filled tail (raw size is 0x200).
        let opt = PE_OFF + 24;
        data[opt + 16..opt + 20].copy_from_slice(&0x1200_u32.to_le_bytes());
        let out = inspect(&data, &InspectionLimits::default());
        let pe = out.pe.unwrap();
        let text = &pe.sections[0];
        assert_eq!(text.backing, SectionBacking::FileBacked);
        assert_eq!(pe.entry_point_file_offset, None);
        assert_eq!(pe.entry_point_available, Some(false));
        assert!(
            text.anomalies
                .iter()
                .any(|anomaly| anomaly.kind == SectionAnomalyKind::EntryPointInside)
        );
    }

    #[test]
    fn raw_past_eof_is_reported_not_hidden() {
        let sections = [(".text", 0x3000, 0x1000, 0x3000, 0x400, 0x6000_0020)];
        let data = pe32(0x600, &sections);
        let pe = inspect(&data, &InspectionLimits::default()).pe.unwrap();
        let text = &pe.sections[0];
        assert!(!text.raw_in_bounds);
        assert_eq!(text.raw_end, 0x3400);
        assert_eq!(
            text.backing,
            SectionBacking::RawTruncated { available: 0x200 }
        );
        assert!(
            text.anomalies
                .iter()
                .any(|anomaly| anomaly.kind == SectionAnomalyKind::RawPastEof)
        );
    }

    #[test]
    fn unsectioned_ranges_cover_header_gap_gap_and_overlay() {
        let sections = [
            (".text", 0x1000, 0x1000, 0x200, 0x400, 0x6000_0020),
            (".data", 0x1000, 0x2000, 0x200, 0x700, 0xC000_0040),
        ];
        let data = pe32(0xA00, &sections);
        let pe = inspect(&data, &InspectionLimits::default()).pe.unwrap();
        let section_table_end = (SECTION_TABLE + 2 * 40) as u64;
        assert_eq!(SECTION_TABLE, 0x178);
        assert_eq!(
            pe.unsectioned,
            vec![
                FileRegion {
                    offset: section_table_end,
                    length: 0x400 - section_table_end,
                    kind: FileRegionKind::HeadersToFirstSection
                },
                FileRegion {
                    offset: 0x600,
                    length: 0x100,
                    kind: FileRegionKind::BetweenSections
                }
            ]
        );
        // .text raw is [0x400,0x600), .data raw is [0x700,0x900): a gap.
        assert!(pe.unsectioned.iter().any(|region| {
            region.kind == FileRegionKind::BetweenSections
                && region.offset == 0x600
                && region.length == 0x100
        }));
        assert_eq!(
            pe.overlay,
            Some(FileRegion {
                offset: 0x900,
                length: 0x100,
                kind: FileRegionKind::Overlay
            })
        );
    }

    #[test]
    fn trailing_overlay_is_separate_from_interior_gaps() {
        let sections = [(".text", 0x1000, 0x1000, 0x200, 0x400, 0x6000_0020)];
        let data = pe32(0xA00, &sections);
        let pe = inspect(&data, &InspectionLimits::default()).pe.unwrap();
        assert_eq!(
            pe.overlay,
            Some(FileRegion {
                offset: 0x600,
                length: 0x400,
                kind: FileRegionKind::Overlay
            })
        );
        assert!(pe.unsectioned.iter().all(|region| region.offset != 0x600));
    }

    #[test]
    fn truncated_section_table_keeps_partial_pe_findings() {
        let mut data = pe32(0x800, &sample_sections());
        // Cut inside the section table: the optional header still parses, but
        // the full 40-byte entry does not.
        data.truncate(SECTION_TABLE + 8);
        let out = inspect(&data, &InspectionLimits::default());
        assert!(out.pe.is_none());
        assert!(out.protection.is_none());
        assert!(
            out.issues
                .iter()
                .any(|issue| issue.area == "pe" && issue.severity == InspectionSeverity::Warning)
        );
    }

    #[test]
    fn unrecognized_magic_reports_words_but_runs_no_probe() {
        let mut data = protected(0x3000, 0x4000);
        let mut info = [0u32; 8];
        primitives::decrypt_data1(&data, &mut info);
        // Coherent payload descriptor, but the magic is not supported.
        info[1] = 0x4E4E_4F4B ^ 0x0101_0101;
        let mut key = info[0];
        primitives::write_u32(&mut data, 0x1000, key);
        for i in 0..7u32 {
            let cell = info[(i + 1) as usize] ^ key;
            primitives::write_u32(&mut data, 0x1004 + i * 4, cell);
            key = i.wrapping_mul(i) ^ (key.wrapping_add(cell).wrapping_sub(i));
        }
        let protection = inspect(&data, &InspectionLimits::default())
            .protection
            .expect("words still reported");
        assert!(!protection.magic_recognized);
        assert_eq!(protection.header_words.len(), 8);
        assert_eq!(protection.probe.status, ProbeOutcome::Unavailable);
        assert!(protection.discovery.candidates.is_empty());
        assert_eq!(protection.discovery.status, ProbeOutcome::Unavailable);
    }

    #[test]
    fn malformed_large_pe_offset_with_coherent_header_does_not_panic() {
        let mut data = protected(0x3000, 0x4000);
        // e_lfanew far past the file while the protection table stays valid.
        data[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        let out = inspect(&data, &InspectionLimits::default());
        assert!(out.pe.is_none());
        let protection = out.protection.expect("header table is independent of PE");
        assert_eq!(protection.payload, None);
        assert_eq!(protection.probe.status, ProbeOutcome::Unavailable);
        assert_eq!(protection.discovery.status, ProbeOutcome::Unavailable);

        // A crafted PE offset that still points at bytes shaped like a PE must
        // not drive discovery either.
        let mut data = protected(0x3000, 0x4000);
        let crafted = data.len() as u32 - 0x20;
        data[0x3C..0x40].copy_from_slice(&crafted.to_le_bytes());
        data[crafted as usize..crafted as usize + 4].copy_from_slice(b"PE\0\0");
        let out = inspect(&data, &InspectionLimits::default());
        assert!(out.pe.is_none());
        assert_eq!(
            out.protection.unwrap().probe.status,
            ProbeOutcome::Unavailable
        );
    }

    #[test]
    fn payload_ending_exactly_at_eof_still_decodes() {
        let prefix = 0x3000usize;
        let source = 0x1100usize;
        let file_len = source + prefix;
        let mut data = pe32(file_len, &sample_sections());
        let info = [
            0x1122_3344u32,
            MAGIC_KONN,
            0x196C,
            0x20_0000,
            0x100,
            prefix as u32,
            0x20_0000u32 + prefix as u32 - 0x2000,
            0xA0,
        ];
        let mut key = info[0];
        primitives::write_u32(&mut data, 0x1000, key);
        for i in 0..7u32 {
            let cell = info[(i + 1) as usize] ^ key;
            primitives::write_u32(&mut data, 0x1004 + i * 4, cell);
            key = i.wrapping_mul(i) ^ (key.wrapping_add(cell).wrapping_sub(i));
        }
        let protection = inspect(&data, &InspectionLimits::default())
            .protection
            .unwrap();
        assert_eq!(protection.probe.status, ProbeOutcome::Decoded);
        // The fixture declares total == prefix and ends at EOF, so there is no
        // raw tail: the scratch span is the decoded prefix itself.
        assert_eq!(protection.probe.prefix_bytes, prefix as u64);
        assert_eq!(protection.probe.tail_bytes, 0);
        assert_eq!(protection.probe.decoded_length, prefix as u64);
        assert_eq!(protection.probe.requested_length, prefix as u64);
    }

    #[test]
    fn garbage_input_returns_an_explained_empty_result() {
        for data in [&b""[..], b"MZ", &[0xAAu8; 64][..]] {
            let out = inspect(data, &InspectionLimits::default());
            assert_eq!(out.input_len, data.len() as u64);
            assert!(out.pe.is_none());
            assert!(out.protection.is_none());
            assert!(!out.issues.is_empty());
            assert_eq!(out.work.prefix_bytes_decoded, 0);
            assert!(!out.work.budget_limited);
        }
    }

    /// PE32 fixture with a valid header table at 0x1000 and a payload the
    /// header declares. `prefix_len` is the payload prefix and `total` the
    /// declared payload length; the file is sized to hold both, plus a 0x1000
    /// raw tail. Payload bytes are synthetic (not a real loader key), so the
    /// prefix decodes to deterministic bytes and no stage structure exists.
    fn protected(prefix_len: usize, total: u32) -> Vec<u8> {
        let source = 0x1100usize;
        let file_len = source + prefix_len + 0x1000;
        let mut data = pe32(file_len, &sample_sections());
        let info = [
            0x1122_3344u32,
            MAGIC_KONN,
            0x196C,
            0x20_0000,
            0x100,
            total,
            0x20_0000u32 + (prefix_len as u32).wrapping_sub(0x2000),
            0xA0,
        ];
        for (index, word) in info.into_iter().enumerate() {
            primitives::write_u32(&mut data, (0x1000 + index * 4) as u32, word);
        }
        // Re-encode the header cells the same way `decrypt_data1` reads them.
        let mut key = info[0];
        primitives::write_u32(&mut data, 0x1000, key);
        for i in 0..7u32 {
            let cell = info[(i + 1) as usize] ^ key;
            primitives::write_u32(&mut data, 0x1004 + i * 4, cell);
            key = i.wrapping_mul(i) ^ (key.wrapping_add(cell).wrapping_sub(i));
        }
        // Source of the declared payload: info[4] + 0x1000 = 0x1100.
        let source = 0x1100usize;
        let fill = prefix_len.min(file_len.saturating_sub(source));
        for i in 0..fill {
            data[source + i] = (i % 251) as u8;
        }
        data
    }

    /// PE32+ fixture shaped like `protected`, with a caller-supplied plaintext
    /// payload prefix so an anchor/descriptor can be planted.
    fn protected_pe64(prefix_len: usize, plain: &[u8]) -> Vec<u8> {
        let source = 0x1100usize;
        let file_len = source + prefix_len + 0x1000;
        let mut data = pe32(file_len, &sample_sections());
        let opt = PE_OFF + 24;
        // PE32+ optional header: magic + ImageBase (u64) + SizeOfImage.
        data[opt..opt + 2].copy_from_slice(&0x20B_u16.to_le_bytes());
        data[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
        data[opt + 56..opt + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
        data[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());
        let info = [
            0x1122_3344u32,
            MAGIC_KONN,
            0x196C,
            0x20_0000,
            0x100,
            prefix_len as u32,
            0x20_0000u32 + (prefix_len as u32).wrapping_sub(0x2000),
            0xA0,
        ];
        let mut key = info[0];
        primitives::write_u32(&mut data, 0x1000, key);
        for i in 0..7u32 {
            let cell = info[(i + 1) as usize] ^ key;
            primitives::write_u32(&mut data, 0x1004 + i * 4, cell);
            key = i.wrapping_mul(i) ^ (key.wrapping_add(cell).wrapping_sub(i));
        }
        encode_prefix(&mut data, &info, plain);
        data
    }

    #[test]
    fn pe32_plus_anchor_and_stage1_descriptor_are_reported() {
        let prefix = 0x3000usize;
        let mut plain = vec![0u8; prefix];
        // The anchor scan starts at info[6]-info[3]+0x1000 = 0x2000.
        let anchor = 0x2100usize;
        primitives::write_u32(&mut plain, anchor as u32, 0x20_0000);
        // `anchor+8` must be an absolute RVA below info[6], with a 0x200-aligned
        // distance to it, and must not itself look like an anchor.
        primitives::write_u32(&mut plain, anchor as u32 + 8, 0x20_0C00);
        // Stage1 descriptor at anchor+120: (start, length), in image.
        primitives::write_u32(&mut plain, (anchor + 120) as u32, 0x20_2000);
        primitives::write_u32(&mut plain, (anchor + 124) as u32, 0x40);
        let data = protected_pe64(prefix, &plain);
        let out = inspect(&data, &InspectionLimits::default());
        let pe = out.pe.expect("PE32+ parses");
        assert_eq!(pe.format, Some(TargetFormat::Pe32Plus));
        let protection = out.protection.unwrap();
        assert_eq!(protection.probe.status, ProbeOutcome::Decoded);
        let candidate = protection
            .discovery
            .candidates
            .iter()
            .find(|candidate| candidate.kind == ShellCandidateKind::Pe32PlusAnchor)
            .expect("anchor candidate");
        assert_eq!(candidate.payload_offset, Some(anchor as u64));
        assert_eq!(candidate.image_rva, Some(0x20_0000 + anchor as u32));
        assert_eq!(candidate.status, CandidateStatus::StructuralCandidate);
        let field = |name: &str| {
            candidate
                .fields
                .iter()
                .find(|field| field.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
        };
        assert_eq!(field("stage1_start").value, 0x20_2000);
        assert_eq!(field("stage1_length").value, 0x40);
        assert_eq!(
            field("stage1_start").space,
            Some(AddressSpace::WorkingImageRva)
        );
    }

    #[test]
    fn header_words_decode_with_source_offsets_and_verified_semantics() {
        let data = protected(0x3000, 0x4000);
        let protection = inspect(&data, &InspectionLimits::default())
            .protection
            .expect("table present");
        assert!(protection.magic_recognized);
        assert_eq!(protection.magic, Some(MAGIC_KONN));
        assert_eq!(protection.header_words.len(), 8);
        let words: Vec<u32> = protection
            .header_words
            .iter()
            .map(|word| word.decoded_word)
            .collect();
        assert_eq!(
            words,
            vec![
                0x1122_3344,
                MAGIC_KONN,
                0x196C,
                0x20_0000,
                0x100,
                0x4000,
                0x20_0000 + 0x1000,
                0xA0
            ]
        );
        for (index, word) in protection.header_words.iter().enumerate() {
            assert_eq!(word.index, index as u8);
            assert_eq!(word.source_file_offset, (0x1000 + index * 4) as u64);
        }
        assert_eq!(
            protection.header_words[1].semantic,
            Some(HeaderWordSemantic::Magic)
        );
        assert_eq!(
            protection.header_words[3].semantic,
            Some(HeaderWordSemantic::DestinationRva)
        );
        assert_eq!(
            protection.header_words[4].semantic,
            Some(HeaderWordSemantic::PayloadSource)
        );
        assert_eq!(
            protection.header_words[5].semantic,
            Some(HeaderWordSemantic::TotalLength)
        );
        assert_eq!(
            protection.header_words[6].semantic,
            Some(HeaderWordSemantic::EndMarker)
        );
        // Not used semantically by the pipeline, so no invented name.
        assert_eq!(protection.header_words[2].semantic, None);
        assert_eq!(protection.header_words[7].semantic, None);
    }

    #[test]
    fn declared_payload_checks_use_each_space() {
        let data = protected(0x3000, 0x4000);
        let protection = inspect(&data, &InspectionLimits::default())
            .protection
            .unwrap();
        let payload = protection.payload.expect("payload");
        assert_eq!(payload.source_file_offset, 0x1100);
        assert_eq!(payload.destination_rva, 0x20_0000);
        assert_eq!(payload.prefix_length, 0x3000);
        assert_eq!(payload.total_length, 0x4000);
        let names: Vec<&str> = payload.checks.iter().map(|check| check.name).collect();
        assert_eq!(
            names,
            [
                "declared_prefix",
                "source_prefix",
                "declared_payload",
                "source_raw_tail"
            ]
        );
        // The fixture is sized to hold the source prefix and raw tail, so
        // every declared range is in bounds and the probe decodes it.
        assert!(payload.checks.iter().all(|check| check.in_bounds));
        assert_eq!(protection.probe.status, ProbeOutcome::Decoded);
    }

    #[test]
    fn zero_and_overflow_descriptors_do_not_panic() {
        // size_of_image = 0.
        let mut data = protected(0x3000, 0x4000);
        let opt = PE_OFF + 24;
        data[opt + 56..opt + 60].copy_from_slice(&0u32.to_le_bytes());
        let out = inspect(&data, &InspectionLimits::default());
        assert!(out.pe.is_some());

        // info[6] behind info[3]: the prefix length wraps into a huge value.
        let mut data = protected(0x3000, 0x4000);
        let mut info = [0u32; 8];
        primitives::decrypt_data1(&data, &mut info);
        info[6] = 1;
        let mut key = info[0];
        primitives::write_u32(&mut data, 0x1000, key);
        for i in 0..7u32 {
            let cell = info[(i + 1) as usize] ^ key;
            primitives::write_u32(&mut data, 0x1004 + i * 4, cell);
            key = i.wrapping_mul(i) ^ (key.wrapping_add(cell).wrapping_sub(i));
        }
        let out = inspect(&data, &InspectionLimits::default());
        let protection = out.protection.unwrap();
        assert_eq!(protection.probe.status, ProbeOutcome::Unavailable);
        assert!(!out.work.budget_limited);
    }

    #[test]
    fn prefix_probe_honours_the_scratch_budget() {
        let data = protected(0x3000, 0x4000);
        let limits = InspectionLimits {
            prefix_scratch_bytes: 0x100,
            ..InspectionLimits::default()
        };
        let out = inspect(&data, &limits);
        let protection = out.protection.unwrap();
        assert_eq!(protection.probe.status, ProbeOutcome::BudgetLimited);
        assert!(out.work.budget_limited);
        assert_eq!(out.work.prefix_bytes_decoded, 0);
    }

    #[test]
    fn candidate_list_honours_the_candidate_cap() {
        let data = protected(0x3000, 0x4000);
        let full = inspect(&data, &InspectionLimits::default());
        let limits = InspectionLimits {
            max_candidates: 1,
            ..InspectionLimits::default()
        };
        let capped = inspect(&data, &limits);
        if let (Some(full), Some(capped)) = (full.protection, capped.protection) {
            assert!(capped.discovery.candidates.len() <= 1);
            assert!(capped.discovery.candidates.len() <= full.discovery.candidates.len());
        }
    }

    #[test]
    fn issue_list_is_bounded() {
        let data = vec![0u8; 8];
        let limits = InspectionLimits {
            max_issues: 1,
            ..InspectionLimits::default()
        };
        let out = inspect(&data, &limits);
        assert!(out.issues.len() <= 1);
    }

    /// Replace the declared payload prefix with an encoded plaintext scratch.
    /// `plain` is indexed from `info[3]`; the test-only encoder is the inverse
    /// of the prefix recurrence in `decode_payload_scratch`.
    fn encode_prefix(data: &mut [u8], info: &[u32; 8], plain: &[u8]) {
        let source = info[4] as usize + 0x1000;
        let mut key = info[0].wrapping_add(!((plain.len() as u32) & !3));
        let words = (plain.len() / 4) as u32;
        for i in 0..words {
            let off = (i * 4) as usize;
            let word = primitives::get_u32(plain, off as u32);
            let cell = word ^ key;
            data[source + off..source + off + 4].copy_from_slice(&cell.to_le_bytes());
            key = i.wrapping_mul(i) ^ (key.wrapping_add(cell).wrapping_add(i));
        }
    }

    #[test]
    fn synthetic_pe32_shell_table_is_a_structural_candidate() {
        let mut data = protected(0x3000, 0x4000);
        let mut info = [0u32; 8];
        primitives::decrypt_data1(&data, &mut info);
        // Standard (non-compact) shell table whose `+0x88` field is the shell
        // marker, placed at/after the declared shell start (`info[6]-info[3]`,
        // the locator's lower bound for a table candidate).
        let shell_start = (info[6] - info[3]) as usize;
        let table = shell_start + 0x200;
        let marker = table + 0x88;
        let mut plain = vec![0u8; 0x3000];
        for (offset, value) in [
            (marker, info[6]),
            (marker + 4, 0x1800u32),
            (table + 0x58, 0x1E0u32),
            (table + 0x5C, 0x40u32),
            (table + 0x98, 0x20_2000u32),
            (table + 0x9C, 4u32),
            (table + 0xA8, 0x20_2000u32),
            (table + 0xAC, 0x80u32),
        ] {
            if offset + 4 <= plain.len() {
                primitives::write_u32(&mut plain, offset as u32, value);
            }
        }
        encode_prefix(&mut data, &info, &plain);
        let out = inspect(&data, &InspectionLimits::default());
        let protection = out.protection.unwrap();
        assert_eq!(protection.probe.status, ProbeOutcome::Decoded);
        let candidate = protection
            .discovery
            .candidates
            .iter()
            .find(|candidate| candidate.payload_offset == Some(table as u64))
            .expect("synthetic table must be found");
        assert_eq!(candidate.kind, ShellCandidateKind::Pe32ShellTable);
        assert_eq!(candidate.status, CandidateStatus::StructuralCandidate);
        assert_eq!(candidate.payload_offset, Some(table as u64));
        assert_eq!(candidate.image_rva, Some(0x20_0000 + table as u32));
        assert_eq!(candidate.source_file_offset, Some(0x1100 + table as u64));
        for (name, value) in [
            ("compact_layout", 0),
            ("header_start", 0x1E0),
            ("header_size", 0x40),
            ("stage_descriptor_start", 0x20_2000),
            ("stage_descriptor_size", 4),
            ("checksum_start", 0x20_2000),
            ("checksum_size", 0x80),
        ] {
            assert!(
                candidate
                    .fields
                    .iter()
                    .any(|field| field.name == name && field.value == value),
                "missing {name}=0x{value:X}: {:?}",
                candidate.fields
            );
        }
        let header = candidate
            .fields
            .iter()
            .find(|field| field.name == "header_start")
            .unwrap();
        assert_eq!(header.space, Some(AddressSpace::WorkingImageRva));
        let header_size = candidate
            .fields
            .iter()
            .find(|field| field.name == "header_size")
            .unwrap();
        assert_eq!(header_size.space, None, "a size is not an address");
        // The descriptor's absolute RVA 0x202000 is offset 0x2000 from the
        // payload base 0x200000, inside the 0x3000 decoded prefix.
        assert!(
            candidate
                .fields
                .iter()
                .all(|field| field.name != "stage_beyond_prefix"),
            "stage descriptor is inside the decoded prefix"
        );
        assert!(
            candidate
                .reason
                .contains("shape matches the declared image")
        );
    }

    #[test]
    fn serialized_inspection_is_stable_snake_case() {
        let data = pe32(0x800, &sample_sections());
        let out = inspect(&data, &InspectionLimits::default());
        let value = serde_json::to_value(&out).expect("serializes");
        assert_eq!(value["pe"]["format"], "pe32");
        assert_eq!(value["pe"]["kind"], "native_exe");
        assert_eq!(value["pe"]["sections"][0]["backing"], "file_backed");
        assert_eq!(
            value["pe"]["named_flags"][0]["field"],
            "coff_characteristics"
        );
        assert_eq!(
            value["work"]["prefix_scratch_limit"],
            DEFAULT_PREFIX_SCRATCH_BYTES
        );
        assert!(value.get("protection").is_none());
    }

    #[test]
    fn inspection_never_selects_or_recovers() {
        let data = protection_like();
        let out = inspect(&data, &InspectionLimits::default());
        // No field in the inspection claim recovery: this is a structural
        // assertion — the type has no selected/recovery field at all.
        let value = serde_json::to_value(&out).unwrap();
        assert!(value.get("selected").is_none());
        assert!(value.get("recovery").is_none());
    }

    fn protection_like() -> Vec<u8> {
        protected(0x3000, 0x4000)
    }
}
