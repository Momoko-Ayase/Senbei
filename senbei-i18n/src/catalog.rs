//! Every localizable string Senbei shows, as typed values.
//!
//! The English rendering of each variant (in `en.rs`) is the wording the
//! engine and the command line have always used; the other language modules
//! translate it. Adding a variant fails to compile until every language
//! renders it.

/// A message recorded in a report: an error, a warning, a stage detail, or a
/// static validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Msg {
    // -- Windows recovery -------------------------------------------------
    CompanionMissing,
    CompanionMismatch,
    InputTooShort {
        actual: usize,
        required: usize,
    },
    NotProtected,
    InvalidPeOffset {
        offset: i64,
        input_len: usize,
    },
    DllNeedsPe32Plus {
        found: u16,
    },
    LayoutUnsupported,
    InternalPanic {
        file: String,
        line: u32,
        column: u32,
        message: String,
    },
    /// An internal decode failure. The recorded English names the specific
    /// table or stage; other languages show this summary with that English
    /// as technical detail.
    DecodeFailed,

    // -- Input formats ----------------------------------------------------
    NotPe,
    NotElf64,
    NotAarch64,
    /// Structural metadata transform wording (`il2cpp`).
    NotMetadata,
    /// Android metadata wording (`IL2CPP`).
    NotIl2cppMetadata,
    UnsupportedMetadataVersion {
        version: u32,
    },
    /// A metadata transform failure. The recorded English names the check.
    MetadataTransformFailed,

    // -- Android resource limits ------------------------------------------
    LimitEntry {
        requested: u64,
        limit: u64,
    },
    LimitTotal {
        requested: u64,
        adding: u64,
        limit: u64,
    },
    LimitEntries {
        requested: usize,
        limit: usize,
    },
    LimitDepth {
        requested: usize,
        limit: usize,
    },

    // -- Driver outcomes --------------------------------------------------
    OutputNotRetained,
    DryRunDiscarded,
    TransformNoop,
    CompanionUnmatched,
    CompanionUnreadable {
        reason: String,
    },
    CompanionUnreadableUnknown,
    MetadataLeftUntouched {
        version: u32,
    },
    UnexpectedPanic {
        message: String,
    },
    InputNotExamined,
    NoCandidateValidated,
    NoModule0c,
    AmbiguousModule0c,
    UnsafePackageEntry {
        package: String,
    },
    UnsafeNestedEntry {
        path: String,
    },

    // -- Static validation of a restored PE --------------------------------
    EntryStubTargetOutsideCode {
        branch: &'static str,
        target: i64,
    },
    MissingMz,
    TruncatedDosHeader,
    MissingPeSignature {
        offset: u32,
    },
    TruncatedCoffHeader,
    TruncatedOptionalHeader,
    BadOptionalMagic {
        magic: u16,
    },
    ImplausibleSectionCount {
        count: u32,
    },
    ZeroSizeOfImage,
    SectionTablePastEof,
    SectionRawPastEof {
        index: usize,
        start: u32,
        end: usize,
        file_len: usize,
    },
    NoBaseRelocations,
    ZeroEntryPoint,
    EntryUnmapped {
        rva: u32,
    },
    EntryAllZeros {
        rva: u32,
    },
    EntryAllInt3 {
        rva: u32,
    },
    EntryNotExecutable {
        rva: u32,
    },
    ImportDirectoryUnmapped {
        rva: u32,
    },
    ImportNameUnmapped {
        index: u32,
        rva: u32,
    },
    ImportNameUnreadable {
        index: u32,
        rva: u32,
    },
    ClrDirectoryUnmapped {
        rva: u32,
    },
    ClrHeaderBadSize {
        rva: u32,
        size: u32,
    },
    ClrMetadataUnmapped {
        rva: u32,
    },
    ClrMetadataNoBsjb {
        rva: u32,
    },
}

/// One verbose progress line from a recovery pipeline.
///
/// The English wording, trailing dots included, is what `--verbose` has
/// always printed after the `[n/9]` counter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    // PE32+ EXE-style loader
    DecryptHeader,
    DecryptPayload,
    LocateConfig,
    DecryptStage2,
    DecryptStages3To5,
    DecryptSections,
    DecryptSectionsNewLayout,
    LoadSections,
    DecryptImports,
    RebuildHeaders,
    // PE32 loader
    Pe32LocateConfig,
    Pe32Stages,
    Pe32EighthStage,
    Pe32Load,
    Pe32Text { formula: &'static str },
    Pe32TextSkip,
    Pe32Imports,
    Pe32Rebuild,
    // DLL loader
    InitKeys,
    DecryptKeyTable,
    DecryptPrimary,
    RelocsParams,
    DecryptBlock1,
    DecryptBlocks2To3,
    DecryptBlock4,
    DllSections,
    FixHeaders,
    // Android staged loader
    AndroidPrimary,
    AndroidAuxiliary,
    AndroidTables,
    // Output
    WriteTo { dest: String },
}

/// A report value as the command line shows it: a status, stage, route,
/// platform, kind, or piece of evidence.
///
/// Each variant is one wire value of a report enum; [`Term::from_value`]
/// maps the JSON spelling to it. English is that spelling with spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Term {
    // statuses
    Ok,
    Suspect,
    Recognized,
    NotRecognized,
    Skipped,
    Error,
    Restored,
    Duplicate,
    NotTarget,
    Unchanged,
    Inventoried,
    Failed,
    Blocked,
    NotAttempted,
    Succeeded,
    Rejected,
    Clean,
    Warnings,
    NotRun,
    // companion states
    Absent,
    Spliced,
    Unmatched,
    Unreadable,
    // stages
    Detection,
    ManifestInventory,
    EntryProbe,
    Recovery,
    StaticValidation,
    OutputWrite,
    // entry kinds
    SharedLibrary,
    Metadata,
    // routes
    ExeStyle,
    Dll,
    AndroidStaged,
    MetadataSeeded,
    MetadataStructural,
    MetadataMethodIndices,
    // platforms
    WindowsPe,
    AndroidElf,
    Il2cppMetadata,
    // kinds
    NativeExe,
    ManagedExe,
    NativeDll,
    ManagedDll,
    // evidence
    HeaderMagic,
    ExternalCompanionDeclaration,
    CompanionSpliced,
    PrivateSection,
    AesSchedule,
    ValidatedMetadataTransform,
    // metadata layout definitions
    Known,
    ContextRequired,
    Unverified,
    // research input views
    Original,
    SplicedCompanion,
}

impl Term {
    /// The term for a report enum's JSON spelling, such as `not_attempted`.
    pub fn from_value(value: &str) -> Option<Term> {
        Some(match value {
            "ok" => Term::Ok,
            "suspect" => Term::Suspect,
            "recognized" => Term::Recognized,
            "not_recognized" => Term::NotRecognized,
            "skipped" => Term::Skipped,
            "error" => Term::Error,
            "restored" => Term::Restored,
            "duplicate" => Term::Duplicate,
            "not_target" => Term::NotTarget,
            "unchanged" => Term::Unchanged,
            "inventoried" => Term::Inventoried,
            "failed" => Term::Failed,
            "blocked" => Term::Blocked,
            "not_attempted" => Term::NotAttempted,
            "succeeded" => Term::Succeeded,
            "rejected" => Term::Rejected,
            "clean" => Term::Clean,
            "warnings" => Term::Warnings,
            "not_run" => Term::NotRun,
            "absent" => Term::Absent,
            "spliced" => Term::Spliced,
            "unmatched" => Term::Unmatched,
            "unreadable" => Term::Unreadable,
            "detection" => Term::Detection,
            "manifest_inventory" => Term::ManifestInventory,
            "entry_probe" => Term::EntryProbe,
            "recovery" => Term::Recovery,
            "static_validation" => Term::StaticValidation,
            "output_write" => Term::OutputWrite,
            "shared_library" => Term::SharedLibrary,
            "metadata" => Term::Metadata,
            "exe_style" => Term::ExeStyle,
            "dll" => Term::Dll,
            "android_staged" => Term::AndroidStaged,
            "metadata_seeded" => Term::MetadataSeeded,
            "metadata_structural" => Term::MetadataStructural,
            "metadata_method_indices" => Term::MetadataMethodIndices,
            "windows_pe" => Term::WindowsPe,
            "android_elf" => Term::AndroidElf,
            "il2cpp_metadata" => Term::Il2cppMetadata,
            "native_exe" => Term::NativeExe,
            "managed_exe" => Term::ManagedExe,
            "native_dll" => Term::NativeDll,
            "managed_dll" => Term::ManagedDll,
            "header_magic" => Term::HeaderMagic,
            "external_companion_declaration" => Term::ExternalCompanionDeclaration,
            "companion_spliced" => Term::CompanionSpliced,
            "private_section" => Term::PrivateSection,
            "aes_schedule" => Term::AesSchedule,
            "validated_metadata_transform" => Term::ValidatedMetadataTransform,
            "known" => Term::Known,
            "context_required" => Term::ContextRequired,
            "unverified" => Term::Unverified,
            "original" => Term::Original,
            "spliced_companion" => Term::SplicedCompanion,
            _ => return None,
        })
    }
}

/// Command-line wording: help, usage errors, per-file lines, summaries, and
/// the labels of the text report.
///
/// Arguments that arrive already colored (counts, paths) are strings, so a
/// translation can move them without losing the color.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cli {
    // -- severity labels and run chrome -----------------------------------
    Error,
    Warning,
    DoneIn {
        ms: u128,
    },
    PressEnter,
    ScanUnreadable {
        count: usize,
    },
    Summary {
        unpacked: String,
        skipped: String,
        errors: String,
        suspect: String,
        metadata: String,
    },
    SummaryPackages {
        packages: String,
    },
    IntegrityFailed,
    IntegrityFailedLikelyCrash,
    // -- per-file lines ---------------------------------------------------
    MetadataLine {
        rel: String,
        dest: String,
        remapped: String,
    },
    MetadataVersionLine {
        version: String,
        dest: String,
        remapped: String,
    },
    MetadataAlreadyClean {
        version: String,
    },
    MetadataNothingToDo,
    EmbeddedMetadataLine {
        input: String,
        dest: String,
    },
    EmbeddedMetadataFailed,
    MetadataUnsupportedLine {
        version: u32,
    },
    // -- usage errors -----------------------------------------------------
    OutRequiresDirectory,
    UnknownOption {
        option: String,
    },
    MultipleInputs {
        first: String,
        second: String,
    },
    SubcommandNeedsPath {
        subcommand: String,
    },
    InspectNoDryRun,
    InspectNoOut,
    DryRunNoOut,
    ColorRequiresMode,
    ThreadsRequiresInteger,
    LimitRequiresInteger {
        flag: String,
    },
    LimitMustBePositive {
        flag: String,
    },
    LimitTooLarge {
        flag: String,
    },
    UnknownLimit {
        flag: String,
    },
    // -- help -------------------------------------------------------------
    HelpPath,
    HelpInspect,
    HelpUnpack,
    HelpJson,
    HelpDryRun,
    HelpThreads,
    HelpColor,
    HelpScanAll,
    HelpStrictIntegrity,
    HelpLimits {
        entry_mib: u64,
        total_mib: u64,
        entries: usize,
        depth: usize,
    },
    HelpExitCodes,
    /// `SENBEI_LANG`: the display language and what stays English.
    HelpLanguage,
    // -- text report ------------------------------------------------------
    ReportScanHeading,
    ReportScan {
        skipped: usize,
        walk_errors: usize,
        probe_errors: usize,
    },
    ReportScanIncomplete,
    AnalysisIncomplete,
    AnalysisIncompleteInput,
    AnalysisIncompleteEntry,
    Source {
        size: u64,
    },
    Target {
        platform: String,
        format: String,
        kind: String,
    },
    FormatUnavailable,
    KindUnavailable,
    ProtectionRecognition {
        status: String,
    },
    Evidence {
        evidence: String,
    },
    Route {
        route: String,
        outcome: String,
    },
    SelectedRoute {
        route: String,
    },
    StaticRecovery {
        status: String,
    },
    OutputValidation {
        status: String,
    },
    Companion {
        state: String,
    },
    CompanionIdentity {
        size: u64,
        sha256: String,
    },
    InputView {
        view: String,
    },
    InputViewSplicedNote,
    MetadataIdentity {
        version: u32,
        layout: String,
    },
    SeededTokens {
        value: bool,
    },
    StructuralTokens {
        value: bool,
    },
    MethodIndexRestore {
        value: bool,
        context: bool,
    },
    Container {
        kind: String,
        entries: usize,
        manifests: usize,
    },
    Manifest {
        source: String,
        package: String,
        version: String,
    },
    Unnamed,
    Candidate {
        entry: String,
    },
    MetadataEvidence,
    Entry {
        name: String,
        status: String,
    },
    EntryRoute {
        route: String,
    },
    EntryMetadataVersion {
        version: u32,
    },
    EntryRemapped {
        remapped: usize,
    },
    ModuleContextSource {
        source: String,
    },
    StageLine {
        stage: String,
        status: String,
    },
    Recovered {
        size: u64,
        sha256: String,
    },
    InspectionStatus {
        status: String,
        ms: u64,
    },
    DiagnosticWarning,
    DiagnosticError,
    DiagnosticReason,
    DiagnosticDetail,
    DiagnosticEnglish,
}
