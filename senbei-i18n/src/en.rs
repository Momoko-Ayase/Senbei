//! English: the wording Senbei has always produced. Every other language
//! translates these strings; reports, logs, and JSON keep them verbatim.

use std::borrow::Cow;

use crate::{Cli, Msg, Step, Term};

pub(crate) fn msg(msg: &Msg) -> Cow<'static, str> {
    match msg {
        Msg::CompanionMissing => "Companion missing? This loader expects a matching <input>._ payload. Keep it beside the input file (or add both files in the browser) and try again.".into(),
        Msg::CompanionMismatch => "Companion doesn't match: the supplied ._ payload is too short or its header differs from the loader's. Use the companion from the same build; either file may be damaged.".into(),
        Msg::InputTooShort { actual, required } => format!("input too short (need at least {required} bytes, got {actual})").into(),
        Msg::NotProtected => "not a CrackProof-protected file".into(),
        Msg::InvalidPeOffset { offset, input_len } => format!("invalid PE header offset {offset} for {input_len}-byte input").into(),
        Msg::DllNeedsPe32Plus { found } => format!("DLL pipeline requires PE32+ optional-header magic, got 0x{found:04X}").into(),
        Msg::LayoutUnsupported => "stage5 marker not found — this build's layout is not supported by this unpacker".into(),
        Msg::InternalPanic { file, line, column, message } => format!("internal panic at {file}:{line}:{column}: {message}").into(),
        Msg::DecodeFailed => "the protected data did not decode as expected; the file may be damaged, or this build's layout is not supported".into(),
        Msg::NotPe => "input is not a PE image".into(),
        Msg::NotElf64 => "input is not an ELF64 little-endian image".into(),
        Msg::NotAarch64 => "input is not an AArch64 image".into(),
        Msg::NotMetadata => "not an il2cpp global-metadata.dat".into(),
        Msg::NotIl2cppMetadata => "not an IL2CPP global-metadata.dat".into(),
        Msg::UnsupportedMetadataVersion { version } => format!("unsupported metadata version {version}").into(),
        Msg::MetadataTransformFailed => "the metadata transform did not validate".into(),
        Msg::LimitEntry { requested, limit } => format!("resource limit: entry of {requested} bytes exceeds the {limit}-byte ceiling").into(),
        Msg::LimitTotal { requested, adding, limit } => format!("resource limit: task total of {requested} bytes exceeds the {limit}-byte ceiling (adding {adding} bytes)").into(),
        Msg::LimitEntries { requested, limit } => format!("resource limit: {requested} entries exceed the ceiling of {limit}").into(),
        Msg::LimitDepth { requested, limit } => format!("resource limit: nesting depth {requested} exceeds the ceiling of {limit}").into(),
        Msg::OutputNotRetained => "research inspection: no output file was retained".into(),
        Msg::DryRunDiscarded => "dry run: the produced output was discarded".into(),
        Msg::TransformNoop => "the transform ran and validated; nothing needed rewriting".into(),
        Msg::CompanionUnmatched => "a sibling `._` exists but is not this stub's payload".into(),
        Msg::CompanionUnreadable { reason } => format!("the sibling `._` could not be read: {reason}").into(),
        Msg::CompanionUnreadableUnknown => "the sibling `._` could not be read".into(),
        Msg::MetadataLeftUntouched { version } => format!("unsupported metadata version {version}, left untouched").into(),
        Msg::UnexpectedPanic { message } => format!("unexpected panic: {message}").into(),
        Msg::InputNotExamined => "input could not be examined".into(),
        Msg::NoCandidateValidated => "no candidate validated".into(),
        Msg::NoModule0c => "no module 0x0C for v24.1 metadata".into(),
        Msg::AmbiguousModule0c => "ambiguous module 0x0C binding".into(),
        Msg::UnsafePackageEntry { package } => format!("unsafe entry path in package `{package}`").into(),
        Msg::UnsafeNestedEntry { path } => format!("unsafe entry path in `{path}`").into(),
        Msg::EntryStubTargetOutsideCode { branch, target } => format!("entry point {branch} target 0x{target:X} is outside executable sections (DD8 selection is likely wrong)").into(),
        Msg::MissingMz => "missing 'MZ' DOS signature".into(),
        Msg::TruncatedDosHeader => "truncated DOS header (no e_lfanew)".into(),
        Msg::MissingPeSignature { offset } => format!("missing 'PE\\0\\0' signature at 0x{offset:X}").into(),
        Msg::TruncatedCoffHeader => "truncated COFF header".into(),
        Msg::TruncatedOptionalHeader => "truncated optional header".into(),
        Msg::BadOptionalMagic { magic } => format!("bad optional-header magic 0x{magic:X}").into(),
        Msg::ImplausibleSectionCount { count } => format!("implausible section count {count}").into(),
        Msg::ZeroSizeOfImage => "SizeOfImage is zero".into(),
        Msg::SectionTablePastEof => "section table extends past end of file".into(),
        Msg::SectionRawPastEof { index, start, end, file_len } => format!("section #{index} raw data [0x{start:X}..0x{end:X}] exceeds file size 0x{file_len:X}").into(),
        Msg::NoBaseRelocations => "native DLL has no base relocation table (DD[5] is zero) — will crash when loaded at a non-preferred base".into(),
        Msg::ZeroEntryPoint => "entry point RVA is zero".into(),
        Msg::EntryUnmapped { rva } => format!("entry point RVA 0x{rva:X} does not map into any section").into(),
        Msg::EntryAllZeros { rva } => format!("entry point at RVA 0x{rva:X} is all zeros (stub not recovered)").into(),
        Msg::EntryAllInt3 { rva } => format!("entry point at RVA 0x{rva:X} is all int3 padding (stub not recovered)").into(),
        Msg::EntryNotExecutable { rva } => format!("entry point RVA 0x{rva:X} is not in an executable section").into(),
        Msg::ImportDirectoryUnmapped { rva } => format!("import directory RVA 0x{rva:X} does not map into any section").into(),
        Msg::ImportNameUnmapped { index, rva } => format!("import descriptor {index} DLL name RVA 0x{rva:X} does not map into any section").into(),
        Msg::ImportNameUnreadable { index, rva } => format!("import descriptor {index} DLL name at RVA 0x{rva:X} is not readable ASCII (imports left encrypted?)").into(),
        Msg::ClrDirectoryUnmapped { rva } => format!("CLR (COR20) directory RVA 0x{rva:X} does not map into any section").into(),
        Msg::ClrHeaderBadSize { rva, size } => format!("COR20 header at RVA 0x{rva:X} has cb 0x{size:X} (expected 0x48) — CLR header corrupt").into(),
        Msg::ClrMetadataUnmapped { rva } => format!("CLR MetaData RVA 0x{rva:X} does not map into any section").into(),
        Msg::ClrMetadataNoBsjb { rva } => format!("CLR MetaData at RVA 0x{rva:X} lacks 'BSJB' signature (metadata corrupt — managed image will not load)").into(),
    }
}

pub(crate) fn step(step: &Step) -> Cow<'static, str> {
    match step {
        Step::DecryptHeader => "Decrypting file header...".into(),
        Step::DecryptPayload => "Decrypting payload...".into(),
        Step::LocateConfig => "Locating config layout...".into(),
        Step::DecryptStage2 => "Decrypting stage2...".into(),
        Step::DecryptStages3To5 => "Decrypting stages 3-5...".into(),
        Step::DecryptSections => "Decrypting section data...".into(),
        Step::DecryptSectionsNewLayout => "Decrypting section data (new layout)...".into(),
        Step::LoadSections => "Loading and decompressing sections...".into(),
        Step::DecryptImports => "Decrypting import strings...".into(),
        Step::RebuildHeaders => "Reconstructing PE headers...".into(),
        Step::Pe32LocateConfig => "Locating config layout (PE32)...".into(),
        Step::Pe32Stages => "Decrypting stages (PE32)...".into(),
        Step::Pe32EighthStage => "Decrypting eighthStage (PE32)...".into(),
        Step::Pe32Load => "Loading and decompressing file data (PE32)...".into(),
        Step::Pe32Text { formula } => {
            format!("Decrypting .text (PE32 dd8, formula={formula})...").into()
        }
        Step::Pe32TextSkip => "Skipping .text dd8 (already plaintext)...".into(),
        Step::Pe32Imports => "Decrypting import strings (PE32)...".into(),
        Step::Pe32Rebuild => "Rebuilding PE file layout (PE32)...".into(),
        Step::InitKeys => "Initializing keys...".into(),
        Step::DecryptKeyTable => "Decrypting key table...".into(),
        Step::DecryptPrimary => "Decrypting primary descriptor...".into(),
        Step::RelocsParams => "Processing relocations & decomp params...".into(),
        Step::DecryptBlock1 => "Decrypting code block 1 (addr3)...".into(),
        Step::DecryptBlocks2To3 => "Decrypting code blocks 2-3 (addr3b, addr4)...".into(),
        Step::DecryptBlock4 => "Decrypting code block 4 (addr5)...".into(),
        Step::DllSections => "Decrypting & decompressing sections...".into(),
        Step::FixHeaders => "Fixing up PE header & section table...".into(),
        Step::AndroidPrimary => "Decoding primary 0x9D target-image container...".into(),
        Step::AndroidAuxiliary => "Decoding auxiliary 0x9D ELF materialization container...".into(),
        Step::AndroidTables => "Rebuilding static ELF dynamic-linker tables...".into(),
        Step::WriteTo { dest } => format!("Write to {dest}").into(),
    }
}

pub(crate) fn term(term: &Term) -> Cow<'static, str> {
    match term {
        Term::Ok => "ok",
        Term::Suspect => "suspect",
        Term::Recognized => "recognized",
        Term::NotRecognized => "not recognized",
        Term::Skipped => "skipped",
        Term::Error => "error",
        Term::Restored => "restored",
        Term::Duplicate => "duplicate",
        Term::NotTarget => "not target",
        Term::Unchanged => "unchanged",
        Term::Inventoried => "inventoried",
        Term::Failed => "failed",
        Term::Blocked => "blocked",
        Term::NotAttempted => "not attempted",
        Term::Succeeded => "succeeded",
        Term::Rejected => "rejected",
        Term::Clean => "clean",
        Term::Warnings => "warnings",
        Term::NotRun => "not run",
        Term::Absent => "absent",
        Term::Spliced => "spliced",
        Term::Unmatched => "unmatched",
        Term::Unreadable => "unreadable",
        Term::Detection => "detection",
        Term::ManifestInventory => "manifest inventory",
        Term::EntryProbe => "entry probe",
        Term::Recovery => "recovery",
        Term::StaticValidation => "static validation",
        Term::OutputWrite => "output write",
        Term::SharedLibrary => "shared library",
        Term::Metadata => "metadata",
        Term::ExeStyle => "exe style",
        Term::Dll => "dll",
        Term::AndroidStaged => "android staged",
        Term::MetadataSeeded => "metadata seeded",
        Term::MetadataStructural => "metadata structural",
        Term::MetadataMethodIndices => "metadata method indices",
        Term::WindowsPe => "windows pe",
        Term::AndroidElf => "android elf",
        Term::Il2cppMetadata => "il2cpp metadata",
        Term::NativeExe => "native exe",
        Term::ManagedExe => "managed exe",
        Term::NativeDll => "native dll",
        Term::ManagedDll => "managed dll",
        Term::HeaderMagic => "header magic",
        Term::ExternalCompanionDeclaration => "external companion declaration",
        Term::CompanionSpliced => "companion spliced",
        Term::PrivateSection => "private section",
        Term::AesSchedule => "aes schedule",
        Term::ValidatedMetadataTransform => "validated metadata transform",
        Term::Known => "known",
        Term::ContextRequired => "context required",
        Term::Unverified => "unverified",
        Term::Original => "original",
        Term::SplicedCompanion => "spliced companion",
    }
    .into()
}

pub(crate) fn cli(cli: &Cli) -> Cow<'static, str> {
    match cli {
        Cli::Error => "error".into(),
        Cli::Warning => "warning".into(),
        Cli::DoneIn { ms } => format!("done in {ms} ms").into(),
        Cli::PressEnter => "\nPress Enter to exit…".into(),
        Cli::ScanUnreadable { count } => format!("{count} file(s) could not be read during the scan and may be missed targets").into(),
        Cli::Summary { unpacked, skipped, errors, suspect, metadata } => format!("{unpacked} unpacked · {skipped} skipped · {errors} errors · {suspect} suspect · {metadata} metadata").into(),
        Cli::SummaryPackages { packages } => format!(" · {packages} packages").into(),
        Cli::IntegrityFailed => "integrity check failed".into(),
        Cli::IntegrityFailedLikelyCrash => "! integrity check failed (likely to crash at runtime)".into(),
        Cli::MetadataLine { rel, dest, remapped } => format!("metadata  {rel}  ->  {dest}  ({remapped} method fields remapped)").into(),
        Cli::MetadataVersionLine { version, dest, remapped } => format!("metadata v{version} -> {dest} ({remapped} method fields remapped)").into(),
        Cli::MetadataAlreadyClean { version } => format!("metadata v{version}:").into(),
        Cli::MetadataNothingToDo => "already de-obfuscated, nothing to do".into(),
        Cli::EmbeddedMetadataLine { input, dest } => format!("metadata  {input} (embedded)  ->  {dest}").into(),
        Cli::EmbeddedMetadataFailed => "embedded metadata".into(),
        Cli::MetadataUnsupportedLine { version } => format!("unsupported metadata version {version}, left untouched").into(),
        Cli::OutRequiresDirectory => "--out requires a directory argument".into(),
        Cli::UnknownOption { option } => format!("unknown option '{option}'").into(),
        Cli::MultipleInputs { first, second } => format!("multiple input paths given ('{first}' and '{second}')").into(),
        Cli::SubcommandNeedsPath { subcommand } => format!("'{subcommand}' requires an input path").into(),
        Cli::InspectNoDryRun => "'inspect' writes nothing; drop --dry-run".into(),
        Cli::InspectNoOut => "'inspect' writes nothing; --out is not allowed".into(),
        Cli::DryRunNoOut => "--dry-run writes no output; --out is not allowed".into(),
        Cli::ColorRequiresMode => "--color requires auto, always, or never".into(),
        Cli::ThreadsRequiresInteger => "--threads requires a positive integer argument".into(),
        Cli::LimitRequiresInteger { flag } => format!("{flag} requires an unsigned integer argument").into(),
        Cli::LimitMustBePositive { flag } => format!("{flag} must be greater than zero").into(),
        Cli::LimitTooLarge { flag } => format!("{flag} exceeds the supported byte range").into(),
        Cli::UnknownLimit { flag } => format!("unknown resource option '{flag}'").into(),
        Cli::HelpPath => "  <file|folder>\n\
             \x20              a CrackProof PE (.exe/.dll), an il2cpp global-metadata.dat,\n\
             \x20              a protected Android AArch64 library (.so), an Android app\n\
             \x20              package (.apk/.apks/.xapk), or a folder containing any of\n\
             \x20              these. The bare form is the same as 'unpack'."
            .into(),
        Cli::HelpInspect => "  inspect PATH\n\
             \x20              run the real static recovery for research, and report\n\
             \x20              everything observed: recognition evidence, each route\n\
             \x20              tried and why it was rejected, the route selected, the\n\
             \x20              static check's verdict, and the engines' own structural\n\
             \x20              evidence (protected-header fields, seeds, module records,\n\
             \x20              restored-image facts). Nothing is kept: no output file,\n\
             \x20              no log, no temporary tree, and the input is never run."
            .into(),
        Cli::HelpUnpack => "  unpack PATH  detection and recovery; writes outputs (the default).".into(),
        Cli::HelpJson => "  --json       write one versioned machine-readable report to stdout and\n\
             \x20              nothing else. Implies quiet and --no-log."
            .into(),
        Cli::HelpDryRun => "  --dry-run    run the real recovery but keep nothing: no output tree and\n\
             \x20              no log. Android extraction still uses its own temporary\n\
             \x20              workspace, which is discarded."
            .into(),
        Cli::HelpThreads => "  --threads N  positive worker cap for this run. Overrides SENBEI_THREADS;\n\
             \x20              1 selects the sequential path. The environment is unchanged."
            .into(),
        Cli::HelpColor => "  --color MODE auto (default), always, or never; --color=MODE also works.\n\
             \x20              Auto colors terminal stdout/stderr separately, unless\n\
             \x20              NO_COLOR is nonempty or TERM=dumb. Explicit always/never\n\
             \x20              override these variables. JSON and saved logs stay plain."
            .into(),
        Cli::HelpScanAll => "  --scan-all   probe selected .exe/.dll/.so/metadata names below the\n\
             \x20              size floor; other filenames remain excluded."
            .into(),
        Cli::HelpStrictIntegrity => "  --strict-integrity\n\
             \x20              exit non-zero when any output fails the static integrity\n\
             \x20              check (a suspect) or a file errors. Off by default: a\n\
             \x20              suspect is still written and the process exits 0 unless\n\
             \x20              a file errors. Quiet levels are unchanged.\n\
             \x20              With 'inspect', the check applies to the image actually\n\
             \x20              recovered for research; no output file is retained."
            .into(),
        Cli::HelpLimits { entry_mib, total_mib, entries, depth } => format!(
            "  Android resource limits (MiB = 1048576 bytes):\n\
             \x20 --max-entry-mib N  single archive entry/decoded buffer/output (default {entry_mib})\n\
             \x20 --max-total-mib N  cumulative archive bytes and per-engine task budget (default {total_mib})\n\
             \x20 --max-entries N    archive entries/stage-2 records (default {entries})\n\
             \x20 --max-depth N      nesting depth, root = 0 (default {depth})\n\
             \x20 Limits are checked before extraction/allocation; they are not a peak-RSS cap."
        )
        .into(),
        Cli::HelpLanguage => "  SENBEI_LANG  display language: en, zh-CN, zh-TW, ja, or ko. Unset, the\n\
             \x20              system language is used. JSON and saved logs stay English."
            .into(),
        Cli::HelpExitCodes => "  Exit codes: 0 success, 1 a target failed (or a suspect with\n\
             \x20 --strict-integrity), 2 the command line was rejected."
            .into(),
        Cli::ReportScanHeading => "scan".into(),
        Cli::ReportScan { skipped, walk_errors, probe_errors } => format!("{skipped} probed non-targets · {walk_errors} walk errors · {probe_errors} probe errors").into(),
        Cli::ReportScanIncomplete => "analysis is incomplete; some directory entries or selected files could not be examined".into(),
        Cli::AnalysisIncomplete => "analysis incomplete".into(),
        Cli::AnalysisIncompleteInput => "I/O, resource limits or infrastructure prevented the requested work".into(),
        Cli::AnalysisIncompleteEntry => "requested entry analysis could not finish".into(),
        Cli::Source { size } => format!("source: {size} bytes (0x{size:X})").into(),
        Cli::Target { platform, format, kind } => format!("target: {platform} · {format} · {kind}").into(),
        Cli::FormatUnavailable => "format unavailable".into(),
        Cli::KindUnavailable => "kind not applicable or unavailable".into(),
        Cli::ProtectionRecognition { status } => format!("protection recognition: {status}").into(),
        Cli::Evidence { evidence } => format!("evidence: {evidence}").into(),
        Cli::Route { route, outcome } => format!("route {route}: {outcome}").into(),
        Cli::SelectedRoute { route } => format!("selected route: {route}").into(),
        Cli::StaticRecovery { status } => format!("static recovery: {status}").into(),
        Cli::OutputValidation { status } => format!("output static validation: {status}").into(),
        Cli::Companion { state } => format!("companion: {state}").into(),
        Cli::CompanionIdentity { size, sha256 } => format!("{size} bytes · SHA-256 {sha256}").into(),
        Cli::InputView { view } => format!("analysis input view: {view}").into(),
        Cli::InputViewSplicedNote => "file offsets below 0x1000 address the stub; offsets at/above 0x1000 address companion offset (file offset - 0x1000)".into(),
        Cli::MetadataIdentity { version, layout } => format!("IL2CPP metadata version: {version} · layout definition {layout}").into(),
        Cli::SeededTokens { value } => format!("seeded method tokens: {value}").into(),
        Cli::StructuralTokens { value } => format!("structural method tokens: {value}").into(),
        Cli::MethodIndexRestore { value, context } => format!("method-index restoration: {value} · application context required: {context}").into(),
        Cli::Container { kind, entries, manifests } => format!("container: {kind} · {entries} entries · {manifests} manifests").into(),
        Cli::Manifest { source, package, version } => format!("manifest {source} → {package} {version}").into(),
        Cli::Unnamed => "<unnamed>".into(),
        Cli::Candidate { entry } => format!("candidate: {entry}").into(),
        Cli::MetadataEvidence => "metadata transform evidence".into(),
        Cli::Entry { name, status } => format!("entry {name}: {status}").into(),
        Cli::EntryRoute { route } => format!("route: {route}").into(),
        Cli::EntryMetadataVersion { version } => format!("metadata version: {version}").into(),
        Cli::EntryRemapped { remapped } => format!("remapped method fields: {remapped}").into(),
        Cli::ModuleContextSource { source } => format!("module context source: {source}").into(),
        Cli::StageLine { stage, status } => format!("stage {stage}: {status}").into(),
        Cli::Recovered { size, sha256 } => format!("recovered: {size} bytes · SHA-256 {sha256}").into(),
        Cli::InspectionStatus { status, ms } => format!("inspection status: {status} · {ms} ms").into(),
        Cli::DiagnosticWarning => "warning".into(),
        Cli::DiagnosticError => "error".into(),
        Cli::DiagnosticReason => "reason".into(),
        Cli::DiagnosticDetail => "detail".into(),
        Cli::DiagnosticEnglish => "in English".into(),
    }
}
