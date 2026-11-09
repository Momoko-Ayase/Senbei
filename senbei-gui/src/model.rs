//! The session: what was added, what each input is, and what its last run found.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use senbei_engine::{RecoveryStatus, ValidationStatus};
use senbei_i18n::{Message, Step};
use senbei_io::report::{
    EntryReport, EntryStatus, InputReport, InputStatus, Mode, Report, Role, ScanReport, Stage,
    StageStatus,
};

use crate::backend::{GroupId, Identity, ItemId, Produced};
use crate::labels::{tv, wire};
use crate::text::{Text, t};
use crate::theme::Tone;

// ------------------------------------------------------------- verdicts

/// The visible outcome of one input or entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Recovered,
    Suspect,
    Recognized,
    Skipped,
    Error,
    Incomplete,
    RecoveryFailed,
    RecoveryBlocked,
    Entry(EntryStatus),
}

/// The input-list filter chips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    #[default]
    All,
    Recovered,
    Suspect,
    Failed,
    Skipped,
}

impl Filter {
    pub const ALL: [Filter; 5] = [
        Filter::All,
        Filter::Recovered,
        Filter::Suspect,
        Filter::Failed,
        Filter::Skipped,
    ];

    pub fn label(self) -> Cow<'static, str> {
        t(match self {
            Filter::All => Text::FilterAll,
            Filter::Recovered => Text::FilterOk,
            Filter::Suspect => Text::FilterSuspect,
            Filter::Failed => Text::FilterFailed,
            Filter::Skipped => Text::FilterSkipped,
        })
    }
}

impl Verdict {
    pub fn of_input(input: &InputReport) -> Verdict {
        let profile = input.profile.as_ref();
        let validation = profile.map(|profile| profile.static_validation);
        if input.analysis_incomplete {
            return Verdict::Incomplete;
        }
        match input.status {
            InputStatus::Error => Verdict::Error,
            InputStatus::Suspect => Verdict::Suspect,
            _ if matches!(
                validation,
                Some(ValidationStatus::Warnings | ValidationStatus::Failed)
            ) =>
            {
                Verdict::Suspect
            }
            InputStatus::Skipped => Verdict::Skipped,
            InputStatus::Recognized => match profile.map(|profile| profile.recovery) {
                Some(RecoveryStatus::Failed) => Verdict::RecoveryFailed,
                Some(RecoveryStatus::Blocked) => Verdict::RecoveryBlocked,
                Some(RecoveryStatus::Succeeded) => Verdict::Recovered,
                _ => Verdict::Recognized,
            },
            InputStatus::Ok => Verdict::Recovered,
        }
    }

    pub fn of_entry(entry: &EntryReport) -> Verdict {
        if entry.analysis_incomplete {
            Verdict::Incomplete
        } else {
            Verdict::Entry(entry.status)
        }
    }

    pub fn tone(self) -> Tone {
        match self {
            Verdict::Recovered => Tone::Ok,
            Verdict::Recognized => Tone::Info,
            Verdict::Suspect => Tone::Warn,
            Verdict::Error
            | Verdict::Incomplete
            | Verdict::RecoveryFailed
            | Verdict::RecoveryBlocked => Tone::Err,
            Verdict::Skipped => Tone::Skip,
            Verdict::Entry(EntryStatus::Restored) => Tone::Ok,
            Verdict::Entry(EntryStatus::Error) => Tone::Err,
            Verdict::Entry(_) => Tone::Skip,
        }
    }

    pub fn label(self) -> Cow<'static, str> {
        match self {
            Verdict::Recovered => t(Text::StatusOk),
            Verdict::Suspect => t(Text::StatusSuspect),
            Verdict::Recognized => t(Text::StatusRecognized),
            Verdict::Skipped => t(Text::StatusSkipped),
            Verdict::Error => t(Text::StatusError),
            Verdict::Incomplete => t(Text::StatusIncomplete),
            Verdict::RecoveryFailed => t(Text::RecoveryFailed),
            Verdict::RecoveryBlocked => t(Text::RecoveryBlocked),
            Verdict::Entry(status) => tv("entryStatus", &status),
        }
    }

    pub fn filter(self) -> Filter {
        match self.tone() {
            Tone::Ok | Tone::Info => Filter::Recovered,
            Tone::Warn => Filter::Suspect,
            Tone::Err => Filter::Failed,
            Tone::Skip => Filter::Skipped,
        }
    }
}

/// True for an entry that was probed and acted on, as opposed to a listed or
/// probed-and-skipped one.
pub fn is_target_entry(entry: &EntryReport) -> bool {
    !matches!(
        entry.status,
        EntryStatus::NotTarget | EntryStatus::Inventoried
    )
}

// ------------------------------------------------------------------ log

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Step,
    Detail,
    Warn,
    Error,
}

/// One log line, kept structured so it reads in whatever language is current.
#[derive(Debug, Clone)]
pub enum LogBody {
    RunStarted {
        mode: Mode,
        inputs: usize,
    },
    Scan {
        candidates: usize,
        skipped: usize,
    },
    ScanIncomplete,
    InputStarted {
        index: usize,
        total: usize,
        path: String,
    },
    Companion {
        name: String,
    },
    Step {
        position: Option<(u8, u8)>,
        step: Step,
    },
    Detail(String),
    Stage {
        stage: Stage,
        status: StageStatus,
        duration: Option<u64>,
        detail: Option<Message>,
    },
    Message(Message),
    Entry {
        label: String,
        verdict: Verdict,
    },
    Finished {
        verdict: Verdict,
        duration: u64,
    },
    Summary(Counts),
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub at: String,
    pub level: Level,
    pub body: LogBody,
}

impl LogLine {
    pub fn new(at: impl Into<String>, level: Level, body: LogBody) -> Self {
        Self {
            at: at.into(),
            level,
            body,
        }
    }
}

/// Counts over a set of inputs, by filter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub inputs: usize,
    pub recovered: usize,
    pub suspect: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl Counts {
    pub fn add(&mut self, verdict: Verdict) {
        match verdict.filter() {
            Filter::Recovered => self.recovered += 1,
            Filter::Suspect => self.suspect += 1,
            Filter::Failed => self.failed += 1,
            Filter::Skipped | Filter::All => self.skipped += 1,
        }
    }

    pub fn get(&self, filter: Filter) -> usize {
        match filter {
            Filter::All => self.inputs,
            Filter::Recovered => self.recovered,
            Filter::Suspect => self.suspect,
            Filter::Failed => self.failed,
            Filter::Skipped => self.skipped,
        }
    }
}

// ---------------------------------------------------------- inputs, groups

/// Where an input stands in the current job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunState {
    #[default]
    Idle,
    Queued,
    Running,
    /// The job was cancelled before reaching it.
    WillNotRun,
}

/// The last finished run of one input.
#[derive(Debug, Clone)]
pub struct ItemResult {
    pub mode: Mode,
    pub report: InputReport,
    pub log: Vec<LogLine>,
    pub restored: Option<Produced>,
    pub entries: Vec<(String, Produced)>,
}

impl ItemResult {
    pub fn verdict(&self) -> Verdict {
        Verdict::of_input(&self.report)
    }

    /// Bytes produced for the entry labelled `label`.
    pub fn entry_bytes(&self, label: &str) -> Option<&Produced> {
        self.entries
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, produced)| produced)
    }
}

#[derive(Debug, Clone)]
pub struct Item {
    pub id: ItemId,
    pub path: PathBuf,
    pub name: String,
    /// `None` while the input is being identified.
    pub identity: Option<Identity>,
    pub run: RunState,
    pub result: Option<ItemResult>,
    /// A package's entry rows are folded.
    pub folded: bool,
}

impl Item {
    pub fn new(id: ItemId, path: PathBuf) -> Self {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        Self {
            id,
            path,
            name,
            identity: None,
            run: RunState::Idle,
            result: None,
            folded: false,
        }
    }

    pub fn verdict(&self) -> Option<Verdict> {
        self.result.as_ref().map(ItemResult::verdict)
    }

    pub fn is_package(&self) -> bool {
        match (&self.result, &self.identity) {
            (Some(result), _) => result.report.role == Role::Container,
            (None, Some(Identity::Package { .. })) => true,
            _ => false,
        }
    }

    /// Entries of the last run.
    pub fn entries(&self) -> &[EntryReport] {
        self.result
            .as_ref()
            .map(|result| result.report.entries.as_slice())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupKind {
    /// Files added one by one.
    Files,
    /// A folder added as a whole.
    Folder(PathBuf),
}

/// The run-level part of a group's last run.
#[derive(Debug, Clone)]
pub struct GroupRun {
    pub mode: Mode,
    pub duration_ms: u64,
    pub errors: Vec<Message>,
    pub cancelled: bool,
    pub log: Vec<LogLine>,
    /// The whole report of the last folder run, for export.
    pub report: Option<Report>,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: GroupId,
    pub kind: GroupKind,
    pub items: Vec<Item>,
    /// Targets found so far while the add-time scan runs.
    pub scanning: Option<usize>,
    pub scan: Option<ScanReport>,
    pub last_run: Option<GroupRun>,
    pub folded: bool,
}

impl Group {
    pub fn new(id: GroupId, kind: GroupKind) -> Self {
        Self {
            id,
            kind,
            items: Vec::new(),
            scanning: None,
            scan: None,
            last_run: None,
            folded: false,
        }
    }

    pub fn root(&self) -> Option<&Path> {
        match &self.kind {
            GroupKind::Folder(root) => Some(root),
            GroupKind::Files => None,
        }
    }

    pub fn title(&self) -> Cow<'static, str> {
        match &self.kind {
            GroupKind::Files => t(Text::GroupFiles),
            GroupKind::Folder(root) => root
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| root.display().to_string())
                .into(),
        }
    }

    pub fn counts(&self) -> Counts {
        let mut counts = Counts {
            inputs: self.items.len(),
            ..Counts::default()
        };
        for verdict in self.items.iter().filter_map(Item::verdict) {
            counts.add(verdict);
        }
        counts
    }
}

/// What the detail pane shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sel {
    Group(GroupId),
    Item(ItemId),
    /// An entry of a package, by its index in the package's last report.
    Entry(ItemId, usize),
}

// ---------------------------------------------------------------- tags

fn extension_tag(name: &str) -> String {
    Path::new(name)
        .extension()
        .map(|extension| extension.to_string_lossy().to_uppercase())
        .unwrap_or_else(|| "?".to_owned())
}

pub fn format_label(format: Option<senbei_engine::TargetFormat>) -> String {
    use senbei_engine::TargetFormat;
    match format {
        Some(TargetFormat::Pe32Plus) => "PE32+".into(),
        Some(TargetFormat::Pe32) => "PE32".into(),
        Some(TargetFormat::Elf64Aarch64) => "ELF64 AArch64".into(),
        Some(other) => wire(&other).unwrap_or_default(),
        None => "—".into(),
    }
}

/// The short type tag of an input, from its last run or else its identity.
/// A run that failed before it read the format keeps the tag the file's
/// header gave when it was added.
pub fn kind_tag(item: &Item) -> String {
    item.result
        .as_ref()
        .and_then(|result| known_report_tag(&result.report))
        .or_else(|| identity_tag(item.identity.as_ref()?))
        .unwrap_or_else(|| extension_tag(&item.name))
}

/// The tag an identity gives, when it names a format.
fn identity_tag(identity: &Identity) -> Option<String> {
    match identity {
        Identity::Windows { profile, .. } if profile.observed.format.is_some() => {
            Some(format_kind(profile.observed.format, profile.observed.kind))
        }
        Identity::Metadata { identity, .. } => Some(metadata_tag(
            identity.as_ref().map(|identity| identity.raw_version),
        )),
        Identity::AndroidLibrary { .. } => Some(identity_format(identity)?),
        Identity::Package {
            container: Ok(container),
            ..
        } => Some(container.kind.to_uppercase()),
        _ => None,
    }
}

/// The binary format an identity read from the file's header, if any.
pub fn identity_format(identity: &Identity) -> Option<String> {
    match identity {
        Identity::Windows { profile, .. } if profile.observed.format.is_some() => {
            Some(format_label(profile.observed.format))
        }
        Identity::AndroidLibrary { .. } => Some(format_label(Some(
            senbei_engine::TargetFormat::Elf64Aarch64,
        ))),
        _ => None,
    }
}

fn format_kind(
    format: Option<senbei_engine::TargetFormat>,
    kind: Option<senbei_engine::Kind>,
) -> String {
    let format = format_label(format);
    match kind {
        Some(kind) => format!("{format} {}", tv("kindShort", &kind)),
        None => format,
    }
}

fn metadata_tag(version: Option<u32>) -> String {
    t(Text::TagMetadata {
        v: version
            .map(|version| version.to_string())
            .unwrap_or_else(|| "?".into()),
    })
    .into_owned()
}

/// The tag a report gives, when it names a format, a metadata version, or a
/// container kind.
fn known_report_tag(input: &InputReport) -> Option<String> {
    if let Some(container) = &input.container {
        return Some(container.kind.to_uppercase());
    }
    if input.role == Role::Container {
        return None;
    }
    let observed = &input.profile.as_ref()?.observed;
    if observed.platform == senbei_engine::Platform::Il2cppMetadata {
        return Some(metadata_tag(
            observed.metadata_version.or(input.metadata_version),
        ));
    }
    observed.format?;
    Some(format_kind(observed.format, observed.kind))
}

/// The type tag of a package entry.
pub fn entry_tag(entry: &EntryReport) -> String {
    use senbei_io::report::EntryKind;
    match entry.kind {
        Some(EntryKind::Metadata) => metadata_tag(entry.metadata_version),
        Some(EntryKind::SharedLibrary) => "ELF64 AArch64".into(),
        None => extension_tag(entry_inner(&entry.name)),
    }
}

/// The entry part of a package label, after the last `::`.
pub fn entry_inner(label: &str) -> &str {
    label.rsplit_once("::").map_or(label, |(_, inner)| inner)
}

/// The nested-package part of a package label, before the last `::`.
pub fn entry_source(label: &str) -> &str {
    label.rsplit_once("::").map_or("", |(outer, _)| outer)
}

pub fn mode_label(mode: Mode) -> Cow<'static, str> {
    t(match mode {
        Mode::Inspect => Text::ModeInspect,
        Mode::DryRun => Text::ModeDryRun,
        Mode::Unpack => Text::ModeUnpack,
    })
}

pub fn mode_action(mode: Mode) -> Cow<'static, str> {
    t(match mode {
        Mode::Inspect => Text::TbInspect,
        Mode::DryRun => Text::TbDryRun,
        Mode::Unpack => Text::TbUnpack,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(status: InputStatus) -> InputReport {
        let mut input = InputReport::new(Path::new("x.dll"), Role::Content);
        input.status = status;
        input
    }

    #[test]
    fn verdicts_follow_the_mockup() {
        assert_eq!(
            Verdict::of_input(&input(InputStatus::Ok)),
            Verdict::Recovered
        );
        assert_eq!(
            Verdict::of_input(&input(InputStatus::Skipped)),
            Verdict::Skipped
        );
        let mut incomplete = input(InputStatus::Error);
        incomplete.analysis_incomplete = true;
        assert_eq!(Verdict::of_input(&incomplete), Verdict::Incomplete);
        let mut recognized = input(InputStatus::Recognized);
        let mut profile = senbei_engine::ProtectionProfile::new(
            senbei_engine::ObservedTarget::windows(None, None),
        );
        profile.recovery = RecoveryStatus::Failed;
        recognized.profile = Some(profile);
        assert_eq!(Verdict::of_input(&recognized), Verdict::RecoveryFailed);
        assert_eq!(Verdict::RecoveryFailed.filter(), Filter::Failed);
        assert_eq!(Verdict::Recognized.filter(), Filter::Recovered);
    }

    #[test]
    fn labels_split_at_the_last_separator() {
        let label = r"app.apks\split.apk::lib\arm64-v8a\libx.so";
        assert_eq!(entry_inner(label), r"lib\arm64-v8a\libx.so");
        assert_eq!(entry_source(label), r"app.apks\split.apk");
    }
}
