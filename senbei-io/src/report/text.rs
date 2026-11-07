//! Human-readable research reports. JSON retains the same underlying evidence.
//!
//! The summary lines of an input (target, recognition, routes, stages, and
//! findings) follow the reader's language. The structural research sections
//! (PE layout, recovery trace, Android and metadata evidence) are technical
//! dumps and stay English, like the JSON they mirror.

use std::fmt::{self, Write};

use senbei_engine::windows::{ResearchTrace, TraceValue, WindowsInspection};
use senbei_i18n::{Cli, Lang, Localize, Message, Term};
use serde::Serialize;
use serde_json::Value;

use super::{AndroidResearchReport, InputReport};
use crate::ui::{Painted, Palette, Tone};

struct Text {
    contents: String,
    palette: Palette,
    lang: Lang,
}

impl Text {
    #[cfg(test)]
    fn new(palette: Palette) -> Self {
        Self::in_language(palette, Lang::En)
    }

    fn in_language(palette: Palette, lang: Lang) -> Self {
        Self {
            contents: String::new(),
            palette,
            lang,
        }
    }

    fn say(&self, line: Cli) -> String {
        line.localize(self.lang).into_owned()
    }
}

impl Write for Text {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.contents.write_str(value)
    }
}

fn status(palette: Palette, value: &impl Serialize) -> Painted<String> {
    status_text(palette, label(value))
}

fn status_text(palette: Palette, value: String) -> Painted<String> {
    palette.paint(tone_of(&value), value)
}

/// The tone of a report value, judged by its English meaning.
fn tone_of(value: &str) -> Tone {
    match value.replace('_', " ").as_str() {
        "ok" | "clean" | "succeeded" | "restored" | "unchanged" | "accepted" | "matched"
        | "validated" => Tone::Success,
        "error" | "failed" | "unreadable" | "rejected" => Tone::Error,
        "warning" | "warnings" | "suspect" | "blocked" | "unmatched" | "budget limited" => {
            Tone::Warning
        }
        "skipped" | "not run" | "not attempted" | "unavailable" | "absent" | "duplicate"
        | "not recognized" => Tone::Muted,
        _ => Tone::Value,
    }
}

fn label(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(text)) => text.replace('_', " "),
        Ok(value) => value.to_string(),
        Err(_) => "unavailable".to_owned(),
    }
}

/// [`label`] in `lang`, for the values the catalog names.
fn term(lang: Lang, value: &impl Serialize) -> String {
    if let Ok(Value::String(wire)) = serde_json::to_value(value)
        && let Some(term) = Term::from_value(&wire)
    {
        return term.localize(lang).into_owned();
    }
    label(value)
}

/// [`status`] in the reader's language: toned by the English value.
fn term_status(text: &Text, value: &impl Serialize) -> String {
    text.palette
        .paint(tone_of(&label(value)), term(text.lang, value))
        .to_string()
}

fn hex<T: Into<u64>>(palette: Palette, value: Option<T>) -> Painted<String> {
    let tone = if value.is_some() {
        Tone::Value
    } else {
        Tone::Muted
    };
    palette.paint(
        tone,
        value
            .map(|value| format!("0x{:X}", value.into()))
            .unwrap_or_else(|| "unavailable".to_owned()),
    )
}

fn diagnostic(text: &mut Text, indent: &str, kind: &str, message: &str) {
    let tone = match kind {
        "error" => Tone::Error,
        "warning" | "parse issue" | "reason" => Tone::Warning,
        _ => Tone::Muted,
    };
    let palette = text.palette;
    for line in message.lines() {
        let _ = writeln!(text, "{indent}{}: {line}", palette.paint(tone, kind));
    }
}

/// How a finding is labelled in the summary part of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Finding {
    Warning,
    Error,
    Reason,
    Detail,
}

impl Finding {
    fn label(self) -> Cli {
        match self {
            Self::Warning => Cli::DiagnosticWarning,
            Self::Error => Cli::DiagnosticError,
            Self::Reason => Cli::DiagnosticReason,
            Self::Detail => Cli::DiagnosticDetail,
        }
    }

    fn tone(self) -> Tone {
        match self {
            Self::Error => Tone::Error,
            Self::Warning | Self::Reason => Tone::Warning,
            Self::Detail => Tone::Muted,
        }
    }
}

/// A finding in the reader's language. When the translation does not show
/// everything the English said, the English follows on its own muted line.
fn finding(text: &mut Text, indent: &str, kind: Finding, message: &Message) {
    let palette = text.palette;
    let label = text.say(kind.label());
    for line in message.localized(text.lang).lines() {
        let _ = writeln!(
            text,
            "{indent}{}: {line}",
            palette.paint(kind.tone(), &label)
        );
    }
    if let Some(english) = message.detail(text.lang) {
        let label = text.say(Cli::DiagnosticEnglish);
        for line in english.lines() {
            let _ = writeln!(
                text,
                "{indent}  {}",
                palette.paint(Tone::Muted, format!("{label}: {line}"))
            );
        }
    }
}

pub(super) fn render_input(input: &InputReport, palette: Palette, lang: Lang) -> String {
    let mut text = Text::in_language(palette, lang);
    let _ = writeln!(text, "{}", palette.paint(Tone::Heading, &input.path));
    if input.analysis_incomplete {
        let line = format!(
            "  {}: {}",
            palette.paint(Tone::Error, text.say(Cli::AnalysisIncomplete)),
            text.say(Cli::AnalysisIncompleteInput)
        );
        let _ = writeln!(text, "{line}");
    }
    if let Some(source) = &input.source {
        let line = text.say(Cli::Source { size: source.size });
        let _ = writeln!(text, "  {line}");
        let _ = writeln!(
            text,
            "  SHA-256: {}",
            palette.paint(Tone::Muted, &source.sha256)
        );
    }
    if let Some(profile) = &input.profile {
        let target = &profile.observed;
        let line = text.say(Cli::Target {
            platform: term(lang, &target.platform),
            format: target
                .format
                .as_ref()
                .map(|format| term(lang, format))
                .unwrap_or_else(|| text.say(Cli::FormatUnavailable)),
            kind: target
                .kind
                .as_ref()
                .map(|kind| term(lang, kind))
                .unwrap_or_else(|| text.say(Cli::KindUnavailable)),
        });
        let _ = writeln!(text, "  {line}");
        let line = text.say(Cli::ProtectionRecognition {
            status: term_status(&text, &profile.recognition),
        });
        let _ = writeln!(text, "  {line}");
        if !profile.evidence.is_empty() {
            let evidence = profile
                .evidence
                .iter()
                .map(|evidence| term(lang, evidence))
                .collect::<Vec<_>>()
                .join(", ");
            let line = text.say(Cli::Evidence { evidence });
            let _ = writeln!(text, "    {line}");
        }
        for candidate in &profile.candidates {
            let line = text.say(Cli::Route {
                route: palette
                    .paint(Tone::Label, term(lang, &candidate.layout))
                    .to_string(),
                outcome: term_status(&text, &candidate.outcome),
            });
            let _ = writeln!(text, "  {line}");
            for message in &candidate.warnings {
                finding(&mut text, "    ", Finding::Warning, message);
            }
            for message in &candidate.errors {
                finding(&mut text, "    ", Finding::Reason, message);
            }
        }
        if let Some(selected) = profile.selected {
            let line = text.say(Cli::SelectedRoute {
                route: palette
                    .paint(Tone::Success, term(lang, &selected))
                    .to_string(),
            });
            let _ = writeln!(text, "  {line}");
        }
        let line = text.say(Cli::StaticRecovery {
            status: term_status(&text, &profile.recovery),
        });
        let _ = writeln!(text, "  {line}");
        let line = text.say(Cli::OutputValidation {
            status: term_status(&text, &profile.static_validation),
        });
        let _ = writeln!(text, "  {line}");
    }
    if let Some(companion) = &input.companion {
        let line = text.say(Cli::Companion {
            state: term_status(&text, &companion.state),
        });
        let _ = writeln!(
            text,
            "  {line}{}",
            companion
                .path
                .as_ref()
                .map(|path| format!(" · {path}"))
                .unwrap_or_default()
        );
        if let Some(source) = &companion.source {
            let line = text.say(Cli::CompanionIdentity {
                size: source.size,
                sha256: source.sha256.clone(),
            });
            let _ = writeln!(text, "    {line}");
        }
        if let Some(detail) = &companion.detail {
            finding(&mut text, "    ", Finding::Detail, detail);
        }
    }
    if let Some(research) = &input.research {
        let line = text.say(Cli::InputView {
            view: term(lang, &research.input_view),
        });
        let _ = writeln!(text, "  {line}");
        if research.input_view == super::ResearchInputView::SplicedCompanion {
            let line = text.say(Cli::InputViewSplicedNote);
            let _ = writeln!(text, "    {line}");
        }
        render_windows(&mut text, "protected input", &research.input);
        render_trace(&mut text, &research.trace);
        if let Some(restored) = &research.restored {
            if let (Some(before), Some(after)) = (&research.input.pe, &restored.pe) {
                let _ = writeln!(
                    text,
                    "  protected → recovered: entry RVA {} → {} · SizeOfImage {} → {} · sections {} → {}",
                    hex(palette, before.entry_point_rva),
                    hex(palette, after.entry_point_rva),
                    hex(palette, before.size_of_image),
                    hex(palette, after.size_of_image),
                    before.sections.len(),
                    after.sections.len()
                );
                let _ = writeln!(
                    text,
                    "    DLL characteristics {} → {}",
                    hex(palette, before.dll_characteristics),
                    hex(palette, after.dll_characteristics)
                );
            }
            render_windows(&mut text, "recovered image (not retained)", restored);
        }
    }
    if let Some(metadata) = &input.metadata {
        let identity = text.say(Cli::MetadataIdentity {
            version: metadata.raw_version,
            layout: term(lang, &metadata.layout),
        });
        let _ = writeln!(text, "  {identity}");
        let capabilities = &metadata.capabilities;
        for line in [
            Cli::SeededTokens {
                value: capabilities.seeded_method_tokens,
            },
            Cli::StructuralTokens {
                value: capabilities.structural_method_tokens,
            },
            Cli::MethodIndexRestore {
                value: capabilities.method_index_restore,
                context: capabilities.method_index_requires_context,
            },
        ] {
            let line = text.say(line);
            let _ = writeln!(text, "    {line}");
        }
    }
    if let Some(container) = &input.container {
        let line = text.say(Cli::Container {
            kind: container.kind.clone(),
            entries: container.entry_count,
            manifests: container.manifests.len(),
        });
        let _ = writeln!(text, "  {line}");
        for manifest in &container.manifests {
            let line = text.say(Cli::Manifest {
                source: manifest.source.clone(),
                package: manifest
                    .package
                    .clone()
                    .unwrap_or_else(|| text.say(Cli::Unnamed)),
                version: manifest.version.clone().unwrap_or_default(),
            });
            let _ = writeln!(text, "    {line}");
        }
        for entry in &container.candidate_entries {
            let line = text.say(Cli::Candidate {
                entry: entry.clone(),
            });
            let _ = writeln!(text, "    {line}");
        }
    }
    if let Some(research) = &input.android_research {
        render_android(&mut text, "  ", research);
    }
    if let Some(research) = &input.metadata_research {
        let heading = text.say(Cli::MetadataEvidence);
        let _ = writeln!(text, "  {}:", palette.paint(Tone::Heading, heading));
        render_tree(&mut text, "    ", research);
    }
    for entry in &input.entries {
        let line = text.say(Cli::Entry {
            name: palette.paint(Tone::Label, &entry.name).to_string(),
            status: term_status(&text, &entry.status),
        });
        let _ = writeln!(
            text,
            "  {line}{}",
            entry
                .output
                .as_ref()
                .map(|output| format!(" → {}", output.path))
                .unwrap_or_default()
        );
        if entry.analysis_incomplete {
            let line = format!(
                "    {}: {}",
                palette.paint(Tone::Error, text.say(Cli::AnalysisIncomplete)),
                text.say(Cli::AnalysisIncompleteEntry)
            );
            let _ = writeln!(text, "{line}");
        }
        if let Some(layout) = entry.layout {
            let line = text.say(Cli::EntryRoute {
                route: term(lang, &layout),
            });
            let _ = writeln!(text, "    {line}");
        }
        if let Some(version) = entry.metadata_version {
            let line = text.say(Cli::EntryMetadataVersion { version });
            let _ = writeln!(text, "    {line}");
        }
        if let Some(remapped) = entry.remapped {
            let line = text.say(Cli::EntryRemapped { remapped });
            let _ = writeln!(text, "    {line}");
        }
        for source in &entry.provenance {
            let line = text.say(Cli::ModuleContextSource {
                source: source.clone(),
            });
            let _ = writeln!(text, "    {line}");
        }
        for message in &entry.warnings {
            finding(&mut text, "    ", Finding::Warning, message);
        }
        for message in &entry.errors {
            finding(&mut text, "    ", Finding::Error, message);
        }
        if let Some(research) = &entry.android_research {
            render_android(&mut text, "    ", research);
        }
        if let Some(research) = &entry.metadata_research {
            let heading = text.say(Cli::MetadataEvidence);
            let _ = writeln!(text, "    {}:", palette.paint(Tone::Heading, heading));
            render_tree(&mut text, "      ", research);
        }
    }
    for source in &input.provenance {
        let line = text.say(Cli::ModuleContextSource {
            source: source.clone(),
        });
        let _ = writeln!(text, "  {line}");
    }
    for stage in &input.stages {
        let line = text.say(Cli::StageLine {
            stage: palette
                .paint(Tone::Label, term(lang, &stage.stage))
                .to_string(),
            status: term_status(&text, &stage.status),
        });
        let _ = writeln!(
            text,
            "  {line}{}",
            stage
                .duration_ms
                .map(|elapsed| format!(" · {elapsed} ms"))
                .unwrap_or_default()
        );
        if let Some(detail) = &stage.detail {
            finding(&mut text, "    ", Finding::Detail, detail);
        }
    }
    // The profile repeats input-level findings; each is shown once.
    let mut seen = std::collections::BTreeSet::new();
    let mut findings = vec![
        (Finding::Warning, &input.warnings),
        (Finding::Error, &input.errors),
    ];
    if let Some(profile) = &input.profile {
        findings.push((Finding::Warning, &profile.warnings));
        findings.push((Finding::Error, &profile.errors));
    }
    for (kind, messages) in findings {
        for message in messages {
            if seen.insert((kind, message.text())) {
                finding(&mut text, "  ", kind, message);
            }
        }
    }
    if let Some(recovered) = &input.recovered {
        let line = text.say(Cli::Recovered {
            size: recovered.size,
            sha256: recovered.sha256.clone(),
        });
        let _ = writeln!(text, "  {line}");
    }
    let line = text.say(Cli::InspectionStatus {
        status: term_status(&text, &input.status),
        ms: input.duration_ms,
    });
    let _ = writeln!(text, "  {line}");
    text.contents
}

fn render_windows(text: &mut Text, heading: &str, inspection: &WindowsInspection) {
    let palette = text.palette;
    let _ = writeln!(
        text,
        "  {}: {} bytes",
        palette.paint(Tone::Heading, heading),
        inspection.input_len
    );
    if let Some(pe) = &inspection.pe {
        let machine = match pe.machine {
            Some(0x14c) => "x86",
            Some(0x8664) => "x86-64",
            Some(0xaa64) => "ARM64",
            _ => "unknown machine",
        };
        let _ = writeln!(
            text,
            "    PE header: {} · {machine} ({})",
            hex(palette, pe.pe_offset),
            hex(palette, pe.machine)
        );
        let _ = writeln!(
            text,
            "    PE type: {} · {}",
            pe.format
                .as_ref()
                .map(label)
                .unwrap_or_else(|| "unavailable".to_owned()),
            pe.kind
                .as_ref()
                .map(label)
                .unwrap_or_else(|| "unavailable".to_owned())
        );
        let _ = writeln!(
            text,
            "    image base: {} · SizeOfImage: {} · SizeOfHeaders: {}",
            hex(palette, pe.image_base),
            hex(palette, pe.size_of_image),
            hex(palette, pe.size_of_headers)
        );
        let _ = writeln!(
            text,
            "    entry point: RVA {} · file offset {} · file-backed: {}",
            hex(palette, pe.entry_point_rva),
            hex(palette, pe.entry_point_file_offset),
            pe.entry_point_available
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned())
        );
        let _ = writeln!(
            text,
            "    alignments: section {} · file {}",
            hex(palette, pe.section_alignment),
            hex(palette, pe.file_alignment)
        );
        let _ = writeln!(
            text,
            "    declared flags: COFF {} · DLL {} (runtime behavior not tested)",
            hex(palette, pe.characteristics),
            hex(palette, pe.dll_characteristics)
        );
        for flag in &pe.named_flags {
            let _ = writeln!(
                text,
                "      {}: {} (0x{:04X})",
                label(&flag.field),
                flag.name,
                flag.bit
            );
        }
        let _ = writeln!(
            text,
            "    {} ({}):",
            palette.paint(Tone::Label, "sections"),
            pe.sections.len()
        );
        let _ = writeln!(
            text,
            "{}",
            palette.paint(
                Tone::Label,
                "      # name       RVA          virtual size raw offset   raw size     R W X"
            )
        );
        for section in &pe.sections {
            let p = &section.permissions;
            let name = section.name.escape_debug().to_string();
            let _ = writeln!(
                text,
                "      {:>2} {} 0x{:08X} 0x{:08X}   0x{:08X} 0x{:08X}   {} {} {}",
                section.index,
                palette.paint(Tone::Label, format!("{name:<10}")),
                section.virtual_address,
                section.virtual_size,
                section.raw_offset,
                section.raw_size,
                if p.read { 'R' } else { '-' },
                if p.write { 'W' } else { '-' },
                if p.execute { 'X' } else { '-' }
            );
            let _ = writeln!(
                text,
                "         characteristics: 0x{:08X} · raw backing: {} · raw range in file: {}",
                section.characteristics,
                label(&section.backing),
                section.raw_in_bounds
            );
            if section.virtual_size > section.raw_size {
                let _ = writeln!(
                    text,
                    "         declared virtual tail beyond raw backing: 0x{:X} bytes",
                    section.virtual_size - section.raw_size
                );
            }
            for anomaly in &section.anomalies {
                let _ = writeln!(text, "         observation: {}", label(anomaly));
            }
        }
        let _ = writeln!(
            text,
            "    {} ({}):",
            palette.paint(Tone::Label, "data directories"),
            pe.directories.len()
        );
        for directory in &pe.directories {
            let _ = writeln!(
                text,
                "      {:>2} {} {} 0x{:08X} · size 0x{:X} · file {} · {}",
                directory.index,
                palette.paint(Tone::Label, format!("{:<18}", directory.name)),
                label(&directory.address_space),
                directory.address,
                directory.size,
                hex(palette, directory.file_offset),
                label(&directory.mapping)
            );
            if let Some(note) = directory.note {
                let _ = writeln!(text, "         {note}");
            }
        }
        if pe.unsectioned.is_empty() {
            let _ = writeln!(text, "    unsectioned file ranges: none");
        } else {
            let _ = writeln!(
                text,
                "    unsectioned file ranges (not automatically protector payloads):"
            );
            for region in &pe.unsectioned {
                let _ = writeln!(
                    text,
                    "      {}: file 0x{:X} · length 0x{:X}",
                    label(&region.kind),
                    region.offset,
                    region.length
                );
            }
        }
        match &pe.overlay {
            Some(region) => {
                let _ = writeln!(
                    text,
                    "    trailing overlay: file 0x{:X} · length 0x{:X}",
                    region.offset, region.length
                );
            }
            None => {
                let _ = writeln!(text, "    trailing overlay: none");
            }
        }
        if let Some(issue) = &pe.parse_issue {
            diagnostic(text, "    ", "parse issue", issue);
        }
    }
    if let Some(protection) = &inspection.protection {
        let _ = writeln!(
            text,
            "    header-table decode: magic {} · supported KONN: {}",
            hex(palette, protection.magic),
            protection.magic_recognized
        );
        for word in &protection.header_words {
            let _ = writeln!(
                text,
                "      info[{}] @ file 0x{:X}: raw 0x{:08X} → decoded 0x{:08X}{}",
                word.index,
                word.source_file_offset,
                word.raw_word,
                word.decoded_word,
                word.semantic
                    .as_ref()
                    .map(|semantic| format!(" · {}", label(semantic)))
                    .unwrap_or_default()
            );
        }
        if let Some(payload) = &protection.payload {
            let _ = writeln!(
                text,
                "    {}: file 0x{:X} → working-image RVA 0x{:X}",
                if protection.magic_recognized {
                    "declared payload"
                } else {
                    "candidate payload interpretation (magic not recognized)"
                },
                payload.source_file_offset,
                payload.destination_rva
            );
            let _ = writeln!(
                text,
                "      prefix length 0x{:X} · total length 0x{:X}",
                payload.prefix_length, payload.total_length
            );
            for check in &payload.checks {
                let _ = writeln!(
                    text,
                    "      {}: start 0x{:X} · length 0x{:X} · end 0x{:X} · limit 0x{:X} · in bounds {} · overflow {}",
                    check.name,
                    check.start,
                    check.length,
                    check.end,
                    check.limit,
                    check.in_bounds,
                    check.overflow
                );
            }
        }
        let probe = &protection.probe;
        let _ = writeln!(
            text,
            "    payload probe: {} · scratch requested 0x{:X} · constructed 0x{:X} · ceiling 0x{:X}",
            status(palette, &probe.status),
            probe.requested_length,
            probe.decoded_length,
            probe.limit_bytes
        );
        let _ = writeln!(
            text,
            "      prefix span 0x{:X} · raw-tail span 0x{:X} · actual prefix cipher bytes decoded 0x{:X}",
            probe.prefix_bytes, probe.tail_bytes, inspection.work.prefix_bytes_decoded
        );
        if let Some(reason) = probe.reason {
            let _ = writeln!(text, "      {reason}");
        }
        if !probe.first_words.is_empty() {
            let words = probe
                .first_words
                .iter()
                .map(|word| format!("0x{word:08X}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(text, "      decoded prefix initial words: {words}");
        }
        let discovery = &protection.discovery;
        let _ = writeln!(
            text,
            "    shell discovery: {} · {} positions scanned · {} candidates reported",
            status(palette, &discovery.status),
            discovery.positions_scanned,
            discovery.candidates.len()
        );
        if let Some(reason) = discovery.reason {
            let _ = writeln!(text, "      {reason}");
        }
        for candidate in &discovery.candidates {
            let _ = writeln!(
                text,
                "      {}: {} · decoded offset {} · image RVA {} · source file {}",
                palette.paint(Tone::Label, label(&candidate.kind)),
                status(palette, &candidate.status),
                hex(palette, candidate.payload_offset),
                hex(palette, candidate.image_rva),
                hex(palette, candidate.source_file_offset)
            );
            let _ = writeln!(text, "        {}", candidate.reason);
            for field in &candidate.fields {
                let _ = writeln!(
                    text,
                    "        {} = 0x{:X}{}",
                    palette.paint(Tone::Label, field.name),
                    field.value,
                    field
                        .space
                        .as_ref()
                        .map(|space| format!(" ({})", label(space)))
                        .unwrap_or_default()
                );
            }
        }
    }
    for issue in &inspection.issues {
        let _ = writeln!(
            text,
            "    {} [{}]: {}",
            status(palette, &issue.severity),
            issue.area,
            issue.message
        );
    }
    if inspection.work.budget_limited {
        let _ = writeln!(
            text,
            "    {}",
            palette.paint(
                Tone::Warning,
                "inspection work was budget-limited; omitted probes are not negative evidence"
            )
        );
    }
}

fn render_trace(text: &mut Text, trace: &ResearchTrace) {
    let palette = text.palette;
    let _ = writeln!(
        text,
        "  {} ({} events):",
        palette.paint(Tone::Heading, "actual static-pipeline discoveries"),
        trace.events.len()
    );
    let mut previous = String::new();
    for event in &trace.events {
        let stage = label(&event.stage);
        if previous != stage {
            let _ = writeln!(text, "    {}:", palette.paint(Tone::Label, &stage));
            previous = stage;
        }
        let value = match &event.value {
            TraceValue::U32(value) => format!("0x{value:08X} ({value})"),
            TraceValue::U64(value) => format!("0x{value:X} ({value})"),
            TraceValue::Bool(value) => value.to_string(),
            TraceValue::Text(value) => value.clone(),
            TraceValue::U32s(values) => values
                .iter()
                .map(|value| format!("0x{value:08X}"))
                .collect::<Vec<_>>()
                .join(", "),
            TraceValue::Range { start, length } => {
                format!("start 0x{start:X} · length 0x{length:X}")
            }
        };
        let provenance = event
            .address
            .as_ref()
            .map(|address| format!(" @ {} 0x{:X}", label(&address.space), address.offset))
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "      {}: {}{}",
            palette.paint(Tone::Label, event.name),
            status_text(palette, value),
            palette.paint(Tone::Muted, provenance)
        );
        if let Some(note) = event.note {
            let _ = writeln!(text, "        {note}");
        }
    }
    if trace.truncated {
        let _ = writeln!(
            text,
            "    {}",
            palette.paint(
                Tone::Warning,
                format!(
                    "trace truncated at {} events; {} events omitted",
                    trace.limit, trace.dropped
                )
            )
        );
    }
}

fn render_android(text: &mut Text, indent: &str, research: &AndroidResearchReport) {
    let palette = text.palette;
    let _ = writeln!(
        text,
        "{indent}{}:",
        palette.paint(Tone::Heading, "Android extraction evidence")
    );
    render_tree(text, &format!("{indent}  "), &research.extraction);
    if let Some(restoration) = &research.restoration {
        let _ = writeln!(
            text,
            "{indent}{}:",
            palette.paint(Tone::Heading, "Android restoration evidence")
        );
        render_tree(text, &format!("{indent}  "), restoration);
    }
}

fn render_tree(text: &mut Text, indent: &str, value: &Value) {
    let palette = text.palette;
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                match value {
                    Value::Array(_) | Value::Object(_) => {
                        let _ = writeln!(text, "{indent}{}:", palette.paint(Tone::Label, name));
                        render_tree(text, &format!("{indent}  "), value);
                    }
                    Value::Number(number) => {
                        let numeric = number
                            .as_u64()
                            .map(|value| format!("{value} (0x{value:X})"))
                            .unwrap_or_else(|| number.to_string());
                        let _ = writeln!(
                            text,
                            "{indent}{}: {}",
                            palette.paint(Tone::Label, name),
                            palette.paint(Tone::Value, numeric)
                        );
                    }
                    Value::String(value) => {
                        let _ = writeln!(
                            text,
                            "{indent}{}: {}",
                            palette.paint(Tone::Label, name),
                            status_text(palette, value.escape_debug().to_string())
                        );
                    }
                    _ => {
                        let _ = writeln!(
                            text,
                            "{indent}{}: {}",
                            palette.paint(Tone::Label, name),
                            palette.paint(Tone::Value, value)
                        );
                    }
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let _ = writeln!(text, "{indent}[{index}]");
                render_tree(text, &format!("{indent}  "), value);
            }
        }
        _ => {
            let _ = writeln!(text, "{indent}{value}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{
        CompanionReport, CompanionState, Digest, Role, Stage, StageReport, StageStatus,
    };
    use senbei_engine::{Kind, ObservedTarget, ProtectionProfile, TargetFormat};
    use std::path::Path;

    fn strip_styles(text: &str) -> String {
        let mut plain = String::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                assert_eq!(chars.next(), Some('['));
                for code in chars.by_ref() {
                    if code == 'm' {
                        break;
                    }
                    assert!(code.is_ascii_digit() || code == ';');
                }
            } else {
                plain.push(ch);
            }
        }
        plain
    }

    #[test]
    fn colors_distinguish_findings_from_actual_recovery_verdicts() {
        let palette = Palette::colored();
        for (value, tone) in [
            ("recognized", Tone::Value),
            ("structural_candidate", Tone::Value),
            ("succeeded", Tone::Success),
            ("clean", Tone::Success),
            ("suspect", Tone::Warning),
            ("failed", Tone::Error),
            ("not_attempted", Tone::Muted),
        ] {
            assert_eq!(
                status(palette, &value).to_string(),
                palette.paint(tone, value.replace('_', " ")).to_string()
            );
        }
    }

    #[test]
    fn trace_and_tree_strings_keep_literal_underscores() {
        use senbei_engine::windows::{ResearchEvent, ResearchStage};
        let trace = ResearchTrace {
            events: vec![ResearchEvent {
                stage: ResearchStage::Header,
                name: "route",
                value: TraceValue::Text("exe_style".to_owned()),
                address: None,
                note: None,
            }],
            truncated: false,
            dropped: 0,
            limit: 1,
        };
        for palette in [Palette::plain(), Palette::colored()] {
            let mut text = Text::new(palette);
            render_trace(&mut text, &trace);
            render_tree(
                &mut text,
                "",
                &serde_json::json!({"path": "app_data/module_0c.bin"}),
            );
            let plain = strip_styles(&text.contents);
            assert!(plain.contains("route: exe_style"));
            assert!(plain.contains("path: app_data/module_0c.bin"));
        }
    }

    #[test]
    fn text_keeps_target_source_context_and_diagnostics() {
        let mut input = InputReport::new(Path::new("module.exe"), Role::Content);
        input.source = Some(Digest::of(b"source bytes"));
        input.profile = Some(ProtectionProfile::new(ObservedTarget::windows(
            Some(TargetFormat::Pe32),
            Some(Kind::NativeExe),
        )));
        input.companion = Some(CompanionReport {
            state: CompanionState::Absent,
            path: None,
            detail: None,
            source: None,
        });
        input
            .provenance
            .push("application-scoped module 0x0C".to_owned());
        input.warning("partial discovery");
        input.error("candidate did not validate");
        input.stages.push(
            StageReport::new(Stage::Recovery, StageStatus::Failed)
                .detail("parameters were unavailable"),
        );
        let text = render_input(&input, Palette::plain(), Lang::En);
        let colored = render_input(&input, Palette::colored(), Lang::En);
        assert!(colored.contains('\x1b'));
        assert_eq!(strip_styles(&colored), text);
        for fact in [
            "SHA-256:",
            "pe32",
            "native exe",
            "companion: absent",
            "application-scoped module",
            "warning: partial discovery",
            "error: candidate did not validate",
            "parameters were unavailable",
        ] {
            assert!(text.contains(fact), "missing {fact}: {text}");
        }
    }

    #[test]
    fn trace_values_have_hex_provenance_and_explicit_truncation() {
        use senbei_engine::windows::{AddressSpace, ResearchEvent, ResearchStage, TraceAddress};
        let trace = ResearchTrace {
            events: vec![ResearchEvent {
                stage: ResearchStage::Payload,
                name: "header_seed",
                value: TraceValue::U32(0x1234),
                address: Some(TraceAddress {
                    space: AddressSpace::FileOffset,
                    offset: 0x1000,
                }),
                note: Some("observed during static recovery"),
            }],
            truncated: true,
            dropped: 2,
            limit: 1,
        };
        let mut text = Text::new(Palette::plain());
        render_trace(&mut text, &trace);
        let text = text.contents;
        let mut colored = Text::new(Palette::colored());
        render_trace(&mut colored, &trace);
        assert_eq!(strip_styles(&colored.contents), text);
        assert!(
            colored.contents.contains(
                &Palette::colored()
                    .paint(Tone::Value, "0x00001234 (4660)")
                    .to_string()
            )
        );
        for fact in [
            "0x00001234",
            "file offset 0x1000",
            "observed during static recovery",
            "trace truncated at 1 events; 2 events omitted",
        ] {
            assert!(text.contains(fact), "missing {fact}: {text}");
        }
    }

    #[test]
    fn nested_android_and_metadata_evidence_is_not_hidden() {
        let mut input = InputReport::new(Path::new("library.so"), Role::Content);
        input.android_research = Some(AndroidResearchReport {
            extraction: serde_json::json!({"decoder": {"header_seed": 0x1234}, "module_registry": [{"command_id": 0x9b}]}),
            restoration: Some(
                serde_json::json!({"validation": {"diagnostics": ["mapping warning"]}}),
            ),
        });
        input.metadata_research =
            Some(serde_json::json!({"tried_seeds": [0x5678], "route": "seeded"}));
        let text = render_input(&input, Palette::plain(), Lang::En);
        let colored = render_input(&input, Palette::colored(), Lang::En);
        assert!(colored.contains('\x1b'));
        assert_eq!(strip_styles(&colored), text);
        for fact in [
            "header_seed: 4660 (0x1234)",
            "module_registry:",
            "command_id: 155 (0x9B)",
            "mapping warning",
            "tried_seeds:",
            "route: seeded",
        ] {
            assert!(text.contains(fact), "missing {fact}: {text}");
        }
    }
}
