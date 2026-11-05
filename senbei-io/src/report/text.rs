//! Human-readable research reports. JSON retains the same underlying evidence.

use std::fmt::{self, Write};

use senbei_engine::windows::{ResearchTrace, TraceValue, WindowsInspection};
use serde::Serialize;
use serde_json::Value;

use super::{AndroidResearchReport, InputReport};
use crate::ui::{Painted, Palette, Tone};

struct Text {
    contents: String,
    palette: Palette,
}

impl Text {
    fn new(palette: Palette) -> Self {
        Self {
            contents: String::new(),
            palette,
        }
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
    let normalized = value.replace('_', " ");
    let tone = match normalized.as_str() {
        "ok" | "clean" | "succeeded" | "restored" | "unchanged" | "accepted" | "matched"
        | "validated" => Tone::Success,
        "error" | "failed" | "unreadable" | "rejected" => Tone::Error,
        "warning" | "warnings" | "suspect" | "blocked" | "unmatched" | "budget limited" => {
            Tone::Warning
        }
        "skipped" | "not run" | "not attempted" | "unavailable" | "absent" | "duplicate"
        | "not recognized" => Tone::Muted,
        _ => Tone::Value,
    };
    palette.paint(tone, value)
}

fn label(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(text)) => text.replace('_', " "),
        Ok(value) => value.to_string(),
        Err(_) => "unavailable".to_owned(),
    }
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

pub(super) fn render_input(input: &InputReport, palette: Palette) -> String {
    let mut text = Text::new(palette);
    let _ = writeln!(text, "{}", palette.paint(Tone::Heading, &input.path));
    if input.analysis_incomplete {
        let _ = writeln!(
            text,
            "  {}: I/O, resource limits or infrastructure prevented the requested work",
            palette.paint(Tone::Error, "analysis incomplete")
        );
    }
    if let Some(source) = &input.source {
        let _ = writeln!(
            text,
            "  source: {} bytes (0x{:X})",
            source.size, source.size
        );
        let _ = writeln!(
            text,
            "  SHA-256: {}",
            palette.paint(Tone::Muted, &source.sha256)
        );
    }
    if let Some(profile) = &input.profile {
        let target = &profile.observed;
        let _ = writeln!(
            text,
            "  target: {} · {} · {}",
            label(&target.platform),
            target
                .format
                .as_ref()
                .map(label)
                .unwrap_or_else(|| "format unavailable".to_owned()),
            target
                .kind
                .as_ref()
                .map(label)
                .unwrap_or_else(|| "kind not applicable or unavailable".to_owned())
        );
        let _ = writeln!(
            text,
            "  protection recognition: {}",
            status(palette, &profile.recognition)
        );
        if !profile.evidence.is_empty() {
            let evidence = profile
                .evidence
                .iter()
                .map(label)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(text, "    evidence: {evidence}");
        }
        for candidate in &profile.candidates {
            let _ = writeln!(
                text,
                "  route {}: {}",
                palette.paint(Tone::Label, label(&candidate.layout)),
                status(palette, &candidate.outcome)
            );
            for message in &candidate.warnings {
                diagnostic(&mut text, "    ", "warning", message);
            }
            for message in &candidate.errors {
                diagnostic(&mut text, "    ", "reason", message);
            }
        }
        if let Some(selected) = profile.selected {
            let _ = writeln!(
                text,
                "  selected route: {}",
                palette.paint(Tone::Success, label(&selected))
            );
        }
        let _ = writeln!(
            text,
            "  static recovery: {}",
            status(palette, &profile.recovery)
        );
        let _ = writeln!(
            text,
            "  output static validation: {}",
            status(palette, &profile.static_validation)
        );
    }
    if let Some(companion) = &input.companion {
        let _ = writeln!(
            text,
            "  companion: {}{}",
            status(palette, &companion.state),
            companion
                .path
                .as_ref()
                .map(|path| format!(" · {path}"))
                .unwrap_or_default()
        );
        if let Some(source) = &companion.source {
            let _ = writeln!(
                text,
                "    {} bytes · SHA-256 {}",
                source.size, source.sha256
            );
        }
        if let Some(detail) = &companion.detail {
            diagnostic(&mut text, "    ", "detail", detail);
        }
    }
    if let Some(research) = &input.research {
        let _ = writeln!(
            text,
            "  analysis input view: {}",
            label(&research.input_view)
        );
        if research.input_view == super::ResearchInputView::SplicedCompanion {
            let _ = writeln!(
                text,
                "    file offsets below 0x1000 address the stub; offsets at/above 0x1000 address companion offset (file offset - 0x1000)"
            );
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
        let _ = writeln!(
            text,
            "  IL2CPP metadata version: {} · layout definition {}",
            metadata.raw_version,
            label(&metadata.layout)
        );
        let _ = writeln!(
            text,
            "    seeded method tokens: {}",
            metadata.capabilities.seeded_method_tokens
        );
        let _ = writeln!(
            text,
            "    structural method tokens: {}",
            metadata.capabilities.structural_method_tokens
        );
        let _ = writeln!(
            text,
            "    method-index restoration: {} · application context required: {}",
            metadata.capabilities.method_index_restore,
            metadata.capabilities.method_index_requires_context
        );
    }
    if let Some(container) = &input.container {
        let _ = writeln!(
            text,
            "  container: {} · {} entries · {} manifests",
            container.kind,
            container.entry_count,
            container.manifests.len()
        );
        for manifest in &container.manifests {
            let _ = writeln!(
                text,
                "    manifest {} → {} {}",
                manifest.source,
                manifest.package.as_deref().unwrap_or("<unnamed>"),
                manifest.version.as_deref().unwrap_or("")
            );
        }
        for entry in &container.candidate_entries {
            let _ = writeln!(text, "    candidate: {entry}");
        }
    }
    if let Some(research) = &input.android_research {
        render_android(&mut text, "  ", research);
    }
    if let Some(research) = &input.metadata_research {
        let _ = writeln!(
            text,
            "  {}:",
            palette.paint(Tone::Heading, "metadata transform evidence")
        );
        render_tree(&mut text, "    ", research);
    }
    for entry in &input.entries {
        let _ = writeln!(
            text,
            "  entry {}: {}{}",
            palette.paint(Tone::Label, &entry.name),
            status(palette, &entry.status),
            entry
                .output
                .as_ref()
                .map(|output| format!(" → {}", output.path))
                .unwrap_or_default()
        );
        if entry.analysis_incomplete {
            let _ = writeln!(
                text,
                "    {}: requested entry analysis could not finish",
                palette.paint(Tone::Error, "analysis incomplete")
            );
        }
        if let Some(layout) = entry.layout {
            let _ = writeln!(text, "    route: {}", label(&layout));
        }
        if let Some(version) = entry.metadata_version {
            let _ = writeln!(text, "    metadata version: {version}");
        }
        if let Some(remapped) = entry.remapped {
            let _ = writeln!(text, "    remapped method fields: {remapped}");
        }
        for source in &entry.provenance {
            let _ = writeln!(text, "    module context source: {source}");
        }
        for message in &entry.warnings {
            diagnostic(&mut text, "    ", "warning", message);
        }
        for message in &entry.errors {
            diagnostic(&mut text, "    ", "error", message);
        }
        if let Some(research) = &entry.android_research {
            render_android(&mut text, "    ", research);
        }
        if let Some(research) = &entry.metadata_research {
            let _ = writeln!(
                text,
                "    {}:",
                palette.paint(Tone::Heading, "metadata transform evidence")
            );
            render_tree(&mut text, "      ", research);
        }
    }
    for source in &input.provenance {
        let _ = writeln!(text, "  module context source: {source}");
    }
    for stage in &input.stages {
        let _ = writeln!(
            text,
            "  stage {}: {}{}",
            palette.paint(Tone::Label, label(&stage.stage)),
            status(palette, &stage.status),
            stage
                .duration_ms
                .map(|elapsed| format!(" · {elapsed} ms"))
                .unwrap_or_default()
        );
        if let Some(detail) = &stage.detail {
            diagnostic(&mut text, "    ", "detail", detail);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for (kind, messages) in [("warning", &input.warnings), ("error", &input.errors)] {
        for message in messages {
            if seen.insert((kind, message.as_str())) {
                diagnostic(&mut text, "  ", kind, message);
            }
        }
    }
    if let Some(profile) = &input.profile {
        for (kind, messages) in [("warning", &profile.warnings), ("error", &profile.errors)] {
            for message in messages {
                if seen.insert((kind, message.as_str())) {
                    diagnostic(&mut text, "  ", kind, message);
                }
            }
        }
    }
    if let Some(recovered) = &input.recovered {
        let _ = writeln!(
            text,
            "  recovered: {} bytes · SHA-256 {}",
            recovered.size, recovered.sha256
        );
    }
    let _ = writeln!(
        text,
        "  inspection status: {} · {} ms",
        status(palette, &input.status),
        input.duration_ms
    );
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
        let text = render_input(&input, Palette::plain());
        let colored = render_input(&input, Palette::colored());
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
        let text = render_input(&input, Palette::plain());
        let colored = render_input(&input, Palette::colored());
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
