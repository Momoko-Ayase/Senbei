//! Human-readable research reports. JSON retains the same underlying evidence.

use std::fmt::Write;

use senbei_engine::windows::{ResearchTrace, TraceValue, WindowsInspection};
use serde::Serialize;
use serde_json::Value;

use super::{AndroidResearchReport, InputReport};

fn label(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(text)) => text.replace('_', " "),
        Ok(value) => value.to_string(),
        Err(_) => "unavailable".to_owned(),
    }
}

fn hex<T: Into<u64>>(value: Option<T>) -> String {
    value
        .map(|value| format!("0x{:X}", value.into()))
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn diagnostic(text: &mut String, indent: &str, kind: &str, message: &str) {
    for line in message.lines() {
        let _ = writeln!(text, "{indent}{kind}: {line}");
    }
}

pub(super) fn render_input(input: &InputReport) -> String {
    let mut text = format!("{}\n", input.path);
    if input.analysis_incomplete {
        let _ = writeln!(
            text,
            "  analysis incomplete: I/O, resource limits or infrastructure prevented the requested work"
        );
    }
    if let Some(source) = &input.source {
        let _ = writeln!(
            text,
            "  source: {} bytes (0x{:X})",
            source.size, source.size
        );
        let _ = writeln!(text, "  SHA-256: {}", source.sha256);
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
            label(&profile.recognition)
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
                label(&candidate.layout),
                label(&candidate.outcome)
            );
            for message in &candidate.warnings {
                diagnostic(&mut text, "    ", "warning", message);
            }
            for message in &candidate.errors {
                diagnostic(&mut text, "    ", "reason", message);
            }
        }
        if let Some(selected) = profile.selected {
            let _ = writeln!(text, "  selected route: {}", label(&selected));
        }
        let _ = writeln!(text, "  static recovery: {}", label(&profile.recovery));
        let _ = writeln!(
            text,
            "  output static validation: {}",
            label(&profile.static_validation)
        );
    }
    if let Some(companion) = &input.companion {
        let _ = writeln!(
            text,
            "  companion: {}{}",
            label(&companion.state),
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
                    hex(before.entry_point_rva),
                    hex(after.entry_point_rva),
                    hex(before.size_of_image),
                    hex(after.size_of_image),
                    before.sections.len(),
                    after.sections.len()
                );
                let _ = writeln!(
                    text,
                    "    DLL characteristics {} → {}",
                    hex(before.dll_characteristics),
                    hex(after.dll_characteristics)
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
        let _ = writeln!(text, "  metadata transform evidence:");
        render_tree(&mut text, "    ", research);
    }
    for entry in &input.entries {
        let _ = writeln!(
            text,
            "  entry {}: {}{}",
            entry.name,
            label(&entry.status),
            entry
                .output
                .as_ref()
                .map(|output| format!(" → {}", output.path))
                .unwrap_or_default()
        );
        if entry.analysis_incomplete {
            let _ = writeln!(
                text,
                "    analysis incomplete: requested entry analysis could not finish"
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
            let _ = writeln!(text, "    metadata transform evidence:");
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
            label(&stage.stage),
            label(&stage.status),
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
        label(&input.status),
        input.duration_ms
    );
    text
}

fn render_windows(text: &mut String, heading: &str, inspection: &WindowsInspection) {
    let _ = writeln!(text, "  {heading}: {} bytes", inspection.input_len);
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
            hex(pe.pe_offset),
            hex(pe.machine)
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
            hex(pe.image_base),
            hex(pe.size_of_image),
            hex(pe.size_of_headers)
        );
        let _ = writeln!(
            text,
            "    entry point: RVA {} · file offset {} · file-backed: {}",
            hex(pe.entry_point_rva),
            hex(pe.entry_point_file_offset),
            pe.entry_point_available
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_owned())
        );
        let _ = writeln!(
            text,
            "    alignments: section {} · file {}",
            hex(pe.section_alignment),
            hex(pe.file_alignment)
        );
        let _ = writeln!(
            text,
            "    declared flags: COFF {} · DLL {} (runtime behavior not tested)",
            hex(pe.characteristics),
            hex(pe.dll_characteristics)
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
        let _ = writeln!(text, "    sections ({}):", pe.sections.len());
        let _ = writeln!(
            text,
            "      # name       RVA          virtual size raw offset   raw size     R W X"
        );
        for section in &pe.sections {
            let p = &section.permissions;
            let name = section.name.escape_debug().to_string();
            let _ = writeln!(
                text,
                "      {:>2} {:<10} 0x{:08X} 0x{:08X}   0x{:08X} 0x{:08X}   {} {} {}",
                section.index,
                name,
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
        let _ = writeln!(text, "    data directories ({}):", pe.directories.len());
        for directory in &pe.directories {
            let _ = writeln!(
                text,
                "      {:>2} {:<18} {} 0x{:08X} · size 0x{:X} · file {} · {}",
                directory.index,
                directory.name,
                label(&directory.address_space),
                directory.address,
                directory.size,
                hex(directory.file_offset),
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
            hex(protection.magic),
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
            label(&probe.status),
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
            label(&discovery.status),
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
                label(&candidate.kind),
                label(&candidate.status),
                hex(candidate.payload_offset),
                hex(candidate.image_rva),
                hex(candidate.source_file_offset)
            );
            let _ = writeln!(text, "        {}", candidate.reason);
            for field in &candidate.fields {
                let _ = writeln!(
                    text,
                    "        {} = 0x{:X}{}",
                    field.name,
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
            label(&issue.severity),
            issue.area,
            issue.message
        );
    }
    if inspection.work.budget_limited {
        let _ = writeln!(
            text,
            "    inspection work was budget-limited; omitted probes are not negative evidence"
        );
    }
}

fn render_trace(text: &mut String, trace: &ResearchTrace) {
    let _ = writeln!(
        text,
        "  actual static-pipeline discoveries ({} events):",
        trace.events.len()
    );
    let mut previous = String::new();
    for event in &trace.events {
        let stage = label(&event.stage);
        if previous != stage {
            let _ = writeln!(text, "    {stage}:");
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
        let _ = writeln!(text, "      {}: {value}{provenance}", event.name);
        if let Some(note) = event.note {
            let _ = writeln!(text, "        {note}");
        }
    }
    if trace.truncated {
        let _ = writeln!(
            text,
            "    trace truncated at {} events; {} events omitted",
            trace.limit, trace.dropped
        );
    }
}

fn render_android(text: &mut String, indent: &str, research: &AndroidResearchReport) {
    let _ = writeln!(text, "{indent}Android extraction evidence:");
    render_tree(text, &format!("{indent}  "), &research.extraction);
    if let Some(restoration) = &research.restoration {
        let _ = writeln!(text, "{indent}Android restoration evidence:");
        render_tree(text, &format!("{indent}  "), restoration);
    }
}

fn render_tree(text: &mut String, indent: &str, value: &Value) {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                match value {
                    Value::Array(_) | Value::Object(_) => {
                        let _ = writeln!(text, "{indent}{name}:");
                        render_tree(text, &format!("{indent}  "), value);
                    }
                    Value::Number(number) => {
                        let numeric = number
                            .as_u64()
                            .map(|value| format!("{value} (0x{value:X})"))
                            .unwrap_or_else(|| number.to_string());
                        let _ = writeln!(text, "{indent}{name}: {numeric}");
                    }
                    Value::String(value) => {
                        let _ = writeln!(text, "{indent}{name}: {}", value.escape_debug());
                    }
                    _ => {
                        let _ = writeln!(text, "{indent}{name}: {value}");
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
        let text = render_input(&input);
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
        let mut text = String::new();
        render_trace(&mut text, &trace);
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
        let text = render_input(&input);
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
