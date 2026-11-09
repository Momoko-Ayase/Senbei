//! The research tab: the structural evidence a run collected, by section.

use egui::{
    Align, CornerRadius, Frame, Layout, Margin, Rect, RichText, ScrollArea, Sense, Stroke, Ui,
    UiBuilder, pos2, vec2,
};
use senbei_engine::windows::{
    AddressSpace, DirectoryMapping, PeInspection, ResearchEvent, SectionBacking, TraceValue,
};
use senbei_engine::{ProtectionProfile, ResearchTrace};
use senbei_io::report::{
    AndroidResearchReport, EntryReport, Mode, ResearchInputView, WindowsResearchReport,
};
use serde_json::Value;

use super::table::{self, col, num_col};
use super::widgets::{self, CardSpec};
use super::{Action, Draw, HexView, Tab, ViewState};
use crate::backend::ItemId;
use crate::format;
use crate::labels::{self, tv, tv_str, wire};
use crate::model::{Item, ItemResult, format_label};
use crate::text::{Text, t};
use crate::theme::{self, Tone};

/// The research a subject carries.
pub struct Subject<'a> {
    pub item: ItemId,
    pub entry: Option<usize>,
    pub windows: Option<&'a WindowsResearchReport>,
    pub android: Option<&'a AndroidResearchReport>,
    pub metadata: Option<&'a Value>,
    pub profile: Option<&'a ProtectionProfile>,
    pub mode: Option<Mode>,
    pub comparable: bool,
}

impl<'a> Subject<'a> {
    pub fn item(item: &'a Item, result: &'a ItemResult) -> Self {
        let input = &result.report;
        Self {
            item: item.id,
            entry: None,
            windows: input.research.as_ref(),
            android: input.android_research.as_ref(),
            metadata: input.metadata_research.as_ref(),
            profile: input.profile.as_ref(),
            mode: Some(result.mode),
            comparable: super::detail::comparable(input),
        }
    }

    pub fn entry(item: &'a Item, index: usize, entry: &'a EntryReport, mode: Option<Mode>) -> Self {
        Self {
            item: item.id,
            entry: Some(index),
            windows: None,
            android: entry.android_research.as_ref(),
            metadata: entry.metadata_research.as_ref(),
            profile: None,
            mode,
            comparable: false,
        }
    }
}

enum Nav {
    Group(String),
    Section {
        key: String,
        label: String,
        count: Option<usize>,
    },
}

fn section(key: &str, text: Text, count: Option<usize>) -> Nav {
    Nav::Section {
        key: key.to_owned(),
        label: t(text).into_owned(),
        count,
    }
}

fn group(text: Text) -> Nav {
    Nav::Group(t(text).into_owned())
}

const RESTORATION: [(&str, Text); 7] = [
    ("descriptor", Text::RsARDescriptor),
    ("static_config", Text::RsARStaticConfig),
    ("primary", Text::RsARPrimary),
    ("auxiliary", Text::RsARAuxiliary),
    ("elf_materialization", Text::RsARElfMaterialization),
    ("cleaning", Text::RsARCleaning),
    ("validation", Text::RsARValidation),
];

fn array_len(value: Option<&Value>) -> Option<usize> {
    Some(value.and_then(Value::as_array).map_or(0, Vec::len))
}

/// The issues worth showing for the protected input.
fn input_issues(research: &WindowsResearchReport) -> Vec<&senbei_engine::windows::InspectionIssue> {
    research
        .input
        .issues
        .iter()
        .filter(|issue| !labels::is_quiet(&issue.message))
        .collect()
}

/// The issues worth showing for the restored image, which has no protection
/// header to explain.
fn restored_issues(
    restored: &senbei_engine::windows::WindowsInspection,
) -> Vec<&senbei_engine::windows::InspectionIssue> {
    restored
        .issues
        .iter()
        .filter(|issue| {
            !issue
                .message
                .starts_with("header table decoded but info[1] is ")
        })
        .collect()
}

fn sections(subject: &Subject<'_>) -> Vec<Nav> {
    let mut out = Vec::new();
    if let Some(research) = subject.windows {
        out.push(group(Text::RsGrpInput));
        if let Some(pe) = &research.input.pe {
            out.push(section("pe", Text::RsPeHeader, None));
            out.push(section(
                "sections",
                Text::RsSections,
                Some(pe.sections.len()),
            ));
            out.push(section(
                "dirs",
                Text::RsDirectories,
                Some(pe.directories.iter().filter(|dir| dir.size > 0).count()),
            ));
            out.push(section("regions", Text::RsRegions, None));
        }
        if let Some(protection) = &research.input.protection {
            out.push(group(Text::RsGrpProtection));
            out.push(section(
                "header",
                Text::RsHeaderTable,
                Some(protection.header_words.len()),
            ));
            if protection.payload.is_some() {
                out.push(section("payload", Text::RsPayload, None));
            }
            out.push(section(
                "discovery",
                Text::RsDiscovery,
                Some(protection.discovery.candidates.len()),
            ));
        }
        out.push(group(Text::RsGrpRecovery));
        out.push(section(
            "trace",
            Text::RsTrace,
            Some(research.trace.events.len()),
        ));
        out.push(section(
            "issues",
            Text::RsIssues,
            Some(input_issues(research).len()),
        ));
        if research.restored.is_some() {
            out.push(section("restored", Text::RsRestored, None));
        }
    }
    if let Some(android) = subject.android {
        let extraction = &android.extraction;
        out.push(group(Text::RsGrpExtraction));
        out.push(section("a_stage1", Text::RsAStage1, None));
        out.push(section(
            "a_streams",
            Text::RsAStreams,
            array_len(extraction.get("streams")),
        ));
        out.push(section(
            "a_modules",
            Text::RsAModules,
            array_len(extraction.get("module_registry")),
        ));
        out.push(section(
            "a_artifacts",
            Text::RsAArtifacts,
            array_len(extraction.get("artifacts")),
        ));
        if let Some(restoration) = &android.restoration {
            out.push(group(Text::RsGrpRestoration));
            for (key, text) in RESTORATION {
                if restoration.get(key).is_some_and(Value::is_object) {
                    out.push(section(&format!("a_r:{key}"), text, None));
                }
            }
            out.push(section("a_r:*", Text::RsAScalars, None));
        }
    }
    if let Some(metadata) = subject.metadata {
        out.push(group(Text::RsGrpMetadata));
        if metadata
            .get("report")
            .is_some_and(|report| !report.is_null())
        {
            out.push(section("m_report", Text::RsMReport, None));
        }
        if let Some(discovery) = metadata.get("discovery").filter(|value| !value.is_null()) {
            out.push(section(
                "m_images",
                Text::RsMImages,
                array_len(discovery.get("images")),
            ));
        }
        out.push(section("m_raw", Text::RsMRaw, None));
    }
    if subject.profile.is_some() {
        out.push(group(Text::RsGrpProfile));
        out.push(section("profile", Text::RsProfile, None));
    }
    out
}

pub fn tab(ui: &mut Ui, draw: &mut Draw<'_>, view: &mut ViewState, subject: Subject<'_>) {
    let nav = sections(&subject);
    let keys: Vec<&str> = nav
        .iter()
        .filter_map(|entry| match entry {
            Nav::Section { key, .. } => Some(key.as_str()),
            Nav::Group(_) => None,
        })
        .collect();
    if !keys
        .iter()
        .any(|key| Some(*key) == view.research_section.as_deref())
    {
        view.research_section = keys.first().map(|key| (*key).to_owned());
    }
    let full = ui.available_rect_before_wrap();
    let nav_width = if ui.ctx().content_rect().width() < 1360.0 {
        180.0
    } else {
        210.0
    };
    let nav_rect = Rect::from_min_max(full.min, pos2(full.left() + nav_width, full.bottom()));
    let content_rect = Rect::from_min_max(pos2(nav_rect.right(), full.top()), full.max);
    ui.painter().vline(
        nav_rect.right() - 0.5,
        nav_rect.y_range(),
        Stroke::new(1.0, theme::BORDER),
    );
    ui.scope_builder(UiBuilder::new().max_rect(nav_rect), |ui| {
        ScrollArea::vertical()
            .id_salt(("research-nav", subject.item, subject.entry))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                Frame::new()
                    .inner_margin(Margin::symmetric(6, 10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        nav_list(ui, &nav, view);
                    });
            });
    });
    ui.scope_builder(UiBuilder::new().max_rect(content_rect), |ui| {
        let key = view.research_section.clone().unwrap_or_default();
        ScrollArea::vertical()
            .id_salt(("research", subject.item, subject.entry, key.clone()))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                Frame::new()
                    .inner_margin(Margin {
                        left: 16,
                        right: 16,
                        top: 14,
                        bottom: 30,
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        missing(ui, draw, &subject);
                        content(ui, draw, &subject, &key);
                    });
            });
    });
    ui.allocate_rect(full, Sense::hover());
}

fn nav_list(ui: &mut Ui, nav: &[Nav], view: &mut ViewState) {
    ui.spacing_mut().item_spacing.y = 0.0;
    for entry in nav {
        match entry {
            Nav::Group(label) => {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(label.to_uppercase())
                            .font(theme::tiny())
                            .color(theme::FAINT),
                    );
                });
                ui.add_space(3.0);
            }
            Nav::Section { key, label, count } => {
                let on = view.research_section.as_deref() == Some(key.as_str());
                let (rect, response) =
                    ui.allocate_exact_size(vec2(ui.available_width(), 24.0), Sense::click());
                widgets::describe(&response, egui::Role::Tab, label, Some(on));
                if on {
                    ui.painter()
                        .rect_filled(rect, CornerRadius::same(4), theme::selection());
                } else if response.hovered() {
                    ui.painter()
                        .rect_filled(rect, CornerRadius::same(4), theme::row_hover());
                }
                let color = if on || response.hovered() {
                    theme::TEXT
                } else {
                    theme::DIM
                };
                let count_galley = count.map(|count| {
                    ui.painter().layout_no_wrap(
                        count.to_string(),
                        theme::tiny(),
                        if on { theme::DIM } else { theme::FAINT },
                    )
                });
                let count_width = count_galley
                    .as_ref()
                    .map_or(0.0, |galley| galley.size().x + 6.0);
                let mut job =
                    egui::text::LayoutJob::simple_singleline(label.clone(), theme::body(), color);
                job.wrap =
                    egui::text::TextWrapping::truncate_at_width(rect.width() - 16.0 - count_width);
                let galley = ui.painter().layout_job(job);
                ui.painter().galley(
                    pos2(rect.left() + 8.0, rect.center().y - galley.size().y / 2.0),
                    galley,
                    color,
                );
                if let Some(galley) = count_galley {
                    let pos = pos2(
                        rect.right() - 8.0 - galley.size().x,
                        rect.center().y - galley.size().y / 2.0,
                    );
                    ui.painter().galley(pos, galley, theme::FAINT);
                }
                if response.clicked() {
                    view.research_section = Some(key.clone());
                }
            }
        }
    }
}

fn missing(ui: &mut Ui, draw: &mut Draw<'_>, subject: &Subject<'_>) {
    if subject.windows.is_some() || subject.android.is_some() || subject.metadata.is_some() {
        return;
    }
    if subject.mode == Some(Mode::Inspect) {
        widgets::note(ui, t(Text::ResearchNone));
        ui.add_space(10.0);
        return;
    }
    let item = subject.item;
    widgets::wide_card(
        ui,
        CardSpec::untitled(|ui| {
            widgets::note(ui, t(Text::ResearchNotCollected));
            ui.add_space(8.0);
            if widgets::primary_button(ui, t(Text::ResearchRunInspect), true).clicked() {
                draw.act(Action::RunItem(Mode::Inspect, item));
            }
        }),
    );
    ui.add_space(12.0);
}

// ---------------------------------------------------------------- pieces

fn h3(ui: &mut Ui, title: impl Into<String>, aside: Option<String>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        ui.label(RichText::new(title.into()).font(theme::title(15.0)));
        if let Some(aside) = aside {
            ui.label(widgets::faint(aside).font(theme::small()));
        }
    });
    ui.add_space(8.0);
}

fn h4(ui: &mut Ui, title: impl Into<String>, aside: Option<String>) {
    ui.add_space(14.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        ui.label(widgets::strong(title.into(), 13.0).color(theme::DIM));
        if let Some(aside) = aside {
            ui.label(widgets::faint(aside).font(theme::small()));
        }
    });
    ui.add_space(4.0);
}

/// An address with its space badge; clicking it shows it in Hex.
fn off(ui: &mut Ui, actions: &mut Vec<Action>, space: AddressSpace, offset: u64) {
    off_label(ui, actions, space, offset, format::hex(offset));
}

fn off_label(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    space: AddressSpace,
    offset: u64,
    label: String,
) {
    let short = tv("spaceShort", &space);
    let long = tv("space", &space);
    if widgets::offset_link(ui, &short, &long, &label, true).clicked() {
        actions.push(Action::Jump {
            space: wire(&space).unwrap_or_default(),
            offset,
        });
    }
}

fn opt_hex(value: Option<u64>, width: usize) -> String {
    value.map_or_else(|| "—".to_owned(), |value| format::hex_w(value, width))
}

fn mono(text: impl Into<String>) -> RichText {
    widgets::mono(text)
}

fn hex_and_bytes(ui: &mut Ui, value: u64) {
    ui.label(mono(format::hex(value)));
    ui.label(widgets::faint(format!("({})", format::bytes(value))));
}

fn note_text(note: &str) -> String {
    labels::note(note).text
}

fn content(ui: &mut Ui, draw: &mut Draw<'_>, subject: &Subject<'_>, key: &str) {
    let actions = &mut *draw.actions;
    if let Some(research) = subject.windows {
        let view_note = research.input_view == ResearchInputView::SplicedCompanion;
        match key {
            "pe" => {
                if let Some(pe) = &research.input.pe {
                    pe_header(ui, actions, research, pe, view_note);
                }
                return;
            }
            "sections" => {
                if let Some(pe) = &research.input.pe {
                    sections_table(
                        ui,
                        actions,
                        pe,
                        false,
                        t(Text::RsSections).into_owned(),
                        view_note,
                    );
                }
                return;
            }
            "dirs" => {
                if let Some(pe) = &research.input.pe {
                    directories(ui, actions, pe, view_note);
                }
                return;
            }
            "regions" => {
                if let Some(pe) = &research.input.pe {
                    file_regions(ui, actions, pe);
                }
                return;
            }
            "header" => {
                header_table(ui, actions, research);
                return;
            }
            "payload" => {
                payload(ui, actions, research);
                return;
            }
            "discovery" => {
                discovery(ui, actions, research);
                return;
            }
            "trace" => {
                trace(ui, actions, &research.trace);
                return;
            }
            "issues" => {
                issues(ui, research);
                return;
            }
            "restored" => {
                restored(ui, actions, research, subject.comparable);
                return;
            }
            _ => {}
        }
    }
    if let Some(android) = subject.android {
        match key {
            "a_stage1" => {
                stage1(ui, actions, &android.extraction);
                return;
            }
            "a_streams" => {
                streams(ui, actions, &android.extraction, subject);
                return;
            }
            "a_modules" => {
                modules(ui, &android.extraction, subject);
                return;
            }
            "a_artifacts" => {
                artifacts(ui, &android.extraction, subject);
                return;
            }
            _ => {}
        }
        if let (Some(rest), Some(restoration)) = (key.strip_prefix("a_r:"), &android.restoration) {
            restoration_section(ui, restoration, rest, subject);
            return;
        }
    }
    if let Some(metadata) = subject.metadata {
        match key {
            "m_report" => {
                metadata_report(ui, metadata, subject);
                return;
            }
            "m_images" => {
                metadata_images(ui, metadata, subject);
                return;
            }
            "m_raw" => {
                h3(ui, t(Text::RsMRaw), None);
                let mut rest = metadata.clone();
                if let Some(object) = rest.as_object_mut() {
                    object.remove("discovery");
                    object.remove("report");
                }
                json_tree(ui, ("m_raw", subject.item, subject.entry), &rest, false);
                return;
            }
            _ => {}
        }
    }
    if key == "profile"
        && let Some(profile) = subject.profile
    {
        h3(ui, t(Text::RsProfile), None);
        let value = serde_json::to_value(profile).unwrap_or(Value::Null);
        json_tree(ui, ("profile", subject.item), &value, true);
    }
}

// ------------------------------------------------------------ PE sections

fn spliced_note(ui: &mut Ui, show: bool) {
    if show {
        widgets::note(ui, t(Text::ResearchSplicedNote));
        ui.add_space(8.0);
    }
}

fn pe_header(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    research: &WindowsResearchReport,
    pe: &PeInspection,
    view_note: bool,
) {
    h3(ui, t(Text::RsPeHeader), None);
    spliced_note(ui, view_note);
    let keys = [
        t(Text::PeOffset).into_owned(),
        t(Text::PeMachine).into_owned(),
        t(Text::PeFormat).into_owned(),
        "ImageBase".to_owned(),
        t(Text::PeEntry).into_owned(),
        "SizeOfImage".to_owned(),
        "SizeOfHeaders".to_owned(),
        t(Text::PeAlignment).into_owned(),
        "Characteristics".to_owned(),
        "DllCharacteristics".to_owned(),
        t(Text::PeFlags).into_owned(),
        t(Text::PeInputLen).into_owned(),
        t(Text::PeParseIssue).into_owned(),
    ];
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    widgets::kv(ui, &refs, |rows| {
        rows.row(&keys[0], |ui| match pe.pe_offset {
            Some(offset) => off(ui, actions, AddressSpace::FileOffset, offset),
            None => {
                ui.label("—");
            }
        });
        rows.row(&keys[1], |ui| {
            ui.label(mono(opt_hex(pe.machine.map(u64::from), 4)));
            let name = match pe.machine {
                Some(0x8664) => "x86-64",
                Some(0x14c) => "x86",
                Some(0xaa64) => "ARM64",
                _ => "",
            };
            if !name.is_empty() {
                ui.label(name);
            }
        });
        rows.row(&keys[2], |ui| {
            ui.label(mono(format_label(pe.format)));
            if let Some(kind) = pe.kind {
                ui.label("·");
                ui.label(tv("kind", &kind));
            }
        });
        rows.text(&keys[3], mono(opt_hex(pe.image_base, 0)));
        rows.row(&keys[4], |ui| {
            match pe.entry_point_rva {
                Some(rva) => off(ui, actions, AddressSpace::WorkingImageRva, u64::from(rva)),
                None => {
                    ui.label("—");
                }
            }
            ui.label("→");
            match (pe.entry_point_available, pe.entry_point_file_offset) {
                (Some(true), Some(offset)) => off(ui, actions, AddressSpace::FileOffset, offset),
                _ => {
                    ui.label(widgets::toned(t(Text::PeNotFileBacked), Tone::Warn));
                }
            }
        });
        rows.row(&keys[5], |ui| match pe.size_of_image {
            Some(size) => hex_and_bytes(ui, u64::from(size)),
            None => {
                ui.label("—");
            }
        });
        rows.text(
            &keys[6],
            mono(opt_hex(pe.size_of_headers.map(u64::from), 0)),
        );
        rows.text(
            &keys[7],
            mono(format!(
                "{} / {}",
                opt_hex(pe.section_alignment.map(u64::from), 0),
                opt_hex(pe.file_alignment.map(u64::from), 0)
            )),
        );
        rows.text(
            &keys[8],
            mono(opt_hex(pe.characteristics.map(u64::from), 4)),
        );
        rows.text(
            &keys[9],
            mono(opt_hex(pe.dll_characteristics.map(u64::from), 4)),
        );
        rows.row(&keys[10], |ui| {
            for flag in &pe.named_flags {
                let field = match flag.field {
                    senbei_engine::windows::FlagField::CoffCharacteristics => "Characteristics",
                    senbei_engine::windows::FlagField::DllCharacteristics => "DllCharacteristics",
                };
                widgets::mono_tag(ui, flag.name)
                    .on_hover_text(format!("{field} {}", format::hex_w(u64::from(flag.bit), 4)));
            }
        });
        rows.row(&keys[11], |ui| {
            ui.label(format::bytes(research.input.input_len));
            ui.label(
                widgets::faint(format!("({})", format::hex(research.input.input_len)))
                    .font(theme::mono_small()),
            );
        });
        if let Some(issue) = &pe.parse_issue {
            rows.text(&keys[12], widgets::toned(note_text(issue), Tone::Warn));
        }
    });
}

fn backing_label(backing: &SectionBacking) -> String {
    match backing {
        SectionBacking::RawTruncated { available } => t(Text::BackingRawTruncated {
            n: format::hex(*available),
        })
        .into_owned(),
        other => tv("backing", other).into_owned(),
    }
}

fn sections_table(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    pe: &PeInspection,
    restored: bool,
    title: String,
    view_note: bool,
) {
    h3(ui, title, None);
    spliced_note(ui, view_note);
    let cols = [
        num_col("#").width(28.0),
        col(t(Text::ColName)).width(80.0),
        num_col("RVA").width(84.0),
        num_col(t(Text::ColVsize)).width(84.0),
        num_col(t(Text::ColRawOffset)).width(130.0),
        num_col(t(Text::ColRawSize)).width(84.0),
        col("RWX").width(40.0),
        col(t(Text::ColCharacteristics)).width(96.0),
        col(t(Text::ColBacking)),
    ];
    let sections = &pe.sections;
    table::table(
        ui,
        ("sections", restored, sections.len()),
        &cols,
        sections.len(),
        |index| table::lines(1 + sections[index].anomalies.len()),
        |index, row| {
            let section = &sections[index];
            let permissions = &section.permissions;
            let rwx = format!(
                "{}{}{}",
                if permissions.read { 'R' } else { '-' },
                if permissions.write { 'W' } else { '-' },
                if permissions.execute { 'X' } else { '-' }
            );
            table::num(row, section.index.to_string());
            table::mono(row, section.name.clone());
            table::num(row, format::hex_w(u64::from(section.virtual_address), 8));
            table::num(row, format::hex_w(u64::from(section.virtual_size), 8));
            let raw = u64::from(section.raw_offset);
            table::cell(row, |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if restored {
                        if widgets::link(ui, &format::hex_w(raw, 8)).clicked() {
                            actions.push(Action::JumpView {
                                view: HexView::Restored,
                                offset: raw,
                            });
                        }
                    } else {
                        off_label(
                            ui,
                            actions,
                            AddressSpace::FileOffset,
                            raw,
                            format::hex_w(raw, 8),
                        );
                    }
                });
            });
            table::num(row, format::hex_w(u64::from(section.raw_size), 8));
            table::mono(row, rwx);
            table::mono(row, format::hex_w(u64::from(section.characteristics), 8));
            table::cell(row, |ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(backing_label(&section.backing));
                    for anomaly in &section.anomalies {
                        ui.label(widgets::faint(note_text(&anomaly.detail)).font(theme::small()));
                    }
                });
            });
        },
    );
}

fn mapping_label(mapping: &DirectoryMapping, pe: &PeInspection) -> String {
    match mapping {
        DirectoryMapping::SectionBacked { section } => {
            let name = pe
                .sections
                .iter()
                .find(|candidate| candidate.index == *section)
                .map_or_else(|| section.to_string(), |candidate| candidate.name.clone());
            t(Text::MappingInSection { s: name }).into_owned()
        }
        DirectoryMapping::PartiallyBacked { backed } => t(Text::MappingPartial {
            n: format::hex(*backed),
        })
        .into_owned(),
        other => tv("mapping", other).into_owned(),
    }
}

fn directories(ui: &mut Ui, actions: &mut Vec<Action>, pe: &PeInspection, view_note: bool) {
    h3(ui, t(Text::RsDirectories), None);
    spliced_note(ui, view_note);
    let cols = [
        num_col("#").width(28.0),
        col(t(Text::ColName)).width(150.0),
        col(t(Text::ColAddress)).width(150.0),
        num_col(t(Text::ColSize)).width(84.0),
        col(t(Text::ColFileOffset)).width(150.0),
        col(t(Text::ColMapping)),
    ];
    let dirs = &pe.directories;
    table::table(
        ui,
        "directories",
        &cols,
        dirs.len(),
        |index| table::lines(if dirs[index].note.is_some() { 2 } else { 1 }),
        |index, row| {
            let dir = &dirs[index];
            let empty = dir.size == 0;
            let faint = |text: String| {
                if empty {
                    widgets::faint(text)
                } else {
                    RichText::new(text)
                }
            };
            table::num(row, dir.index.to_string());
            table::text(row, faint(dir.name.to_owned()).font(theme::mono_small()));
            table::cell(row, |ui| {
                if empty {
                    ui.label(widgets::faint("—"));
                } else {
                    off(ui, actions, dir.address_space, u64::from(dir.address));
                }
            });
            table::num(
                row,
                if empty {
                    String::new()
                } else {
                    format::hex(u64::from(dir.size))
                },
            );
            table::cell(row, |ui| {
                if let (Some(offset), false) = (dir.file_offset, empty) {
                    off(ui, actions, AddressSpace::FileOffset, offset);
                }
            });
            table::cell(row, |ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(faint(mapping_label(&dir.mapping, pe)));
                    if let Some(note) = dir.note {
                        ui.label(widgets::faint(note_text(note)).font(theme::small()));
                    }
                });
            });
        },
    );
}

fn file_regions(ui: &mut Ui, actions: &mut Vec<Action>, pe: &PeInspection) {
    h3(ui, t(Text::RsRegions), None);
    widgets::note(ui, t(Text::ResearchRegionsNote));
    ui.add_space(8.0);
    let regions: Vec<&senbei_engine::windows::FileRegion> =
        pe.unsectioned.iter().chain(pe.overlay.as_ref()).collect();
    if regions.is_empty() {
        ui.label(widgets::faint(t(Text::ResearchRegionsNone)));
        return;
    }
    let cols = [
        col(t(Text::ColKind)).width(260.0),
        col(t(Text::ColFileOffset)).width(150.0),
        num_col(t(Text::ColLength)).width(100.0),
        num_col(""),
    ];
    table::table(
        ui,
        "file-regions",
        &cols,
        regions.len(),
        |_| table::lines(1),
        |index, row| {
            let region = regions[index];
            table::text(row, tv("region", &region.kind).into_owned());
            table::cell(row, |ui| {
                off(ui, actions, AddressSpace::FileOffset, region.offset);
            });
            table::num(row, format::hex(region.length));
            table::num(row, format::bytes(region.length));
        },
    );
}

fn header_table(ui: &mut Ui, actions: &mut Vec<Action>, research: &WindowsResearchReport) {
    let Some(protection) = &research.input.protection else {
        return;
    };
    h3(ui, t(Text::RsHeaderTable), None);
    let key = t(Text::ProtMagic);
    widgets::kv(ui, &[&key], |rows| {
        rows.row(&key, |ui| {
            ui.label(mono(opt_hex(protection.magic.map(u64::from), 8)));
            if protection.magic_recognized {
                widgets::pill(ui, t(Text::ProtMagicOk), Tone::Ok);
            } else {
                widgets::pill(ui, t(Text::ProtMagicBad), Tone::Err);
            }
        });
    });
    h4(ui, t(Text::ProtWords), None);
    let cols = [
        num_col("#").width(28.0),
        col(t(Text::ColSource)).width(150.0),
        col(t(Text::ColRaw)).width(100.0),
        col(t(Text::ColDecoded)).width(100.0),
        col(t(Text::ColMeaning)),
    ];
    let words = &protection.header_words;
    table::table(
        ui,
        "header-words",
        &cols,
        words.len(),
        |_| table::lines(1),
        |index, row| {
            let word = &words[index];
            table::num(row, word.index.to_string());
            table::cell(row, |ui| {
                off(
                    ui,
                    actions,
                    AddressSpace::FileOffset,
                    word.source_file_offset,
                );
            });
            table::mono(row, format::hex_w(u64::from(word.raw_word), 8));
            table::mono(row, format::hex_w(u64::from(word.decoded_word), 8));
            table::cell(row, |ui| {
                if let Some(semantic) = word.semantic {
                    widgets::tag(ui, tv("semantic", &semantic));
                }
            });
        },
    );
}

fn payload(ui: &mut Ui, actions: &mut Vec<Action>, research: &WindowsResearchReport) {
    let Some(protection) = &research.input.protection else {
        return;
    };
    let Some(payload) = &protection.payload else {
        return;
    };
    h3(ui, t(Text::RsPayload), None);
    if !protection.magic_recognized {
        ui.label(widgets::toned(t(Text::PayloadUnrecognized), Tone::Warn).font(theme::small()));
        ui.add_space(8.0);
    }
    let keys = [
        t(Text::PayloadSource),
        t(Text::PayloadDest),
        t(Text::PayloadPrefix),
        t(Text::PayloadTotal),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    widgets::kv(ui, &refs, |rows| {
        rows.row(&keys[0], |ui| {
            off(
                ui,
                actions,
                AddressSpace::FileOffset,
                payload.source_file_offset,
            );
        });
        rows.row(&keys[1], |ui| {
            off(
                ui,
                actions,
                AddressSpace::WorkingImageRva,
                u64::from(payload.destination_rva),
            );
        });
        rows.row(&keys[2], |ui| hex_and_bytes(ui, payload.prefix_length));
        rows.row(&keys[3], |ui| hex_and_bytes(ui, payload.total_length));
    });
    h4(ui, t(Text::PayloadChecks), None);
    let cols = [
        col(t(Text::ColCheck)).width(150.0),
        num_col(t(Text::ColStart)).width(90.0),
        num_col(t(Text::ColLength)).width(90.0),
        num_col(t(Text::ColEnd)).width(90.0),
        num_col(t(Text::ColLimit)).width(90.0),
        col(""),
    ];
    let checks = &payload.checks;
    table::table(
        ui,
        "payload-checks",
        &cols,
        checks.len(),
        |_| table::lines(1),
        |index, row| {
            let check = &checks[index];
            table::mono(row, check.name.to_owned());
            table::num(row, format::hex(check.start));
            table::num(row, format::hex(check.length));
            table::num(row, format::hex(check.end));
            table::num(row, format::hex(check.limit));
            if check.in_bounds && !check.overflow {
                table::text(
                    row,
                    widgets::toned(format!("✓ {}", t(Text::PayloadInBounds)), Tone::Ok),
                );
            } else {
                table::text(
                    row,
                    widgets::toned(format!("✕ {}", t(Text::PayloadOutOfBounds)), Tone::Err),
                );
            }
        },
    );
    let probe = &protection.probe;
    h4(ui, t(Text::PayloadProbe), None);
    let keys = [
        t(Text::ColStatus),
        t(Text::PayloadDecoded),
        t(Text::PayloadFirstWords),
        t(Text::ColNote),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    widgets::kv(ui, &refs, |rows| {
        rows.text(&keys[0], tv("probe", &probe.status).into_owned());
        rows.row(&keys[1], |ui| {
            ui.label(format!(
                "{} / {}",
                format::bytes(probe.decoded_length),
                format::bytes(probe.requested_length)
            ));
            ui.label(widgets::faint(format!(
                "({})",
                t(Text::PayloadLimit {
                    l: format::bytes(probe.limit_bytes),
                })
            )));
        });
        rows.text(
            &keys[2],
            mono(
                probe
                    .first_words
                    .iter()
                    .map(|word| format::hex_w(u64::from(*word), 8))
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
        );
        if let Some(reason) = probe.reason
            && !labels::is_quiet(reason)
        {
            rows.row(&keys[3], |ui| {
                widgets::code_spans(ui, &note_text(reason));
            });
        }
    });
}

fn discovery(ui: &mut Ui, actions: &mut Vec<Action>, research: &WindowsResearchReport) {
    let Some(protection) = &research.input.protection else {
        return;
    };
    let report = &protection.discovery;
    h3(
        ui,
        t(Text::RsDiscovery),
        Some(format!(
            "{} · {}",
            tv("probe", &report.status),
            t(Text::DiscScanned {
                n: format::num(u64::from(report.positions_scanned)),
            })
        )),
    );
    if let Some(reason) = report.reason
        && !labels::is_quiet(reason)
    {
        widgets::note(ui, note_text(reason));
        ui.add_space(8.0);
    }
    if report.candidates.is_empty() {
        ui.label(widgets::faint(t(Text::DiscNone)));
        return;
    }
    for candidate in &report.candidates {
        let status = candidate.status;
        let tone = if matches!(
            status,
            senbei_engine::windows::CandidateStatus::StructuralCandidate
                | senbei_engine::windows::CandidateStatus::TrialValidated
        ) {
            Tone::Info
        } else {
            Tone::Skip
        };
        let title = tv("shellKind", &candidate.kind).into_owned();
        let actions = &mut *actions;
        widgets::wide_card(
            ui,
            CardSpec::new(title, |ui| {
                let mut keys: Vec<String> = vec![
                    t(Text::DiscPayloadOffset).into_owned(),
                    t(Text::DiscImageRva).into_owned(),
                    t(Text::DiscSource).into_owned(),
                ];
                keys.extend(candidate.fields.iter().map(|field| field.name.to_owned()));
                let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
                widgets::kv(ui, &refs, |rows| {
                    rows.row(&keys[0], |ui| match candidate.payload_offset {
                        Some(offset) => {
                            off(ui, actions, AddressSpace::DecodedPayloadOffset, offset)
                        }
                        None => {
                            ui.label("—");
                        }
                    });
                    rows.row(&keys[1], |ui| match candidate.image_rva {
                        Some(rva) => {
                            off(ui, actions, AddressSpace::WorkingImageRva, u64::from(rva))
                        }
                        None => {
                            ui.label("—");
                        }
                    });
                    rows.row(&keys[2], |ui| match candidate.source_file_offset {
                        Some(offset) => off(ui, actions, AddressSpace::FileOffset, offset),
                        None => {
                            ui.label("—");
                        }
                    });
                    for field in &candidate.fields {
                        rows.row(field.name, |ui| match field.space {
                            Some(space) => off(ui, actions, space, u64::from(field.value)),
                            None => {
                                ui.label(mono(format::hex(u64::from(field.value))));
                            }
                        });
                    }
                });
                if !labels::is_quiet(candidate.reason) {
                    ui.add_space(8.0);
                    widgets::note(ui, note_text(candidate.reason));
                }
            })
            .aside(move |ui| {
                widgets::pill(ui, tv("candidate", &status), tone);
            }),
        );
        ui.add_space(10.0);
    }
}

fn trace_value(ui: &mut Ui, value: &TraceValue) {
    match value {
        TraceValue::U32(number) => {
            ui.label(mono(format::hex(u64::from(*number))));
            ui.label(widgets::faint(format::num(u64::from(*number))));
        }
        TraceValue::U64(number) => {
            ui.label(mono(format::hex(*number)));
            ui.label(widgets::faint(format::num(*number)));
        }
        TraceValue::Bool(flag) => {
            ui.label(mono(flag.to_string()).color(theme::INFO));
        }
        TraceValue::Text(text) => {
            ui.label(mono(text.clone()).color(theme::STRING));
        }
        TraceValue::U32s(values) => {
            ui.label(mono(
                values
                    .iter()
                    .map(|value| format::hex(u64::from(*value)))
                    .collect::<Vec<_>>()
                    .join(" "),
            ));
        }
        TraceValue::Range { start, length } => {
            ui.label(mono(format!(
                "{} +{}",
                format::hex(*start),
                format::hex(*length)
            )));
        }
    }
}

fn trace(ui: &mut Ui, actions: &mut Vec<Action>, trace: &ResearchTrace) {
    let mut stages: Vec<Vec<&ResearchEvent>> = Vec::new();
    for event in &trace.events {
        match stages.last_mut() {
            Some(last) if last[0].stage == event.stage => last.push(event),
            _ => stages.push(vec![event]),
        }
    }
    h3(
        ui,
        t(Text::RsTrace),
        Some(
            t(Text::TraceSummary {
                n: trace.events.len().to_string(),
                s: stages.len().to_string(),
            })
            .into_owned(),
        ),
    );
    if trace.truncated {
        ui.label(widgets::toned(
            t(Text::TraceTruncated {
                n: trace.dropped.to_string(),
                l: trace.limit.to_string(),
            }),
            Tone::Warn,
        ));
        ui.add_space(6.0);
    }
    for (index, events) in stages.iter().enumerate() {
        let stage = events[0].stage;
        let header = RichText::new(tv("traceStage", &stage)).font(theme::strong(12.5));
        Frame::new()
            .fill(theme::BG)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(CornerRadius::same(4))
            .inner_margin(Margin::symmetric(10, 4))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                egui::CollapsingHeader::new(header)
                    .id_salt(("trace", index))
                    .default_open(index < 6)
                    .show(ui, |ui| {
                        ui.label(
                            widgets::faint(t(Text::TraceEvents {
                                n: events.len().to_string(),
                            }))
                            .font(theme::small()),
                        );
                        let has_notes = events.iter().any(|event| event.note.is_some());
                        let cols = [
                            col(t(Text::ColName)).width(170.0),
                            col(t(Text::ColValue)).width(260.0),
                            col(t(Text::ColAddress)).width(150.0),
                            col(if has_notes {
                                t(Text::ColNote).into_owned()
                            } else {
                                String::new()
                            }),
                        ];
                        table::table(
                            ui,
                            ("trace-table", index),
                            &cols,
                            events.len(),
                            |_| table::lines(1),
                            |row_index, row| {
                                let event = events[row_index];
                                table::mono(row, event.name.to_owned());
                                table::cell(row, |ui| trace_value(ui, &event.value));
                                table::cell(row, |ui| {
                                    if let Some(address) = &event.address {
                                        off(ui, actions, address.space, address.offset);
                                    }
                                });
                                table::text(
                                    row,
                                    widgets::dim(event.note.map(note_text).unwrap_or_default()),
                                );
                            },
                        );
                    });
            });
        ui.add_space(8.0);
    }
}

fn issue_table(ui: &mut Ui, id: &str, issues: &[&senbei_engine::windows::InspectionIssue]) {
    let cols = [
        col(t(Text::ColSeverity)).width(100.0),
        col(t(Text::ColArea)).width(140.0),
        col(t(Text::ColMessage)),
    ];
    table::table(
        ui,
        id,
        &cols,
        issues.len(),
        |_| table::lines(1),
        |index, row| {
            let issue = issues[index];
            table::text(row, tv("severity", &issue.severity).into_owned());
            table::mono(row, issue.area.to_owned());
            table::cell(row, |ui| {
                widgets::code_spans(ui, &note_text(&issue.message));
            });
        },
    );
}

fn issues(ui: &mut Ui, research: &WindowsResearchReport) {
    h3(ui, t(Text::RsIssues), None);
    let list = input_issues(research);
    if list.is_empty() {
        ui.label(widgets::faint(t(Text::IssuesNone)));
    } else {
        issue_table(ui, "input-issues", &list);
    }
    let work = &research.input.work;
    h4(ui, t(Text::IssuesWork), None);
    let keys = [
        t(Text::IssuesScratch),
        t(Text::IssuesCandidates),
        t(Text::IssuesBudget),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    widgets::kv(ui, &refs, |rows| {
        rows.text(
            &keys[0],
            format!(
                "{} / {}",
                format::bytes(work.prefix_bytes_decoded),
                format::bytes(work.prefix_scratch_limit)
            ),
        );
        rows.text(&keys[1], format::num(u64::from(work.candidates_considered)));
        rows.text(
            &keys[2],
            if work.budget_limited {
                widgets::toned(t(Text::CommonYes), Tone::Warn)
            } else {
                RichText::new(t(Text::CommonNo))
            },
        );
    });
}

fn restored(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    research: &WindowsResearchReport,
    comparable: bool,
) {
    let Some(restored) = &research.restored else {
        return;
    };
    h3(ui, t(Text::RsRestored), None);
    if let Some(pe) = &restored.pe {
        sections_table(
            ui,
            actions,
            pe,
            true,
            t(Text::RsSections).into_owned(),
            false,
        );
    }
    let observations = restored_issues(restored);
    if !observations.is_empty() {
        h4(ui, t(Text::RestoredObservations), None);
        issue_table(ui, "restored-issues", &observations);
    }
    if comparable {
        ui.add_space(12.0);
        if ui.button(t(Text::RestoredOpenCompare)).clicked() {
            actions.push(Action::Tab(Tab::Compare));
        }
    }
}

// --------------------------------------------------------------- Android

const FILE_OFFSET_FIELDS: [&str; 4] = [
    "section_offset",
    "header_offset",
    "stage2_file_offset",
    "remaining_file_offset",
];

fn number_value(ui: &mut Ui, value: u64) {
    ui.label(mono(format::hex(value)));
    ui.label(widgets::faint(format::num(value)));
}

fn stage1(ui: &mut Ui, actions: &mut Vec<Action>, extraction: &Value) {
    h3(ui, t(Text::RsAStage1), None);
    let Some(stage1) = extraction.get("stage1").and_then(Value::as_object) else {
        return;
    };
    let keys: Vec<&str> = stage1.keys().map(String::as_str).collect();
    widgets::kv(ui, &keys, |rows| {
        for (key, value) in stage1 {
            rows.row(key, |ui| match value.as_u64() {
                Some(number) if FILE_OFFSET_FIELDS.contains(&key.as_str()) => {
                    off(ui, actions, AddressSpace::FileOffset, number);
                }
                Some(number) => number_value(ui, number),
                None => {
                    ui.label(mono(leaf_text(value)));
                }
            });
        }
    });
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

fn json_text(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn hex_field(value: &Value, key: &str, width: usize) -> String {
    json_u64(value, key).map_or_else(String::new, |number| format::hex_w(number, width))
}

fn streams(ui: &mut Ui, actions: &mut Vec<Action>, extraction: &Value, subject: &Subject<'_>) {
    h3(ui, t(Text::RsAStreams), None);
    widgets::note(ui, t(Text::ResearchAStreamsNote));
    ui.add_space(8.0);
    let empty = Vec::new();
    let streams = extraction
        .get("streams")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for (index, stream) in streams.iter().enumerate() {
        let decoder = stream.get("decoder").cloned().unwrap_or(Value::Null);
        let records = stream
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let summary = t(Text::StreamsSummary {
            d: json_text(stream, "depth"),
            k: json_text(&decoder, "kind"),
            n: records.len().to_string(),
            s: format::bytes(json_u64(stream, "available_size").unwrap_or(0)),
        })
        .into_owned();
        Frame::new()
            .fill(theme::BG)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(CornerRadius::same(4))
            .inner_margin(Margin::symmetric(10, 4))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let header = RichText::new(format!(
                    "{}   {summary}",
                    t(Text::StreamsTitle {
                        id: json_text(stream, "stream_id"),
                    })
                ))
                .font(theme::strong(12.5));
                egui::CollapsingHeader::new(header)
                    .id_salt(("stream", subject.item, subject.entry, index))
                    .default_open(index < 3)
                    .show(ui, |ui| {
                        stream_body(ui, actions, stream, &decoder, &records, index, subject);
                    });
            });
        ui.add_space(8.0);
    }
}

fn stream_body(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    stream: &Value,
    decoder: &Value,
    records: &[Value],
    index: usize,
    subject: &Subject<'_>,
) {
    let origin = match stream.get("parent").filter(|parent| parent.is_object()) {
        Some(parent) => t(Text::StreamsParent {
            s: json_text(parent, "stream_id"),
            r: json_text(parent, "record_index"),
            c: hex_field(parent, "command_id", 0),
        })
        .into_owned(),
        None => t(Text::StreamsRoot).into_owned(),
    };
    let keys = [
        t(Text::StreamsOrigin).into_owned(),
        t(Text::ColFileOffset).into_owned(),
        t(Text::ColSize).into_owned(),
        "SHA-256".to_owned(),
        "header_seed".to_owned(),
        "container_seed".to_owned(),
        "schedule_offset".to_owned(),
        "aes_key_sha256".to_owned(),
    ];
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    widgets::kv(ui, &refs, |rows| {
        rows.text(&keys[0], origin);
        if let Some(offset) = json_u64(stream, "source_file_offset") {
            rows.row(&keys[1], |ui| {
                off(ui, actions, AddressSpace::FileOffset, offset)
            });
        }
        rows.text(&keys[2], mono(hex_field(stream, "available_size", 0)));
        rows.row(&keys[3], |ui| hash(ui, &json_text(stream, "sha256")));
        rows.text(&keys[4], mono(hex_field(decoder, "header_seed", 8)));
        rows.text(&keys[5], mono(hex_field(decoder, "container_seed", 8)));
        rows.text(&keys[6], mono(hex_field(decoder, "schedule_offset", 0)));
        rows.row(&keys[7], |ui| {
            hash(ui, &json_text(decoder, "aes_key_sha256"))
        });
    });
    if records.is_empty() {
        return;
    }
    h4(
        ui,
        t(Text::StreamsRecords),
        Some(format!(
            "{} · {}: {}",
            t(Text::ColImage),
            t(Text::ColMetadata),
            t(Text::ColOffsetSize)
        )),
    );
    // The engine writes "complete" for every record today; the column shows
    // only when one differs.
    let show_status = records
        .iter()
        .any(|record| json_text(record, "extraction_status") != "complete");
    let mut cols = vec![
        num_col("#").width(28.0),
        num_col(t(Text::ColCommand)).width(70.0),
        num_col(t(Text::ColFlags)).width(56.0),
        num_col(t(Text::ColImage)).width(130.0),
        num_col(t(Text::ColMetadata)).width(130.0),
        num_col(t(Text::ColEntry)).width(80.0),
        num_col(t(Text::ColInit)).width(80.0),
        col(t(Text::ColDirect)).width(50.0),
    ];
    if show_status {
        cols.push(col(t(Text::ColStatus)).width(90.0));
    }
    cols.push(num_col(t(Text::ColNested)));
    let span = |record: &Value, offset: &str, size: &str| {
        format!(
            "{} +{}",
            hex_field(record, offset, 0),
            hex_field(record, size, 0)
        )
    };
    table::table(
        ui,
        ("records", subject.item, subject.entry, index),
        &cols,
        records.len(),
        |_| table::lines(1),
        |row_index, row| {
            let record = &records[row_index];
            table::num(row, json_text(record, "index"));
            table::num(row, hex_field(record, "command_id", 0));
            table::num(row, hex_field(record, "flags", 0));
            table::num(row, span(record, "image_offset", "image_size"));
            table::num(row, span(record, "metadata_offset", "metadata_size"));
            table::num(row, hex_field(record, "entry_offset", 0));
            table::num(row, hex_field(record, "init_offset", 0));
            table::text(
                row,
                if record.get("direct").and_then(Value::as_bool) == Some(true) {
                    "✓"
                } else {
                    ""
                },
            );
            if show_status {
                table::mono(row, json_text(record, "extraction_status"));
            }
            table::num(row, json_text(record, "nested_stream_id"));
        },
    );
}

fn hash(ui: &mut Ui, sha256: &str) {
    if sha256.is_empty() {
        ui.label("—");
    } else {
        super::detail::hash_row(ui, sha256);
    }
}

fn short(sha256: &str) -> String {
    let head: String = sha256.chars().take(12).collect();
    format!("{head}…")
}

fn modules(ui: &mut Ui, extraction: &Value, subject: &Subject<'_>) {
    h3(ui, t(Text::RsAModules), None);
    let empty = Vec::new();
    let modules = extraction
        .get("module_registry")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let cols = [
        num_col(t(Text::ColCommand)).width(80.0),
        num_col(t(Text::ColDepth)).width(56.0),
        col(t(Text::ColClassification)).width(160.0),
        num_col(t(Text::ColEntry)).width(90.0),
        num_col(t(Text::ColInit)).width(90.0),
        num_col(t(Text::ColSize)).width(90.0),
        col("SHA-256"),
    ];
    table::table(
        ui,
        ("modules", subject.item, subject.entry),
        &cols,
        modules.len(),
        |_| table::lines(1),
        |index, row| {
            let module = &modules[index];
            table::num(row, hex_field(module, "command_id", 0));
            table::num(row, json_text(module, "depth"));
            table::mono(row, json_text(module, "classification"));
            table::num(row, hex_field(module, "entry_offset", 0));
            table::num(row, hex_field(module, "init_offset", 0));
            table::num(row, format::bytes(json_u64(module, "size").unwrap_or(0)));
            table::text(
                row,
                widgets::faint(short(&json_text(module, "sha256"))).font(theme::mono_small()),
            );
        },
    );
}

fn artifacts(ui: &mut Ui, extraction: &Value, subject: &Subject<'_>) {
    h3(ui, t(Text::RsAArtifacts), None);
    widgets::note(ui, t(Text::ResearchAArtifactsNote));
    ui.add_space(8.0);
    let empty = Vec::new();
    let artifacts = extraction
        .get("artifacts")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let cols = [
        num_col(t(Text::ColDepth)).width(56.0),
        num_col(t(Text::ColStream)).width(64.0),
        num_col(t(Text::ColCommand)).width(80.0),
        col(t(Text::ColKind)).width(120.0),
        col(t(Text::ColClassification)).width(160.0),
        num_col(t(Text::ColSize)).width(90.0),
        col("SHA-256"),
    ];
    table::table(
        ui,
        ("artifacts", subject.item, subject.entry),
        &cols,
        artifacts.len(),
        |_| table::lines(1),
        |index, row| {
            let artifact = &artifacts[index];
            table::num(row, json_text(artifact, "depth"));
            table::num(row, json_text(artifact, "stream_id"));
            table::num(row, hex_field(artifact, "command_id", 0));
            table::mono(row, json_text(artifact, "kind"));
            table::mono(row, json_text(artifact, "classification"));
            table::num(row, format::bytes(json_u64(artifact, "size").unwrap_or(0)));
            table::text(
                row,
                widgets::faint(short(&json_text(artifact, "sha256"))).font(theme::mono_small()),
            );
        },
    );
}

fn redacted(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        ["<input>", "<output>", "<workspace>"]
            .iter()
            .any(|label| text.contains(label))
    })
}

fn restoration_section(ui: &mut Ui, restoration: &Value, key: &str, subject: &Subject<'_>) {
    if key == "*" {
        h3(ui, t(Text::RsAScalars), None);
        let scalars: serde_json::Map<String, Value> = restoration
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter(|(_, value)| {
                        !value.is_object() && !value.is_array() && !redacted(value)
                    })
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        json_tree(
            ui,
            ("a_r", subject.item, subject.entry, key),
            &Value::Object(scalars),
            false,
        );
        return;
    }
    let title = RESTORATION
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, text)| t(text.clone()).into_owned())
        .unwrap_or_else(|| key.to_owned());
    h3(ui, title, None);
    if let Some(value) = restoration.get(key) {
        json_tree(ui, ("a_r", subject.item, subject.entry, key), value, false);
    }
}

// -------------------------------------------------------------- metadata

fn metadata_report(ui: &mut Ui, metadata: &Value, subject: &Subject<'_>) {
    let route = metadata
        .get("route")
        .and_then(Value::as_str)
        .map(|route| tv_str("layout", &format!("metadata_{route}")).into_owned())
        .unwrap_or_else(|| "—".into());
    h3(
        ui,
        t(Text::RsMReport),
        Some(t(Text::MetaRoute { r: route }).into_owned()),
    );
    if let Some(error) = metadata.get("discovery_error").and_then(Value::as_str) {
        widgets::note(ui, t(Text::MetaDiscoveryError));
        widgets::selectable(ui, mono(error).color(theme::DIM));
        ui.add_space(8.0);
    }
    if let Some(report) = metadata.get("report") {
        json_tree(ui, ("m_report", subject.item, subject.entry), report, false);
    }
}

fn metadata_images(ui: &mut Ui, metadata: &Value, subject: &Subject<'_>) {
    h3(ui, t(Text::RsMImages), None);
    let empty = Vec::new();
    let images = metadata
        .get("discovery")
        .and_then(|discovery| discovery.get("images"))
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let cols = [
        num_col(t(Text::MetaImage)).width(60.0),
        num_col(t(Text::MetaMethods)).width(90.0),
        num_col(t(Text::MetaModulus)).width(90.0),
        col(t(Text::MetaClean)).width(90.0),
        col(t(Text::MetaSeedResidues)),
    ];
    table::table(
        ui,
        ("m_images", subject.item, subject.entry),
        &cols,
        images.len(),
        |_| table::lines(1),
        |index, row| {
            let image = &images[index];
            table::num(row, json_text(image, "image"));
            table::num(
                row,
                json_u64(image, "method_count")
                    .map(format::num)
                    .unwrap_or_default(),
            );
            table::num(
                row,
                json_u64(image, "modulus")
                    .map(format::num)
                    .unwrap_or_default(),
            );
            if image.get("clean").and_then(Value::as_bool) == Some(true) {
                table::text(row, widgets::toned("✓", Tone::Ok));
            } else {
                table::text(row, widgets::toned(t(Text::MetaResidues), Tone::Warn));
            }
            let residues = image
                .get("seed_residues")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            table::mono(row, residues);
        },
    );
}

// ------------------------------------------------------------- JSON tree

fn leaf_text(value: &Value) -> String {
    match value {
        Value::String(text) => format!("\"{text}\""),
        Value::Number(number) => match number.as_u64() {
            Some(value) if value > 255 => format!("{} {}", format::hex(value), format::num(value)),
            _ => number.to_string(),
        },
        other => other.to_string(),
    }
}

fn leaf(ui: &mut Ui, key: &str, value: &Value) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.add_space(14.0);
        ui.label(
            RichText::new(key)
                .font(theme::mono_small())
                .color(theme::DIM),
        );
        match value {
            Value::String(text) => {
                widgets::selectable(
                    ui,
                    RichText::new(format!("\"{text}\""))
                        .font(theme::mono_small())
                        .color(theme::STRING),
                );
            }
            Value::Number(number) => match number.as_u64() {
                Some(value) if value > 255 => {
                    widgets::selectable(
                        ui,
                        RichText::new(format::hex(value)).font(theme::mono_small()),
                    );
                    ui.label(widgets::faint(format::num(value)).font(theme::mono_small()));
                }
                _ => {
                    widgets::selectable(
                        ui,
                        RichText::new(number.to_string()).font(theme::mono_small()),
                    );
                }
            },
            other => {
                ui.label(
                    RichText::new(other.to_string())
                        .font(theme::mono_small())
                        .color(theme::INFO),
                );
            }
        }
    });
}

fn json_tree(ui: &mut Ui, id: impl egui::AsIdSalt, value: &Value, open: bool) {
    let id = ui.make_persistent_id(id);
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        json_children(ui, id, value, 0, open);
    });
}

fn json_children(ui: &mut Ui, id: egui::Id, value: &Value, depth: usize, open: bool) {
    let entries: Vec<(String, &Value)> = match value {
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| (key.clone(), value))
            .collect(),
        Value::Array(array) => array
            .iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .collect(),
        other => {
            leaf(ui, "", other);
            return;
        }
    };
    for (key, child) in entries {
        match child {
            Value::Object(_) | Value::Array(_) => {
                let count = match child {
                    Value::Array(array) => format!("[{}]", array.len()),
                    Value::Object(object) => format!("{{{}}}", object.len()),
                    _ => String::new(),
                };
                let header = RichText::new(format!("{key} {count}"))
                    .font(theme::mono_small())
                    .color(theme::DIM);
                let child_id = id.with(&key);
                egui::CollapsingHeader::new(header)
                    .id_salt(child_id)
                    .default_open(open || depth < 1)
                    .show(ui, |ui| json_children(ui, child_id, child, depth + 1, open));
            }
            _ => leaf(ui, &key, child),
        }
    }
}
