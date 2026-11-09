//! The hex view: the original file, its spliced view, or the restored image,
//! with regions, a byte inspector, go-to, and find.

use std::collections::HashMap;
use std::sync::Arc;

use egui::text::LayoutJob;
use egui::{
    Align, Color32, CornerRadius, FontId, Key, Layout, Margin, Rect, RichText, ScrollArea, Sense,
    Stroke, StrokeKind, TextFormat, Ui, UiBuilder, pos2, vec2,
};
use senbei_engine::windows::PeInspection;
use senbei_io::report::{CompanionState, EntryReport, ResearchInputView};
use serde_json::Value;

use super::{Action, Draw, HexState, HexView, Loaded, Session, ViewState, widgets};
use crate::backend::{Identity, Produced, Source};
use crate::format;
use crate::labels::{self, tv};
use crate::model::{Item, Sel};
use crate::text::{Text, t};
use crate::theme;

/// What the hex view shows bytes of.
#[derive(Clone, Copy)]
pub enum Subject<'a> {
    Item(&'a Item),
    Entry {
        item: &'a Item,
        entry: &'a EntryReport,
    },
}

impl<'a> Subject<'a> {
    fn item(&self) -> &'a Item {
        match self {
            Subject::Item(item) | Subject::Entry { item, .. } => item,
        }
    }

    fn windows(&self) -> Option<&'a senbei_io::report::WindowsResearchReport> {
        match self {
            Subject::Item(item) => item.result.as_ref()?.report.research.as_ref(),
            Subject::Entry { .. } => None,
        }
    }

    fn android(&self) -> Option<&'a senbei_io::report::AndroidResearchReport> {
        match self {
            Subject::Item(item) => item.result.as_ref()?.report.android_research.as_ref(),
            Subject::Entry { entry, .. } => entry.android_research.as_ref(),
        }
    }

    /// The `._` file this loader is spliced with, when it is.
    fn companion(&self) -> Option<std::path::PathBuf> {
        let Subject::Item(item) = self else {
            return None;
        };
        match (&item.result, &item.identity) {
            (Some(result), _) => {
                let companion = result.report.companion.as_ref()?;
                (companion.state == CompanionState::Spliced)
                    .then(|| companion.path.clone().map(Into::into))
                    .flatten()
            }
            (
                None,
                Some(Identity::Windows {
                    companion: CompanionState::Spliced,
                    companion_path: Some(path),
                    ..
                }),
            ) => Some(path.into()),
            _ => None,
        }
    }

    fn restored(&self) -> Option<&'a Produced> {
        match self {
            Subject::Item(item) => item.result.as_ref()?.restored.as_ref(),
            Subject::Entry { item, entry, .. } => item.result.as_ref()?.entry_bytes(&entry.name),
        }
    }
}

/// The subject a selection shows, if it has bytes.
fn subject_of(session: &Session, sel: Option<Sel>) -> Option<Subject<'_>> {
    match sel? {
        Sel::Group(_) => None,
        Sel::Item(id) => session.item(id).map(|(_, item)| Subject::Item(item)),
        Sel::Entry(id, index) => {
            let (_, item) = session.item(id)?;
            let entry = item.entries().get(index)?;
            Some(Subject::Entry { item, entry })
        }
    }
}

/// Where a view's bytes come from.
enum Origin {
    Bytes(Arc<[u8]>),
    Load(Source),
    Note(Text),
}

fn views(subject: &Subject<'_>) -> Vec<HexView> {
    let mut views = vec![HexView::Original];
    if subject.companion().is_some() {
        views.push(HexView::Spliced);
    }
    if matches!(
        subject.restored(),
        Some(Produced::Kept(_) | Produced::OnDisk(_) | Produced::TooLarge(_))
    ) {
        views.push(HexView::Restored);
    }
    views
}

fn origin(subject: &Subject<'_>, view: HexView) -> Option<Origin> {
    match view {
        HexView::Original => Some(Origin::Load(match subject {
            Subject::Item(item) => Source::File(item.path.clone()),
            Subject::Entry { item, entry, .. } => Source::Entry {
                package: item.path.clone(),
                label: entry.name.clone(),
            },
        })),
        HexView::Spliced => Some(Origin::Load(Source::Spliced {
            stub: subject.item().path.clone(),
            companion: subject.companion()?,
        })),
        HexView::Restored => match subject.restored()? {
            Produced::Kept(bytes) => Some(Origin::Bytes(bytes.clone())),
            Produced::OnDisk(path) => Some(Origin::Load(Source::File(path.clone()))),
            Produced::TooLarge(_) => Some(Origin::Note(Text::SettingsKeepCapHelp)),
            Produced::NotKept => None,
        },
    }
}

fn current_view(subject: &Subject<'_>, state: &HexState) -> HexView {
    let views = views(subject);
    match state.view {
        Some(view) if views.contains(&view) => view,
        _ if views.contains(&HexView::Spliced) => HexView::Spliced,
        _ => HexView::Original,
    }
}

/// The bytes the hex view shows for the selection, when they are loaded.
pub fn current_bytes(
    session: &Session,
    loaded: &HashMap<Source, Loaded>,
    view: &ViewState,
) -> Option<Arc<[u8]>> {
    let subject = subject_of(session, view.selected)?;
    match origin(&subject, current_view(&subject, &view.hex))? {
        Origin::Bytes(bytes) => Some(bytes),
        Origin::Load(source) => match loaded.get(&source)? {
            Loaded::Ready(bytes) => Some(bytes.clone()),
            _ => None,
        },
        Origin::Note(_) => None,
    }
}

/// Find the needle after the cursor.
pub fn find(bytes: &[u8], state: &mut HexState) {
    let needle = format::parse_needle(&state.find);
    if needle.is_empty() {
        return;
    }
    let from = state
        .focus
        .map_or(0, |focus| (focus as usize).saturating_add(1));
    let found = bytes.get(from..).and_then(|rest| {
        rest.windows(needle.len())
            .position(|window| window == needle)
    });
    match found {
        Some(position) => {
            let at = (from + position) as u64;
            state.focus = Some(at);
            state.highlight = Some((at, at + needle.len() as u64));
            state.note = None;
            state.reveal = true;
        }
        None => state.note = Some(t(Text::HexFindNone).into_owned()),
    }
}

// ------------------------------------------------------------- addresses

/// The file offset of `rva` in an image, if a section or the headers back it.
pub fn rva_to_offset(pe: Option<&PeInspection>, rva: u64) -> Option<u64> {
    let pe = pe?;
    for section in &pe.sections {
        let start = u64::from(section.virtual_address);
        let span = u64::from(section.virtual_size.max(section.raw_size));
        if rva >= start && rva < start + span {
            let delta = rva - start;
            return (delta < u64::from(section.raw_size))
                .then(|| u64::from(section.raw_offset) + delta);
        }
    }
    (rva < u64::from(pe.size_of_headers.unwrap_or(0))).then_some(rva)
}

/// The RVA a file offset maps to, with its section's name.
pub fn offset_to_rva(pe: Option<&PeInspection>, offset: u64) -> Option<(u64, Option<&str>)> {
    let pe = pe?;
    for section in &pe.sections {
        let start = u64::from(section.raw_offset);
        if offset >= start && offset < start + u64::from(section.raw_size) {
            return Some((
                u64::from(section.virtual_address) + (offset - start),
                Some(section.name.as_str()),
            ));
        }
    }
    (offset < u64::from(pe.size_of_headers.unwrap_or(0))).then_some((offset, None))
}

/// The PE headers that describe a view's bytes.
fn view_pe<'a>(subject: &Subject<'a>, view: HexView) -> Option<&'a PeInspection> {
    let research = subject.windows()?;
    match view {
        HexView::Restored => research.restored.as_ref()?.pe.as_ref(),
        // The research offsets address the spliced view; the bare loader
        // shares only its header page with it.
        HexView::Original if research.input_view == ResearchInputView::SplicedCompanion => None,
        _ => research.input.pe.as_ref(),
    }
}

// --------------------------------------------------------------- regions

pub struct Region {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub color: Color32,
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

fn elf_regions(subject: &Subject<'_>, view: HexView, bytes: &[u8]) -> Vec<Region> {
    let mut regions = Vec::new();
    if bytes.len() >= 0x40 && bytes.starts_with(b"\x7fELF") {
        let program_headers = le_u64(bytes, 0x20).unwrap_or(0);
        let entry_size = u64::from(le_u16(bytes, 0x36).unwrap_or(0));
        let count = u64::from(le_u16(bytes, 0x38).unwrap_or(0));
        regions.push(Region {
            name: t(Text::HexRElfHeader).into_owned(),
            start: 0,
            end: 0x40,
            color: theme::REGION_HEADERS,
        });
        regions.push(Region {
            name: t(Text::HexRProgramHeaders).into_owned(),
            start: program_headers,
            end: program_headers + entry_size * count,
            color: theme::REGION_OTHER,
        });
        let mut load = 0;
        for index in 0..count {
            let Ok(at) = usize::try_from(program_headers + index * entry_size) else {
                break;
            };
            if at + 0x38 > bytes.len() {
                break;
            }
            if le_u32(bytes, at) != Some(1) {
                continue;
            }
            let start = le_u64(bytes, at + 8).unwrap_or(0);
            let size = le_u64(bytes, at + 0x20).unwrap_or(0);
            regions.push(Region {
                name: t(Text::HexRLoad {
                    n: load.to_string(),
                })
                .into_owned(),
                start,
                end: start + size,
                color: theme::SECTION_COLORS[load % theme::SECTION_COLORS.len()],
            });
            load += 1;
        }
    }
    if view == HexView::Original
        && let Some(stage1) = subject
            .android()
            .and_then(|research| research.extraction.get("stage1"))
    {
        let span = |offset: &str, size: &str| -> Option<(u64, u64)> {
            let start = json_u64(stage1, offset)?;
            Some((start, start + json_u64(stage1, size)?))
        };
        for (name, offset, size, color) in [
            (
                Text::HexRPrivateSection,
                "section_offset",
                "section_size",
                theme::REGION_PROTECTION,
            ),
            (
                Text::HexRStage2,
                "stage2_file_offset",
                "stage2_size",
                theme::REGION_PREFIX,
            ),
            (
                Text::HexRStreams,
                "remaining_file_offset",
                "remaining_size",
                theme::REGION_TAIL,
            ),
        ] {
            if let Some((start, end)) = span(offset, size) {
                regions.push(Region {
                    name: t(name).into_owned(),
                    start,
                    end,
                    color,
                });
            }
        }
    }
    regions
}

fn regions(subject: &Subject<'_>, view: HexView, bytes: &[u8]) -> Vec<Region> {
    if subject.android().is_some() || bytes.starts_with(b"\x7fELF") {
        return elf_regions(subject, view, bytes);
    }
    let mut regions = Vec::new();
    let Some(research) = subject.windows() else {
        return regions;
    };
    let section_regions = |regions: &mut Vec<Region>, pe: &PeInspection, restored: bool| {
        for (index, section) in pe.sections.iter().enumerate() {
            let start = u64::from(section.raw_offset);
            regions.push(Region {
                name: section.name.clone(),
                start,
                end: if restored {
                    start + u64::from(section.raw_size)
                } else {
                    section.raw_end
                },
                color: theme::SECTION_COLORS[index % theme::SECTION_COLORS.len()],
            });
        }
    };
    if view == HexView::Restored {
        if let Some(pe) = research
            .restored
            .as_ref()
            .and_then(|restored| restored.pe.as_ref())
        {
            regions.push(Region {
                name: t(Text::HexRHeaders).into_owned(),
                start: 0,
                end: u64::from(pe.size_of_headers.unwrap_or(0x1000)),
                color: theme::REGION_HEADERS,
            });
            section_regions(&mut regions, pe, true);
        }
        return regions;
    }
    let spliced = research.input_view == ResearchInputView::SplicedCompanion;
    if view == HexView::Original && spliced {
        regions.push(Region {
            name: t(Text::HexRStubPage).into_owned(),
            start: 0,
            end: 0x1000,
            color: theme::REGION_HEADERS,
        });
        return regions;
    }
    let Some(pe) = research.input.pe.as_ref() else {
        return regions;
    };
    regions.push(Region {
        name: t(Text::HexRHeaders).into_owned(),
        start: 0,
        end: 0x1000,
        color: theme::REGION_HEADERS,
    });
    if let Some(protection) = &research.input.protection {
        if let (Some(first), Some(last)) = (
            protection.header_words.first(),
            protection.header_words.last(),
        ) {
            regions.push(Region {
                name: t(Text::HexRHeaderTable).into_owned(),
                start: first.source_file_offset,
                end: last.source_file_offset + 4,
                color: theme::REGION_PROTECTION,
            });
        }
        if let Some(payload) = &protection.payload {
            for check in payload
                .checks
                .iter()
                .filter(|check| check.name.starts_with("source_"))
            {
                regions.push(Region {
                    name: crate::labels::tv_str("check", check.name).into_owned(),
                    start: check.start,
                    end: check.end,
                    color: if check.name == "source_prefix" {
                        theme::REGION_PREFIX
                    } else {
                        theme::REGION_TAIL
                    },
                });
            }
        }
    }
    section_regions(&mut regions, pe, false);
    if let Some(overlay) = &pe.overlay {
        regions.push(Region {
            name: tv("region", &senbei_engine::windows::FileRegionKind::Overlay).into_owned(),
            start: overlay.offset,
            end: overlay.offset + overlay.length,
            color: theme::REGION_OTHER,
        });
    }
    regions
}

/// The narrowest region holding `offset`, so a table inside a section shows.
fn region_at(regions: &[Region], offset: u64) -> Option<&Region> {
    regions
        .iter()
        .filter(|region| offset >= region.start && offset < region.end)
        .min_by_key(|region| region.end - region.start)
}

// ------------------------------------------------------------------- tab

const ROW: f32 = 19.0;
const SIDE: f32 = 250.0;

/// The bytes of one view: ready, still loading (`Err(None)`), or a reason
/// they cannot be shown. Asks the backend for bytes it has not loaded.
pub fn view_bytes(
    draw: &mut Draw<'_>,
    subject: &Subject<'_>,
    view: HexView,
) -> Result<Arc<[u8]>, Option<String>> {
    match origin(subject, view) {
        Some(Origin::Bytes(bytes)) => Ok(bytes),
        Some(Origin::Load(source)) => match draw.bytes.get(&source) {
            Some(Loaded::Ready(bytes)) => Ok(bytes.clone()),
            Some(Loaded::Failed(error)) => Err(Some(labels::load_error(error))),
            Some(Loaded::Loading) => Err(None),
            None => {
                draw.act(Action::Load(source));
                Err(None)
            }
        },
        Some(Origin::Note(text)) => Err(Some(t(text).into_owned())),
        None => Err(None),
    }
}

pub fn tab(ui: &mut Ui, draw: &mut Draw<'_>, view: &mut ViewState, subject: Subject<'_>) {
    let full = ui.available_rect_before_wrap();
    let views = views(&subject);
    let current = current_view(&subject, &view.hex);
    view.hex.view = Some(current);
    let bytes = view_bytes(draw, &subject, current);
    let pe = view_pe(&subject, current);
    let state = &mut view.hex;

    hex_bar(ui, state, &views, current, bytes.as_ref().ok(), pe);
    widgets::rule(ui);
    if current == HexView::Spliced {
        egui::Frame::new()
            .inner_margin(Margin::symmetric(12, 6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                widgets::note(ui, t(Text::ResearchSplicedNote));
            });
        widgets::rule(ui);
    }
    let status_height = 24.0;
    let top = ui.cursor().top();
    let main = Rect::from_min_max(
        pos2(full.left(), top),
        pos2(
            full.right(),
            (full.bottom() - status_height).max(top + 40.0),
        ),
    );
    let rows_rect = Rect::from_min_max(main.min, pos2(main.right() - SIDE, main.bottom()));
    let side_rect = Rect::from_min_max(pos2(main.right() - SIDE, main.top()), main.max);
    ui.painter().rect_filled(rows_rect, 0, theme::WELL);
    ui.painter().rect_filled(side_rect, 0, theme::PANEL);
    ui.painter().vline(
        side_rect.left() + 0.5,
        side_rect.y_range(),
        Stroke::new(1.0, theme::BORDER),
    );

    let regions = match &bytes {
        Ok(bytes) => regions(&subject, current, bytes),
        Err(_) => Vec::new(),
    };
    match &bytes {
        Ok(bytes) => rows(ui, rows_rect, state, bytes, &regions),
        Err(message) => {
            ui.scope_builder(
                UiBuilder::new().max_rect(rows_rect.shrink(16.0)),
                |ui| match message {
                    Some(message) => widgets::note(ui, message.clone()),
                    None => {
                        ui.spinner();
                    }
                },
            );
        }
    }
    ui.scope_builder(
        UiBuilder::new().max_rect(side_rect.shrink2(vec2(10.0, 8.0))),
        |ui| {
            ScrollArea::vertical()
                .id_salt("hex-side")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    side_panel(ui, state, bytes.as_ref().ok(), pe, &regions, current, draw);
                });
        },
    );
    let status_rect = Rect::from_min_max(pos2(full.left(), main.bottom()), full.max);
    ui.painter().hline(
        status_rect.x_range(),
        status_rect.top() + 0.5,
        Stroke::new(1.0, theme::BORDER),
    );
    ui.scope_builder(
        UiBuilder::new().max_rect(status_rect.shrink2(vec2(12.0, 4.0))),
        |ui| {
            ui.horizontal_centered(|ui| {
                ui.spacing_mut().item_spacing.x = 16.0;
                status(ui, state, bytes.as_ref().ok(), &regions, current);
            });
        },
    );
    ui.allocate_rect(
        Rect::from_min_max(pos2(full.left(), top), full.max),
        Sense::hover(),
    );
}

fn hex_bar(
    ui: &mut Ui,
    state: &mut HexState,
    views: &[HexView],
    current: HexView,
    bytes: Option<&Arc<[u8]>>,
    pe: Option<&PeInspection>,
) {
    egui::Frame::new()
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                let labels: Vec<String> = views
                    .iter()
                    .map(|view| {
                        t(match view {
                            HexView::Original => Text::HexVOriginal,
                            HexView::Spliced => Text::HexVSpliced,
                            HexView::Restored => Text::HexVRestored,
                        })
                        .into_owned()
                    })
                    .collect();
                let index = views.iter().position(|view| *view == current).unwrap_or(0);
                if let Some(chosen) = widgets::segmented(ui, &labels, index) {
                    state.view = Some(views[chosen]);
                    state.focus = None;
                    state.highlight = None;
                    state.note = None;
                    state.top = 0;
                }
                let goto_label = ui.label(widgets::dim(t(Text::HexGoto)));
                let goto = ui
                    .add(
                        egui::TextEdit::singleline(&mut state.goto)
                            .font(theme::mono())
                            .hint_text("0x14E0")
                            .desired_width(104.0),
                    )
                    .labelled_by(goto_label.id);
                if goto.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter)) {
                    go_to(state, pe);
                }
                egui::ComboBox::from_id_salt("hex-goto-space")
                    .selected_text(t(if state.goto_rva {
                        Text::HexAsRva
                    } else {
                        Text::HexAsFile
                    }))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut state.goto_rva, false, t(Text::HexAsFile));
                        ui.selectable_value(&mut state.goto_rva, true, t(Text::HexAsRva));
                    })
                    .response
                    .labelled_by(goto_label.id);
                let (rect, _) = ui.allocate_exact_size(vec2(1.0, 20.0), Sense::hover());
                ui.painter().rect_filled(rect, 0, theme::BORDER);
                let find_label = ui.label(widgets::dim(t(Text::HexFind)));
                let find = ui
                    .add(
                        egui::TextEdit::singleline(&mut state.find)
                            .font(theme::mono())
                            .hint_text(t(Text::HexFindHint))
                            .desired_width(150.0),
                    )
                    .labelled_by(find_label.id);
                let enter = find.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                let next = widgets::ghost_button(ui, t(Text::HexFindNext)).on_hover_text("F3");
                if (enter || next.clicked())
                    && let Some(bytes) = bytes
                {
                    self::find(bytes, state);
                    if enter {
                        find.request_focus();
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let selection = state.highlight.filter(|_| bytes.is_some());
                    let copy = ui
                        .add_enabled_ui(selection.is_some(), |ui| {
                            widgets::ghost_button(ui, t(Text::HexCopySel))
                        })
                        .inner;
                    if copy.clicked()
                        && let (Some((start, end)), Some(bytes)) = (selection, bytes)
                    {
                        ui.ctx().copy_text(selection_text(bytes, start, end));
                    }
                });
            });
        });
}

fn selection_text(bytes: &[u8], start: u64, end: u64) -> String {
    const MAX: u64 = 1024 * 1024;
    let start = start.min(bytes.len() as u64) as usize;
    let end = end.min(start as u64 + MAX).min(bytes.len() as u64) as usize;
    bytes[start..end]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn go_to(state: &mut HexState, pe: Option<&PeInspection>) {
    let Some(value) = format::parse_hex(&state.goto) else {
        return;
    };
    let target = if state.goto_rva {
        match rva_to_offset(pe, value) {
            Some(offset) => offset,
            None => {
                state.note = Some(
                    t(Text::HexRvaUnmapped {
                        o: format::hex(value),
                    })
                    .into_owned(),
                );
                return;
            }
        }
    } else {
        value
    };
    state.focus = Some(target);
    state.highlight = Some((target, target + 16));
    state.note = None;
    state.reveal = true;
}

/// The byte rows, scrolled by row index so files of any size scroll exactly.
fn rows(ui: &mut Ui, rect: Rect, state: &mut HexState, bytes: &[u8], regions: &[Region]) {
    let id = ui.scope_id().with("hex-rows");
    let response = ui.interact(rect, id, Sense::click());
    let len = bytes.len() as u64;
    let total = len.div_ceil(16).max(1);
    let visible = (((rect.height() - 12.0) / ROW).floor().max(1.0)) as u64;
    let max_top = total.saturating_sub(visible);
    if state.reveal {
        if let Some(focus) = state.focus {
            state.top = (focus / 16).saturating_sub(visible / 2).min(max_top);
        }
        state.reveal = false;
    }
    // Wheel and keys scroll whole rows; fractions carry over between frames.
    if ui.rect_contains_pointer(rect) {
        let delta = ui.input(|input| input.smooth_scroll_delta.y);
        if delta != 0.0 {
            let carry: f32 = ui
                .data(|data| data.get_temp(id.with("carry")))
                .unwrap_or(0.0);
            let rows = carry - delta / ROW;
            let whole = rows.trunc();
            ui.data_mut(|data| data.insert_temp(id.with("carry"), rows - whole));
            state.top = (state.top as i64 + whole as i64).clamp(0, max_top as i64) as u64;
        }
        let (page_down, page_up, home, end) = ui.input(|input| {
            (
                input.key_pressed(Key::PageDown),
                input.key_pressed(Key::PageUp),
                input.key_pressed(Key::Home) && input.modifiers.command,
                input.key_pressed(Key::End) && input.modifiers.command,
            )
        });
        if page_down {
            state.top = (state.top + visible).min(max_top);
        }
        if page_up {
            state.top = state.top.saturating_sub(visible);
        }
        if home {
            state.top = 0;
        }
        if end {
            state.top = max_top;
        }
    }
    state.top = state.top.min(max_top);

    let font = theme::mono();
    let char_width = ui
        .painter()
        .layout_no_wrap("0".into(), font.clone(), theme::TEXT)
        .size()
        .x;
    let strip_x = rect.left();
    let offset_right = rect.left() + 4.0 + 10.0 + 92.0;
    let hex_x = offset_right + 10.0;
    let hex_col = |index: usize| (index * 3 + usize::from(index >= 8)) as f32 * char_width;
    let ascii_x = hex_x + hex_col(15) + 2.0 * char_width + 18.0;
    let painter = ui.painter_at(rect);

    // Click and shift-click on a byte.
    if response.clicked()
        && let Some(pos) = response.interact_pointer_pos()
    {
        let row = state.top + ((pos.y - rect.top() - 6.0) / ROW).floor().max(0.0) as u64;
        let column = if pos.x >= ascii_x {
            Some(((pos.x - ascii_x) / char_width).floor() as i64)
        } else if pos.x >= hex_x {
            (0..16)
                .find(|index| {
                    let left = hex_x + hex_col(*index);
                    pos.x >= left && pos.x < left + 2.5 * char_width
                })
                .map(|index| index as i64)
        } else {
            None
        };
        if let Some(column) = column.filter(|column| (0..16).contains(column)) {
            let offset = row * 16 + column as u64;
            if offset < len {
                let extend = ui.input(|input| input.modifiers.shift);
                match (extend, state.focus) {
                    (true, Some(focus)) => {
                        state.highlight = Some((focus.min(offset), focus.max(offset) + 1));
                    }
                    _ => {
                        state.focus = Some(offset);
                        state.highlight = Some((offset, offset + 1));
                    }
                }
                state.note = None;
            }
        }
    }

    for line in 0..=visible {
        let row = state.top + line;
        if row >= total {
            break;
        }
        let base = row * 16;
        let y = rect.top() + 6.0 + line as f32 * ROW;
        if let Some(region) = region_at(regions, base) {
            painter.rect_filled(
                Rect::from_min_size(pos2(strip_x, y), vec2(4.0, ROW)),
                0,
                region.color,
            );
        }
        let focus_row = state.focus.is_some_and(|focus| focus / 16 == row);
        let offset_text = format!("{base:08X}");
        let offset = painter.layout_no_wrap(
            offset_text,
            font.clone(),
            if focus_row {
                theme::ACCENT
            } else {
                theme::FAINT
            },
        );
        painter.galley(
            pos2(offset_right - offset.size().x, y + 1.0),
            offset,
            theme::FAINT,
        );
        let end = (base + 16).min(len);
        let chunk = &bytes[base as usize..end as usize];
        let mut hex_job = LayoutJob::default();
        let mut ascii_job = LayoutJob::default();
        for (index, byte) in chunk.iter().enumerate() {
            let at = base + index as u64;
            let lit = state
                .highlight
                .is_some_and(|(start, end)| at >= start && at < end);
            let cursor = state.focus == Some(at);
            if lit {
                painter.rect_filled(
                    Rect::from_min_size(
                        pos2(hex_x + hex_col(index) - 1.0, y),
                        vec2(2.0 * char_width + 2.0, ROW),
                    ),
                    0,
                    theme::highlight(),
                );
                painter.rect_filled(
                    Rect::from_min_size(
                        pos2(ascii_x + index as f32 * char_width, y),
                        vec2(char_width, ROW),
                    ),
                    0,
                    theme::highlight(),
                );
            }
            if cursor {
                let stroke = Stroke::new(1.0, theme::ACCENT);
                painter.rect_stroke(
                    Rect::from_min_size(
                        pos2(hex_x + hex_col(index) - 1.0, y),
                        vec2(2.0 * char_width + 2.0, ROW),
                    ),
                    CornerRadius::ZERO,
                    stroke,
                    StrokeKind::Inside,
                );
                painter.rect_stroke(
                    Rect::from_min_size(
                        pos2(ascii_x + index as f32 * char_width, y),
                        vec2(char_width, ROW),
                    ),
                    CornerRadius::ZERO,
                    stroke,
                    StrokeKind::Inside,
                );
            }
            let color = if lit || cursor {
                theme::HIGHLIGHT_TEXT
            } else if *byte == 0 {
                theme::ZERO_BYTE
            } else {
                theme::TEXT
            };
            let gap = if index == 7 { "  " } else { " " };
            let format = TextFormat {
                font_id: font.clone(),
                color,
                ..Default::default()
            };
            hex_job.append(&format!("{byte:02X}"), 0.0, format.clone());
            if index + 1 < chunk.len() {
                hex_job.append(gap, 0.0, format);
            }
            let character = if (0x20..0x7f).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            };
            ascii_job.append(
                &character.to_string(),
                0.0,
                TextFormat {
                    font_id: font.clone(),
                    color: if lit || cursor {
                        theme::HIGHLIGHT_TEXT
                    } else {
                        theme::DIM
                    },
                    ..Default::default()
                },
            );
        }
        let hex = painter.layout_job(hex_job);
        painter.galley(pos2(hex_x, y + 1.0), hex, theme::TEXT);
        let ascii = painter.layout_job(ascii_job);
        painter.galley(pos2(ascii_x, y + 1.0), ascii, theme::DIM);
    }
    scrollbar(ui, rect, id, state, total, visible, max_top);
}

fn scrollbar(
    ui: &mut Ui,
    rect: Rect,
    id: egui::Id,
    state: &mut HexState,
    total: u64,
    visible: u64,
    max_top: u64,
) {
    if max_top == 0 {
        return;
    }
    let bar = Rect::from_min_max(pos2(rect.right() - 10.0, rect.top()), rect.max);
    let response = ui.interact(bar, id.with("bar"), Sense::click_and_drag());
    let thumb_height = (bar.height() * visible as f32 / total as f32).clamp(24.0, bar.height());
    let travel = (bar.height() - thumb_height).max(1.0);
    if (response.dragged() || response.clicked())
        && let Some(pos) = response.interact_pointer_pos()
    {
        let fraction = ((pos.y - bar.top() - thumb_height / 2.0) / travel).clamp(0.0, 1.0);
        state.top = (f64::from(fraction) * max_top as f64).round() as u64;
    }
    let fraction = state.top as f64 / max_top as f64;
    let thumb = Rect::from_min_size(
        pos2(
            bar.left() + 2.0,
            bar.top() + (fraction * f64::from(travel)) as f32,
        ),
        vec2(6.0, thumb_height),
    );
    let color = if response.hovered() || response.dragged() {
        theme::HOVER_STROKE
    } else {
        Color32::from_rgb(0x35, 0x3a, 0x44)
    };
    ui.painter()
        .rect_filled(thumb, CornerRadius::same(3), color);
}

fn side_panel(
    ui: &mut Ui,
    state: &HexState,
    bytes: Option<&Arc<[u8]>>,
    pe: Option<&PeInspection>,
    regions: &[Region],
    current: HexView,
    draw: &mut Draw<'_>,
) {
    let heading = |ui: &mut Ui, text: Text| {
        ui.add_space(4.0);
        ui.label(
            RichText::new(t(text).to_uppercase())
                .font(theme::small())
                .color(theme::FAINT),
        );
        ui.add_space(2.0);
    };
    heading(ui, Text::HexInspector);
    match (state.focus, bytes) {
        (Some(focus), Some(bytes)) => inspector(ui, bytes, focus, pe),
        _ => {
            ui.label(widgets::faint(t(Text::HexInspectorHint)));
        }
    }
    ui.add_space(10.0);
    heading(ui, Text::HexRegions);
    if regions.is_empty() {
        ui.label(widgets::faint(t(Text::HexNoRegions)));
        return;
    }
    for region in regions {
        let (rect, response) =
            ui.allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::click());
        widgets::describe(&response, egui::Role::Button, &region.name, None);
        if response.hovered() {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(4), theme::row_hover());
        }
        ui.painter().rect_filled(
            Rect::from_min_size(rect.min + vec2(6.0, 8.0), vec2(10.0, 10.0)),
            CornerRadius::same(2),
            region.color,
        );
        let name = ui
            .painter()
            .layout_no_wrap(region.name.clone(), theme::body(), theme::TEXT);
        ui.painter()
            .galley(rect.min + vec2(24.0, 4.0), name, theme::TEXT);
        let range = ui.painter().layout_no_wrap(
            format!(
                "{} – {}",
                format::hex(region.start),
                format::hex(region.end)
            ),
            FontId::monospace(11.5),
            theme::FAINT,
        );
        ui.painter()
            .galley(rect.min + vec2(24.0, 22.0), range, theme::FAINT);
        if response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            draw.act(Action::JumpView {
                view: current,
                offset: region.start,
            });
        }
    }
}

fn inspector(ui: &mut Ui, bytes: &[u8], focus: u64, pe: Option<&PeInspection>) {
    let Ok(at) = usize::try_from(focus) else {
        return;
    };
    let Some(&byte) = bytes.get(at) else {
        return;
    };
    let mut rows: Vec<(&str, String, String)> =
        vec![("u8", format::hex_w(u64::from(byte), 2), byte.to_string())];
    if let Some(value) = le_u16(bytes, at) {
        rows.push((
            "u16 LE",
            format::hex_w(u64::from(value), 4),
            format::num(u64::from(value)),
        ));
    }
    if let Some(value) = le_u32(bytes, at) {
        rows.push((
            "u32 LE",
            format::hex_w(u64::from(value), 8),
            format::num(u64::from(value)),
        ));
    }
    if let Some(value) = le_u64(bytes, at) {
        rows.push(("u64 LE", format::hex_w(value, 16), String::new()));
    }
    if let Some((rva, section)) = offset_to_rva(pe, focus) {
        rows.push((
            "RVA",
            format::hex(rva),
            section.unwrap_or_default().to_owned(),
        ));
    }
    egui::Grid::new("hex-inspector")
        .num_columns(2)
        .spacing(vec2(10.0, 1.0))
        .show(ui, |ui| {
            for (key, value, aside) in rows {
                ui.label(
                    RichText::new(key)
                        .font(FontId::monospace(11.5))
                        .color(theme::DIM),
                );
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    widgets::selectable(ui, RichText::new(value).font(FontId::monospace(11.5)));
                    if !aside.is_empty() {
                        ui.label(widgets::faint(aside).font(FontId::monospace(11.5)));
                    }
                });
                ui.end_row();
            }
        });
}

fn status(
    ui: &mut Ui,
    state: &HexState,
    bytes: Option<&Arc<[u8]>>,
    regions: &[Region],
    current: HexView,
) {
    let small = |text: String| RichText::new(text).font(theme::small()).color(theme::DIM);
    if let Some(bytes) = bytes {
        ui.label(small(
            t(Text::HexSize {
                s: format::bytes(bytes.len() as u64),
            })
            .into_owned(),
        ));
    }
    if let Some(focus) = state.focus {
        let mut text = t(Text::HexAt {
            o: format::hex(focus),
        })
        .into_owned();
        if let Some(region) = region_at(regions, focus) {
            text.push_str(" · ");
            text.push_str(&region.name);
        }
        ui.label(small(text));
        if current == HexView::Spliced {
            ui.label(small(if focus >= 0x1000 {
                t(Text::HexInCompanion {
                    o: format::hex(focus - 0x1000),
                })
                .into_owned()
            } else {
                t(Text::HexInStub).into_owned()
            }));
        }
    }
    if let Some(note) = &state.note {
        ui.label(RichText::new(note).font(theme::small()).color(theme::WARN));
    }
}
