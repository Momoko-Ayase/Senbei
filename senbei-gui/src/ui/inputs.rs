//! The inputs panel: groups, the inputs in them, and package entries.

use egui::text::{LayoutJob, TextWrapping};
use egui::{
    Align, Align2, Color32, CornerRadius, FontId, Frame, Layout, Margin, Pos2, Rect, Response,
    RichText, ScrollArea, Sense, Stroke, Ui, pos2, vec2,
};
use senbei_io::report::{EntryReport, Mode};

use super::{Action, Draw, ViewState, widgets};
use crate::format;
use crate::labels::tv;
use crate::model::{
    Counts, Filter, Group, GroupKind, Item, RunState, Sel, Verdict, entry_inner, entry_tag,
    is_target_entry, kind_tag, mode_label,
};
use crate::text::{Text, t};
use crate::theme::{self, Tone};

const ROW_HEIGHT: f32 = 44.0;
const GROUP_HEIGHT: f32 = 26.0;
const GROUP_SUB_HEIGHT: f32 = 16.0;

pub fn panel(ui: &mut Ui, draw: &mut Draw<'_>, view: &mut ViewState) {
    let idle = draw.jobs.running.is_none() && draw.jobs.queued.is_empty();
    let any_result = draw.session.items().any(|item| item.result.is_some());
    Frame::new()
        .inner_margin(Margin {
            left: 10,
            right: 10,
            top: 8,
            bottom: 6,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 6.0;
            ui.horizontal(|ui| {
                ui.label(RichText::new(t(Text::InputsTitle)).font(theme::title(15.0)));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let clear = ui
                        .add_enabled_ui(idle, |ui| widgets::ghost_button(ui, t(Text::InputsClear)))
                        .inner;
                    if clear.clicked() {
                        draw.act(Action::Clear);
                    }
                });
            });
            if any_result {
                let counts = counts(draw);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = vec2(4.0, 4.0);
                    for filter in Filter::ALL {
                        let on = view.filter == filter;
                        if widgets::chip(ui, &filter.label(), counts.get(filter), on).clicked() {
                            view.filter = filter;
                        }
                    }
                });
            }
            ui.add(
                egui::TextEdit::singleline(&mut view.search)
                    .hint_text(t(Text::InputsSearch))
                    .desired_width(f32::INFINITY),
            );
        });
    widgets::rule(ui);
    let rows = RowCtx {
        idle,
        caps: draw.caps,
    };
    let session = draw.session;
    let actions = &mut *draw.actions;
    ScrollArea::vertical()
        .id_salt("inputs-list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add_space(4.0);
            let mut shown = 0;
            for group in &session.groups {
                shown += group_rows(ui, actions, &rows, group, view);
            }
            if shown == 0 {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    ui.label(widgets::faint(t(Text::InputsNone)));
                });
            }
            ui.add_space(8.0);
        });
}

/// What every row needs to know about the window.
struct RowCtx {
    idle: bool,
    caps: crate::backend::Capabilities,
}

fn counts(draw: &Draw<'_>) -> Counts {
    let mut counts = Counts::default();
    for item in draw.session.items() {
        counts.inputs += 1;
        if let Some(verdict) = item.verdict() {
            counts.add(verdict);
        }
    }
    counts
}

fn name_matches(name: &str, search: &str) -> bool {
    search.is_empty() || name.to_lowercase().contains(&search.to_lowercase())
}

fn visible(item: &Item, view: &ViewState) -> bool {
    if view.filter != Filter::All
        && let Some(verdict) = item.verdict()
        && verdict.filter() != view.filter
    {
        return false;
    }
    if !view.search.is_empty()
        && !name_matches(&item.name, &view.search)
        && !item
            .entries()
            .iter()
            .any(|entry| name_matches(format::base_name(entry_inner(&entry.name)), &view.search))
    {
        return false;
    }
    true
}

/// Draw one group; returns how many rows it showed.
fn group_rows(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    rows: &RowCtx,
    group: &Group,
    view: &ViewState,
) -> usize {
    let visible_items: Vec<&Item> = group
        .items
        .iter()
        .filter(|item| visible(item, view))
        .collect();
    let filtering = view.filter != Filter::All || !view.search.is_empty();
    if visible_items.is_empty() && group.scanning.is_none() && filtering {
        return 0;
    }
    group_header(ui, actions, group, view, visible_items.len());
    let mut shown = 1;
    if !group.folded {
        for item in visible_items {
            item_row(ui, actions, rows, item, view);
            shown += 1;
            if !item.entries().is_empty() && !item.folded {
                shown += entry_rows(ui, actions, rows, item, view);
            }
        }
    }
    shown
}

/// A single-line galley cut to `width` with an ellipsis.
fn line(
    ui: &Ui,
    text: &str,
    font: FontId,
    color: Color32,
    width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = LayoutJob::simple_singleline(text.to_owned(), font, color);
    job.wrap = TextWrapping::truncate_at_width(width.max(8.0));
    ui.painter().layout_job(job)
}

fn caret(ui: &Ui, at: Pos2, folded: bool) -> Rect {
    let rect = Rect::from_center_size(at, vec2(14.0, 14.0));
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        if folded { "▶" } else { "▼" },
        FontId::proportional(9.0),
        theme::FAINT,
    );
    rect
}

/// Paint a row's background; returns the row's rect and response.
fn row_base(ui: &mut Ui, height: f32, selected: bool) -> (Rect, Response) {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
    if selected {
        ui.painter().rect_filled(rect, 0, theme::selection());
    } else if response.hovered() {
        ui.painter().rect_filled(rect, 0, theme::row_hover());
    }
    (rect, response)
}

fn toggle_pressed(ui: &Ui) -> bool {
    ui.input(|input| input.modifiers.command)
}

fn group_header(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    group: &Group,
    view: &ViewState,
    visible: usize,
) {
    let selected = view.selected == Some(Sel::Group(group.id));
    let sub = match (&group.kind, group.scanning) {
        (_, Some(found)) => Some((
            t(Text::GroupScanning {
                n: found.to_string(),
            })
            .into_owned(),
            theme::INFO,
        )),
        (GroupKind::Folder(root), None) => Some((
            match &group.last_run {
                Some(run) => format!("{} · {}", mode_label(run.mode), root.display()),
                None => root.display().to_string(),
            },
            if selected { theme::DIM } else { theme::FAINT },
        )),
        (GroupKind::Files, None) => None,
    };
    ui.add_space(4.0);
    let height = GROUP_HEIGHT + if sub.is_some() { GROUP_SUB_HEIGHT } else { 0.0 };
    let (rect, response) = row_base(ui, height, selected);
    widgets::describe(
        &response,
        egui::Role::TreeItem,
        &group.title(),
        Some(selected),
    );
    let left = rect.left() + 10.0;
    let top = rect.top() + 5.0;
    let caret_rect = caret(ui, pos2(left + 7.0, top + 8.0), group.folded);
    let count = group.scanning.unwrap_or(visible).to_string();
    let count_galley = ui
        .painter()
        .layout_no_wrap(count, theme::small(), theme::FAINT);
    let count_pos = pos2(rect.right() - 10.0 - count_galley.size().x, top);
    let name_x = left + 20.0;
    let name = line(
        ui,
        &group.title(),
        theme::strong(12.5),
        theme::TEXT,
        count_pos.x - name_x - 6.0,
    );
    ui.painter().galley(pos2(name_x, top), name, theme::TEXT);
    ui.painter().galley(count_pos, count_galley, theme::FAINT);
    if let Some((text, color)) = sub {
        let galley = line(
            ui,
            &text,
            theme::small(),
            color,
            rect.right() - 10.0 - name_x,
        );
        ui.painter().galley(pos2(name_x, top + 17.0), galley, color);
    }
    let response = match group.root() {
        Some(root) => response.on_hover_text(root.display().to_string()),
        None => response,
    };
    if response.clicked() {
        let on_caret = response
            .interact_pointer_pos()
            .is_some_and(|pos| caret_rect.expand(3.0).contains(pos));
        if on_caret {
            actions.push(Action::Fold(Sel::Group(group.id)));
        } else {
            actions.push(Action::Select {
                sel: Sel::Group(group.id),
                toggle: false,
            });
        }
    }
}

/// The dot, label, and label colour of a row.
pub(super) struct RowState {
    pub dot: Option<Tone>,
    pub label: String,
    pub color: Color32,
    pub extra: Option<String>,
    pub time: Option<String>,
}

pub(super) fn row_state(item: &Item) -> RowState {
    let plain = |label: String, color: Color32| RowState {
        dot: None,
        label,
        color,
        extra: None,
        time: None,
    };
    match (item.run, &item.result) {
        (RunState::Running, _) => RowState {
            dot: Some(Tone::Info),
            ..plain(t(Text::RunRunning).into_owned(), theme::INFO)
        },
        (RunState::Queued, _) => plain(t(Text::RunQueued).into_owned(), theme::FAINT),
        (RunState::WillNotRun, None) => plain(t(Text::RunWillNotRun).into_owned(), theme::FAINT),
        (_, Some(result)) => {
            let verdict = result.verdict();
            RowState {
                dot: Some(verdict.tone()),
                label: verdict.label().into_owned(),
                color: verdict.tone().color(),
                extra: Some(mode_label(result.mode).into_owned()),
                time: Some(format::ms(result.report.duration_ms)),
            }
        }
        (_, None) => {
            let not_protected = item
                .identity
                .as_ref()
                .is_some_and(crate::backend::Identity::not_protected);
            plain(
                t(if not_protected {
                    Text::PendingNotProtected
                } else {
                    Text::PendingNotRun
                })
                .into_owned(),
                theme::FAINT,
            )
        }
    }
}

/// Paint the two lines of an input or entry row.
#[allow(clippy::too_many_arguments)]
fn paint_row(
    ui: &Ui,
    rect: Rect,
    indent: f32,
    selected: bool,
    name: &str,
    tag: &str,
    state: &RowState,
    nested: bool,
) {
    if selected {
        ui.painter().rect_filled(
            Rect::from_min_size(rect.min, vec2(2.0, rect.height())),
            0,
            theme::BLUE,
        );
    }
    let top = rect.top() + 4.0;
    let dot_center = pos2(rect.left() + indent + 4.0, top + 10.0);
    widgets::paint_dot(ui, dot_center, state.dot);
    let name_x = dot_center.x + 12.0;
    let tag_galley =
        ui.painter()
            .layout_no_wrap(tag.to_owned(), FontId::proportional(11.0), theme::DIM);
    let tag_size = tag_galley.size() + vec2(10.0, 1.0);
    let tag_rect = Rect::from_min_size(
        pos2(
            rect.right() - 10.0 - tag_size.x,
            top + 10.0 - tag_size.y / 2.0,
        ),
        tag_size,
    );
    let name_galley = line(
        ui,
        name,
        theme::body(),
        theme::TEXT,
        tag_rect.left() - name_x - 8.0,
    );
    ui.painter()
        .galley(pos2(name_x, top + 1.0), name_galley, theme::TEXT);
    ui.painter().rect(
        tag_rect,
        CornerRadius::same(3),
        Color32::TRANSPARENT,
        Stroke::new(1.0, theme::BORDER),
        egui::StrokeKind::Inside,
    );
    ui.painter()
        .galley(tag_rect.min + vec2(5.0, 0.5), tag_galley, theme::DIM);

    let meta_font = FontId::proportional(if nested { 11.0 } else { 11.5 });
    let meta_y = top + 21.0;
    let faint = if selected { theme::DIM } else { theme::FAINT };
    let mut x = name_x;
    let right = rect.right() - 10.0;
    if let Some(time) = &state.time {
        let galley = ui
            .painter()
            .layout_no_wrap(time.clone(), meta_font.clone(), faint);
        let pos = pos2(right - galley.size().x, meta_y);
        ui.painter().galley(pos, galley, faint);
    }
    let label_color = if state.dot.is_none() {
        faint
    } else {
        state.color
    };
    let label = line(
        ui,
        &state.label,
        meta_font.clone(),
        label_color,
        right - x - 60.0,
    );
    let width = label.size().x;
    ui.painter().galley(pos2(x, meta_y), label, label_color);
    x += width + 6.0;
    if let Some(extra) = &state.extra {
        let dot = ui
            .painter()
            .layout_no_wrap("·".to_owned(), meta_font.clone(), faint);
        let dot_width = dot.size().x;
        ui.painter().galley(pos2(x, meta_y), dot, faint);
        x += dot_width + 6.0;
        let extra = line(ui, extra, meta_font, faint, right - x - 60.0);
        ui.painter().galley(pos2(x, meta_y), extra, faint);
    }
}

fn item_row(ui: &mut Ui, actions: &mut Vec<Action>, rows: &RowCtx, item: &Item, view: &ViewState) {
    let sel = Sel::Item(item.id);
    let selected = view.selected == Some(sel) || view.multi.contains(&sel);
    let (rect, response) = row_base(ui, ROW_HEIGHT, selected);
    widgets::describe(&response, egui::Role::TreeItem, &item.name, Some(selected));
    let has_entries = !item.entries().is_empty();
    let caret_rect =
        has_entries.then(|| caret(ui, pos2(rect.left() + 16.0, rect.top() + 14.0), item.folded));
    paint_row(
        ui,
        rect,
        26.0,
        selected,
        &item.name,
        &kind_tag(item),
        &row_state(item),
        false,
    );
    let response = response.on_hover_text(item.path.display().to_string());
    if response.clicked() {
        let on_caret = caret_rect.is_some_and(|caret| {
            response
                .interact_pointer_pos()
                .is_some_and(|pos| caret.expand(3.0).contains(pos))
        });
        if on_caret {
            actions.push(Action::Fold(sel));
        } else {
            actions.push(Action::Select {
                sel,
                toggle: toggle_pressed(ui),
            });
        }
    }
    row_menu(&response, actions, rows, item);
}

fn entry_rows(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    rows: &RowCtx,
    item: &Item,
    view: &ViewState,
) -> usize {
    let entries = item.entries();
    let searching = !view.search.is_empty();
    let mut shown = 0;
    for (index, entry) in entries.iter().enumerate() {
        let name = format::base_name(entry_inner(&entry.name));
        let keep = if searching {
            name_matches(name, &view.search)
        } else {
            is_target_entry(entry)
        };
        if !keep {
            continue;
        }
        entry_row(ui, actions, rows, item, index, entry, view);
        shown += 1;
    }
    let others = entries
        .iter()
        .filter(|entry| !is_target_entry(entry))
        .count();
    if others > 0 && !searching {
        let (rect, response) = row_base(ui, 24.0, false);
        let text = t(Text::EntriesOthers {
            n: others.to_string(),
        });
        widgets::describe(&response, egui::Role::Button, &text, None);
        let galley = line(ui, &text, theme::tiny(), theme::FAINT, rect.width() - 54.0);
        ui.painter().galley(
            pos2(rect.left() + 44.0 + 12.0, rect.top() + 2.0),
            galley,
            theme::FAINT,
        );
        if response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            actions.push(Action::ShowEntries(item.id));
        }
        shown += 1;
    }
    shown
}

fn entry_row(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    rows: &RowCtx,
    item: &Item,
    index: usize,
    entry: &EntryReport,
    view: &ViewState,
) {
    let sel = Sel::Entry(item.id, index);
    let selected = view.selected == Some(sel) || view.multi.contains(&sel);
    let (rect, response) = row_base(ui, ROW_HEIGHT - 2.0, selected);
    widgets::describe(
        &response,
        egui::Role::TreeItem,
        format::base_name(entry_inner(&entry.name)),
        Some(selected),
    );
    let verdict = Verdict::of_entry(entry);
    let state = RowState {
        dot: Some(verdict.tone()),
        label: verdict.label().into_owned(),
        color: verdict.tone().color(),
        extra: entry
            .layout
            .map(|layout| tv("layout", &layout).into_owned()),
        time: None,
    };
    let inner = entry_inner(&entry.name);
    paint_row(
        ui,
        rect,
        44.0,
        selected,
        format::base_name(inner),
        &entry_tag(entry),
        &state,
        true,
    );
    let response = response.on_hover_text(entry_path(item, entry));
    if response.clicked() {
        actions.push(Action::Select {
            sel,
            toggle: toggle_pressed(ui),
        });
    }
    row_menu_entry(&response, actions, rows, item, entry);
}

/// `package › inner\path` for an entry.
pub fn entry_path(item: &Item, entry: &EntryReport) -> String {
    format!(
        "{} › {}",
        item.path.display(),
        entry_inner(&entry.name).replace('/', "\\")
    )
}

fn run_items(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    id: crate::backend::ItemId,
    enabled: bool,
    unpack: bool,
) {
    for (mode, text) in [
        (Mode::Unpack, Text::TbUnpack),
        (Mode::DryRun, Text::TbDryRun),
        (Mode::Inspect, Text::TbInspect),
    ] {
        let allowed = enabled && (mode != Mode::Unpack || unpack);
        if ui
            .add_enabled(allowed, egui::Button::new(t(text)))
            .clicked()
        {
            actions.push(Action::RunItem(mode, id));
            ui.close();
        }
    }
}

fn row_menu(response: &Response, actions: &mut Vec<Action>, rows: &RowCtx, item: &Item) {
    let idle = rows.idle;
    let protected = !item
        .identity
        .as_ref()
        .is_some_and(crate::backend::Identity::not_protected);
    let unpack = rows.caps.unpack;
    let reveal = rows.caps.reveal;
    response.context_menu(|ui| {
        ui.set_min_width(200.0);
        run_items(ui, actions, item.id, protected, unpack);
        ui.separator();
        if reveal && ui.button(t(Text::OvOpenFolder)).clicked() {
            actions.push(Action::Reveal(item.path.clone()));
            ui.close();
        }
        if ui.button(t(Text::MenuCopyPath)).clicked() {
            ui.ctx().copy_text(item.path.display().to_string());
            ui.close();
        }
        ui.separator();
        if ui
            .add_enabled(
                idle,
                egui::Button::new(t(Text::MenuRemove)).shortcut_text("Del"),
            )
            .clicked()
        {
            actions.push(Action::Remove(item.id));
            ui.close();
        }
    });
}

fn row_menu_entry(
    response: &Response,
    actions: &mut Vec<Action>,
    rows: &RowCtx,
    item: &Item,
    entry: &EntryReport,
) {
    let path = entry_path(item, entry);
    let reveal = rows.caps.reveal;
    let unpack = rows.caps.unpack;
    response.context_menu(|ui| {
        ui.set_min_width(200.0);
        run_items(ui, actions, item.id, true, unpack);
        ui.separator();
        if reveal && ui.button(t(Text::OvOpenFolder)).clicked() {
            actions.push(Action::Reveal(item.path.clone()));
            ui.close();
        }
        if ui.button(t(Text::MenuCopyPath)).clicked() {
            ui.ctx().copy_text(path.clone());
            ui.close();
        }
    });
}
