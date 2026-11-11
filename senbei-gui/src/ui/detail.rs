//! The detail pane: what the selected group, input, or entry is and what its
//! last run found.

use std::collections::HashSet;

use egui::{
    Align, CornerRadius, Frame, Layout, Margin, Rect, RichText, ScrollArea, Sense, Stroke,
    StrokeKind, Ui, pos2, vec2,
};
use senbei_engine::{Platform, ProtectionProfile, RecognitionStatus, ValidationStatus};
use senbei_i18n::Message;
use senbei_io::report::{
    CompanionState, EntryReport, EntryStatus, InputReport, InputStatus, Mode, Role, Stage,
    StageStatus,
};
use serde_json::Value;

use super::table::{self, col, num_col};
use super::widgets::{self, CardSpec, MsgKind};
use super::{Action, Draw, Tab, ViewState, hex, logview, research};
use crate::backend::{Identity, Output};
use crate::format;
use crate::labels::{self, Shown, step_title, tv};
use crate::model::{
    Group, Item, ItemResult, RunState, Sel, Verdict, entry_inner, entry_source, entry_tag,
    format_label, identity_format, is_target_entry, kind_tag, mode_label,
};
use crate::text::{Text, t};
use crate::theme::{self, Tone};

// ------------------------------------------------------------------ shell

pub struct TabSpec {
    pub tab: Tab,
    pub label: String,
    pub badge: Option<usize>,
}

fn tab(tab: Tab, text: Text) -> TabSpec {
    TabSpec {
        tab,
        label: t(text).into_owned(),
        badge: None,
    }
}

/// The head of a detail view.
pub struct Head {
    pub title: String,
    pub tag: Option<String>,
    pub pills: Vec<(String, Tone)>,
    pub path: String,
    pub tabs: Vec<TabSpec>,
    pub export: Option<Sel>,
}

fn pill_width(ui: &Ui, text: &str) -> f32 {
    ui.painter()
        .layout_no_wrap(text.to_owned(), theme::small(), theme::TEXT)
        .size()
        .x
        + 18.0
}

/// A detail view: title row, path line, tabs, and a body on the panel colour.
pub fn shell<'a>(
    ui: &mut Ui,
    draw: &mut Draw<'a>,
    view: &mut ViewState,
    head: Head,
    body: impl FnOnce(&mut Ui, &mut Draw<'a>, &mut ViewState),
) {
    if !head.tabs.is_empty() && !head.tabs.iter().any(|spec| spec.tab == view.tab) {
        view.tab = head.tabs[0].tab;
    }
    let has_tabs = !head.tabs.is_empty();
    let mut selected_tab: Option<Rect> = None;
    let header = Frame::new()
        .fill(theme::BG)
        .inner_margin(Margin {
            left: 16,
            right: 16,
            top: 10,
            bottom: if has_tabs { 0 } else { 4 },
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    if let Some(sel) = head.export {
                        if widgets::ghost_button(ui, t(Text::DetailExportText)).clicked() {
                            draw.act(Action::Export { sel, json: false });
                        }
                        if widgets::ghost_button(ui, t(Text::DetailExportJson)).clicked() {
                            draw.act(Action::Export { sel, json: true });
                        }
                    }
                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                        ui.spacing_mut().item_spacing.x = 10.0;
                        let reserved: f32 = head
                            .pills
                            .iter()
                            .map(|(text, _)| pill_width(ui, text) + 10.0)
                            .sum::<f32>()
                            + head
                                .tag
                                .as_deref()
                                .map_or(0.0, |tag| pill_width(ui, tag) + 10.0);
                        let title_width = (ui.available_width() - reserved).max(80.0);
                        ui.scope(|ui| {
                            ui.set_max_width(title_width);
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&head.title).font(theme::strong(17.0)),
                                )
                                .truncate(),
                            );
                        });
                        if let Some(tag) = &head.tag {
                            widgets::tag(ui, tag);
                        }
                        for (text, tone) in &head.pills {
                            widgets::pill(ui, text, *tone);
                        }
                    });
                });
            });
            if !head.path.is_empty() {
                ui.add_space(2.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(&head.path)
                            .font(theme::mono_small())
                            .color(theme::FAINT),
                    )
                    .truncate()
                    .selectable(true),
                );
            }
            ui.add_space(if has_tabs { 6.0 } else { 0.0 });
            if has_tabs {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    for spec in &head.tabs {
                        let on = spec.tab == view.tab;
                        let (rect, clicked) = tab_button(ui, spec, on);
                        if on {
                            selected_tab = Some(rect);
                        }
                        if clicked {
                            view.tab = spec.tab;
                        }
                    }
                });
            }
        });
    // The header's bottom border, open under the selected tab.
    let rect = header.response.rect;
    let stroke = Stroke::new(1.0, theme::BORDER);
    let y = rect.bottom() - 0.5;
    match selected_tab {
        Some(tab) => {
            ui.painter().hline(rect.left()..=tab.left(), y, stroke);
            ui.painter().hline(tab.right()..=rect.right(), y, stroke);
        }
        None => {
            ui.painter().hline(rect.x_range(), y, stroke);
        }
    }
    let body_rect = ui.available_rect_before_wrap();
    ui.painter().rect_filled(body_rect, 0, theme::PANEL);
    body(ui, draw, view);
}

fn tab_button(ui: &mut Ui, spec: &TabSpec, on: bool) -> (Rect, bool) {
    let label = ui
        .painter()
        .layout_no_wrap(spec.label.clone(), theme::body(), theme::TEXT);
    let badge = spec.badge.map(|count| {
        ui.painter()
            .layout_no_wrap(count.to_string(), theme::tiny(), theme::FAINT)
    });
    let width = label.size().x + badge.as_ref().map_or(0.0, |badge| badge.size().x + 4.0) + 24.0;
    let (rect, response) = ui.allocate_exact_size(vec2(width, 30.0), Sense::click());
    widgets::describe(&response, egui::Role::Tab, &spec.label, Some(on));
    let color = if on || response.hovered() {
        theme::TEXT
    } else {
        theme::DIM
    };
    if on {
        let painted = rect.translate(vec2(0.0, 1.0));
        ui.painter().rect(
            painted,
            CornerRadius {
                nw: 4,
                ne: 4,
                sw: 0,
                se: 0,
            },
            theme::PANEL,
            Stroke::NONE,
            StrokeKind::Inside,
        );
        let stroke = Stroke::new(1.0, theme::BORDER);
        let (l, r, top, bottom) = (
            painted.left() + 0.5,
            painted.right() - 0.5,
            painted.top() + 0.5,
            painted.bottom(),
        );
        ui.painter().vline(l, top..=bottom, stroke);
        ui.painter().vline(r, top..=bottom, stroke);
        ui.painter().hline(l..=r, top, stroke);
    }
    let text_pos = pos2(
        rect.left() + 12.0,
        rect.center().y - label.size().y / 2.0 + 1.0,
    );
    let label_width = label.size().x;
    ui.painter().galley(text_pos, label, color);
    if let Some(badge) = badge {
        let pos = pos2(
            text_pos.x + label_width + 4.0,
            rect.center().y - badge.size().y / 2.0 + 1.0,
        );
        ui.painter().galley(pos, badge, theme::FAINT);
    }
    (rect, response.clicked())
}

/// A padded, scrolling body.
pub fn padded(ui: &mut Ui, id: impl egui::AsIdSalt, add: impl FnOnce(&mut Ui)) {
    ScrollArea::vertical()
        .id_salt(id)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            Frame::new()
                .inner_margin(Margin {
                    left: 16,
                    right: 16,
                    top: 14,
                    bottom: 24,
                })
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    add(ui);
                });
        });
}

fn pick(ui: &mut Ui) {
    let rect = ui.available_rect_before_wrap();
    ui.painter().rect_filled(rect, 0, theme::PANEL);
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        ui.centered_and_justified(|ui| {
            ui.label(widgets::faint(t(Text::DetailPick)));
        });
    });
}

// --------------------------------------------------------------- dispatch

pub fn pane(ui: &mut Ui, draw: &mut Draw<'_>, view: &mut ViewState) {
    let session = draw.session;
    match view.selected {
        None => pick(ui),
        Some(Sel::Group(id)) => match session.group(id) {
            Some(group) if group.scanning.is_some() => scanning(ui, draw, view, group),
            Some(group) => group_detail(ui, draw, view, group),
            None => pick(ui),
        },
        Some(Sel::Item(id)) => match session.item(id) {
            Some((_, item)) => item_pane(ui, draw, view, item),
            None => pick(ui),
        },
        Some(Sel::Entry(id, index)) => {
            match session
                .item(id)
                .and_then(|(_, item)| item.entries().get(index).map(|entry| (item, entry)))
            {
                Some((item, entry)) => entry_detail(ui, draw, view, item, index, entry),
                None => pick(ui),
            }
        }
    }
}

fn item_pane<'a>(ui: &mut Ui, draw: &mut Draw<'a>, view: &mut ViewState, item: &'a Item) {
    match (item.run, &item.result) {
        (RunState::Running | RunState::Queued, _) | (RunState::WillNotRun, None) => {
            run_detail(ui, draw, view, item)
        }
        (_, None) => pending(ui, draw, view, item),
        (_, Some(result)) if result.report.role == Role::Container => {
            package_detail(ui, draw, view, item, result)
        }
        (_, Some(result)) => item_detail(ui, draw, view, item, result),
    }
}

fn last_run_line(item: &Item, result: &ItemResult) -> String {
    format!(
        "{} · {}",
        item.path.display(),
        t(Text::DetailLastRun {
            mode: mode_label(result.mode).into_owned(),
            t: format::ms(result.report.duration_ms),
        })
    )
}

// ----------------------------------------------------------------- groups

fn group_detail<'a>(ui: &mut Ui, draw: &mut Draw<'a>, view: &mut ViewState, group: &'a Group) {
    let live = draw
        .jobs
        .running
        .as_ref()
        .and_then(|running| running.group_runs.get(&group.id));
    let run = live.or(group.last_run.as_ref());
    let has_results = group.items.iter().any(|item| item.result.is_some());
    let pill = if live.is_some() {
        Some((t(Text::RunRunning).into_owned(), Tone::Info))
    } else {
        run.map(|run| (mode_label(run.mode).into_owned(), Tone::Info))
    };
    let head = Head {
        title: group.title().into_owned(),
        tag: None,
        pills: pill.into_iter().collect(),
        path: group
            .root()
            .map(|root| root.display().to_string())
            .unwrap_or_default(),
        tabs: vec![
            tab(Tab::Overview, Text::TabOverview),
            tab(Tab::Log, Text::TabLog),
        ],
        export: has_results.then_some(Sel::Group(group.id)),
    };
    shell(ui, draw, view, head, |ui, draw, view| {
        if view.tab == Tab::Log {
            let lines = run.map(|run| run.log.as_slice()).unwrap_or_default();
            logview::log_view(ui, view, ("group-log", group.id), lines);
            return;
        }
        let counts = group.counts();
        let duration = match run {
            Some(run) if run.duration_ms > 0 => run.duration_ms,
            _ => group
                .items
                .iter()
                .filter_map(|item| item.result.as_ref())
                .map(|result| result.report.duration_ms)
                .sum(),
        };
        padded(ui, ("group", group.id), |ui| {
            let scan = group.scan;
            let incomplete = scan.is_some_and(|scan| scan.walk_errors > 0 || scan.probe_errors > 0);
            let mut blocks: Vec<(MsgKind, Shown)> = Vec::new();
            if incomplete {
                blocks.push((
                    MsgKind::Warning,
                    Shown {
                        text: t(Text::BatchScanIncomplete).into_owned(),
                        technical: None,
                        quiet: false,
                    },
                ));
            }
            for error in run.map(|run| run.errors.as_slice()).unwrap_or_default() {
                blocks.push((MsgKind::Error, labels::message(error)));
            }
            if !blocks.is_empty() {
                widgets::wide_card(
                    ui,
                    CardSpec::new(t(Text::OvMessages), move |ui| {
                        widgets::messages(ui, &blocks)
                    }),
                );
                ui.add_space(12.0);
            }
            let mut cards = vec![
                CardSpec::new(t(Text::BatchSummary), move |ui| {
                    let keys = [
                        t(Text::BatchInputs),
                        t(Text::FilterOk),
                        t(Text::FilterSuspect),
                        t(Text::FilterFailed),
                        t(Text::FilterSkipped),
                    ];
                    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
                    widgets::kv(ui, &refs, |rows| {
                        rows.text(&keys[0], counts.inputs.to_string());
                        rows.text(
                            &keys[1],
                            widgets::toned(counts.recovered.to_string(), Tone::Ok),
                        );
                        rows.text(&keys[2], count_text(counts.suspect, Tone::Warn));
                        rows.text(&keys[3], count_text(counts.failed, Tone::Err));
                        rows.text(&keys[4], counts.skipped.to_string());
                    });
                })
                .aside(move |ui| {
                    // Nothing has run yet: no time to show.
                    if has_results || duration > 0 {
                        ui.label(widgets::faint(format::ms(duration)).font(theme::small()));
                    }
                }),
            ];
            if let Some(scan) = scan {
                cards.push(CardSpec::new(t(Text::BatchScan), move |ui| {
                    let keys = [
                        t(Text::BatchNonTarget),
                        t(Text::BatchWalkErrors),
                        t(Text::BatchProbeErrors),
                    ];
                    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
                    widgets::kv(ui, &refs, |rows| {
                        rows.text(&keys[0], scan.non_target_skipped.to_string());
                        rows.text(&keys[1], count_text(scan.walk_errors, Tone::Warn));
                        rows.text(&keys[2], count_text(scan.probe_errors, Tone::Warn));
                    });
                    ui.add_space(8.0);
                    widgets::note(ui, t(Text::BatchScanNote));
                }));
            }
            widgets::card_grid(ui, ("group-cards", group.id), cards);
            let actions = &mut *draw.actions;
            widgets::wide_card(
                ui,
                CardSpec::new(t(Text::BatchInputs), |ui| {
                    group_table(ui, actions, group);
                }),
            );
        });
    });
}

fn count_text(count: usize, tone: Tone) -> RichText {
    if count > 0 {
        widgets::toned(count.to_string(), tone)
    } else {
        RichText::new(count.to_string())
    }
}

fn group_table(ui: &mut Ui, actions: &mut Vec<Action>, group: &Group) {
    let cols = [
        col("").width(18.0),
        col(t(Text::ColName)).width(260.0).grow(),
        col(t(Text::ColType)).width(130.0),
        col(t(Text::ColOutcome)).width(130.0),
        col(t(Text::ColRoute)).width(210.0),
        num_col(t(Text::ColTime)).width(80.0),
    ];
    let items = &group.items;
    let mut clicked = None;
    table::table_clickable(
        ui,
        ("group-table", group.id),
        &cols,
        items.len(),
        |_| table::lines(1),
        |index, row| {
            let item = &items[index];
            // The same state the inputs panel shows for this row.
            let state = super::inputs::row_state(item);
            table::cell(row, |ui| {
                widgets::dot(ui, state.dot);
            });
            table::text(row, item.name.clone());
            table::cell(row, |ui| {
                widgets::tag(ui, kind_tag(item));
            });
            table::text(row, RichText::new(state.label).color(state.color));
            let route = match &item.result {
                Some(result) if result.report.container.is_some() => t(Text::EntriesSummary {
                    n: result
                        .report
                        .entries
                        .iter()
                        .filter(|entry| is_target_entry(entry))
                        .count()
                        .to_string(),
                })
                .into_owned(),
                Some(result) => result
                    .report
                    .profile
                    .as_ref()
                    .and_then(|profile| profile.selected)
                    .map(|layout| tv("layout", &layout).into_owned())
                    .unwrap_or_else(|| "—".into()),
                None => String::new(),
            };
            table::text(row, route);
            table::num(row, state.time.unwrap_or_default());
        },
        |index| clicked = Some(index),
    );
    if let Some(index) = clicked {
        actions.push(Action::Select {
            sel: Sel::Item(items[index].id),
            toggle: false,
        });
    }
}

fn scanning<'a>(ui: &mut Ui, draw: &mut Draw<'a>, view: &mut ViewState, group: &'a Group) {
    let head = Head {
        title: group.title().into_owned(),
        tag: None,
        pills: vec![(t(Text::ScanRunning).into_owned(), Tone::Info)],
        path: group
            .root()
            .map(|root| root.display().to_string())
            .unwrap_or_default(),
        tabs: Vec::new(),
        export: None,
    };
    let found = group.scanning.unwrap_or_default();
    shell(ui, draw, view, head, |ui, _, _| {
        padded(ui, ("scanning", group.id), |ui| {
            widgets::wide_card(
                ui,
                CardSpec::new(t(Text::BatchScan), move |ui| {
                    let key = t(Text::ScanFound);
                    widgets::kv(ui, &[&key], |rows| {
                        rows.text(&key, found.to_string());
                    });
                    ui.add_space(8.0);
                    widgets::note(ui, t(Text::BatchScanNote));
                }),
            );
        });
    });
}

// ----------------------------------------------------- inputs not yet run

fn pending<'a>(ui: &mut Ui, draw: &mut Draw<'a>, view: &mut ViewState, item: &'a Item) {
    let not_protected = item.identity.as_ref().is_some_and(Identity::not_protected);
    let head = Head {
        title: item.name.clone(),
        tag: Some(kind_tag(item)),
        pills: vec![(
            t(if not_protected {
                Text::PendingNotProtected
            } else {
                Text::PendingNotRun
            })
            .into_owned(),
            Tone::Skip,
        )],
        path: item.path.display().to_string(),
        tabs: vec![
            tab(Tab::Overview, Text::TabOverview),
            tab(Tab::Hex, Text::TabHex),
        ],
        export: None,
    };
    let caps = draw.caps;
    shell(ui, draw, view, head, |ui, draw, view| {
        if view.tab == Tab::Hex {
            hex::tab(ui, draw, view, hex::Subject::Item(item));
            return;
        }
        let actions = &mut *draw.actions;
        padded(ui, ("pending", item.id), |ui| {
            let unreadable = match &item.identity {
                Some(Identity::Unreadable(error)) => Some(labels::note(error)),
                Some(Identity::NotAFile) => Some(labels::note(&t(Text::PendingNotAFile))),
                _ => None,
            };
            if let Some(error) = unreadable {
                widgets::wide_card(
                    ui,
                    CardSpec::new(t(Text::OvMessages), |ui| {
                        widgets::messages(ui, &[(MsgKind::Error, error)]);
                    }),
                );
                ui.add_space(12.0);
            }
            if let Some(Identity::Package {
                container: Err(error),
                ..
            }) = &item.identity
            {
                widgets::wide_card(
                    ui,
                    CardSpec::new(t(Text::OvMessages), |ui| {
                        widgets::messages(ui, &[(MsgKind::Error, labels::note(error))]);
                    }),
                );
                ui.add_space(12.0);
            }
            let cards = vec![
                CardSpec::new(t(Text::PendingIdentified), |ui| identity_rows(ui, item)),
                CardSpec::new(t(Text::PendingNext), move |ui| {
                    next_actions(ui, actions, item, not_protected, caps.unpack);
                }),
            ];
            widgets::card_grid(ui, ("pending-cards", item.id), cards);
        });
    });
}

fn identity_rows(ui: &mut Ui, item: &Item) {
    let Some(identity) = &item.identity else {
        ui.spinner();
        return;
    };
    let mut rows: Vec<(String, widgets::Body<'_>)> = Vec::new();
    let text_row = |key: Text, value: RichText| -> (String, widgets::Body<'static>) {
        (
            t(key).into_owned(),
            Box::new(move |ui: &mut Ui| {
                widgets::selectable(ui, value);
            }),
        )
    };
    match identity {
        Identity::Package {
            container: Ok(container),
            ..
        } => {
            rows.push(text_row(
                Text::PkgKind,
                RichText::new(container.kind.to_uppercase()),
            ));
            if let Some(named) = container.manifests.iter().find(|manifest| manifest.named) {
                let package = named.package.clone().unwrap_or_default();
                let version = named.version.clone().unwrap_or_default();
                rows.push((
                    t(Text::PkgPackage).into_owned(),
                    Box::new(move |ui: &mut Ui| {
                        widgets::selectable(ui, widgets::mono(package));
                        ui.label(widgets::faint(version));
                    }),
                ));
            }
            rows.push(text_row(
                Text::PkgEntries,
                RichText::new(format::num(container.entry_count as u64)),
            ));
            rows.push(text_row(
                Text::PkgCandidates,
                RichText::new(format::num(container.candidate_entries.len() as u64)),
            ));
        }
        Identity::Windows {
            size,
            profile,
            companion,
            companion_path,
        } => {
            rows.push(text_row(
                Text::OvPlatform,
                RichText::new(tv("platform", &profile.observed.platform)),
            ));
            rows.push(text_row(
                Text::OvFormat,
                widgets::mono(format_label(profile.observed.format)),
            ));
            if let Some(kind) = profile.observed.kind {
                rows.push(text_row(Text::OvKind, RichText::new(tv("kind", &kind))));
            }
            rows.push(text_row(
                Text::OvSource,
                RichText::new(format::bytes(*size)),
            ));
            if *companion != CompanionState::Absent {
                let state = if *companion == CompanionState::Spliced {
                    t(Text::CompanionPaired).into_owned()
                } else {
                    tv("companion", companion).into_owned()
                };
                let name = companion_path
                    .as_deref()
                    .map(|path| format::base_name(path).to_owned());
                rows.push((
                    t(Text::OvCompanion).into_owned(),
                    Box::new(move |ui: &mut Ui| {
                        ui.label(state);
                        if let Some(name) = name {
                            ui.label("·");
                            widgets::selectable(ui, widgets::mono(name));
                        }
                    }),
                ));
            }
        }
        Identity::Metadata { size, identity } => {
            rows.push(text_row(
                Text::OvPlatform,
                RichText::new(tv("platform", &Platform::Il2cppMetadata)),
            ));
            if let Some(identity) = identity {
                rows.push(text_row(
                    Text::OvMetadataVersion,
                    RichText::new(identity.raw_version.to_string()),
                ));
            }
            rows.push(text_row(
                Text::OvSource,
                RichText::new(format::bytes(*size)),
            ));
        }
        Identity::AndroidLibrary { size } => {
            rows.push(text_row(
                Text::OvPlatform,
                RichText::new(tv("platform", &Platform::AndroidElf)),
            ));
            rows.push(text_row(Text::OvFormat, widgets::mono("ELF64 AArch64")));
            rows.push(text_row(
                Text::OvSource,
                RichText::new(format::bytes(*size)),
            ));
        }
        Identity::NotTarget { size } => {
            rows.push(text_row(
                Text::OvSource,
                RichText::new(format::bytes(*size)),
            ));
        }
        Identity::Package {
            container: Err(_),
            size,
        } => {
            rows.push(text_row(
                Text::OvSource,
                RichText::new(format::bytes(*size)),
            ));
        }
        Identity::Unreadable(_) | Identity::NotAFile => {}
    }
    let keys: Vec<String> = rows.iter().map(|(key, _)| key.clone()).collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    widgets::kv(ui, &refs, |kv| {
        for (key, value) in rows {
            kv.row(key, value);
        }
    });
}

fn next_actions(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    item: &Item,
    not_protected: bool,
    can_unpack: bool,
) {
    let choices = [
        (Mode::Unpack, Text::TbUnpack, Text::PendingUnpackDesc, true),
        (Mode::DryRun, Text::TbDryRun, Text::PendingDryRunDesc, false),
        (
            Mode::Inspect,
            Text::TbInspect,
            Text::PendingInspectDesc,
            false,
        ),
    ];
    // The buttons share one column, at least 110 points and as wide as the
    // widest label needs, so all three line up in every language. Measuring in
    // the primary button's semibold font also covers the regular ones.
    let column = choices
        .iter()
        .map(|(_, label, ..)| widgets::primary_button_width(ui, &t(label.clone())))
        .fold(110.0, f32::max);
    for (index, (mode, label, desc, primary)) in choices.into_iter().enumerate() {
        if index > 0 {
            widgets::rule(ui);
        }
        ui.add_space(6.0);
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let enabled = !not_protected && (mode != Mode::Unpack || can_unpack);
            let clicked = ui
                .allocate_ui_with_layout(
                    vec2(column, 24.0),
                    Layout::top_down_justified(Align::Center),
                    |ui| {
                        if primary {
                            widgets::primary_button(ui, t(label), enabled).clicked()
                        } else {
                            ui.add_enabled(
                                enabled,
                                egui::Button::new(t(label)).min_size(vec2(column, 24.0)),
                            )
                            .clicked()
                        }
                    },
                )
                .inner;
            if clicked {
                actions.push(Action::RunItem(mode, item.id));
            }
            ui.add(egui::Label::new(widgets::dim(t(desc))).wrap());
        });
        ui.add_space(6.0);
    }
    if not_protected {
        ui.add_space(8.0);
        widgets::note(ui, t(Text::PendingNotProtectedNote));
    }
}

// --------------------------------------------------------- running inputs

fn run_detail<'a>(ui: &mut Ui, draw: &mut Draw<'a>, view: &mut ViewState, item: &'a Item) {
    let (label, tone) = match item.run {
        RunState::Running => (t(Text::RunRunning), Tone::Info),
        RunState::Queued => (t(Text::RunQueued), Tone::Skip),
        _ => (t(Text::RunWillNotRun), Tone::Skip),
    };
    let head = Head {
        title: item.name.clone(),
        tag: Some(kind_tag(item)),
        pills: vec![(label.into_owned(), tone)],
        path: item.path.display().to_string(),
        tabs: Vec::new(),
        export: None,
    };
    let running = draw
        .jobs
        .running
        .as_ref()
        .filter(|running| running.current == Some(item.id));
    let state = item.run;
    shell(ui, draw, view, head, |ui, _, view| match state {
        RunState::Running => {
            padded(ui, ("running", item.id), |ui| {
                widgets::wide_card(
                    ui,
                    CardSpec::new(t(Text::RunProgress), |ui| {
                        let step = running.and_then(|running| running.step.as_ref());
                        progress_stages(ui, step);
                    }),
                );
                ui.add_space(12.0);
                let lines = running
                    .map(|running| running.live.as_slice())
                    .unwrap_or_default();
                widgets::wide_card(
                    ui,
                    CardSpec::new(t(Text::TabLog), |ui| {
                        logview::log_box(ui, view.log_filter, lines);
                    }),
                );
            });
        }
        RunState::Queued => {}
        _ => padded(ui, ("will-not-run", item.id), |ui| {
            widgets::note(ui, t(Text::RunCancelledNote));
        }),
    });
}

/// The step a running input is on, as the status bar and progress card show it.
pub fn step_text(step: &(Option<(u8, u8)>, senbei_i18n::Step)) -> String {
    let (position, step) = step;
    match position {
        Some((index, total)) => t(Text::RunStep {
            i: index.to_string(),
            n: total.to_string(),
            s: step_title(step).into_owned(),
        })
        .into_owned(),
        None => step_title(step).into_owned(),
    }
}

fn progress_stages(ui: &mut Ui, step: Option<&(Option<(u8, u8)>, senbei_i18n::Step)>) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
        let detection_done = step.is_some();
        stage_chip(
            ui,
            if detection_done {
                ("✓", Tone::Ok)
            } else {
                ("●", Tone::Info)
            },
            &tv("stage", &Stage::Detection),
            None,
            if detection_done {
                (tv("stageStatus", &StageStatus::Ok).into_owned(), Tone::Ok)
            } else {
                (t(Text::RunRunning).into_owned(), Tone::Info)
            },
            None,
            false,
        );
        arrow(ui);
        stage_chip(
            ui,
            ("●", Tone::Info),
            &tv("stage", &Stage::Recovery),
            None,
            (step.map(step_text).unwrap_or_default(), Tone::Info),
            None,
            !detection_done,
        );
        arrow(ui);
        stage_chip_dimmed(ui, &tv("stage", &Stage::StaticValidation));
        arrow(ui);
        stage_chip_dimmed(ui, &tv("stage", &Stage::OutputWrite));
    });
}

fn arrow(ui: &mut Ui) {
    ui.label(widgets::faint("→"));
}

fn stage_frame() -> Frame {
    Frame::new()
        .fill(theme::PANEL)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(10, 5))
}

#[allow(clippy::too_many_arguments)]
fn stage_chip(
    ui: &mut Ui,
    icon: (&str, Tone),
    name: &str,
    duration: Option<u64>,
    status: (String, Tone),
    detail: Option<String>,
    dimmed: bool,
) {
    let opacity = if dimmed { 0.5 } else { 1.0 };
    ui.scope(|ui| {
        ui.multiply_opacity(opacity);
        stage_frame().show(ui, |ui| {
            ui.set_min_width(120.0);
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    ui.label(widgets::toned(icon.0, icon.1).font(theme::strong(12.5)));
                    ui.label(widgets::strong(name, 12.5));
                    if let Some(duration) = duration
                        && duration > 0
                    {
                        ui.label(widgets::faint(format::ms(duration)).font(theme::small()));
                    }
                });
                if !status.0.is_empty() {
                    ui.label(widgets::toned(status.0, status.1).font(theme::small()));
                }
                if let Some(detail) = detail {
                    ui.scope(|ui| {
                        ui.set_max_width(360.0);
                        ui.add(egui::Label::new(widgets::dim(detail).font(theme::small())).wrap());
                    });
                }
            });
        });
    });
}

fn stage_chip_dimmed(ui: &mut Ui, name: &str) {
    ui.scope(|ui| {
        ui.multiply_opacity(0.5);
        stage_frame().show(ui, |ui| {
            ui.set_min_width(120.0);
            ui.label(widgets::strong(name, 12.5));
        });
    });
}

// ------------------------------------------------------------ results

fn item_detail<'a>(
    ui: &mut Ui,
    draw: &mut Draw<'a>,
    view: &mut ViewState,
    item: &'a Item,
    result: &'a ItemResult,
) {
    let input = &result.report;
    let verdict = result.verdict();
    let mut pills = vec![(verdict.label().into_owned(), verdict.tone())];
    if input
        .companion
        .as_ref()
        .is_some_and(|companion| companion.state == CompanionState::Spliced)
    {
        pills.push((t(Text::CompanionSplicedPill).into_owned(), Tone::Info));
    }
    let mut tabs = vec![
        tab(Tab::Overview, Text::TabOverview),
        tab(Tab::Research, Text::TabResearch),
        tab(Tab::Hex, Text::TabHex),
    ];
    if comparable(input) {
        tabs.push(tab(Tab::Compare, Text::TabCompare));
    }
    tabs.push(tab(Tab::Log, Text::TabLog));
    let head = Head {
        title: item.name.clone(),
        tag: Some(kind_tag(item)),
        pills,
        path: last_run_line(item, result),
        tabs,
        export: Some(Sel::Item(item.id)),
    };
    shell(ui, draw, view, head, |ui, draw, view| match view.tab {
        Tab::Research => research::tab(ui, draw, view, research::Subject::item(item, result)),
        Tab::Hex => hex::tab(ui, draw, view, hex::Subject::Item(item)),
        Tab::Compare => super::compare::tab(ui, draw, view, item, result),
        Tab::Log => logview::log_view(ui, view, ("item-log", item.id), &result.log),
        _ => overview(ui, draw, item, result),
    });
}

/// True when both the input and its restored image have PE headers.
pub fn comparable(input: &InputReport) -> bool {
    input.research.as_ref().is_some_and(|research| {
        research.input.pe.is_some()
            && research
                .restored
                .as_ref()
                .is_some_and(|restored| restored.pe.is_some())
    })
}

/// Every message an input reports, each once, where a reader looks for it.
struct Plan<'a> {
    top: Vec<(MsgKind, &'a Message)>,
    validation: Vec<(MsgKind, &'a Message)>,
    shown: HashSet<&'a str>,
}

fn message_plan(input: &InputReport) -> Plan<'_> {
    let profile = input.profile.as_ref();
    let validation_status = profile.map(|profile| profile.static_validation);
    let mut validation: Vec<(MsgKind, &Message)> = Vec::new();
    if matches!(
        validation_status,
        Some(ValidationStatus::Warnings | ValidationStatus::Failed)
    ) && let Some(profile) = profile
    {
        let errors = profile
            .errors
            .iter()
            .map(|message| (MsgKind::Error, message));
        let warnings = profile
            .warnings
            .iter()
            .map(|message| (MsgKind::Warning, message));
        validation.extend(
            errors
                .chain(warnings)
                .filter(|(_, message)| !message.text().trim().is_empty()),
        );
    }
    let mut shown: HashSet<&str> = validation
        .iter()
        .map(|(_, message)| message.text())
        .collect();
    let mut top = Vec::new();
    let mut add = |kind: MsgKind, message| {
        let message: &Message = message;
        if !message.text().trim().is_empty()
            && shown.insert(message.text())
            && !labels::message(message).quiet
        {
            top.push((kind, message));
        }
    };
    for message in &input.errors {
        add(MsgKind::Error, message);
    }
    for message in &input.warnings {
        add(MsgKind::Warning, message);
    }
    if validation.is_empty()
        && let Some(profile) = profile
    {
        for message in &profile.errors {
            add(MsgKind::Error, message);
        }
        for message in &profile.warnings {
            add(MsgKind::Warning, message);
        }
    }
    Plan {
        top,
        validation,
        shown,
    }
}

/// Size and hash of produced bytes.
fn identity_value(ui: &mut Ui, size: Option<u64>, sha256: Option<&str>) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        match (size, sha256) {
            (None, None) => {
                ui.label("—");
            }
            _ => {
                if let Some(size) = size {
                    ui.label(format::bytes(size));
                }
                if let Some(sha256) = sha256 {
                    hash_row(ui, sha256);
                }
            }
        }
    });
}

pub fn hash_row(ui: &mut Ui, sha256: &str) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        widgets::selectable(ui, widgets::mono(format::short_hash(sha256)))
            .on_hover_text(sha256.to_owned());
        widgets::copy_button(ui, sha256);
    });
}

fn json_str<'v>(value: &'v Value, key: &str) -> Option<&'v str> {
    value.get(key)?.as_str()
}

fn json_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

fn overview<'a>(ui: &mut Ui, draw: &mut Draw<'a>, item: &'a Item, result: &'a ItemResult) {
    let input = &result.report;
    let caps = draw.caps;
    let actions = &mut *draw.actions;
    padded(ui, ("overview", item.id), |ui| {
        let profile = input.profile.as_ref();
        let plan = message_plan(input);
        let skipped = input.status == InputStatus::Skipped;
        if !plan.top.is_empty() {
            let blocks: Vec<(MsgKind, Shown)> = plan
                .top
                .iter()
                .map(|(kind, message)| {
                    (
                        if skipped { MsgKind::Info } else { *kind },
                        labels::message(message),
                    )
                })
                .collect();
            widgets::wide_card(
                ui,
                CardSpec::new(t(Text::OvMessages), move |ui| {
                    widgets::messages(ui, &blocks)
                }),
            );
            ui.add_space(12.0);
        }
        let shown = &plan.shown;
        // A run that stopped before it read the format still has the format
        // the file's header showed when it was added.
        let header_format = item.identity.as_ref().and_then(identity_format);
        widgets::card_grid(
            ui,
            ("overview-top", item.id),
            vec![
                CardSpec::new(t(Text::OvRecognition), move |ui| {
                    recognition(ui, profile, header_format.as_deref())
                })
                .aside(move |ui| {
                    let text = profile
                        .map(|profile| tv("recognition", &profile.recognition))
                        .unwrap_or_else(|| "—".into());
                    ui.label(widgets::faint(text).font(theme::small()));
                }),
                CardSpec::new(t(Text::OvRoutes), |ui| routes(ui, profile, shown)),
            ],
        );
        if !input.stages.is_empty() {
            widgets::wide_card(
                ui,
                CardSpec::new(t(Text::OvStages), |ui| stages(ui, input, shown)),
            );
            ui.add_space(12.0);
        }
        let mut lower: Vec<CardSpec<'_>> = Vec::new();
        if let Some(card) = validation_card(input, &plan) {
            lower.push(card);
        }
        let digests = Digests::of(input);
        if !digests.is_empty() {
            lower.push(CardSpec::new(t(Text::OvIdentity), move |ui| {
                identity_card(ui, actions, caps.reveal, input, digests);
            }));
        }
        if let Some(metadata) = &input.metadata {
            lower.push(CardSpec::new(t(Text::OvMetadata), move |ui| {
                metadata_card(ui, metadata, &input.provenance);
            }));
        }
        if let Some(valid) = input
            .android_research
            .as_ref()
            .and_then(|research| research.restoration.as_ref())
            .and_then(|restoration| restoration.get("validation"))
            .filter(|valid| valid.is_object())
        {
            lower.push(CardSpec::new(t(Text::OvRestoredElf), move |ui| {
                elf_card(ui, valid);
            }));
        }
        widgets::card_grid(ui, ("overview-lower", item.id), lower);
    });
}

fn recognition(ui: &mut Ui, profile: Option<&ProtectionProfile>, header_format: Option<&str>) {
    let observed = profile.map(|profile| &profile.observed);
    let known = profile.is_some_and(|profile| {
        profile.recognition != RecognitionStatus::NotAttempted || profile.observed.format.is_some()
    });
    let metadata = observed.is_some_and(|observed| observed.platform == Platform::Il2cppMetadata);
    let keys = [
        t(Text::OvPlatform),
        t(Text::OvFormat),
        t(Text::OvKind),
        t(Text::OvEvidence),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    widgets::kv(ui, &refs, |rows| {
        rows.text(
            &keys[0],
            match observed {
                Some(observed) if known => tv("platform", &observed.platform).into_owned(),
                _ => "—".into(),
            },
        );
        if !metadata {
            let format = match observed.and_then(|observed| observed.format) {
                Some(format) => format_label(Some(format)),
                None => header_format.map_or_else(|| format_label(None), str::to_owned),
            };
            rows.text(&keys[1], widgets::mono(format));
        }
        if let Some(kind) = observed.and_then(|observed| observed.kind) {
            rows.text(&keys[2], tv("kind", &kind).into_owned());
        }
        rows.row(&keys[3], |ui| {
            let evidence = profile
                .map(|profile| profile.evidence.as_slice())
                .unwrap_or_default();
            if evidence.is_empty() {
                ui.label(widgets::faint(t(Text::OvNoEvidence)));
            }
            for item in evidence {
                widgets::pill(ui, tv("evidence", item), Tone::Skip);
            }
        });
    });
}

fn routes(ui: &mut Ui, profile: Option<&ProtectionProfile>, shown: &HashSet<&str>) {
    let candidates = profile
        .map(|profile| profile.candidates.as_slice())
        .unwrap_or_default();
    if candidates.is_empty() {
        ui.label(widgets::faint(t(Text::OvNoRoutes)));
        return;
    }
    for (index, attempt) in candidates.iter().enumerate() {
        if index > 0 {
            widgets::rule(ui);
        }
        ui.add_space(6.0);
        let tone = match attempt.outcome {
            senbei_engine::AttemptOutcome::Succeeded => Tone::Ok,
            senbei_engine::AttemptOutcome::NotAttempted => Tone::Skip,
            _ => Tone::Err,
        };
        ui.horizontal(|ui| {
            ui.label(tv("layout", &attempt.layout));
            if profile.and_then(|profile| profile.selected) == Some(attempt.layout) {
                ui.label(
                    widgets::toned(format!("★ {}", t(Text::OvSelected)), Tone::Warn)
                        .font(theme::small()),
                );
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                widgets::pill(ui, tv("outcome", &attempt.outcome), tone);
            });
        });
        let reasons: Vec<(MsgKind, Shown)> = attempt
            .errors
            .iter()
            .map(|message| (MsgKind::Error, message))
            .chain(
                attempt
                    .warnings
                    .iter()
                    .map(|message| (MsgKind::Warning, message)),
            )
            .filter(|(_, message)| !shown.contains(message.text()))
            .map(|(kind, message)| (kind, labels::message(message)))
            .collect();
        if !reasons.is_empty() {
            ui.add_space(4.0);
            widgets::messages(ui, &reasons);
        }
        ui.add_space(6.0);
    }
}

fn stages(ui: &mut Ui, input: &InputReport, shown: &HashSet<&str>) {
    let skipped = input.status == InputStatus::Skipped;
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
        for (index, stage) in input.stages.iter().enumerate() {
            if index > 0 {
                arrow(ui);
            }
            let status = if skipped && stage.status == StageStatus::Failed {
                StageStatus::Skipped
            } else {
                stage.status
            };
            let (icon, tone) = match status {
                StageStatus::Ok => ("✓", Tone::Ok),
                StageStatus::Skipped => ("–", Tone::Skip),
                StageStatus::Failed => ("✕", Tone::Err),
                StageStatus::Blocked => ("⏸", Tone::Warn),
            };
            let detail = stage.detail.as_ref().and_then(|detail| {
                let hidden = shown.contains(detail.text())
                    || detail.text().contains('\\')
                    || labels::message(detail).quiet;
                (!hidden).then(|| labels::message(detail).text)
            });
            stage_chip(
                ui,
                (icon, tone),
                &tv("stage", &stage.stage),
                stage.duration_ms,
                (tv("stageStatus", &status).into_owned(), tone),
                detail,
                false,
            );
        }
    });
}

fn validation_card<'a>(input: &'a InputReport, plan: &Plan<'a>) -> Option<CardSpec<'a>> {
    let profile = input.profile.as_ref()?;
    let status = profile.static_validation;
    let metadata = profile.observed.platform == Platform::Il2cppMetadata;
    let note = match status {
        ValidationStatus::Warnings => t(Text::OvValidationWarnings),
        ValidationStatus::Failed => t(Text::OvValidationFailed),
        _ if metadata && status != ValidationStatus::Clean => t(Text::OvValidationMetadata),
        _ => return None,
    };
    let tone = match status {
        ValidationStatus::Clean => Tone::Ok,
        ValidationStatus::Warnings => Tone::Warn,
        ValidationStatus::Failed => Tone::Err,
        ValidationStatus::NotRun => Tone::Skip,
    };
    let blocks: Vec<(MsgKind, Shown)> = plan
        .validation
        .iter()
        .map(|(kind, message)| (*kind, labels::message(message)))
        .collect();
    Some(
        CardSpec::new(t(Text::OvValidation), move |ui| {
            widgets::note(ui, note);
            if !blocks.is_empty() {
                ui.add_space(8.0);
                widgets::messages(ui, &blocks);
            }
        })
        .aside(move |ui| {
            widgets::pill(ui, tv("validation", &status), tone);
        }),
    )
}

/// Size and hash of the bytes an input read and recovered, from the report or
/// else from the Android restoration record.
struct Digests {
    source: (Option<u64>, Option<String>),
    recovered: (Option<u64>, Option<String>),
    companion: bool,
    outputs: bool,
}

impl Digests {
    fn of(input: &InputReport) -> Self {
        let restoration = input
            .android_research
            .as_ref()
            .and_then(|research| research.restoration.as_ref());
        let source = match (&input.source, restoration) {
            (Some(digest), _) => (Some(digest.size), Some(digest.sha256.clone())),
            (None, Some(restoration)) => (
                None,
                json_str(restoration, "input_sha256").map(str::to_owned),
            ),
            (None, None) => (None, None),
        };
        let recovered = match (&input.recovered, restoration) {
            (Some(digest), _) => (Some(digest.size), Some(digest.sha256.clone())),
            (None, Some(restoration)) => (
                json_u64(restoration, "output_size"),
                json_str(restoration, "output_sha256").map(str::to_owned),
            ),
            (None, None) => (None, None),
        };
        Self {
            source,
            recovered,
            companion: input.companion.is_some(),
            outputs: !input.outputs.is_empty(),
        }
    }

    fn is_empty(&self) -> bool {
        self.source == (None, None)
            && self.recovered == (None, None)
            && !self.companion
            && !self.outputs
    }
}

fn identity_card(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    reveal: bool,
    input: &InputReport,
    digests: Digests,
) {
    let Digests {
        source, recovered, ..
    } = digests;
    let keys = [
        t(Text::OvSource),
        t(Text::OvCompanion),
        t(Text::OvRecovered),
        t(Text::OvOutput),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    widgets::kv(ui, &refs, |rows| {
        if source != (None, None) {
            rows.row(&keys[0], |ui| {
                identity_value(ui, source.0, source.1.as_deref());
            });
        }
        if let Some(companion) = &input.companion {
            rows.row(&keys[1], |ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    // State and size on one line, the hash under them.
                    let state = tv("companion", &companion.state);
                    match &companion.source {
                        Some(source) => {
                            ui.label(format!("{state} · {}", format::bytes(source.size)));
                            hash_row(ui, &source.sha256);
                        }
                        None => {
                            ui.label(state);
                        }
                    }
                    if let Some(detail) = &companion.detail {
                        let shown = labels::message(detail);
                        if !shown.quiet {
                            widgets::code_spans(ui, &shown.text);
                        }
                    }
                    if let Some(path) = &companion.path {
                        widgets::selectable(
                            ui,
                            widgets::mono(format::base_name(path)).color(theme::FAINT),
                        );
                    }
                });
            });
        }
        if recovered != (None, None) {
            rows.row(&keys[2], |ui| {
                identity_value(ui, recovered.0, recovered.1.as_deref());
            });
        }
        for output in &input.outputs {
            rows.row(&keys[3], |ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    widgets::selectable(ui, widgets::mono(&output.path));
                    ui.horizontal(|ui| {
                        ui.label(format::bytes(output.size));
                        if reveal && widgets::ghost_button(ui, t(Text::OvOpenFolder)).clicked() {
                            actions.push(Action::Reveal(output.path.clone().into()));
                        }
                    });
                });
            });
        }
    });
}

fn metadata_card(ui: &mut Ui, metadata: &senbei_metadata::MetadataIdentity, provenance: &[String]) {
    let keys = [
        t(Text::OvMetadataVersion),
        t(Text::OvMetadataLayout),
        t(Text::OvCapSeeded),
        t(Text::OvCapStructural),
        t(Text::OvCapIndices),
        t(Text::OvCapContext),
        t(Text::OvProvenance),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    let caps = metadata.capabilities;
    widgets::kv(ui, &refs, |rows| {
        rows.text(&keys[0], metadata.raw_version.to_string());
        rows.text(&keys[1], tv("metaLayout", &metadata.layout).into_owned());
        rows.row(&keys[2], |ui| {
            widgets::yes_no(ui, caps.seeded_method_tokens)
        });
        rows.row(&keys[3], |ui| {
            widgets::yes_no(ui, caps.structural_method_tokens)
        });
        rows.row(&keys[4], |ui| {
            widgets::yes_no(ui, caps.method_index_restore)
        });
        rows.row(&keys[5], |ui| {
            widgets::yes_no(ui, caps.method_index_requires_context);
        });
        if !provenance.is_empty() {
            rows.text(&keys[6], widgets::mono(provenance.join("\n")));
        }
    });
}

fn elf_card(ui: &mut Ui, valid: &Value) {
    let keys = [
        t(Text::OvFormat),
        t(Text::OvElfSections),
        t(Text::OvElfSymbols),
        t(Text::OvElfRelocs),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    let text = |key: &str| json_str(valid, key).unwrap_or_default().to_owned();
    let count = |key: &str| {
        json_u64(valid, key)
            .map(format::num)
            .unwrap_or_else(|| "—".into())
    };
    widgets::kv(ui, &refs, |rows| {
        // The engine spells the machine in capitals; the pair this tool
        // restores reads the same as everywhere else in the window.
        let format = match (text("format").as_str(), text("machine").as_str()) {
            ("ELF64", "AARCH64") => format_label(Some(senbei_engine::TargetFormat::Elf64Aarch64)),
            (format, machine) => format!("{format} {machine}"),
        };
        rows.text(&keys[0], widgets::mono(format));
        rows.text(
            &keys[1],
            format!("{} · {}", count("sections"), count("segments")),
        );
        rows.text(&keys[2], count("dynamic_symbols"));
        rows.text(
            &keys[3],
            format!(
                "{} · {}",
                count("dynamic_relocations"),
                count("pltgot_relocations")
            ),
        );
    });
}

// ------------------------------------------------------------- packages

fn package_detail<'a>(
    ui: &mut Ui,
    draw: &mut Draw<'a>,
    view: &mut ViewState,
    item: &'a Item,
    result: &'a ItemResult,
) {
    let input = &result.report;
    let verdict = result.verdict();
    let named = input
        .container
        .as_ref()
        .and_then(|container| container.manifests.iter().find(|manifest| manifest.named))
        .and_then(|manifest| manifest.package.clone());
    let mut pills = vec![(verdict.label().into_owned(), verdict.tone())];
    if let Some(named) = named {
        pills.push((named, Tone::Skip));
    }
    let head = Head {
        title: item.name.clone(),
        tag: Some(kind_tag(item)),
        pills,
        path: last_run_line(item, result),
        tabs: vec![
            tab(Tab::Overview, Text::TabOverview),
            TabSpec {
                tab: Tab::Entries,
                label: t(Text::TabEntries).into_owned(),
                badge: Some(input.entries.len()),
            },
            tab(Tab::Log, Text::TabLog),
        ],
        export: Some(Sel::Item(item.id)),
    };
    shell(ui, draw, view, head, |ui, draw, view| match view.tab {
        Tab::Entries => package_entries(ui, draw, view, item, input),
        Tab::Log => logview::log_view(ui, view, ("item-log", item.id), &result.log),
        _ => package_overview(ui, draw, item, input),
    });
}

fn package_overview<'a>(ui: &mut Ui, draw: &mut Draw<'a>, item: &'a Item, input: &'a InputReport) {
    let actions = &mut *draw.actions;
    padded(ui, ("package", item.id), |ui| {
        let blocks: Vec<(MsgKind, Shown)> = input
            .errors
            .iter()
            .map(|message| (MsgKind::Error, labels::message(message)))
            .chain(
                input
                    .warnings
                    .iter()
                    .map(|message| (MsgKind::Warning, labels::message(message))),
            )
            .filter(|(_, shown)| !shown.quiet)
            .collect();
        if !blocks.is_empty() {
            widgets::wide_card(
                ui,
                CardSpec::new(t(Text::OvMessages), move |ui| {
                    widgets::messages(ui, &blocks)
                }),
            );
            ui.add_space(12.0);
        }
        let Some(container) = &input.container else {
            return;
        };
        let mut counts: Vec<(EntryStatus, usize)> = Vec::new();
        for status in [
            EntryStatus::Restored,
            EntryStatus::Unchanged,
            EntryStatus::Duplicate,
            EntryStatus::Error,
            EntryStatus::NotTarget,
        ] {
            let count = input
                .entries
                .iter()
                .filter(|entry| entry.status == status)
                .count();
            if count > 0 {
                counts.push((status, count));
            }
        }
        widgets::card_grid(
            ui,
            ("package-cards", item.id),
            vec![
                CardSpec::new(t(Text::PkgTitle), move |ui| {
                    let keys = [
                        t(Text::PkgKind),
                        t(Text::PkgEntries),
                        t(Text::PkgCandidates),
                        t(Text::PkgNested),
                    ];
                    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
                    widgets::kv(ui, &refs, |rows| {
                        rows.text(&keys[0], container.kind.to_uppercase());
                        rows.text(&keys[1], format::num(container.entry_count as u64));
                        rows.text(
                            &keys[2],
                            format::num(container.candidate_entries.len() as u64),
                        );
                        if !container.nested_packages.is_empty() {
                            rows.text(
                                &keys[3],
                                widgets::mono(container.nested_packages.join("\n")),
                            );
                        }
                    });
                    ui.add_space(8.0);
                    widgets::note(ui, t(Text::PkgNote));
                }),
                CardSpec::new(t(Text::PkgResult), move |ui| {
                    let labels: Vec<String> = counts
                        .iter()
                        .map(|(status, _)| tv("entryStatus", status).into_owned())
                        .collect();
                    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
                    widgets::kv(ui, &refs, |rows| {
                        for ((status, count), label) in counts.iter().zip(&labels) {
                            let text = match status {
                                EntryStatus::Error => widgets::toned(count.to_string(), Tone::Err),
                                EntryStatus::Restored => {
                                    widgets::toned(count.to_string(), Tone::Ok)
                                }
                                _ => RichText::new(count.to_string()),
                            };
                            rows.text(label, text);
                        }
                    });
                }),
            ],
        );
        widgets::wide_card(
            ui,
            CardSpec::new(t(Text::PkgManifests), move |ui| {
                let cols = [
                    col(t(Text::ColSource)).width(220.0),
                    col(t(Text::PkgPackage)).width(260.0),
                    col(t(Text::PkgVersion)),
                ];
                let manifests = &container.manifests;
                table::table(
                    ui,
                    ("manifests", item.id),
                    &cols,
                    manifests.len(),
                    |_| table::lines(1),
                    |index, row| {
                        let manifest = &manifests[index];
                        table::mono(row, format::base_name(&manifest.source).to_owned());
                        match &manifest.package {
                            Some(package) => table::mono(row, package.clone()),
                            None => table::text(row, widgets::faint(t(Text::PkgUnnamed))),
                        }
                        table::mono(row, manifest.version.clone().unwrap_or_default());
                    },
                );
            })
            .aside(move |ui| {
                ui.label(
                    widgets::faint(container.manifests.len().to_string()).font(theme::small()),
                );
            }),
        );
        ui.add_space(12.0);
        let targets: Vec<usize> = input
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| is_target_entry(entry))
            .map(|(index, _)| index)
            .collect();
        if targets.is_empty() {
            widgets::wide_card(
                ui,
                CardSpec::untitled(|ui| widgets::note(ui, t(Text::PkgNoTargets))),
            );
        } else {
            widgets::wide_card(
                ui,
                CardSpec::new(t(Text::PkgTargets), |ui| {
                    entry_table(ui, actions, item, &input.entries, &targets);
                }),
            );
        }
    });
}

fn entry_table(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    item: &Item,
    entries: &[EntryReport],
    shown: &[usize],
) {
    // A column no shown entry has a value for is left out: Android entries
    // carry no route, and only Unpack keeps outputs.
    let routes = shown.iter().any(|index| {
        let entry = &entries[*index];
        entry.layout.is_some() || entry.remapped.is_some()
    });
    let outputs = shown.iter().any(|index| entries[*index].output.is_some());
    let mut cols = vec![
        col("").width(18.0),
        col(t(Text::ColName)).width(240.0),
        col(t(Text::ColType)).width(120.0),
        col(t(Text::ColStatus)).width(110.0),
    ];
    if routes {
        cols.push(col(t(Text::ColRoute)).width(170.0));
    }
    if outputs {
        cols.push(col(t(Text::OvOutput)));
    }
    let mut clicked = None;
    table::table_clickable(
        ui,
        ("entries", item.id, shown.len(), routes, outputs),
        &cols,
        shown.len(),
        |_| table::lines(2),
        |index, row| {
            let entry = &entries[shown[index]];
            let verdict = Verdict::of_entry(entry);
            table::cell(row, |ui| {
                widgets::dot(ui, Some(verdict.tone()));
            });
            let inner = entry_inner(&entry.name);
            let source = entry_source(&entry.name);
            let folder = inner
                .replace('/', "\\")
                .rsplit_once('\\')
                .map(|(folder, _)| format!("{folder}\\"))
                .unwrap_or_default();
            let place = if source.is_empty() {
                folder
            } else {
                format!("{} › {folder}", format::base_name(source))
            };
            table::cell(row, |ui| {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.add(
                        egui::Label::new(
                            RichText::new(format::base_name(inner)).font(theme::mono_small()),
                        )
                        .truncate(),
                    );
                    ui.add(egui::Label::new(widgets::faint(place).font(theme::small())).truncate());
                });
            });
            table::cell(row, |ui| {
                widgets::tag(ui, entry_tag(entry));
            });
            table::text(row, widgets::toned(verdict.label(), verdict.tone()));
            if routes {
                table::cell(row, |ui| {
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        if let Some(layout) = entry.layout {
                            ui.add(egui::Label::new(tv("layout", &layout)).truncate());
                        }
                        if let Some(remapped) = entry.remapped {
                            ui.add(
                                egui::Label::new(
                                    widgets::faint(t(Text::EntriesRemapped {
                                        n: format::num(remapped as u64),
                                    }))
                                    .font(theme::small()),
                                )
                                .truncate(),
                            );
                        }
                    });
                });
            }
            if outputs {
                table::mono(
                    row,
                    entry
                        .output
                        .as_ref()
                        .map(|output| output.path.clone())
                        .unwrap_or_default(),
                );
            }
        },
        |index| clicked = Some(index),
    );
    if let Some(index) = clicked {
        actions.push(Action::Select {
            sel: Sel::Entry(item.id, shown[index]),
            toggle: false,
        });
    }
}

fn package_entries<'a>(
    ui: &mut Ui,
    draw: &mut Draw<'a>,
    view: &mut ViewState,
    item: &'a Item,
    input: &'a InputReport,
) {
    let actions = &mut *draw.actions;
    let entries = &input.entries;
    let non_targets = entries
        .iter()
        .filter(|entry| !is_target_entry(entry))
        .count();
    padded(ui, ("package-entries", item.id), |ui| {
        ui.checkbox(
            &mut view.show_non_targets,
            widgets::dim(t(Text::EntriesShowNonTargets {
                n: non_targets.to_string(),
            })),
        );
        ui.add_space(8.0);
        let mut shown: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| view.show_non_targets || is_target_entry(entry))
            .map(|(index, _)| index)
            .collect();
        if shown.is_empty() {
            shown = (0..entries.len()).collect();
        }
        entry_table(ui, actions, item, entries, &shown);
        if let Some(container) = &input.container {
            ui.add_space(12.0);
            egui::CollapsingHeader::new(widgets::dim(t(Text::PkgInventory {
                n: container.candidate_entries.len().to_string(),
            })))
            .id_salt(("inventory", item.id))
            .show(ui, |ui| {
                Frame::new()
                    .fill(theme::WELL)
                    .corner_radius(CornerRadius::same(4))
                    .inner_margin(Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ScrollArea::vertical()
                            .id_salt(("inventory-list", item.id))
                            .max_height(280.0)
                            .show(ui, |ui| {
                                widgets::selectable(
                                    ui,
                                    widgets::mono(container.candidate_entries.join("\n")),
                                );
                            });
                    });
            });
        }
    });
}

fn entry_detail<'a>(
    ui: &mut Ui,
    draw: &mut Draw<'a>,
    view: &mut ViewState,
    item: &'a Item,
    index: usize,
    entry: &'a EntryReport,
) {
    let verdict = Verdict::of_entry(entry);
    let mut tabs = vec![tab(Tab::Overview, Text::TabOverview)];
    if entry.android_research.is_some() || entry.metadata_research.is_some() {
        tabs.push(tab(Tab::Research, Text::TabResearch));
    }
    tabs.push(tab(Tab::Hex, Text::TabHex));
    let inner = entry_inner(&entry.name);
    let head = Head {
        title: format::base_name(inner).to_owned(),
        tag: Some(entry_tag(entry)),
        pills: vec![(verdict.label().into_owned(), verdict.tone())],
        path: super::inputs::entry_path(item, entry),
        tabs,
        export: None,
    };
    let mode = item.result.as_ref().map(|result| result.mode);
    let reveal = draw.caps.reveal;
    shell(ui, draw, view, head, |ui, draw, view| match view.tab {
        Tab::Research => research::tab(
            ui,
            draw,
            view,
            research::Subject::entry(item, index, entry, mode),
        ),
        Tab::Hex => hex::tab(ui, draw, view, hex::Subject::Entry { item, entry }),
        _ => {
            let actions = &mut *draw.actions;
            padded(ui, ("entry", item.id, index), |ui| {
                let blocks: Vec<(MsgKind, Shown)> = entry
                    .errors
                    .iter()
                    .map(|message| (MsgKind::Error, labels::message(message)))
                    .chain(
                        entry
                            .warnings
                            .iter()
                            .map(|message| (MsgKind::Warning, labels::message(message))),
                    )
                    .filter(|(_, shown)| !shown.quiet)
                    .collect();
                if !blocks.is_empty() {
                    widgets::wide_card(
                        ui,
                        CardSpec::new(t(Text::OvMessages), move |ui| {
                            widgets::messages(ui, &blocks)
                        }),
                    );
                    ui.add_space(12.0);
                }
                let restoration = entry
                    .android_research
                    .as_ref()
                    .and_then(|research| research.restoration.as_ref());
                let mut cards = vec![CardSpec::new(t(Text::EntriesTitle), move |ui| {
                    entry_rows(ui, actions, reveal, item, entry, verdict, restoration);
                })];
                if let Some(valid) = restoration
                    .and_then(|restoration| restoration.get("validation"))
                    .filter(|valid| valid.is_object())
                {
                    cards.push(CardSpec::new(t(Text::OvRestoredElf), move |ui| {
                        elf_card(ui, valid);
                    }));
                }
                widgets::card_grid(ui, ("entry-cards", item.id, index), cards);
            });
        }
    });
}

fn entry_rows(
    ui: &mut Ui,
    actions: &mut Vec<Action>,
    reveal: bool,
    item: &Item,
    entry: &EntryReport,
    verdict: Verdict,
    restoration: Option<&Value>,
) {
    let keys = [
        t(Text::ColStatus),
        t(Text::ColType),
        t(Text::ColRoute),
        t(Text::OvMetadataVersion),
        t(Text::EntriesRemappedLabel),
        t(Text::OvProvenance),
        t(Text::OvSource),
        t(Text::OvRecovered),
        t(Text::OvOutput),
    ];
    let refs: Vec<&str> = keys.iter().map(|key| key.as_ref()).collect();
    widgets::kv(ui, &refs, |rows| {
        rows.text(&keys[0], widgets::toned(verdict.label(), verdict.tone()));
        if let Some(kind) = entry.kind {
            rows.text(&keys[1], tv("entryKind", &kind).into_owned());
        }
        if let Some(layout) = entry.layout {
            rows.text(&keys[2], tv("layout", &layout).into_owned());
        }
        if let Some(version) = entry.metadata_version {
            rows.text(&keys[3], version.to_string());
        }
        if let Some(remapped) = entry.remapped {
            rows.text(&keys[4], format::num(remapped as u64));
        }
        if !entry.provenance.is_empty() {
            rows.text(&keys[5], widgets::mono(entry.provenance.join("\n")));
        }
        if let Some(restoration) = restoration {
            rows.row(&keys[6], |ui| match json_str(restoration, "input_sha256") {
                Some(sha256) => hash_row(ui, sha256),
                None => {
                    ui.label("—");
                }
            });
            rows.row(&keys[7], |ui| {
                identity_value(
                    ui,
                    json_u64(restoration, "output_size"),
                    json_str(restoration, "output_sha256"),
                );
            });
        }
        if let Some(output) = &entry.output {
            rows.row(&keys[8], |ui| {
                widgets::selectable(ui, widgets::mono(&output.path));
                if reveal && widgets::ghost_button(ui, t(Text::OvOpenFolder)).clicked() {
                    actions.push(Action::Reveal(output.path.clone().into()));
                }
            });
        }
    });
    let _ = item;
}

/// The output-location label of the top bar.
pub fn output_label(output: &Output) -> String {
    match output {
        Output::Beside => t(Text::TbOutputBeside).into_owned(),
        Output::Folder(folder) => folder.display().to_string(),
    }
}
