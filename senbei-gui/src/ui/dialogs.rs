//! The window's frame and overlays: top bar, banner, status bar, the empty
//! session, the drop overlay, and the legal, settings, and close dialogs.

use egui::text::LayoutJob;
use egui::{
    Align, Align2, Color32, ComboBox, Context, CornerRadius, Frame, Id, Layout, Margin, Modal,
    Order, Popup, Rect, Response, RichText, Sense, Shape, Stroke, TextFormat, TextureHandle, Ui,
    pos2, vec2,
};
use senbei_i18n::Lang;
use senbei_io::report::Mode;

use super::{Action, Draw, SettingsTab, ViewState, widgets};
use crate::backend::{Output, Pick};
use crate::format;
use crate::model::mode_action;
use crate::settings::Settings;
use crate::text::{Text, strong_runs, t};
use crate::theme::{self, Tone};

fn icon_image(icon: Option<&TextureHandle>, size: f32) -> Option<egui::Image<'static>> {
    icon.map(|texture| egui::Image::new((texture.id(), vec2(size, size))))
}

// ---------------------------------------------------------------- top bar

pub struct TopBar<'a> {
    pub targets: usize,
    pub has_selection: bool,
    pub icon: Option<&'a TextureHandle>,
}

fn run_label(mode: Mode, has_selection: bool, targets: usize) -> String {
    let n = targets.to_string();
    t(match (mode, has_selection) {
        (Mode::Unpack, true) => Text::TbUnpackN { n },
        (Mode::Unpack, false) => Text::TbUnpackAll,
        (Mode::DryRun, true) => Text::TbDryRunN { n },
        (Mode::DryRun, false) => Text::TbDryRunAll,
        (Mode::Inspect, true) => Text::TbInspectN { n },
        (Mode::Inspect, false) => Text::TbInspectAll,
    })
    .into_owned()
}

pub fn topbar(ui: &mut Ui, draw: &mut Draw<'_>, view: &mut ViewState, bar: TopBar<'_>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if let Some(image) = icon_image(bar.icon, 26.0) {
            ui.add(image);
        }
        ui.label(RichText::new("Senbei").font(theme::title(19.0)));
        ui.label(
            RichText::new(env!("CARGO_PKG_VERSION"))
                .font(theme::tiny())
                .color(theme::FAINT),
        );
        ui.add_space(6.0);
        if ui
            .button(t(Text::TbAddFiles))
            .on_hover_text("Ctrl+O")
            .clicked()
        {
            draw.act(Action::Pick(Pick::Files));
        }
        if draw.caps.folders && ui.button(t(Text::TbAddFolder)).clicked() {
            draw.act(Action::Pick(Pick::Folder));
        }
        separator(ui);
        let enabled = !draw.session.is_empty() && bar.targets > 0;
        let unpack = widgets::primary_button(
            ui,
            format!(
                "▶ {}",
                run_label(Mode::Unpack, bar.has_selection, bar.targets)
            ),
            enabled && draw.caps.unpack,
        )
        .on_hover_text(t(Text::TbUnpackTip));
        if unpack.clicked() {
            draw.act(Action::Run(Mode::Unpack));
        }
        for (mode, tip) in [
            (Mode::DryRun, Text::TbDryRunTip),
            (Mode::Inspect, Text::TbInspectTip),
        ] {
            let button = ui
                .add_enabled(
                    enabled,
                    egui::Button::new(run_label(mode, bar.has_selection, bar.targets)),
                )
                .on_hover_text(t(tip));
            if button.clicked() {
                draw.act(Action::Run(mode));
            }
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let settings = ui
                .add(egui::Button::new(RichText::new("⚙").size(15.0)))
                .on_hover_text(t(Text::TbSettings));
            if settings.clicked() {
                view.settings_open = true;
            }
            if draw.caps.unpack {
                output_chip(ui, draw);
            }
        });
    });
}

fn separator(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(1.0, 22.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, theme::BORDER);
}

fn output_chip(ui: &mut Ui, draw: &mut Draw<'_>) {
    let label = super::detail::output_label(&draw.settings.output);
    let prefix =
        ui.painter()
            .layout_no_wrap(t(Text::TbOutput).into_owned(), theme::body(), theme::DIM);
    let caret = ui
        .painter()
        .layout_no_wrap("▾".into(), theme::body(), theme::FAINT);
    let mut job = LayoutJob::simple_singleline(label, theme::body(), theme::TEXT);
    job.wrap = egui::text::TextWrapping::truncate_at_width(
        340.0 - prefix.size().x - caret.size().x - 28.0,
    );
    let value = ui.painter().layout_job(job);
    let size = vec2(
        prefix.size().x + value.size().x + caret.size().x + 12.0 + 16.0,
        24.0,
    );
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    widgets::describe(&response, egui::Role::Button, &t(Text::TbOutput), None);
    let stroke = if response.hovered() {
        theme::HOVER_STROKE
    } else {
        theme::BORDER
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(4),
        Color32::TRANSPARENT,
        Stroke::new(1.0, stroke),
        egui::StrokeKind::Inside,
    );
    let mut x = rect.left() + 8.0;
    let y = |galley: &std::sync::Arc<egui::Galley>| rect.center().y - galley.size().y / 2.0;
    let prefix_width = prefix.size().x;
    let prefix_y = y(&prefix);
    ui.painter().galley(pos2(x, prefix_y), prefix, theme::DIM);
    x += prefix_width + 6.0;
    let value_width = value.size().x;
    let value_y = y(&value);
    ui.painter().galley(pos2(x, value_y), value, theme::TEXT);
    x += value_width + 6.0;
    let caret_y = y(&caret);
    ui.painter().galley(pos2(x, caret_y), caret, theme::FAINT);
    let response = response.on_hover_text(t(Text::TbOutputTip));
    let current = draw.settings.output.clone();
    let recent = draw.settings.recent_output.clone();
    Popup::menu(&response).width(330.0).show(|ui| {
        let choice = |ui: &mut Ui, on: bool, label: String, sub: Option<String>| -> bool {
            let mut clicked = false;
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(widgets::toned(if on { "●" } else { "○" }, Tone::Warn));
                ui.vertical(|ui| {
                    clicked = ui
                        .add(egui::Button::new(label).frame_when_inactive(false))
                        .clicked();
                    if let Some(sub) = sub {
                        ui.label(widgets::faint(sub).font(theme::mono_small()));
                    }
                });
            });
            clicked
        };
        if choice(
            ui,
            current == Output::Beside,
            t(Text::TbOutputBeside).into_owned(),
            None,
        ) {
            draw.act(Action::SetOutput(Output::Beside));
            ui.close();
        }
        if let Some(recent) = recent {
            let on = current == Output::Folder(recent.clone());
            if choice(
                ui,
                on,
                t(Text::SettingsOutputRecent).into_owned(),
                Some(recent.display().to_string()),
            ) {
                draw.act(Action::SetOutput(Output::Folder(recent)));
                ui.close();
            }
        }
        ui.separator();
        if ui
            .add(egui::Button::new(t(Text::SettingsOutputChoose)).frame_when_inactive(false))
            .clicked()
        {
            draw.act(Action::Pick(Pick::Output));
            ui.close();
        }
    });
}

pub fn banner(ui: &mut Ui, vars: &[String]) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.label(widgets::toned("⚠", Tone::Warn));
        let names = vars
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let text = t(Text::BannerEnv { vars: names });
        let mut job = LayoutJob::default();
        for (index, part) in text.split('`').enumerate() {
            let code = index % 2 == 1;
            job.append(
                part,
                0.0,
                TextFormat {
                    font_id: if code { theme::mono() } else { theme::body() },
                    color: if code { theme::TEXT } else { theme::WARN },
                    ..Default::default()
                },
            );
        }
        ui.label(job);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(widgets::faint(t(Text::BannerEnvHint)));
        });
    });
}

// ------------------------------------------------------------- status bar

pub fn statusbar(ui: &mut Ui, draw: &mut Draw<'_>, notice: Option<&super::Notice>) {
    ui.horizontal(|ui| {
        ui.set_min_height(22.0);
        ui.spacing_mut().item_spacing.x = 14.0;
        let small = |text: String| RichText::new(text).font(theme::small()).color(theme::DIM);
        if let Some(running) = &draw.jobs.running {
            ui.label(widgets::toned("●", Tone::Info));
            ui.label(widgets::strong(mode_action(running.plan.mode), 12.5).color(theme::TEXT));
            let total = running.total.max(running.done);
            let fraction = if total == 0 {
                0.0
            } else {
                running.done as f32 / total as f32
            };
            progress(ui, fraction);
            ui.label(small(format!("{} / {}", running.done, total)));
            if let Some((_, item)) = running.current.and_then(|id| draw.session.item(id)) {
                ui.scope(|ui| {
                    ui.set_max_width(420.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(&item.name)
                                .font(theme::mono_small())
                                .color(theme::TEXT),
                        )
                        .truncate(),
                    );
                });
            }
            if let Some(step) = &running.step {
                ui.label(small(super::detail::step_text(step)));
            }
            ui.label(
                RichText::new(format::clock(
                    running.input_started.elapsed().as_millis() as u64
                ))
                .font(theme::small())
                .color(theme::FAINT),
            );
            if !draw.jobs.queued.is_empty() {
                ui.label(
                    RichText::new(t(Text::RunQueue {
                        n: draw.jobs.queued.len().to_string(),
                    }))
                    .font(theme::small())
                    .color(theme::FAINT),
                );
            }
            let stopping = running.cancel_requested;
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let cancel = ui.add_enabled(
                    !stopping,
                    egui::Button::new(RichText::new(t(Text::RunCancel)).color(theme::ERR)),
                );
                if cancel.clicked() {
                    draw.act(Action::Cancel);
                }
                if stopping {
                    ui.label(
                        RichText::new(t(Text::RunStopping))
                            .font(theme::small())
                            .color(theme::WARN),
                    );
                }
            });
            return;
        }
        if let Some(group) = draw
            .session
            .groups
            .iter()
            .find(|group| group.scanning.is_some())
        {
            ui.label(widgets::toned("●", Tone::Info));
            ui.label(small(
                t(Text::ScanStatus {
                    p: group.title().into_owned(),
                    n: group.scanning.unwrap_or_default().to_string(),
                })
                .into_owned(),
            ));
            return;
        }
        ui.label(widgets::toned("●", Tone::Ok));
        ui.label(small(t(Text::StatusReady).into_owned()));
        if let Some(notice) = notice {
            ui.add(
                egui::Label::new(
                    RichText::new(&notice.text)
                        .font(theme::small())
                        .color(notice.tone.color()),
                )
                .truncate(),
            );
        }
    });
}

fn progress(ui: &mut Ui, fraction: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(220.0, 8.0), Sense::hover());
    ui.painter().rect(
        rect,
        CornerRadius::same(4),
        theme::WELL,
        Stroke::new(1.0, theme::BORDER),
        egui::StrokeKind::Inside,
    );
    let filled = Rect::from_min_size(
        rect.min,
        vec2(rect.width() * fraction.clamp(0.0, 1.0), rect.height()),
    );
    ui.painter()
        .rect_filled(filled, CornerRadius::same(4), theme::ACCENT);
}

// ------------------------------------------------------------ empty state

fn dashed_rect(ui: &Ui, rect: Rect, color: Color32, width: f32) {
    let points = [
        rect.left_top(),
        rect.right_top(),
        rect.right_bottom(),
        rect.left_bottom(),
        rect.left_top(),
    ];
    ui.painter().extend(Shape::dashed_line(
        &points,
        Stroke::new(width, color),
        6.0,
        4.0,
    ));
}

pub fn empty_state(ui: &mut Ui, draw: &mut Draw<'_>, icon: Option<&TextureHandle>) {
    let full = ui.available_rect_before_wrap();
    let width = (full.width() - 60.0).clamp(200.0, 640.0);
    let height = 330.0;
    let rect = Rect::from_center_size(full.center(), vec2(width, height));
    ui.painter()
        .rect_filled(rect, CornerRadius::same(10), theme::BG);
    dashed_rect(ui, rect, theme::BORDER_STRONG, 1.5);
    ui.scope_builder(
        egui::UiBuilder::new().max_rect(rect.shrink2(vec2(30.0, 30.0))),
        |ui| {
            ui.vertical_centered(|ui| {
                ui.spacing_mut().item_spacing.y = 6.0;
                if let Some(image) = icon_image(icon, 84.0) {
                    ui.add(image);
                }
                ui.add_space(6.0);
                ui.label(RichText::new(t(Text::EmptyTitle)).font(theme::title(21.0)));
                ui.add_space(8.0);
                let kinds = [
                    ".exe".to_owned(),
                    ".dll".to_owned(),
                    ".exe._ / .dll._".to_owned(),
                    "global-metadata.dat".to_owned(),
                    ".so".to_owned(),
                    ".apk".to_owned(),
                    ".apks".to_owned(),
                    ".xapk".to_owned(),
                    t(Text::EmptyFolders).into_owned(),
                ];
                centered_wrap(ui, &kinds);
                ui.add_space(12.0);
                widgets::centered_row(ui, "empty-buttons", |ui| {
                    if widgets::primary_button(ui, t(Text::TbAddFiles), true).clicked() {
                        draw.act(Action::Pick(Pick::Files));
                    }
                    if draw.caps.folders && ui.button(t(Text::TbAddFolder)).clicked() {
                        draw.act(Action::Pick(Pick::Folder));
                    }
                });
                ui.add_space(14.0);
                ui.label(widgets::faint(t(Text::EmptyLocal)));
            });
        },
    );
}

/// Tags laid out in centred rows.
fn centered_wrap(ui: &mut Ui, tags: &[String]) {
    let max = ui.available_width();
    let widths: Vec<f32> = tags
        .iter()
        .map(|tag| {
            ui.painter()
                .layout_no_wrap(tag.clone(), egui::FontId::monospace(11.0), theme::DIM)
                .size()
                .x
                + 10.0
        })
        .collect();
    let gap = 6.0;
    let mut rows: Vec<Vec<usize>> = vec![Vec::new()];
    let mut width = 0.0;
    for (index, tag_width) in widths.iter().enumerate() {
        if width + tag_width > max && !rows.last().is_some_and(Vec::is_empty) {
            rows.push(Vec::new());
            width = 0.0;
        }
        rows.last_mut().expect("a row").push(index);
        width += tag_width + gap;
    }
    for row in rows {
        let row_width: f32 = row.iter().map(|index| widths[*index]).sum::<f32>()
            + gap * row.len().saturating_sub(1) as f32;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            ui.add_space(((max - row_width) / 2.0).max(0.0));
            for index in row {
                widgets::mono_tag(ui, &tags[index]);
            }
        });
    }
}

// --------------------------------------------------------------- overlays

pub struct Overlays<'a> {
    pub legal_pending: bool,
    pub icon: Option<&'a TextureHandle>,
    pub detected: Lang,
}

pub fn overlays(
    ctx: &Context,
    draw: &mut Draw<'_>,
    view: &mut ViewState,
    settings: &mut Settings,
    overlays: Overlays<'_>,
) {
    if ctx.input(|input| !input.raw.hovered_files.is_empty()) {
        drop_overlay(ctx);
    }
    if view.settings_open {
        settings_modal(ctx, draw, view, settings, &overlays);
    }
    if view.close_confirm {
        close_modal(ctx, draw, view);
    }
    if overlays.legal_pending || view.legal_open {
        legal_modal(ctx, draw, view, settings, &overlays);
    }
}

fn drop_overlay(ctx: &Context) {
    egui::Area::new(Id::unique("drop-overlay"))
        .order(Order::Foreground)
        .fixed_pos(pos2(0.0, 0.0))
        .show(ctx, |ui| {
            let screen = ctx.content_rect();
            ui.painter()
                .rect_filled(screen, 0, Color32::from_rgba_unmultiplied(12, 14, 17, 199));
            let galley = ui.painter().layout_no_wrap(
                t(Text::DragTitle).into_owned(),
                theme::title(22.0),
                theme::ACCENT,
            );
            let size = galley.size() + vec2(140.0, 80.0);
            let rect = Rect::from_center_size(screen.center(), size);
            ui.painter()
                .rect_filled(rect, CornerRadius::same(12), theme::BG);
            dashed_rect(ui, rect, theme::ACCENT, 2.0);
            ui.painter()
                .galley(rect.center() - galley.size() / 2.0, galley, theme::ACCENT);
        });
}

fn modal_frame() -> Frame {
    Frame::new()
        .fill(theme::PANEL)
        .stroke(Stroke::new(1.0, theme::BORDER_STRONG))
        .corner_radius(CornerRadius::same(8))
}

fn modal_section(ui: &mut Ui, margin: Margin, add: impl FnOnce(&mut Ui)) {
    Frame::new().inner_margin(margin).show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui);
    });
}

fn language_combo(ui: &mut Ui, id: &str, settings: &mut Settings, detected: Lang) -> Response {
    let current = settings.lang(detected);
    ComboBox::from_id_salt(id)
        .selected_text(current.native_name())
        .show_ui(ui, |ui| {
            for lang in Lang::ALL {
                if ui
                    .selectable_label(lang == current, lang.native_name())
                    .clicked()
                {
                    settings.language = Some(lang.tag().to_owned());
                }
            }
        })
        .response
        .accessible_name(t(Text::SettingsLanguage))
}

fn legal_modal(
    ctx: &Context,
    draw: &mut Draw<'_>,
    view: &mut ViewState,
    settings: &mut Settings,
    overlays: &Overlays<'_>,
) {
    Modal::new(Id::unique("legal"))
        .frame(modal_frame())
        .backdrop_color(theme::backdrop())
        .show(ctx, |ui| {
            ui.set_width(620.0_f32.min(ctx.content_rect().width() - 40.0));
            ui.spacing_mut().item_spacing.y = 0.0;
            modal_section(ui, Margin::symmetric(16, 12), |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    if let Some(image) = icon_image(overlays.icon, 24.0) {
                        ui.add(image);
                    }
                    ui.label(RichText::new(t(Text::LegalTitle)).font(theme::title(17.0)));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        language_combo(ui, "legal-language", settings, overlays.detected);
                    });
                });
            });
            widgets::rule(ui);
            modal_section(ui, Margin::symmetric(16, 14), |ui| {
                ui.spacing_mut().item_spacing.y = 10.0;
                for text in [Text::LegalP1, Text::LegalP2, Text::LegalP3, Text::LegalP4] {
                    let text = t(text);
                    let mut job = LayoutJob::default();
                    for (strong, run) in strong_runs(&text) {
                        job.append(
                            run,
                            0.0,
                            TextFormat {
                                font_id: if strong {
                                    theme::strong(13.5)
                                } else {
                                    theme::body()
                                },
                                color: if strong { theme::TEXT } else { theme::DIM },
                                ..Default::default()
                            },
                        );
                    }
                    job.wrap.max_width = ui.available_width();
                    ui.add(egui::Label::new(job).wrap());
                }
            });
            widgets::rule(ui);
            modal_section(ui, Margin::symmetric(16, 10), |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if widgets::primary_button(ui, t(Text::LegalAccept), true).clicked() {
                        draw.act(Action::AcceptLegal);
                        settings.legal_accepted = true;
                        view.legal_open = false;
                    }
                    if ui.button(t(Text::LegalQuit)).clicked() {
                        if overlays.legal_pending {
                            draw.act(Action::Quit);
                        } else {
                            view.legal_open = false;
                        }
                    }
                });
            });
        });
}

fn close_modal(ctx: &Context, draw: &mut Draw<'_>, view: &mut ViewState) {
    let response = Modal::new(Id::unique("close-confirm"))
        .frame(modal_frame())
        .backdrop_color(theme::backdrop())
        .show(ctx, |ui| {
            ui.set_width(520.0);
            ui.spacing_mut().item_spacing.y = 0.0;
            modal_section(ui, Margin::symmetric(16, 12), |ui| {
                ui.label(RichText::new(t(Text::CloseTitle)).font(theme::title(17.0)));
            });
            widgets::rule(ui);
            modal_section(ui, Margin::symmetric(16, 14), |ui| {
                ui.add(egui::Label::new(widgets::dim(t(Text::CloseBody))).wrap());
            });
            widgets::rule(ui);
            modal_section(ui, Margin::symmetric(16, 10), |ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    if widgets::primary_button(ui, t(Text::CloseStop), true).clicked() {
                        draw.act(Action::StopAndClose);
                    }
                    if ui.button(t(Text::CloseKeep)).clicked() {
                        view.close_confirm = false;
                    }
                });
            });
        });
    if response.should_close() {
        view.close_confirm = false;
    }
}

// ---------------------------------------------------------------- settings

/// A settings row: its label, its control, and an optional help line. The
/// control returns its main widget, which the label names for screen readers.
fn field(ui: &mut Ui, label: Text, help: Option<Text>, control: impl FnOnce(&mut Ui) -> Response) {
    labelled_row(ui, label, help, |ui, label| {
        control(ui).labelled_by(label);
    });
}

/// A row that only shows a value beside its label, such as a link, which
/// keeps its own name.
fn info_row(ui: &mut Ui, label: Text, value: impl FnOnce(&mut Ui)) {
    labelled_row(ui, label, None, |ui, _| value(ui));
}

fn labelled_row(ui: &mut Ui, label: Text, help: Option<Text>, add: impl FnOnce(&mut Ui, Id)) {
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        let label = ui
            .allocate_ui_with_layout(
                vec2(210.0, 24.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.set_width(210.0);
                    ui.add(egui::Label::new(t(label)).wrap())
                },
            )
            .inner;
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 4.0;
            ui.horizontal(|ui| add(ui, label.id));
            if let Some(help) = help {
                ui.add(egui::Label::new(widgets::faint(t(help)).font(theme::small())).wrap());
            }
        });
    });
}

fn mib(ui: &mut Ui, value: &mut u64) -> Response {
    let response = ui.add(egui::DragValue::new(value).range(1..=1_048_576).speed(16.0));
    ui.label("MiB");
    response
}

fn settings_modal(
    ctx: &Context,
    draw: &mut Draw<'_>,
    view: &mut ViewState,
    settings: &mut Settings,
    overlays: &Overlays<'_>,
) {
    let response = Modal::new(Id::unique("settings"))
        .frame(modal_frame())
        .backdrop_color(theme::backdrop())
        .show(ctx, |ui| {
            ui.set_width(760.0_f32.min(ctx.content_rect().width() - 40.0));
            ui.spacing_mut().item_spacing.y = 0.0;
            modal_section(ui, Margin::symmetric(16, 12), |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(t(Text::SettingsTitle)).font(theme::title(17.0)));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::ghost_button(ui, "✕").clicked() {
                            view.settings_open = false;
                        }
                    });
                });
            });
            widgets::rule(ui);
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.allocate_ui_with_layout(
                    vec2(160.0, 380.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.set_min_size(vec2(160.0, 380.0));
                        modal_section(ui, Margin::symmetric(6, 8), |ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for (tab, text) in [
                                (SettingsTab::General, Text::SettingsTabGeneral),
                                (SettingsTab::Processing, Text::SettingsTabProcessing),
                                (SettingsTab::Android, Text::SettingsTabAndroid),
                                (SettingsTab::Memory, Text::SettingsTabMemory),
                                (SettingsTab::About, Text::SettingsTabAbout),
                            ] {
                                if nav_item(ui, &t(text), view.settings_tab == tab) {
                                    view.settings_tab = tab;
                                }
                            }
                        });
                    },
                );
                let line = ui.available_rect_before_wrap();
                ui.painter().vline(
                    line.left(),
                    line.top()..=line.top() + 380.0,
                    Stroke::new(1.0, theme::BORDER),
                );
                ui.vertical(|ui| {
                    modal_section(ui, Margin::symmetric(16, 12), |ui| {
                        ui.spacing_mut().item_spacing.y = 12.0;
                        settings_pane(ui, draw, view, settings, overlays);
                    });
                });
            });
            widgets::rule(ui);
            modal_section(ui, Margin::symmetric(16, 10), |ui| {
                ui.horizontal(|ui| {
                    if widgets::ghost_button(ui, t(Text::SettingsReset)).clicked() {
                        settings.reset();
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::primary_button(ui, t(Text::SettingsDone), true).clicked() {
                            view.settings_open = false;
                        }
                    });
                });
            });
        });
    if response.should_close() {
        view.settings_open = false;
    }
}

fn nav_item(ui: &mut Ui, label: &str, on: bool) -> bool {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 26.0), Sense::click());
    widgets::describe(&response, egui::Role::Tab, label, Some(on));
    if on {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(4), theme::selection());
    } else if response.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(4), theme::row_hover());
    }
    ui.painter().text(
        pos2(rect.left() + 10.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        theme::body(),
        if on { theme::TEXT } else { theme::DIM },
    );
    response.clicked()
}

fn settings_pane(
    ui: &mut Ui,
    draw: &mut Draw<'_>,
    view: &mut ViewState,
    settings: &mut Settings,
    overlays: &Overlays<'_>,
) {
    match view.settings_tab {
        SettingsTab::General => {
            field(ui, Text::SettingsLanguage, None, |ui| {
                language_combo(ui, "settings-language", settings, overlays.detected)
            });
            if draw.caps.unpack {
                field(
                    ui,
                    Text::SettingsOutput,
                    Some(Text::SettingsOutputHelp),
                    |ui| {
                        let label = super::detail::output_label(&settings.output);
                        ComboBox::from_id_salt("settings-output")
                            .selected_text(label)
                            .width(260.0)
                            .show_ui(ui, |ui| {
                                if ui
                                    .selectable_label(
                                        settings.output == Output::Beside,
                                        t(Text::TbOutputBeside),
                                    )
                                    .clicked()
                                {
                                    settings.output = Output::Beside;
                                }
                                if let Some(recent) = settings.recent_output.clone() {
                                    let on = settings.output == Output::Folder(recent.clone());
                                    if ui
                                        .selectable_label(on, recent.display().to_string())
                                        .clicked()
                                    {
                                        settings.output = Output::Folder(recent);
                                    }
                                }
                                if ui
                                    .selectable_label(false, t(Text::SettingsOutputChoose))
                                    .clicked()
                                {
                                    draw.act(Action::Pick(Pick::Output));
                                }
                            })
                            .response
                    },
                );
                field(ui, Text::SettingsLog, Some(Text::SettingsLogHelp), |ui| {
                    ui.checkbox(&mut settings.write_log, "")
                });
            }
        }
        SettingsTab::Processing => {
            let cores = std::thread::available_parallelism().map_or(1, usize::from);
            field(ui, Text::SettingsThreads, None, |ui| {
                let label = |threads: usize| {
                    if threads == 0 {
                        t(Text::SettingsThreadsAuto {
                            n: cores.to_string(),
                        })
                        .into_owned()
                    } else {
                        threads.to_string()
                    }
                };
                ComboBox::from_id_salt("settings-threads")
                    .selected_text(label(settings.threads))
                    .show_ui(ui, |ui| {
                        let mut choices = vec![0, 1, 2, 4, 8, 16, 32, 64];
                        choices.retain(|count| *count == 0 || *count <= cores);
                        if !choices.contains(&cores) {
                            choices.push(cores);
                        }
                        for count in choices {
                            ui.selectable_value(&mut settings.threads, count, label(count));
                        }
                    })
                    .response
            });
            field(
                ui,
                Text::SettingsScanAll,
                Some(Text::SettingsScanAllHelp),
                |ui| ui.checkbox(&mut settings.scan_all, ""),
            );
        }
        SettingsTab::Android => {
            widgets::note(ui, t(Text::SettingsAndroidNote));
            field(
                ui,
                Text::SettingsMaxEntry,
                Some(Text::SettingsMaxEntryHelp),
                |ui| mib(ui, &mut settings.max_entry_mib),
            );
            field(
                ui,
                Text::SettingsMaxTotal,
                Some(Text::SettingsMaxTotalHelp),
                |ui| mib(ui, &mut settings.max_total_mib),
            );
            field(
                ui,
                Text::SettingsMaxEntries,
                Some(Text::SettingsMaxEntriesHelp),
                |ui| {
                    ui.add(
                        egui::DragValue::new(&mut settings.max_entries)
                            .range(1..=100_000_000)
                            .speed(100.0),
                    )
                },
            );
            field(
                ui,
                Text::SettingsMaxDepth,
                Some(Text::SettingsMaxDepthHelp),
                |ui| ui.add(egui::DragValue::new(&mut settings.max_depth).range(0..=1024)),
            );
        }
        SettingsTab::Memory => {
            field(
                ui,
                Text::SettingsKeepBytes,
                Some(Text::SettingsKeepBytesHelp),
                |ui| ui.checkbox(&mut settings.keep_bytes, ""),
            );
            field(
                ui,
                Text::SettingsKeepCap,
                Some(Text::SettingsKeepCapHelp),
                |ui| {
                    ui.add_enabled_ui(settings.keep_bytes, |ui| {
                        mib(ui, &mut settings.keep_cap_mib)
                    })
                    .inner
                },
            );
        }
        SettingsTab::About => about(ui, view, overlays),
    }
}

fn about(ui: &mut Ui, view: &mut ViewState, overlays: &Overlays<'_>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        if let Some(image) = icon_image(overlays.icon, 72.0) {
            ui.add(image);
        }
        ui.vertical(|ui| {
            ui.label(RichText::new("Senbei").font(theme::title(22.0)));
            ui.label(widgets::dim(t(Text::AboutVersion {
                v: env!("CARGO_PKG_VERSION").to_owned(),
            })));
        });
    });
    ui.add(egui::Label::new(widgets::dim(t(Text::AboutDesc))).wrap());
    info_row(ui, Text::AboutLicense, |ui| {
        ui.label("AGPL-3.0-only");
    });
    info_row(ui, Text::AboutSource, |ui| {
        ui.hyperlink_to(
            RichText::new("github.com/Momoko-Ayase/Senbei").font(theme::mono()),
            "https://github.com/Momoko-Ayase/Senbei",
        );
    });
    if ui.button(t(Text::AboutLegal)).clicked() {
        view.settings_open = false;
        view.legal_open = true;
    }
}
