//! Small pieces every view is built from.

use egui::{
    Align, Align2, Color32, CornerRadius, FontId, Frame, Layout, Margin, Rect, Response, RichText,
    Sense, Stroke, StrokeKind, Ui, Vec2, WidgetText, vec2,
};

use crate::labels::Shown;
use crate::text::{Text, t};
use crate::theme::{self, Tone};

/// Name a painted control for screen readers and automation.
pub fn describe(response: &Response, role: egui::Role, label: &str, selected: Option<bool>) {
    let enabled = response.enabled();
    response.widget_info(|| match selected {
        Some(selected) => egui::WidgetInfo::selected(role, enabled, selected, label),
        None => egui::WidgetInfo::labeled(role, enabled, label),
    });
}

/// Text in the dim colour.
pub fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text).color(theme::DIM)
}

/// Text in the faint colour.
pub fn faint(text: impl Into<String>) -> RichText {
    RichText::new(text).color(theme::FAINT)
}

/// Monospace text.
pub fn mono(text: impl Into<String>) -> RichText {
    RichText::new(text).font(theme::mono())
}

/// Text in a tone's colour.
pub fn toned(text: impl Into<String>, tone: Tone) -> RichText {
    RichText::new(text).color(tone.color())
}

/// Semibold text.
pub fn strong(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(theme::strong(size))
}

/// A label that wraps and can be selected and copied.
pub fn selectable(ui: &mut Ui, text: impl Into<WidgetText>) -> Response {
    ui.add(egui::Label::new(text).wrap().selectable(true))
}

/// How a boxed label looks.
struct BoxStyle {
    font: FontId,
    color: Color32,
    padding: Vec2,
    radius: f32,
    fill: Color32,
    stroke: Stroke,
}

/// Paint `text` in a box of the given style.
fn boxed(ui: &mut Ui, text: &str, style: BoxStyle) -> Response {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), style.font, style.color);
    let size = galley.size() + 2.0 * style.padding;
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            CornerRadius::same(style.radius.min(rect.height() / 2.0) as u8),
            style.fill,
            style.stroke,
            StrokeKind::Inside,
        );
        ui.painter()
            .galley(rect.min + style.padding, galley, style.color);
    }
    response
}

/// A rounded status pill.
pub fn pill(ui: &mut Ui, text: impl AsRef<str>, tone: Tone) -> Response {
    boxed(
        ui,
        text.as_ref(),
        BoxStyle {
            font: theme::small(),
            color: tone.color(),
            padding: vec2(8.0, 1.5),
            radius: 999.0,
            fill: tone.soft(),
            stroke: Stroke::new(1.0, tone.border()),
        },
    )
}

/// A small bordered type tag.
pub fn tag(ui: &mut Ui, text: impl AsRef<str>) -> Response {
    boxed(
        ui,
        text.as_ref(),
        BoxStyle {
            font: FontId::proportional(11.0),
            color: theme::DIM,
            padding: vec2(5.0, 0.5),
            radius: 3.0,
            fill: Color32::TRANSPARENT,
            stroke: Stroke::new(1.0, theme::BORDER),
        },
    )
}

/// A monospace tag, as for flag names and file kinds.
pub fn mono_tag(ui: &mut Ui, text: impl AsRef<str>) -> Response {
    boxed(
        ui,
        text.as_ref(),
        BoxStyle {
            font: FontId::monospace(11.0),
            color: theme::DIM,
            padding: vec2(5.0, 0.5),
            radius: 3.0,
            fill: Color32::TRANSPARENT,
            stroke: Stroke::new(1.0, theme::BORDER),
        },
    )
}

/// An 8 px status dot; `None` draws a hollow one.
pub fn dot(ui: &mut Ui, tone: Option<Tone>) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
    paint_dot(ui, rect.center(), tone);
    response
}

pub fn paint_dot(ui: &Ui, center: egui::Pos2, tone: Option<Tone>) {
    match tone {
        Some(tone) => {
            ui.painter().circle_filled(center, 4.0, tone.color());
        }
        None => {
            ui.painter()
                .circle_stroke(center, 3.5, Stroke::new(1.0, theme::FAINT));
        }
    }
}

/// A filter chip with a count.
pub fn chip(ui: &mut Ui, label: &str, count: usize, on: bool) -> Response {
    let font = theme::small();
    let label_galley = ui.painter().layout_no_wrap(
        label.to_owned(),
        font.clone(),
        if on { theme::TEXT } else { theme::DIM },
    );
    let count_galley = ui.painter().layout_no_wrap(
        count.to_string(),
        font,
        if on { theme::DIM } else { theme::FAINT },
    );
    let padding = vec2(8.0, 1.5);
    let gap = 4.0;
    let size = vec2(
        label_galley.size().x + gap + count_galley.size().x,
        label_galley.size().y,
    ) + 2.0 * padding;
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    describe(&response, egui::Role::Button, label, Some(on));
    if ui.is_rect_visible(rect) {
        let (fill, stroke) = if on {
            (theme::selection(), theme::BLUE)
        } else {
            (Color32::TRANSPARENT, theme::BORDER)
        };
        ui.painter().rect(
            rect,
            CornerRadius::same(99),
            fill,
            Stroke::new(1.0, stroke),
            StrokeKind::Inside,
        );
        let mut pos = rect.min + padding;
        let label_color = if on || response.hovered() {
            theme::TEXT
        } else {
            theme::DIM
        };
        let width = label_galley.size().x;
        ui.painter().galley(pos, label_galley, label_color);
        pos.x += width + gap;
        ui.painter().galley(pos, count_galley, theme::FAINT);
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A filled amber button for the main action.
pub fn primary_button(ui: &mut Ui, text: impl Into<String>, enabled: bool) -> Response {
    let text = text.into();
    let font = theme::strong(13.5);
    let galley = ui
        .painter()
        .layout_no_wrap(text.clone(), font, theme::ACCENT_INK);
    let padding = ui.spacing().button_padding;
    let size = vec2(
        galley.size().x + 2.0 * padding.x,
        (galley.size().y + 2.0 * padding.y).max(ui.spacing().interact_size.y),
    );
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(size, sense);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, enabled, &text));
    if ui.is_rect_visible(rect) {
        let fill = if !enabled {
            theme::ACCENT.gamma_multiply(0.45)
        } else if response.hovered() {
            theme::ACCENT_HOVER
        } else {
            theme::ACCENT
        };
        ui.painter().rect_filled(rect, CornerRadius::same(4), fill);
        let pos = rect.center() - galley.size() / 2.0;
        ui.painter().galley(
            pos,
            galley,
            if enabled {
                theme::ACCENT_INK
            } else {
                theme::ACCENT_INK.gamma_multiply(0.7)
            },
        );
    }
    if enabled {
        response.on_hover_cursor(egui::CursorIcon::PointingHand)
    } else {
        response
    }
}

/// A frameless button that shows its frame on hover.
pub fn ghost_button(ui: &mut Ui, text: impl Into<String>) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(theme::DIM).font(theme::small()))
            .frame_when_inactive(false),
    )
}

/// A small "Copy" button that puts `value` on the clipboard.
pub fn copy_button(ui: &mut Ui, value: &str) {
    if ghost_button(ui, t(Text::DetailCopy)).clicked() {
        ui.ctx().copy_text(value.to_owned());
    }
}

/// A segmented control; returns the newly chosen index.
pub fn segmented(ui: &mut Ui, options: &[String], current: usize) -> Option<usize> {
    let mut chosen = None;
    Frame::new()
        .stroke(Stroke::new(1.0, theme::BORDER_STRONG))
        .corner_radius(CornerRadius::same(4))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.horizontal(|ui| {
                for (index, option) in options.iter().enumerate() {
                    if index > 0 {
                        let (rect, _) = ui.allocate_exact_size(vec2(1.0, 22.0), Sense::hover());
                        ui.painter().rect_filled(rect, 0, theme::BORDER_STRONG);
                    }
                    let on = index == current;
                    let galley = ui.painter().layout_no_wrap(
                        option.clone(),
                        theme::body(),
                        if on { theme::TEXT } else { theme::DIM },
                    );
                    let size = vec2(galley.size().x + 20.0, 22.0);
                    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
                    describe(&response, egui::Role::Tab, option, Some(on));
                    if on {
                        ui.painter().rect_filled(rect, 0, theme::selection());
                    } else if response.hovered() {
                        ui.painter().rect_filled(rect, 0, theme::row_hover());
                    }
                    let pos = rect.center() - galley.size() / 2.0;
                    ui.painter().galley(pos, galley, theme::TEXT);
                    if response.clicked() && !on {
                        chosen = Some(index);
                    }
                }
            });
        });
    chosen
}

/// A card: a bordered panel with an Asul title and an optional aside.
pub fn card<R>(
    ui: &mut Ui,
    title: Option<&str>,
    aside: impl FnOnce(&mut Ui),
    body: impl FnOnce(&mut Ui) -> R,
) -> R {
    card_sized(ui, title, aside, 0.0, body).0
}

fn card_frame() -> Frame {
    Frame::new()
        .fill(theme::BG)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin {
            left: 12,
            right: 12,
            top: 10,
            bottom: 12,
        })
}

/// A card whose contents are at least `min_height` tall; also returns the
/// height its contents need on their own. Both are content heights, so a
/// grid row that feeds the tallest need back in settles instead of growing.
fn card_sized<R>(
    ui: &mut Ui,
    title: Option<&str>,
    aside: impl FnOnce(&mut Ui),
    min_height: f32,
    body: impl FnOnce(&mut Ui) -> R,
) -> (R, f32) {
    let response = card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        // egui measures a minimum height from the cursor, so it is set while
        // the cursor is still at the top.
        ui.set_min_height(min_height);
        let contents = ui.scope(|ui| {
            if let Some(title) = title {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(title)
                            .font(theme::title(14.5))
                            .color(theme::TEXT),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), aside);
                });
                ui.add_space(4.0);
            }
            body(ui)
        });
        (contents.inner, contents.response.rect.height())
    });
    response.inner
}

/// Contents drawn later, once their place is known.
pub type Body<'a> = Box<dyn FnOnce(&mut Ui) + 'a>;

/// A card body: its title, its aside, and its contents.
pub struct CardSpec<'a> {
    pub title: Option<String>,
    pub aside: Option<Body<'a>>,
    pub body: Body<'a>,
}

impl<'a> CardSpec<'a> {
    pub fn new(title: impl Into<String>, body: impl FnOnce(&mut Ui) + 'a) -> Self {
        Self {
            title: Some(title.into()),
            aside: None,
            body: Box::new(body),
        }
    }

    pub fn untitled(body: impl FnOnce(&mut Ui) + 'a) -> Self {
        Self {
            title: None,
            aside: None,
            body: Box::new(body),
        }
    }

    pub fn aside(mut self, aside: impl FnOnce(&mut Ui) + 'a) -> Self {
        self.aside = Some(Box::new(aside));
        self
    }
}

/// A full-width card.
pub fn wide_card(ui: &mut Ui, spec: CardSpec<'_>) {
    let CardSpec { title, aside, body } = spec;
    card(
        ui,
        title.as_deref(),
        |ui| {
            if let Some(aside) = aside {
                aside(ui);
            }
        },
        body,
    );
}

/// Widgets laid out left to right, centred in the available width. The row
/// measures itself and remembers its width; a pass whose width changed is
/// discarded, so the row never shows off centre.
pub fn centered_row(ui: &mut Ui, id: impl egui::AsIdSalt, add: impl FnOnce(&mut Ui)) {
    let id = ui.make_persistent_id(id);
    let known: Option<f32> = ui.data(|data| data.get_temp(id));
    let available = ui.available_width();
    ui.horizontal(|ui| {
        ui.add_space(known.map_or(0.0, |width| ((available - width) / 2.0).max(0.0)));
        let start = ui.cursor().min.x;
        add(ui);
        let width = ui.min_rect().right() - start;
        if known.is_none_or(|known| (known - width).abs() > 0.5) {
            ui.data_mut(|data| data.insert_temp(id, width));
            ui.ctx().request_discard("centred row measured");
        }
    });
}

/// The two-column card grid: cards in pairs of equal height, one column when
/// the pane is narrow; an odd last card takes the whole row.
pub fn card_grid(ui: &mut Ui, id: impl egui::AsIdSalt, cards: Vec<CardSpec<'_>>) {
    let id = ui.make_persistent_id(id);
    let narrow = ui.available_width() < 760.0;
    let gap = 12.0;
    let mut cards = cards.into_iter().peekable();
    let mut row = 0;
    while let Some(first) = cards.next() {
        if narrow || cards.peek().is_none() {
            wide_card(ui, first);
            ui.add_space(gap);
            continue;
        }
        let second = cards.next().expect("peeked");
        let row_id = id.with(row);
        let remembered: f32 = ui.data(|data| data.get_temp(row_id)).unwrap_or(0.0);
        let width = (ui.available_width() - gap) / 2.0;
        let mut tallest: f32 = 0.0;
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for spec in [first, second] {
                ui.allocate_ui_with_layout(vec2(width, 0.0), Layout::top_down(Align::Min), |ui| {
                    ui.set_width(width);
                    let CardSpec { title, aside, body } = spec;
                    let (_, height) = card_sized(
                        ui,
                        title.as_deref(),
                        |ui| {
                            if let Some(aside) = aside {
                                aside(ui);
                            }
                        },
                        remembered,
                        body,
                    );
                    tallest = tallest.max(height);
                });
            }
        });
        if (tallest - remembered).abs() > 0.5 {
            ui.data_mut(|data| data.insert_temp(row_id, tallest));
            ui.ctx().request_repaint();
        }
        ui.add_space(gap);
        row += 1;
    }
}

/// Key-value rows with a key column sized to its widest key.
pub struct Kv<'a> {
    ui: &'a mut Ui,
    key_width: f32,
}

impl Kv<'_> {
    /// A row with a value drawn by `value`.
    pub fn row(&mut self, key: impl AsRef<str>, value: impl FnOnce(&mut Ui)) {
        let key_width = self.key_width;
        self.ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            let (rect, _) = ui.allocate_exact_size(vec2(key_width, 18.0), Sense::hover());
            ui.painter().text(
                rect.left_top() + vec2(0.0, 1.0),
                Align2::LEFT_TOP,
                key.as_ref(),
                theme::body(),
                theme::DIM,
            );
            ui.vertical(|ui| {
                ui.set_max_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    value(ui);
                });
            });
        });
    }

    /// A row with a plain text value.
    pub fn text(&mut self, key: impl AsRef<str>, value: impl Into<WidgetText>) {
        let value = value.into();
        self.row(key, |ui| {
            selectable(ui, value);
        });
    }
}

/// Key-value rows; `keys` sizes the key column.
pub fn kv(ui: &mut Ui, keys: &[&str], add_rows: impl FnOnce(&mut Kv<'_>)) {
    kv_sized(ui, keys, 130.0, add_rows);
}

/// [`kv`] with a smaller minimum key column, for dense panels.
pub fn kv_sized(ui: &mut Ui, keys: &[&str], min_key: f32, add_rows: impl FnOnce(&mut Kv<'_>)) {
    let widest = keys
        .iter()
        .map(|key| {
            ui.painter()
                .layout_no_wrap((*key).to_owned(), theme::body(), theme::DIM)
                .size()
                .x
        })
        .fold(0.0_f32, f32::max);
    let key_width = widest.clamp(min_key, 260.0).ceil();
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 3.0;
        let mut rows = Kv { ui, key_width };
        add_rows(&mut rows);
    });
}

/// How a message block is marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgKind {
    Error,
    Warning,
    Info,
}

/// A message: icon, text, and the English it leaves out behind a toggle.
pub fn message_block(ui: &mut Ui, kind: MsgKind, shown: &Shown) {
    let (icon, tone, border) = match kind {
        MsgKind::Error => ("✕", Tone::Err, Tone::Err.color().gamma_multiply(0.4)),
        MsgKind::Warning => ("!", Tone::Warn, Tone::Warn.color().gamma_multiply(0.4)),
        MsgKind::Info => ("i", Tone::Info, theme::BORDER),
    };
    Frame::new()
        .fill(theme::PANEL)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let (rect, _) = ui.allocate_exact_size(vec2(14.0, 18.0), Sense::hover());
                ui.painter().text(
                    rect.center_top() + vec2(0.0, 1.0),
                    Align2::CENTER_TOP,
                    icon,
                    theme::strong(13.0),
                    tone.color(),
                );
                ui.vertical(|ui| {
                    code_spans(ui, &shown.text);
                    if let Some(technical) = &shown.technical {
                        egui::CollapsingHeader::new(
                            faint(t(Text::DetailTechnical)).font(theme::small()),
                        )
                        .id_salt(("technical", technical))
                        .show(ui, |ui| {
                            selectable(ui, mono(technical).color(theme::DIM));
                        });
                    }
                });
            });
        });
}

/// Text with `` `code` `` spans set in monospace, as engine messages write
/// identifiers.
pub fn code_spans(ui: &mut Ui, text: &str) -> Response {
    let mut job = egui::text::LayoutJob::default();
    for (index, part) in text.split('`').enumerate() {
        if part.is_empty() {
            continue;
        }
        let code = index % 2 == 1 && text.matches('`').count() >= 2;
        job.append(
            part,
            0.0,
            egui::TextFormat {
                font_id: if code { theme::mono() } else { theme::body() },
                color: theme::TEXT,
                ..Default::default()
            },
        );
    }
    job.wrap.max_width = ui.available_width();
    ui.add(egui::Label::new(job).wrap().selectable(true))
}

/// A list of message blocks.
pub fn messages(ui: &mut Ui, blocks: &[(MsgKind, Shown)]) {
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 6.0;
        for (kind, shown) in blocks {
            message_block(ui, *kind, shown);
        }
    });
}

/// A dim note paragraph.
pub fn note(ui: &mut Ui, text: impl Into<String>) {
    ui.add(egui::Label::new(RichText::new(text).color(theme::DIM).font(theme::small())).wrap());
}

/// An offset or RVA with its address-space badge, clickable when the hex view
/// can show it.
pub fn offset_link(
    ui: &mut Ui,
    space_short: &str,
    space_long: &str,
    value: &str,
    linkable: bool,
) -> Response {
    let badge_font = FontId::proportional(10.5);
    let badge = ui
        .painter()
        .layout_no_wrap(space_short.to_owned(), badge_font, theme::DIM);
    let color = if linkable { theme::INFO } else { theme::TEXT };
    let text = ui
        .painter()
        .layout_no_wrap(value.to_owned(), theme::mono_small(), color);
    let badge_pad = vec2(4.0, 0.5);
    let badge_size = badge.size() + 2.0 * badge_pad;
    let size = vec2(
        badge_size.x + 4.0 + text.size().x,
        badge_size.y.max(text.size().y),
    );
    let sense = if linkable {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(size, sense);
    if ui.is_rect_visible(rect) {
        let badge_rect = Rect::from_min_size(
            egui::pos2(rect.left(), rect.center().y - badge_size.y / 2.0),
            badge_size,
        );
        ui.painter()
            .rect_filled(badge_rect, CornerRadius::same(3), theme::PANEL_2);
        ui.painter()
            .galley(badge_rect.min + badge_pad, badge, theme::DIM);
        let text_pos = egui::pos2(
            badge_rect.right() + 4.0,
            rect.center().y - text.size().y / 2.0,
        );
        let text_width = text.size().x;
        ui.painter().galley(text_pos, text, color);
        if linkable && response.hovered() {
            let y = text_pos.y + 14.0;
            ui.painter().hline(
                text_pos.x..=text_pos.x + text_width,
                y,
                Stroke::new(1.0, theme::INFO),
            );
        }
    }
    if linkable {
        response
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .on_hover_text(t(Text::ResearchJump {
                space: space_long.to_owned(),
            }))
    } else {
        response.on_hover_text(space_long.to_owned())
    }
}

/// A clickable monospace offset, without a space badge.
pub fn link(ui: &mut Ui, text: &str) -> Response {
    let response = ui.add(
        egui::Label::new(mono(text).color(theme::INFO).font(theme::mono_small()))
            .sense(Sense::click()),
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A horizontal rule in the border colour.
pub fn rule(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, theme::BORDER);
}

/// Yes/no in the overview's colours.
pub fn yes_no(ui: &mut Ui, value: bool) {
    if value {
        ui.label(toned(t(Text::CommonYes), Tone::Ok));
    } else {
        ui.label(faint(t(Text::CommonNo)));
    }
}
