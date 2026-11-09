//! The dark workbench theme: the mockup's palette, type scale, and fonts.

use std::collections::BTreeMap;
use std::sync::Arc;

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Stroke, Style,
    TextStyle, Visuals,
};

// ---------------------------------------------------------------- palette

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

/// `rgba(r, g, b, alpha)` as a premultiplied colour.
fn rgba(r: u8, g: u8, b: u8, alpha: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(r, g, b, (alpha * 255.0).round() as u8)
}

pub const BG: Color32 = rgb(0x14, 0x16, 0x1a);
pub const PANEL: Color32 = rgb(0x1d, 0x20, 0x26);
pub const PANEL_2: Color32 = rgb(0x23, 0x27, 0x2e);
pub const WELL: Color32 = rgb(0x0c, 0x0e, 0x11);
pub const BORDER: Color32 = rgb(0x2e, 0x32, 0x3b);
pub const BORDER_STRONG: Color32 = rgb(0x3c, 0x41, 0x4c);
pub const TEXT: Color32 = rgb(0xe4, 0xe7, 0xec);
pub const DIM: Color32 = rgb(0x9a, 0xa3, 0xb0);
pub const FAINT: Color32 = rgb(0x80, 0x88, 0x96);
pub const ACCENT: Color32 = rgb(0xe8, 0xb6, 0x4c);
pub const ACCENT_HOVER: Color32 = rgb(0xf0, 0xc4, 0x63);
pub const ACCENT_INK: Color32 = rgb(0x1a, 0x14, 0x08);
pub const BLUE: Color32 = rgb(0x3b, 0x82, 0xf6);
pub const OK: Color32 = rgb(0x6f, 0xcf, 0x7c);
pub const ERR: Color32 = rgb(0xe0, 0x6c, 0x6c);
pub const WARN: Color32 = ACCENT;
pub const SKIP: Color32 = rgb(0x8b, 0x93, 0xa1);
pub const INFO: Color32 = rgb(0x7a, 0xa7, 0xf7);
pub const STRING: Color32 = rgb(0xc9, 0xd4, 0x8b);
pub const ZERO_BYTE: Color32 = rgb(0x4a, 0x50, 0x5b);
pub const HOVER_FILL: Color32 = rgb(0x2a, 0x2f, 0x37);
pub const HOVER_STROKE: Color32 = rgb(0x56, 0x60, 0x70);
pub const HIGHLIGHT_TEXT: Color32 = rgb(0xff, 0xf3, 0xd6);

pub fn selection() -> Color32 {
    rgba(59, 130, 246, 0.20)
}
pub fn row_hover() -> Color32 {
    rgba(255, 255, 255, 0.035)
}
pub fn accent_soft() -> Color32 {
    rgba(232, 182, 76, 0.14)
}
pub fn highlight() -> Color32 {
    rgba(232, 182, 76, 0.28)
}
pub fn diff() -> Color32 {
    rgba(224, 108, 108, 0.30)
}
pub fn backdrop() -> Color32 {
    rgba(8, 9, 11, 0.72)
}

/// Section colours, in section order, for hex strips and the region list.
pub const SECTION_COLORS: [Color32; 8] = [
    rgb(0x6f, 0xcf, 0x7c),
    rgb(0xe8, 0xb6, 0x4c),
    rgb(0xc7, 0x92, 0xea),
    rgb(0x4f, 0xc1, 0xc9),
    rgb(0xf7, 0x8c, 0x6c),
    rgb(0xa3, 0xbe, 0x8c),
    rgb(0xd7, 0xda, 0xe0),
    rgb(0x82, 0xaa, 0xff),
];
pub const REGION_HEADERS: Color32 = INFO;
pub const REGION_PROTECTION: Color32 = ERR;
pub const REGION_PREFIX: Color32 = rgb(0xf0, 0xa0, 0x4b);
pub const REGION_TAIL: Color32 = rgb(0xb4, 0x8a, 0x55);
pub const REGION_OTHER: Color32 = SKIP;

/// What an outcome looks like: the dot, pill, and label colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Ok,
    Warn,
    Err,
    Info,
    Skip,
}

impl Tone {
    pub fn color(self) -> Color32 {
        match self {
            Tone::Ok => OK,
            Tone::Warn => WARN,
            Tone::Err => ERR,
            Tone::Info => INFO,
            Tone::Skip => SKIP,
        }
    }

    /// The translucent fill behind a pill.
    pub fn soft(self) -> Color32 {
        match self {
            Tone::Ok => rgba(111, 207, 124, 0.13),
            Tone::Warn => rgba(232, 182, 76, 0.13),
            Tone::Err => rgba(224, 108, 108, 0.13),
            Tone::Info => rgba(59, 130, 246, 0.14),
            Tone::Skip => Color32::TRANSPARENT,
        }
    }

    /// The pill border.
    pub fn border(self) -> Color32 {
        match self {
            Tone::Ok => rgba(111, 207, 124, 0.45),
            Tone::Warn => rgba(232, 182, 76, 0.45),
            Tone::Err => rgba(224, 108, 108, 0.45),
            Tone::Info => rgba(59, 130, 246, 0.45),
            Tone::Skip => BORDER_STRONG,
        }
    }
}

// ------------------------------------------------------------------- type

/// Font family of the Asul titles, falling back to the UI font for scripts
/// Asul does not cover.
pub fn title_family() -> FontFamily {
    FontFamily::Name("title".into())
}

/// Semibold UI text.
pub fn strong_family() -> FontFamily {
    FontFamily::Name("strong".into())
}

pub fn body() -> FontId {
    FontId::proportional(13.5)
}
pub fn small() -> FontId {
    FontId::proportional(12.0)
}
pub fn tiny() -> FontId {
    FontId::proportional(11.5)
}
pub fn mono() -> FontId {
    FontId::monospace(12.5)
}
pub fn mono_small() -> FontId {
    FontId::monospace(12.0)
}
pub fn strong(size: f32) -> FontId {
    FontId::new(size, strong_family())
}
pub fn title(size: f32) -> FontId {
    FontId::new(size, title_family())
}

/// One installed font face.
#[derive(Clone)]
pub struct Face {
    pub name: String,
    pub data: Arc<FontData>,
}

/// The faces of one display language, best first. Each list may be empty;
/// egui's bundled fonts back every family.
#[derive(Clone, Default)]
pub struct FontSet {
    pub ui: Vec<Face>,
    pub strong: Vec<Face>,
    pub mono: Vec<Face>,
}

/// The Asul title face, embedded. Licensed under the SIL Open Font License;
/// see `assets/fonts/OFL.txt`.
const ASUL_BOLD: &[u8] = include_bytes!("../assets/fonts/Asul-Bold.ttf");

/// Font definitions: the language's system fonts first, egui's bundled fonts
/// after them for symbols they lack.
pub fn font_definitions(set: &FontSet) -> FontDefinitions {
    let mut defs = FontDefinitions::default();
    let bundled_proportional = defs
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let bundled_mono = defs
        .families
        .get(&FontFamily::Monospace)
        .cloned()
        .unwrap_or_default();
    let mut install = |faces: &[Face]| -> Vec<String> {
        faces
            .iter()
            .map(|face| {
                defs.font_data.insert(face.name.clone(), face.data.clone());
                face.name.clone()
            })
            .collect()
    };
    let ui = install(&set.ui);
    let strong = install(&set.strong);
    let mono = install(&set.mono);
    defs.font_data.insert(
        "Asul-Bold".into(),
        Arc::new(FontData::from_static(ASUL_BOLD)),
    );

    let chain = |first: &[String], rest: &[String]| -> Vec<String> {
        let mut out: Vec<String> = first.to_vec();
        for name in rest {
            if !out.contains(name) {
                out.push(name.clone());
            }
        }
        out
    };
    let proportional = chain(&ui, &bundled_proportional);
    let strong_chain = chain(&strong, &proportional);
    let mut title_chain = vec!["Asul-Bold".to_owned()];
    title_chain.extend(strong_chain.iter().cloned());
    // Monospace falls back to the UI chain so CJK in paths still renders.
    let mono_chain = chain(&chain(&mono, &bundled_mono), &proportional);

    let mut families = BTreeMap::new();
    families.insert(FontFamily::Proportional, proportional);
    families.insert(FontFamily::Monospace, mono_chain);
    families.insert(strong_family(), strong_chain);
    families.insert(title_family(), title_chain);
    defs.families = families;
    defs
}

// ------------------------------------------------------------------ style

/// The workbench style: flat fills, 1 px strokes, 4 px corners.
pub fn style(base: &Style) -> Style {
    let mut style = base.clone();
    style.text_styles = [
        (TextStyle::Body, body()),
        (TextStyle::Button, body()),
        (TextStyle::Small, small()),
        (TextStyle::Monospace, mono()),
        (TextStyle::Heading, strong(17.0)),
    ]
    .into();
    let spacing = &mut style.spacing;
    spacing.item_spacing = egui::vec2(8.0, 4.0);
    spacing.button_padding = egui::vec2(10.0, 4.0);
    spacing.interact_size.y = 24.0;
    spacing.window_margin = Margin::same(12);
    spacing.menu_margin = Margin::same(4);
    spacing.scroll.bar_width = 10.0;
    spacing.scroll.floating = false;
    spacing.combo_width = 120.0;
    spacing.text_edit_width = 160.0;
    style.visuals = visuals();
    style.interaction.selectable_labels = false;
    style.url_in_tooltip = false;
    style
}

fn visuals() -> Visuals {
    let mut visuals = Visuals::dark();
    let radius = CornerRadius::same(4);
    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = PANEL;
    visuals.window_fill = PANEL;
    visuals.window_stroke = Stroke::new(1.0, BORDER_STRONG);
    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.menu_corner_radius = CornerRadius::same(6);
    visuals.extreme_bg_color = WELL;
    visuals.faint_bg_color = row_hover();
    visuals.code_bg_color = PANEL_2;
    visuals.hyperlink_color = INFO;
    visuals.warn_fg_color = WARN;
    visuals.error_fg_color = ERR;
    visuals.selection.bg_fill = selection();
    visuals.selection.stroke = Stroke::new(1.0, BLUE);
    visuals.text_edit_bg_color = Some(WELL);
    visuals.striped = false;

    let w = &mut visuals.widgets;
    w.noninteractive.bg_fill = PANEL;
    w.noninteractive.weak_bg_fill = PANEL;
    w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    w.noninteractive.corner_radius = radius;

    w.inactive.bg_fill = PANEL_2;
    w.inactive.weak_bg_fill = PANEL_2;
    w.inactive.bg_stroke = Stroke::new(1.0, BORDER_STRONG);
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    w.inactive.corner_radius = radius;
    w.inactive.expansion = 0.0;

    w.hovered.bg_fill = HOVER_FILL;
    w.hovered.weak_bg_fill = HOVER_FILL;
    w.hovered.bg_stroke = Stroke::new(1.0, HOVER_STROKE);
    w.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    w.hovered.corner_radius = radius;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = PANEL_2;
    w.active.weak_bg_fill = PANEL_2;
    w.active.bg_stroke = Stroke::new(1.0, HOVER_STROKE);
    w.active.fg_stroke = Stroke::new(1.0, TEXT);
    w.active.corner_radius = radius;
    w.active.expansion = 0.0;

    w.open.bg_fill = PANEL_2;
    w.open.weak_bg_fill = PANEL_2;
    w.open.bg_stroke = Stroke::new(1.0, HOVER_STROKE);
    w.open.fg_stroke = Stroke::new(1.0, TEXT);
    w.open.corner_radius = radius;
    visuals
}
