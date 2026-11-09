//! Tables in the mockup's style: dim headers, right-aligned numbers, a capped
//! height with its own scroll.

use egui::{Align, Layout, RichText, Ui};
use egui_extras::{Column, TableBuilder, TableRow};

use crate::theme;

/// One column: its header and whether it holds numbers.
pub struct Col {
    pub head: String,
    pub numeric: bool,
    pub width: Option<f32>,
    /// Takes the width the other columns leave; the last column by default.
    pub grow: bool,
}

pub fn col(head: impl Into<String>) -> Col {
    Col {
        head: head.into(),
        numeric: false,
        width: None,
        grow: false,
    }
}

pub fn num_col(head: impl Into<String>) -> Col {
    Col {
        numeric: true,
        ..col(head)
    }
}

impl Col {
    pub fn width(mut self, width: f32) -> Self {
        self.width = Some(width);
        self
    }

    pub fn grow(mut self) -> Self {
        self.grow = true;
        self
    }
}

/// A table of `rows` rows. `height` gives each row's height; `cells` fills a
/// row in column order.
pub fn table(
    ui: &mut Ui,
    id: impl egui::AsIdSalt,
    cols: &[Col],
    rows: usize,
    height: impl Fn(usize) -> f32,
    cells: impl FnMut(usize, &mut TableRow<'_, '_>),
) {
    build(ui, id, cols, rows, height, cells, None::<fn(usize)>);
}

/// [`table`] whose rows can be clicked; `clicked` receives the row index.
pub fn table_clickable(
    ui: &mut Ui,
    id: impl egui::AsIdSalt,
    cols: &[Col],
    rows: usize,
    height: impl Fn(usize) -> f32,
    cells: impl FnMut(usize, &mut TableRow<'_, '_>),
    clicked: impl FnMut(usize),
) {
    build(ui, id, cols, rows, height, cells, Some(clicked));
}

fn build(
    ui: &mut Ui,
    id: impl egui::AsIdSalt,
    cols: &[Col],
    rows: usize,
    height: impl Fn(usize) -> f32,
    mut cells: impl FnMut(usize, &mut TableRow<'_, '_>),
    mut clicked: Option<impl FnMut(usize)>,
) {
    let max_height = 520.0;
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(egui::CornerRadius::same(4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let mut builder = TableBuilder::new(ui)
                .id_salt(id)
                .striped(false)
                .resizable(true)
                .vscroll(true)
                // Both bounds: a table inside a card grid row would otherwise
                // take the row's settled height and scroll short tables.
                .min_scrolled_height(max_height)
                .max_scroll_height(max_height)
                .auto_shrink([false, true])
                .cell_layout(Layout::left_to_right(Align::Center));
            if clicked.is_some() {
                builder = builder.sense(egui::Sense::click());
            }
            let last = cols.len().saturating_sub(1);
            let grow = cols.iter().position(|column| column.grow).unwrap_or(last);
            for (index, column) in cols.iter().enumerate() {
                let spec = if index == grow {
                    Column::remainder().at_least(40.0).clip(true)
                } else {
                    match column.width {
                        Some(width) => Column::initial(width).at_least(18.0).clip(true),
                        None => Column::auto().at_least(24.0).clip(true),
                    }
                };
                builder = builder.column(spec.resizable(index != grow && index != last));
            }
            builder
                .header(24.0, |mut header| {
                    for column in cols {
                        header.col(|ui| {
                            let text = RichText::new(&column.head)
                                .color(theme::DIM)
                                .font(theme::small());
                            if column.numeric {
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    ui.label(text);
                                });
                            } else {
                                ui.label(text);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.heterogeneous_rows((0..rows).map(&height), |mut row| {
                        let index = row.index();
                        cells(index, &mut row);
                        if let Some(clicked) = &mut clicked
                            && row.response().clicked()
                        {
                            clicked(index);
                        }
                    });
                });
        });
}

/// A right-aligned monospace cell.
pub fn num(row: &mut TableRow<'_, '_>, text: impl Into<String>) {
    let text = text.into();
    row.col(|ui| {
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(text).font(theme::mono_small()));
        });
    });
}

// Cells leave truncation to the table: it truncates clipped columns, but not
// in the sizing pass that measures auto-sized columns at full width.

/// A plain text cell.
pub fn text(row: &mut TableRow<'_, '_>, text: impl Into<egui::WidgetText>) {
    let text = text.into();
    row.col(|ui| {
        ui.add(egui::Label::new(text));
    });
}

/// A monospace cell.
pub fn mono(row: &mut TableRow<'_, '_>, text: impl Into<String>) {
    let text = text.into();
    row.col(|ui| {
        ui.add(egui::Label::new(
            RichText::new(text).font(theme::mono_small()),
        ));
    });
}

/// A cell drawn by `add`.
pub fn cell(row: &mut TableRow<'_, '_>, add: impl FnOnce(&mut Ui)) {
    row.col(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        add(ui);
    });
}

/// Row height for `lines` lines of table text.
pub fn lines(lines: usize) -> f32 {
    20.0 + 16.0 * lines.saturating_sub(1) as f32
}
