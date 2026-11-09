//! The compare tab: the protected input's headers and sections beside the
//! restored image's.

use egui::{ComboBox, CornerRadius, Rect, RichText, ScrollArea, Sense, Ui, pos2, vec2};
use senbei_engine::windows::{PeInspection, SectionInspection};

use super::detail::padded;
use super::hex::{self, Subject};
use super::table::{self, col};
use super::widgets::{self, CardSpec};
use super::{Draw, HexView, ViewState};
use crate::format;
use crate::labels::tv;
use crate::model::{Item, ItemResult};
use crate::text::{Text, t};
use crate::theme::{self, Tone};

/// Longest stretch of a section the byte comparison covers.
const COMPARE_LIMIT: u64 = 1024 * 1024;
const ROW: f32 = 19.0;

/// One compared value: label, original, restored, changed.
struct Field {
    label: String,
    original: String,
    restored: String,
    changed: bool,
}

fn field(label: impl Into<String>, original: String, restored: String) -> Field {
    let changed = original != restored;
    Field {
        label: label.into(),
        original,
        restored,
        changed,
    }
}

fn opt(value: Option<impl Into<u64>>, width: usize) -> String {
    value.map_or_else(|| "—".into(), |value| format::hex_w(value.into(), width))
}

fn header_fields(a_len: u64, b_len: u64, a: &PeInspection, b: &PeInspection) -> Vec<Field> {
    let entry = t(Text::PeEntry);
    let overlay = |pe: &PeInspection| {
        pe.overlay
            .as_ref()
            .map_or_else(|| "—".into(), |overlay| format::bytes(overlay.length))
    };
    vec![
        field(
            t(Text::CmpFileSize),
            format::bytes(a_len),
            format::bytes(b_len),
        ),
        field(
            format!("{entry} (RVA)"),
            opt(a.entry_point_rva, 0),
            opt(b.entry_point_rva, 0),
        ),
        field(
            format!("{entry} ({})", t(Text::ColFileOffset)),
            opt(a.entry_point_file_offset, 0),
            opt(b.entry_point_file_offset, 0),
        ),
        field("ImageBase", opt(a.image_base, 0), opt(b.image_base, 0)),
        field(
            "SizeOfImage",
            opt(a.size_of_image, 0),
            opt(b.size_of_image, 0),
        ),
        field(
            "SizeOfHeaders",
            opt(a.size_of_headers, 0),
            opt(b.size_of_headers, 0),
        ),
        field(
            t(Text::PeAlignment),
            format!(
                "{} / {}",
                opt(a.section_alignment, 0),
                opt(a.file_alignment, 0)
            ),
            format!(
                "{} / {}",
                opt(b.section_alignment, 0),
                opt(b.file_alignment, 0)
            ),
        ),
        field(
            "Characteristics",
            opt(a.characteristics, 4),
            opt(b.characteristics, 4),
        ),
        field(
            "DllCharacteristics",
            opt(a.dll_characteristics, 4),
            opt(b.dll_characteristics, 4),
        ),
        field(
            t(Text::CmpSections),
            a.sections.len().to_string(),
            b.sections.len().to_string(),
        ),
        field(
            tv("region", &senbei_engine::windows::FileRegionKind::Overlay),
            overlay(a),
            overlay(b),
        ),
    ]
}

/// A three-column table whose changed rows get the soft warn fill and a
/// warn-coloured restored value, as in the mockup.
fn changed_table(ui: &mut Ui, id: &str, head: [String; 3], rows: &[Field], mono_label: bool) {
    let [name, original, restored] = head;
    let cols = [col(name), col(original), col(restored)];
    ui.scope(|ui| {
        // Changed rows reuse the table's selection highlight; keep their text
        // colour so the labels do not read as links.
        let visuals = ui.visuals_mut();
        visuals.selection.bg_fill = Tone::Warn.soft();
        visuals.selection.stroke.color = theme::TEXT;
        changed_rows(ui, id, &cols, rows, mono_label);
    });
}

fn changed_rows(ui: &mut Ui, id: &str, cols: &[table::Col], rows: &[Field], mono_label: bool) {
    table::table(
        ui,
        id,
        cols,
        rows.len(),
        |_| table::lines(1),
        |index, row| {
            let field = &rows[index];
            row.set_selected(field.changed);
            let label = RichText::new(&field.label);
            table::text(
                row,
                if mono_label {
                    label.font(theme::mono_small())
                } else {
                    label
                },
            );
            table::mono(row, field.original.clone());
            let restored = RichText::new(&field.restored).font(theme::mono_small());
            table::text(
                row,
                if field.changed {
                    restored.color(theme::WARN)
                } else {
                    restored
                },
            );
        },
    );
}

fn section_cell(section: Option<&SectionInspection>) -> String {
    section.map_or_else(
        || "—".into(),
        |section| {
            format!(
                "{} · {} · {}+{}",
                format::hex(u64::from(section.virtual_address)),
                format::hex(u64::from(section.virtual_size)),
                format::hex(u64::from(section.raw_offset)),
                format::hex(u64::from(section.raw_size))
            )
        },
    )
}

pub fn tab<'a>(
    ui: &mut Ui,
    draw: &mut Draw<'a>,
    view: &mut ViewState,
    item: &'a Item,
    result: &'a ItemResult,
) {
    let Some(research) = &result.report.research else {
        return;
    };
    let (Some(a), Some(restored)) = (&research.input.pe, &research.restored) else {
        return;
    };
    let Some(b) = &restored.pe else {
        return;
    };
    let fields = header_fields(research.input.input_len, restored.input_len, a, b);
    let mut names: Vec<&str> = Vec::new();
    for section in a.sections.iter().chain(&b.sections) {
        if !names.contains(&section.name.as_str()) {
            names.push(&section.name);
        }
    }
    let section_rows: Vec<Field> = names
        .iter()
        .map(|name| {
            let x = a.sections.iter().find(|section| section.name == *name);
            let y = b.sections.iter().find(|section| section.name == *name);
            let changed = match (x, y) {
                (Some(x), Some(y)) => {
                    x.raw_offset != y.raw_offset
                        || x.raw_size != y.raw_size
                        || x.virtual_size != y.virtual_size
                        || x.characteristics != y.characteristics
                }
                _ => true,
            };
            Field {
                label: (*name).to_owned(),
                original: section_cell(x),
                restored: section_cell(y),
                changed,
            }
        })
        .collect();
    let directory_rows: Vec<Field> = a
        .directories
        .iter()
        .zip(&b.directories)
        .filter(|(x, y)| x.size > 0 || y.size > 0)
        .map(|(x, y)| Field {
            label: x.name.to_owned(),
            original: format!(
                "{} +{}",
                format::hex(u64::from(x.address)),
                format::hex(u64::from(x.size))
            ),
            restored: format!(
                "{} +{}",
                format::hex(u64::from(y.address)),
                format::hex(u64::from(y.size))
            ),
            changed: x.address != y.address || x.size != y.size,
        })
        .collect();
    let shared: Vec<String> = a
        .sections
        .iter()
        .filter(|section| b.sections.iter().any(|other| other.name == section.name))
        .map(|section| section.name.clone())
        .collect();
    if !view
        .compare_section
        .as_ref()
        .is_some_and(|name| shared.contains(name))
    {
        view.compare_section = shared
            .iter()
            .find(|name| *name == ".text")
            .or(shared.first())
            .cloned();
        view.compare_diff = None;
    }
    let subject = Subject::Item(item);
    let spliced = research.input_view == senbei_io::report::ResearchInputView::SplicedCompanion;
    let original_view = if spliced {
        HexView::Spliced
    } else {
        HexView::Original
    };
    let original = hex::view_bytes(draw, &subject, original_view);
    let restored_bytes = hex::view_bytes(draw, &subject, HexView::Restored);

    padded(ui, ("compare", item.id), |ui| {
        if !fields.iter().any(|field| field.changed) {
            widgets::pill(ui, t(Text::CmpNoChange), Tone::Ok);
            ui.add_space(12.0);
        }
        let head = [
            t(Text::ColField).into_owned(),
            t(Text::CmpOriginal).into_owned(),
            t(Text::CmpRestored).into_owned(),
        ];
        let name_head = [
            t(Text::ColName).into_owned(),
            t(Text::CmpOriginal).into_owned(),
            t(Text::CmpRestored).into_owned(),
        ];
        let directories_aside = format!("RVA +{}", t(Text::ColSize));
        widgets::card_grid(
            ui,
            ("compare-cards", item.id),
            vec![
                CardSpec::new(t(Text::CmpHeaders), |ui| {
                    changed_table(ui, "compare-fields", head, &fields, false);
                }),
                CardSpec::new(t(Text::RsDirectories), |ui| {
                    changed_table(ui, "compare-dirs", name_head.clone(), &directory_rows, true);
                })
                .aside(move |ui| {
                    ui.label(widgets::faint(directories_aside).font(theme::small()));
                }),
            ],
        );
        let sections_aside = format!(
            "RVA · {} · {}+{}",
            t(Text::ColVsize),
            t(Text::ColRawOffset),
            t(Text::ColRawSize)
        );
        widgets::wide_card(
            ui,
            CardSpec::new(t(Text::RsSections), |ui| {
                changed_table(
                    ui,
                    "compare-sections",
                    name_head.clone(),
                    &section_rows,
                    true,
                );
            })
            .aside(move |ui| {
                ui.label(widgets::faint(sections_aside).font(theme::small()));
            }),
        );
        ui.add_space(12.0);
        let mut next = false;
        let section_name = view.compare_section.clone().unwrap_or_default();
        let mut chosen = None;
        widgets::wide_card(
            ui,
            CardSpec::new(t(Text::CmpBytes), |ui| {
                let x = a
                    .sections
                    .iter()
                    .find(|section| section.name == section_name);
                let y = b
                    .sections
                    .iter()
                    .find(|section| section.name == section_name);
                match (x, y, &original, &restored_bytes) {
                    (Some(x), Some(y), Ok(left), Ok(right)) => {
                        let view_name = t(if spliced {
                            Text::HexVSpliced
                        } else {
                            Text::HexVOriginal
                        });
                        compare_bytes(ui, view, x, y, left, right, &view_name);
                    }
                    (_, _, Err(Some(message)), _) | (_, _, _, Err(Some(message))) => {
                        widgets::note(ui, message.clone());
                    }
                    _ => {
                        ui.spinner();
                    }
                }
            })
            .aside(|ui| {
                ComboBox::from_id_salt(("compare-section", item.id))
                    .selected_text(&section_name)
                    .show_ui(ui, |ui| {
                        for name in &shared {
                            if ui.selectable_label(*name == section_name, name).clicked() {
                                chosen = Some(name.clone());
                            }
                        }
                    })
                    .response
                    .accessible_name(t(Text::RsSections));
                if widgets::ghost_button(ui, t(Text::CmpNextDiff)).clicked() {
                    next = true;
                }
            }),
        );
        if let Some(name) = chosen {
            view.compare_section = Some(name);
            view.compare_diff = None;
        }
        if next {
            // Advanced on the next frame, once the rows are known.
            ui.ctx()
                .data_mut(|data| data.insert_temp(egui::Id::unique("compare-next"), true));
            ui.ctx().request_repaint();
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn compare_bytes(
    ui: &mut Ui,
    view: &mut ViewState,
    x: &SectionInspection,
    y: &SectionInspection,
    left: &[u8],
    right: &[u8],
    view_name: &str,
) {
    let a_start = u64::from(x.raw_offset);
    let b_start = u64::from(y.raw_offset);
    let available = |bytes: &[u8], start: u64, size: u32| {
        (bytes.len() as u64)
            .saturating_sub(start)
            .min(u64::from(size))
    };
    let len = available(left, a_start, x.raw_size)
        .min(available(right, b_start, y.raw_size))
        .min(COMPARE_LIMIT);
    let a = &left[a_start as usize..(a_start + len) as usize];
    let b = &right[b_start as usize..(b_start + len) as usize];
    let rows = len.div_ceil(16) as usize;
    let mut differing = 0usize;
    let mut diff_rows = Vec::new();
    for row in 0..rows {
        let start = row * 16;
        let end = (start + 16).min(a.len());
        let count = a[start..end]
            .iter()
            .zip(&b[start..end])
            .filter(|(p, q)| p != q)
            .count();
        if count > 0 {
            differing += count;
            diff_rows.push(row);
        }
    }
    let advance = ui
        .ctx()
        .data_mut(|data| data.remove_temp::<bool>(egui::Id::unique("compare-next")))
        .unwrap_or(false);
    let mut scroll_to = None;
    if advance && !diff_rows.is_empty() {
        let next = view
            .compare_diff
            .map_or(0, |index| (index + 1) % diff_rows.len());
        view.compare_diff = Some(next);
        scroll_to = Some(diff_rows[next]);
    }
    let current_row = view
        .compare_diff
        .and_then(|index| diff_rows.get(index))
        .copied();
    widgets::note(
        ui,
        t(Text::CmpBytesNote {
            len: format::hex(len),
            n: format::num(differing as u64),
            s: x.name.clone(),
        }),
    );
    ui.add_space(8.0);
    let font = theme::mono();
    let char_width = ui
        .painter()
        .layout_no_wrap("0".into(), font.clone(), theme::TEXT)
        .size()
        .x;
    let column = |index: usize| (index * 3 + usize::from(index >= 8)) as f32 * char_width;
    let block = column(15) + 2.0 * char_width;
    let offset_width = 6.0 * char_width;
    let left_x = 4.0 + 14.0 + offset_width + 14.0;
    let right_x = left_x + block + 14.0;
    egui::Frame::new()
        .fill(theme::WELL)
        .stroke(egui::Stroke::new(1.0, theme::BORDER))
        .corner_radius(CornerRadius::same(4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            // Column heads.
            let (head, _) =
                ui.allocate_exact_size(vec2(ui.available_width(), 24.0), Sense::hover());
            let painter = ui.painter();
            let left_head = format!(
                "{} · {view_name} @ {}",
                t(Text::CmpOriginal),
                format::hex(a_start)
            );
            let right_head = format!("{} @ {}", t(Text::CmpRestored), format::hex(b_start));
            painter.text(
                pos2(head.left() + left_x, head.center().y),
                egui::Align2::LEFT_CENTER,
                left_head,
                theme::small(),
                theme::DIM,
            );
            painter.text(
                pos2(head.left() + right_x, head.center().y),
                egui::Align2::LEFT_CENTER,
                right_head,
                theme::small(),
                theme::DIM,
            );
            painter.hline(
                head.x_range(),
                head.bottom(),
                egui::Stroke::new(1.0, theme::BORDER),
            );
            let mut area = ScrollArea::vertical()
                .id_salt(("compare-rows", x.name.as_str()))
                .max_height(360.0)
                .auto_shrink([false, true]);
            if let Some(row) = scroll_to {
                area = area.vertical_scroll_offset((row as f32 * ROW - 2.0 * ROW).max(0.0));
            }
            ui.spacing_mut().item_spacing.y = 0.0;
            area.show_rows(ui, ROW, rows, |ui, range| {
                for row in range {
                    let (rect, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), ROW), Sense::hover());
                    paint_row(
                        ui,
                        rect,
                        row,
                        a,
                        b,
                        current_row == Some(row),
                        (left_x, right_x, offset_width),
                        &column,
                    );
                }
            });
        });
}

#[allow(clippy::too_many_arguments)]
fn paint_row(
    ui: &Ui,
    rect: Rect,
    row: usize,
    a: &[u8],
    b: &[u8],
    current: bool,
    (left_x, right_x, offset_width): (f32, f32, f32),
    column: &dyn Fn(usize) -> f32,
) {
    let painter = ui.painter();
    let font = theme::mono();
    let start = row * 16;
    let end = (start + 16).min(a.len());
    let any = a[start..end] != b[start..end];
    if current {
        painter.rect_filled(rect, 0, theme::accent_soft());
    }
    let strip = Rect::from_min_size(rect.min, vec2(4.0, rect.height()));
    if current {
        painter.rect_filled(strip, 0, theme::ACCENT);
    } else if any {
        painter.rect_filled(strip, 0, theme::ERR.gamma_multiply(0.55));
    }
    painter.text(
        pos2(rect.left() + 18.0 + offset_width, rect.top() + 1.0),
        egui::Align2::RIGHT_TOP,
        format!("+{start:04X}"),
        font.clone(),
        theme::FAINT,
    );
    for (index, (p, q)) in a[start..end].iter().zip(&b[start..end]).enumerate() {
        let differs = p != q;
        for (x, value) in [(left_x, *p), (right_x, *q)] {
            let at = pos2(rect.left() + x + column(index), rect.top());
            if differs {
                let width = painter
                    .layout_no_wrap("00".into(), font.clone(), theme::TEXT)
                    .size()
                    .x;
                painter.rect_filled(
                    Rect::from_min_size(at - vec2(1.0, 0.0), vec2(width + 2.0, ROW)),
                    0,
                    theme::diff(),
                );
            }
            let color = if differs {
                egui::Color32::from_rgb(0xff, 0xd9, 0xd9)
            } else if value == 0 {
                theme::ZERO_BYTE
            } else {
                theme::TEXT
            };
            painter.text(
                at + vec2(0.0, 1.0),
                egui::Align2::LEFT_TOP,
                format!("{value:02X}"),
                font.clone(),
                color,
            );
        }
    }
}
