//! The log tab: structured log lines in the display language.

use egui::{Align, Layout, Margin, RichText, ScrollArea, Ui, vec2};

use super::{LogFilter, ViewState, widgets};
use crate::format;
use crate::labels::{self, step_title};
use crate::model::{Level, LogBody, LogLine, mode_action};
use crate::text::{Text, t};
use crate::theme;

/// The text of one log line.
pub fn line_text(line: &LogLine) -> String {
    match &line.body {
        LogBody::RunStarted { mode, inputs } => t(Text::LogRunStarted {
            mode: mode_action(*mode).into_owned(),
            n: inputs.to_string(),
        })
        .into_owned(),
        LogBody::Scan {
            candidates,
            skipped,
        } => t(Text::LogScan {
            n: candidates.to_string(),
            s: skipped.to_string(),
        })
        .into_owned(),
        LogBody::ScanIncomplete => t(Text::BatchScanIncomplete).into_owned(),
        LogBody::InputStarted { index, total, path } => t(Text::LogInputStarted {
            i: index.to_string(),
            n: total.to_string(),
            p: path.clone(),
        })
        .into_owned(),
        LogBody::Companion { name } => t(Text::LogCompanion { p: name.clone() }).into_owned(),
        LogBody::Step { position, step } => match position {
            Some((index, total)) => t(Text::LogStep {
                i: index.to_string(),
                n: total.to_string(),
                s: step_title(step).into_owned(),
            })
            .into_owned(),
            None => step_title(step).into_owned(),
        },
        LogBody::Detail(text) => text.clone(),
        LogBody::Stage {
            stage,
            status,
            duration,
            detail,
        } => {
            let mut text = format!(
                "{}: {}",
                labels::tv("stage", stage),
                labels::tv("stageStatus", status)
            );
            if let Some(duration) = duration.filter(|duration| *duration > 0) {
                text.push_str(&format!(" ({})", format::ms(duration)));
            }
            if let Some(detail) = detail {
                let shown = labels::message(detail);
                if !shown.quiet {
                    text.push_str(" — ");
                    text.push_str(&shown.text);
                }
            }
            text
        }
        LogBody::Message(message) => labels::message(message).text,
        LogBody::Entry { label, verdict } => t(Text::LogEntry {
            p: label.replace('/', "\\"),
            o: verdict.label().into_owned(),
        })
        .into_owned(),
        LogBody::Finished { verdict, duration } => t(Text::LogInputFinished {
            o: verdict.label().into_owned(),
            t: format::ms(*duration),
        })
        .into_owned(),
        LogBody::Summary(counts) => t(Text::LogSummary {
            ok: counts.recovered.to_string(),
            suspect: counts.suspect.to_string(),
            failed: counts.failed.to_string(),
            skipped: counts.skipped.to_string(),
        })
        .into_owned(),
    }
}

fn level_label(level: Level) -> (String, egui::Color32) {
    match level {
        Level::Info => (t(Text::LogLvInfo).into_owned(), theme::SKIP),
        Level::Step => (t(Text::LogLvStep).into_owned(), theme::INFO),
        Level::Detail => (String::new(), theme::SKIP),
        Level::Warn => (t(Text::LogLvWarn).into_owned(), theme::WARN),
        Level::Error => (t(Text::LogLvError).into_owned(), theme::ERR),
    }
}

fn keep(filter: LogFilter, level: Level) -> bool {
    match filter {
        LogFilter::All => true,
        LogFilter::NoSteps => !matches!(level, Level::Step | Level::Detail),
        LogFilter::Problems => matches!(level, Level::Warn | Level::Error),
    }
}

/// The log as plain text, for the clipboard.
pub fn plain(lines: &[LogLine], filter: LogFilter) -> String {
    let mut out = String::new();
    for line in lines.iter().filter(|line| keep(filter, line.level)) {
        let (level, _) = level_label(line.level);
        out.push_str(&format!("{} {:<6} {}\n", line.at, level, line_text(line)));
    }
    out
}

/// Log lines without a bar or scroll of their own.
pub fn log_box(ui: &mut Ui, filter: LogFilter, lines: &[LogLine]) {
    ui.scope(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        for line in lines.iter().filter(|line| keep(filter, line.level)) {
            log_line(ui, line);
        }
    });
}

fn log_line(ui: &mut Ui, line: &LogLine) {
    let detail = line.level == Level::Detail;
    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        let font = if detail {
            theme::mono_small()
        } else {
            theme::mono()
        };
        ui.allocate_ui_with_layout(vec2(96.0, 16.0), Layout::left_to_right(Align::Min), |ui| {
            ui.set_width(96.0);
            ui.label(
                RichText::new(&line.at)
                    .font(font.clone())
                    .color(theme::FAINT),
            );
        });
        let (level, color) = level_label(line.level);
        ui.allocate_ui_with_layout(vec2(56.0, 16.0), Layout::left_to_right(Align::Min), |ui| {
            ui.set_width(56.0);
            ui.label(RichText::new(level).font(theme::tiny()).color(color));
        });
        if detail {
            ui.add_space(14.0);
        }
        let text = RichText::new(line_text(line)).font(font).color(if detail {
            theme::DIM
        } else {
            theme::TEXT
        });
        ui.add(egui::Label::new(text).wrap().selectable(true));
    });
}

/// The log tab: a filter bar and the lines below it.
pub fn log_view(ui: &mut Ui, view: &mut ViewState, id: impl egui::AsIdSalt, lines: &[LogLine]) {
    egui::Frame::new()
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let options = [
                    t(Text::LogFAll).into_owned(),
                    t(Text::LogFNosteps).into_owned(),
                    t(Text::LogFProblems).into_owned(),
                ];
                let filters = [LogFilter::All, LogFilter::NoSteps, LogFilter::Problems];
                let current = filters
                    .iter()
                    .position(|filter| *filter == view.log_filter)
                    .unwrap_or(0);
                if let Some(index) = widgets::segmented(ui, &options, current) {
                    view.log_filter = filters[index];
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if widgets::ghost_button(ui, t(Text::LogCopy)).clicked() {
                        ui.ctx().copy_text(plain(lines, view.log_filter));
                    }
                });
            });
        });
    widgets::rule(ui);
    ScrollArea::both()
        .id_salt(id)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Frame::new()
                .inner_margin(Margin::symmetric(12, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    log_box(ui, view.log_filter, lines);
                });
        });
}
