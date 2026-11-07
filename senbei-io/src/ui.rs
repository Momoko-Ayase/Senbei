use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::Style;
use senbei_engine::{IntegrityReport, Kind};
use senbei_i18n::{Cli, Lang, Localize, Message, Step};
use std::cell::Cell;
use std::fmt::{self, Display};
use std::io::IsTerminal;
use std::path::Path;

/// Color policy for human-readable console output. Machine reports and logs
/// never use the console palette.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

thread_local! {
    static COLOR_MODE: Cell<ColorMode> = const { Cell::new(ColorMode::Auto) };
}

/// Apply a console policy to one caller's run, restoring it on return or panic.
pub fn with_color_mode<R>(mode: ColorMode, f: impl FnOnce() -> R) -> R {
    struct Restore(ColorMode);
    impl Drop for Restore {
        fn drop(&mut self) {
            COLOR_MODE.set(self.0);
        }
    }
    let _restore = Restore(COLOR_MODE.replace(mode));
    f()
}

/// Presentation roles shared by unpack progress and research reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Heading,
    Label,
    Value,
    Success,
    Warning,
    Error,
    Muted,
}

/// A resolved palette. Explicit palettes keep string rendering deterministic;
/// only the console entry points consult the terminal and environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    colored: bool,
}

impl Palette {
    pub const fn plain() -> Self {
        Self { colored: false }
    }

    pub const fn colored() -> Self {
        Self { colored: true }
    }

    pub const fn is_colored(self) -> bool {
        self.colored
    }

    pub fn stdout() -> Self {
        Self::for_stream(false)
    }

    pub fn stderr() -> Self {
        Self::for_stream(true)
    }

    fn for_stream(stderr: bool) -> Self {
        let terminal = if stderr {
            std::io::stderr().is_terminal()
        } else {
            std::io::stdout().is_terminal()
        };
        let mode = COLOR_MODE.get();
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        let dumb = std::env::var_os("TERM").is_some_and(|value| value == "dumb");
        let mut colored = color_enabled(mode, terminal, no_color, dumb);
        if colored && terminal && !enable_ansi(stderr) && mode == ColorMode::Auto {
            colored = false;
        }
        Self { colored }
    }

    pub fn paint<T: Display>(self, tone: Tone, value: T) -> Painted<T> {
        Painted {
            palette: self,
            tone,
            value,
        }
    }
}

pub(crate) fn count(palette: Palette, value: usize, nonzero: Tone) -> Painted<usize> {
    palette.paint(if value == 0 { Tone::Muted } else { nonzero }, value)
}

/// The run summary in `lang`: unpacked, skipped, errors, suspect, metadata,
/// and packages (shown only when nonzero), each colored when nonzero.
pub(crate) fn summary_line(
    palette: Palette,
    lang: Lang,
    [unpacked, skipped, errors, suspect, metadata, packages]: [usize; 6],
) -> String {
    let mut line = Cli::Summary {
        unpacked: count(palette, unpacked, Tone::Success).to_string(),
        skipped: count(palette, skipped, Tone::Muted).to_string(),
        errors: count(palette, errors, Tone::Error).to_string(),
        suspect: count(palette, suspect, Tone::Warning).to_string(),
        metadata: count(palette, metadata, Tone::Success).to_string(),
    }
    .localize(lang)
    .into_owned();
    if packages > 0 {
        line.push_str(
            &Cli::SummaryPackages {
                packages: palette.paint(Tone::Value, packages).to_string(),
            }
            .localize(lang),
        );
    }
    line
}

/// The muted line that shows the English a translated message came from.
fn english_line(palette: Palette, lang: Lang, english: &str) -> String {
    palette
        .paint(
            Tone::Muted,
            format!("{}: {english}", Cli::DiagnosticEnglish.localize(lang)),
        )
        .to_string()
}

/// `error: <message>` in `lang`, newline-terminated. When the translation
/// does not show everything the English said, the English follows.
pub(crate) fn error_lines(palette: Palette, lang: Lang, message: &Message) -> String {
    let mut lines = format!(
        "{}: {}\n",
        palette.paint(Tone::Error, Cli::Error.localize(lang)),
        message.localized(lang)
    );
    if let Some(english) = message.detail(lang) {
        lines.push_str(&format!("  {}\n", english_line(palette, lang, english)));
    }
    lines
}

/// Print `error: <message>` to stderr in the process language.
pub fn print_error(message: &Message) {
    eprint!(
        "{}",
        error_lines(Palette::stderr(), senbei_i18n::current(), message)
    );
}

/// Print `error: <error chain>` to stderr in the process language.
pub fn print_anyhow(error: &anyhow::Error) {
    print_error(&crate::message::of_error(error));
}

/// Print `error: <what>: <error chain>` to stderr in the process language.
pub(crate) fn print_error_about(what: Cli, error: &anyhow::Error) {
    let lang = senbei_i18n::current();
    let palette = Palette::stderr();
    let message = crate::message::of_error(error);
    eprintln!(
        "{}: {}: {}",
        palette.paint(Tone::Error, Cli::Error.localize(lang)),
        what.localize(lang),
        message.localized(lang)
    );
    if let Some(english) = message.detail(lang) {
        eprintln!("  {}", english_line(palette, lang, english));
    }
}

/// The verbose `Write to <dest>` line after an output was written, with the
/// destination colored when `painted`. A run with an observer receives it as
/// a progress event instead.
pub(crate) fn write_to(dest: &Path, painted: bool) {
    let event = senbei_engine::progress::Event::Step {
        step: Step::WriteTo {
            dest: dest.display().to_string(),
        },
        position: None,
    };
    if !senbei_engine::progress::emit(&event) {
        let dest = if painted {
            Palette::stdout()
                .paint(Tone::Value, dest.display())
                .to_string()
        } else {
            dest.display().to_string()
        };
        println!(
            "{}",
            Step::WriteTo { dest }.localize(senbei_i18n::current())
        );
    }
}

fn color_enabled(mode: ColorMode, terminal: bool, no_color: bool, dumb: bool) -> bool {
    match mode {
        ColorMode::Auto => terminal && !no_color && !dumb,
        ColorMode::Always => true,
        ColorMode::Never => false,
    }
}

#[cfg(windows)]
fn enable_ansi(stderr: bool) -> bool {
    use windows::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle,
        STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode,
    };

    // These borrowed standard handles are not closed. Read the existing mode
    // before enabling VT so other console flags are preserved.
    unsafe {
        let Ok(handle) = GetStdHandle(if stderr {
            STD_ERROR_HANDLE
        } else {
            STD_OUTPUT_HANDLE
        }) else {
            return false;
        };
        let mut mode = CONSOLE_MODE::default();
        if GetConsoleMode(handle, &mut mode).is_err() {
            return false;
        }
        mode.contains(ENABLE_VIRTUAL_TERMINAL_PROCESSING)
            || SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING).is_ok()
    }
}

#[cfg(not(windows))]
fn enable_ansi(_stderr: bool) -> bool {
    true
}

/// A styled console value. The underlying value is never modified or stored in
/// a report, so formatting the same data for JSON or a log remains plain.
pub struct Painted<T> {
    palette: Palette,
    tone: Tone,
    value: T,
}

impl<T: Display> Display for Painted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.palette.colored {
            return Display::fmt(&self.value, f);
        }
        let style = match self.tone {
            Tone::Heading => Style::new().cyan().bold(),
            Tone::Label => Style::new().blue().bold(),
            Tone::Value => Style::new().cyan(),
            Tone::Success => Style::new().green(),
            Tone::Warning => Style::new().yellow(),
            Tone::Error => Style::new().red(),
            Tone::Muted => Style::new().dimmed(),
        };
        Display::fmt(&style.style(&self.value), f)
    }
}

/// Create a progress bar for `n` items. Hidden when `quiet` is true.
pub fn progress(n: u64, quiet: bool) -> ProgressBar {
    if quiet || n == 0 {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(n);
    let template = if Palette::stderr().is_colored() {
        "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}"
    } else {
        "[{elapsed_precise}] {bar:40} {pos}/{len} {msg}"
    };
    bar.set_style(
        ProgressStyle::default_bar()
            .template(template)
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    bar
}

/// Print a success line, suspending the progress bar.
pub fn ok(bar: &ProgressBar, quiet: bool, rel: &Path, kind: Kind, dest: &Path) {
    ok_label(
        bar,
        quiet,
        &rel.display().to_string(),
        &format!("{kind:?}"),
        dest,
    );
}

/// Print a success line with a free-form kind label (Android targets),
/// suspending the progress bar.
pub fn ok_label(bar: &ProgressBar, quiet: bool, rel: &str, label: &str, dest: &Path) {
    if quiet {
        return;
    }
    let palette = Palette::stdout();
    let msg = format!(
        "{} {}  {}  ->  {}",
        palette.paint(Tone::Success, "✓"),
        palette.paint(Tone::Success, label),
        palette.paint(Tone::Label, rel),
        palette.paint(Tone::Value, dest.display())
    );
    bar.suspend(|| println!("{msg}"));
}

/// Print a success line for de-obfuscated IL2CPP metadata, reporting how many
/// protected method fields were remapped.
pub fn metadata(bar: &ProgressBar, quiet: bool, rel: &Path, remapped: usize, dest: &Path) {
    if quiet {
        return;
    }
    let palette = Palette::stdout();
    let line = Cli::MetadataLine {
        rel: palette.paint(Tone::Label, rel.display()).to_string(),
        dest: palette.paint(Tone::Value, dest.display()).to_string(),
        remapped: palette.paint(Tone::Value, remapped).to_string(),
    };
    let msg = format!(
        "{} {}",
        palette.paint(Tone::Success, "✓"),
        line.localize(senbei_i18n::current())
    );
    bar.suspend(|| println!("{msg}"));
}

/// Print an error line, suspending the progress bar.
pub fn err(bar: &ProgressBar, quiet: bool, rel: &Path, e: &anyhow::Error) {
    if quiet {
        return;
    }
    let palette = Palette::stderr();
    let lang = senbei_i18n::current();
    let message = crate::message::of_error(e);
    let mut msg = format!(
        "{} {}  {}",
        palette.paint(Tone::Error, "✗"),
        palette.paint(Tone::Label, rel.display()),
        message.localized(lang)
    );
    if let Some(english) = message.detail(lang) {
        msg.push_str(&format!("\n    {}", english_line(palette, lang, english)));
    }
    bar.suspend(|| eprintln!("{msg}"));
}

/// Print a warning for an output that failed the static integrity check,
/// suspending the progress bar.
pub fn suspect(bar: &ProgressBar, quiet: bool, rel: &Path, report: &IntegrityReport) {
    if quiet {
        return;
    }
    let palette = Palette::stderr();
    let lang = senbei_i18n::current();
    let msg = format!(
        "{} {}  {}: {}",
        palette.paint(Tone::Warning, "!"),
        palette.paint(Tone::Label, rel.display()),
        palette.paint(Tone::Warning, Cli::IntegrityFailed.localize(lang)),
        issues(report, lang)
    );
    bar.suspend(|| eprintln!("{msg}"));
}

/// The static check's findings in `lang`, separated as in the log.
pub(crate) fn issues(report: &IntegrityReport, lang: Lang) -> String {
    report
        .issues
        .iter()
        .map(|issue| issue.localized(lang))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_color_checks_each_destination_and_environment() {
        for terminal in [false, true] {
            for no_color in [false, true] {
                for dumb in [false, true] {
                    assert_eq!(
                        color_enabled(ColorMode::Auto, terminal, no_color, dumb),
                        terminal && !no_color && !dumb
                    );
                    assert!(color_enabled(ColorMode::Always, terminal, no_color, dumb));
                    assert!(!color_enabled(ColorMode::Never, terminal, no_color, dumb));
                }
            }
        }
    }

    #[test]
    fn explicit_palettes_preserve_text_and_distinguish_severity() {
        for tone in [
            Tone::Heading,
            Tone::Label,
            Tone::Value,
            Tone::Success,
            Tone::Warning,
            Tone::Error,
            Tone::Muted,
        ] {
            assert_eq!(
                Palette::plain().paint(tone, "模块 → 0x1234").to_string(),
                "模块 → 0x1234"
            );
            let styled = Palette::colored().paint(tone, "模块 → 0x1234").to_string();
            assert!(styled.starts_with("\x1b["));
            assert!(styled.ends_with("\x1b[0m"));
            assert!(styled.contains("模块 → 0x1234"));
        }
        assert!(
            Palette::colored()
                .paint(Tone::Error, "error")
                .to_string()
                .contains("[31m")
        );
        assert!(
            Palette::colored()
                .paint(Tone::Warning, "warning")
                .to_string()
                .contains("[33m")
        );
        assert!(
            Palette::colored()
                .paint(Tone::Success, "ok")
                .to_string()
                .contains("[32m")
        );
    }

    #[test]
    fn nested_color_scopes_restore_the_enclosing_policy() {
        let previous = COLOR_MODE.get();
        with_color_mode(ColorMode::Never, || {
            assert!(!Palette::stdout().is_colored());
            with_color_mode(ColorMode::Always, || {
                assert!(Palette::stdout().is_colored());
                assert!(Palette::stderr().is_colored());
            });
            assert!(!Palette::stderr().is_colored());
        });
        assert_eq!(COLOR_MODE.get(), previous);
    }

    #[test]
    fn panic_restores_color_policy_and_callers_are_thread_local() {
        with_color_mode(ColorMode::Never, || {
            let failure = std::panic::catch_unwind(|| {
                with_color_mode(ColorMode::Always, || panic!("synthetic unwind"));
            });
            assert!(failure.is_err());
            assert_eq!(COLOR_MODE.get(), ColorMode::Never);
            std::thread::spawn(|| {
                with_color_mode(ColorMode::Always, || {
                    assert!(Palette::stdout().is_colored())
                });
            })
            .join()
            .unwrap();
            assert!(!Palette::stdout().is_colored());
        });
    }
}
