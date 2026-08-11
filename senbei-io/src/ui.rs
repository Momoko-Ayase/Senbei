use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use senbei_pe::{IntegrityReport, Kind};
use std::path::Path;

/// Create a progress bar for `n` items. Hidden when `quiet` is true.
pub fn progress(n: u64, quiet: bool) -> ProgressBar {
    if quiet || n == 0 {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(n);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
    );
    bar
}

/// Print a green success line, suspending the progress bar.
pub fn ok(bar: &ProgressBar, quiet: bool, rel: &Path, kind: Kind, dest: &Path) {
    if quiet {
        return;
    }
    let msg = format!(
        "{} {:?}  {}  ->  {}",
        "✓".green(),
        kind,
        rel.display(),
        dest.display()
    );
    bar.suspend(|| println!("{msg}"));
}

/// Print a green success line for a de-obfuscated il2cpp `global-metadata.dat`,
/// reporting how many method tokens were remapped.
pub fn metadata(bar: &ProgressBar, quiet: bool, rel: &Path, remapped: usize, dest: &Path) {
    if quiet {
        return;
    }
    let msg = format!(
        "{} metadata  {}  ->  {}  ({} method tokens remapped)",
        "✓".green(),
        rel.display(),
        dest.display(),
        remapped
    );
    bar.suspend(|| println!("{msg}"));
}

/// Print a red error line, suspending the progress bar.
pub fn err(bar: &ProgressBar, quiet: bool, rel: &Path, e: &anyhow::Error) {
    if quiet {
        return;
    }
    let msg = format!("{} {}  {e:#}", "✗".red(), rel.display());
    bar.suspend(|| eprintln!("{msg}"));
}

/// Print a yellow warning line for a file that unpacked but failed the static
/// integrity check (likely to crash at runtime), suspending the progress bar.
pub fn suspect(bar: &ProgressBar, quiet: bool, rel: &Path, report: &IntegrityReport) {
    if quiet {
        return;
    }
    let msg = format!(
        "{} {}  integrity check failed: {}",
        "!".yellow(),
        rel.display(),
        report.issues.join("; ")
    );
    bar.suspend(|| eprintln!("{msg}"));
}
