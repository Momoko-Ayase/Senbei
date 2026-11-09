use std::path::{Path, PathBuf};
use std::time::Instant;

use senbei_i18n::{Cli, Lang, Localize, Message, Msg};

use crate::atomic::write_atomic;
use crate::message::{Coded, of_error};
pub use crate::report::{Collector, Mode, REPORT_FORMAT_VERSION, Report};
use crate::report::{
    CompanionReport, CompanionState, ContainerReport, Digest, EntryKind, EntryReport, EntryStatus,
    InputReport, InputStatus, OutputFile, Role, Stage, StageReport, StageStatus,
};
use crate::ui::{Palette, Tone};
pub use crate::windows::{
    UnpackedImage, unpack_bytes, unpack_bytes_force_exe, unpack_bytes_force_exe_profiled,
    unpack_bytes_force_exe_profiled_v, unpack_bytes_profiled, unpack_bytes_profiled_v, unpack_one,
    unpack_one_v,
};

/// Summary of a folder-mode run.
#[derive(Default)]
pub struct Summary {
    pub unpacked: usize,
    pub skipped: usize,
    pub errors: usize,
    /// Files that unpacked without error but failed the static integrity check
    /// — likely to crash at runtime (e.g. 0xC0000005). Counted in addition to
    /// `unpacked` (a suspect file is still written).
    pub suspect: usize,
    /// il2cpp `global-metadata.dat` files de-obfuscated (protected method fields remapped),
    /// including blobs unwrapped from restored Android libraries.
    pub metadata: usize,
    /// Android app packages (`.apk`/`.apks`/`.xapk`) opened and searched.
    pub packages: usize,
    /// Wall-clock duration of the folder run in milliseconds.
    pub duration_ms: u128,
}

impl Summary {
    /// The plain English summary line, as the log file records it.
    pub fn line(&self) -> String {
        self.line_in(crate::ui::Palette::plain(), Lang::En)
    }

    /// Console rendering in the process language, without adding
    /// presentation escapes to log data.
    pub fn line_with_palette(&self, palette: crate::ui::Palette) -> String {
        self.line_in(palette, senbei_i18n::current())
    }

    /// The summary line in `lang`.
    pub fn line_in(&self, palette: crate::ui::Palette, lang: Lang) -> String {
        crate::ui::summary_line(
            palette,
            lang,
            [
                self.unpacked,
                self.skipped,
                self.errors,
                self.suspect,
                self.metadata,
                self.packages,
            ],
        )
    }
}

/// Default output root for a folder unpack: `<root>/unpack`.
pub fn default_out_root_for_folder(root: &Path) -> PathBuf {
    root.join("unpack")
}

/// Default output root for a single-file unpack: `<parent>/unpack` (or `./unpack`
/// when the input has no parent directory).
pub fn default_out_root_for_file(input: &Path) -> PathBuf {
    let parent = input
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent.join("unpack")
}

/// Unpack all CrackProof-protected files under `root`, writing results into
/// a mirrored subtree under `out_dir` (or `root/unpack` if None).
///
/// Each file is processed independently: a panic or error in one file is
/// isolated and counted as an error; the loop continues.
pub fn run_folder(root: &Path, out_dir: Option<&Path>, quiet: bool) -> anyhow::Result<Summary> {
    run_folder_v(root, out_dir, if quiet { 1 } else { 0 }, false, false)
}

/// Like [`run_folder`], but prints detailed `[N/9]` step progress (and a final
/// `Write to <dest>` line) for each EXE when `verbose` is true.
///
/// `quiet` is a level: `>= 1` suppresses per-file UI lines and the progress bar.
/// When `no_log` is true, no `senbei-*.log` is created under the out root.
pub fn run_folder_v(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
) -> anyhow::Result<Summary> {
    run_folder_opts(
        root,
        out_dir,
        quiet,
        verbose,
        no_log,
        crate::scan::scan_all_env(),
    )
}

/// Like [`run_folder_v`], but with the scan pre-filter explicitly controlled.
///
/// When `scan_all` is true selected target names below the minimum size are
/// also opened and content-probed. Other filenames are never opened.
pub fn run_folder_opts(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    scan_all: bool,
) -> anyhow::Result<Summary> {
    run_folder_with_limits(
        root,
        out_dir,
        quiet,
        verbose,
        no_log,
        scan_all,
        &senbei_engine::android::ResourceLimits::default(),
    )
}

/// Folder mode with explicit Android archive and decoder ceilings.
pub fn run_folder_with_limits(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
) -> anyhow::Result<Summary> {
    run_folder_inner(
        root, out_dir, quiet, verbose, no_log, scan_all, limits, None,
    )
}

/// Folder mode, additionally recording a per-input report.
///
/// Behaviour, ordering, deduplication, and outputs are those of
/// [`run_folder_with_limits`]; the collector only observes.
#[allow(clippy::too_many_arguments)]
pub fn run_folder_reported(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
    report: &mut Collector,
) -> anyhow::Result<Summary> {
    run_folder_inner(
        root,
        out_dir,
        quiet,
        verbose,
        no_log,
        scan_all,
        limits,
        Some(report),
    )
}

/// A report carrying only a run-level failure.
///
/// Used when a run cannot start at all (an unreadable input, a rejected
/// command line), so `--json` callers still receive one versioned document.
pub fn error_report(mode: Mode, message: impl Into<Message>) -> Report {
    let mut collector = Collector::new(mode);
    collector.push_error(message);
    collector.finish()
}

/// Folder mode, additionally recording a per-input report.
///
/// Behaviour, ordering, deduplication, and outputs are those of
/// [`run_folder_with_limits`]; the collector only observes.
#[allow(clippy::too_many_arguments)]
fn run_folder_inner(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
    reporter: Option<&mut Collector>,
) -> anyhow::Result<Summary> {
    observed(reporter, |reporter| {
        run_folder_body(
            root, out_dir, quiet, verbose, no_log, scan_all, limits, reporter,
        )
    })
}

/// Run `body` with the pipelines' verbose progress sent to the collector's
/// observer, when it has one. Without an observer progress prints as before.
fn observed<R>(
    reporter: Option<&mut Collector>,
    body: impl FnOnce(Option<&mut Collector>) -> R,
) -> R {
    match reporter.as_deref().and_then(Collector::observer).cloned() {
        Some(observer) => senbei_engine::progress::with_sink(
            move |event| observer.progress(event),
            || body(reporter),
        ),
        None => body(reporter),
    }
}

/// True once the run's front end asked it to stop. Checked before each input.
fn stop(reporter: &mut Option<&mut Collector>) -> bool {
    reporter.as_deref_mut().is_some_and(Collector::should_stop)
}

/// Tell the run's observer that work on `path` began.
fn started(reporter: &Option<&mut Collector>, path: &Path) {
    if let Some(observer) = reporter.as_deref().and_then(Collector::observer) {
        observer.input_started(path);
    }
}

/// Verbose pipeline steps are shown on an unquiet console, or sent to an
/// observer, which never prints them.
fn verbose_steps(verbose: bool, quiet: u8, reporter: &Option<&mut Collector>) -> bool {
    verbose
        && (quiet == 0
            || reporter
                .as_deref()
                .is_some_and(|reporter| reporter.observer().is_some()))
}

#[allow(clippy::too_many_arguments)]
fn run_folder_body(
    root: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
    mut reporter: Option<&mut Collector>,
) -> anyhow::Result<Summary> {
    let t0 = std::time::Instant::now();
    let out_root = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_out_root_for_folder(root));
    std::fs::create_dir_all(&out_root)?;
    let log = if no_log {
        None
    } else {
        let log = crate::logfile::Log::create(&out_root)?;
        log.step(&format!("Senbei {}", env!("CARGO_PKG_VERSION")));
        log.step(&format!(
            "started {}",
            crate::logfile::local_stamp_display()
        ));
        log.step(&format!("input {}", root.display()));
        log.step(&format!("out {}", out_root.display()));
        Some(log)
    };
    // Single merged directory walk: returns CrackProof unpack candidates, il2cpp
    // metadata blobs, and Android targets from one traversal (see
    // [`crate::scan::find_targets_opts`]). Files the free directory metadata
    // already rules out are never opened — on asset-heavy trees the per-file
    // open+read latency, not the traversal, is the whole cost.
    let scan = crate::scan::find_targets_with_limits(root, scan_all, limits);
    let candidates = scan.crackproof.as_slice();
    let metas = scan.metadata.as_slice();
    let scan_stats = &scan.stats;
    // Files the scan could not classify are potential missed targets, not
    // clean skips: an unreadable directory or a locked il2cpp game assembly must
    // fail the run (exit 1) rather than report "0 errors" over a partial scan.
    let scan_failed = scan_stats.walk_errors + scan_stats.probe_errors;
    if scan_failed > 0 && quiet == 0 {
        let lang = senbei_i18n::current();
        eprintln!(
            "{}: {}",
            Palette::stderr().paint(Tone::Warning, Cli::Warning.localize(lang)),
            Cli::ScanUnreadable { count: scan_failed }.localize(lang)
        );
    }
    if let Some(log) = &log {
        if scan_stats.walk_errors > 0 {
            log.step(&format!(
                "scan: {} directory entry(s) unreadable",
                scan_stats.walk_errors
            ));
        }
        if scan_stats.probe_errors > 0 {
            log.step(&format!(
                "scan: {} file(s) failed content probe (unreadable or detector panic)",
                scan_stats.probe_errors
            ));
        }
    }
    let suppress_file_lines = quiet >= 1;
    // Quiet wins over verbose: step progress only when quiet == 0 (spec: verbose
    // lines only when quiet == 0; quiet ≥ 2 must stay fully silent even with -v).
    // An observer receives the steps instead of the console.
    let verbose_steps = verbose_steps(verbose, quiet, &reporter);
    // Verbose mode prints multi-line `[N/9]` step output per file straight to
    // stdout; an active progress bar would be clobbered by it, so hide the bar
    // (its per-file ok/err lines still print) when verbose is on.
    let android_targets = scan.android_so.len() + scan.android_packages.len();
    let bar = crate::ui::progress(
        (candidates.len() + android_targets) as u64,
        quiet >= 1 || verbose,
    );
    let mut s = Summary {
        skipped: scan_stats.skipped,
        errors: scan_failed,
        ..Summary::default()
    };
    // Research inspection runs the ordinary drivers but reads their results as
    // observations: a failed recovery is a finding, not a failed inspection.
    let research = reporter
        .as_deref()
        .is_some_and(|reporter| reporter.mode() == Mode::Inspect);
    if let Some(reporter) = reporter.as_deref_mut() {
        reporter.set_scan(crate::report::ScanReport {
            non_target_skipped: scan_stats.skipped,
            walk_errors: scan_stats.walk_errors,
            probe_errors: scan_stats.probe_errors,
        });
        if let Some(observer) = reporter.observer() {
            observer.scanned(
                candidates.len()
                    + scan.android_so.len()
                    + scan.android_packages.len()
                    + metas.len(),
            );
        }
    }

    for input in candidates {
        if stop(&mut reporter) {
            break;
        }
        started(&reporter, input);
        let rel = rel_in_tree(root, input);
        let dest = out_root.join(out_name(&rel));
        let started = Instant::now();

        // Wrap in catch_unwind so a single bad file never aborts the folder run.
        // A reporting run goes through the profiled entry point so the report
        // carries the route the pipeline actually selected; a research run
        // additionally keeps its structural facts. An ordinary run keeps the
        // unchanged call.
        let profiled = reporter.is_some();
        let input_owned = input.clone();
        let dest_owned = dest.clone();
        let result = senbei_engine::catch_unwind_quiet(|| {
            if profiled {
                let (profile, observed, result) =
                    unpack_one_researched(&input_owned, &dest_owned, verbose_steps, research);
                (Some(profile), observed, result)
            } else {
                (
                    None,
                    None,
                    unpack_one_v(&input_owned, &dest_owned, verbose_steps),
                )
            }
        });

        match result {
            Ok((profile, observed, Ok((kind, report)))) => {
                s.unpacked += 1;
                crate::ui::ok(&bar, suppress_file_lines, &rel, kind, &dest);
                if let Some(log) = &log {
                    log.step(&format!("OK {rel:?} -> {dest:?} ({kind:?})"));
                }
                if !report.ok() {
                    s.suspect += 1;
                    crate::ui::suspect(&bar, suppress_file_lines, &rel, &report);
                    if let Some(log) = &log {
                        log.step(&format!("SUSPECT {rel:?}: {}", report.issues.join("; ")));
                    }
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = windows_input(input, &dest, kind, &report, profile, started);
                    apply_windows_research(&mut reported, observed);
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            Ok((profile, observed, Err(e))) => {
                // A recovery that ran and failed is an ordinary driver outcome.
                // The per-input report is what inspection reads, and
                // `inspect_status` turns it into a finding rather than an error.
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = match profile {
                        Some(profile) => failed_input_with_profile(input, &e, profile, started),
                        None => failed_input(input, &e, started),
                    };
                    apply_windows_research(&mut reported, observed);
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::Error::new(Coded::panic("", panic_payload(&panic)));
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!(
                        "ERR {rel:?}: panic during unpack: {}",
                        panic_payload(&panic)
                    ));
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(failed_input(input, &e, started));
                }
            }
        }
        bar.inc(1);
    }

    // Android pass. Loose libraries restore before packages so an identical
    // library keeps the loose destination (loose beats `.apk` beats bundle).
    // Module 0x0C stays inside the application that produced it: an extracted
    // `lib/<abi>/` tree shares with that tree's `assets/` metadata only, and a
    // package shares only with splits of the same package name and version.
    let mut android_cache = if research {
        crate::android::run_cache_for_research(limits)
    } else {
        crate::android::run_cache_with_limits(limits)
    };
    let loose = crate::android::loose_scopes(&scan.android_so, metas);
    for scoped in loose.iter().filter(|scoped| {
        scan.android_so
            .iter()
            .any(|library| library == &scoped.path)
    }) {
        if stop(&mut reporter) {
            break;
        }
        started(&reporter, &scoped.path);
        let rel = rel_in_tree(root, &scoped.path);
        let dest = out_root.join(out_name(&rel));
        let input_owned = scoped.path.clone();
        let dest_owned = dest.clone();
        let key = scoped.key.clone();
        let label = rel.display().to_string();
        let started = Instant::now();
        let result = senbei_engine::catch_unwind_quiet(|| {
            crate::android::restore_loose_library(
                &input_owned,
                &dest_owned,
                &label,
                &key,
                verbose_steps,
                &mut android_cache,
            )
        });
        let report_outcome;
        let mut report_validation: Option<crate::android::ValidationDiagnostics> = None;
        let mut report_research: Option<crate::report::AndroidResearchReport> = None;
        let mut report_incomplete = false;
        match result {
            Ok(Ok(mut outcome)) => {
                // A restore that failed after extraction still reports what the
                // extraction observed, so the research facts are taken first.
                report_research = outcome.research.take();
                match outcome.status {
                    crate::android::EntryStatus::Duplicate => {
                        s.skipped += 1;
                        if let Some(log) = &log {
                            log.step(&format!("SKIP {rel:?}: duplicate of an earlier target"));
                        }
                        report_outcome = Some(InputStatus::Skipped);
                    }
                    crate::android::EntryStatus::Failed(e) => {
                        s.errors += 1;
                        crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                        if let Some(log) = &log {
                            log.step(&format!("ERR {rel:?}: {e:#}"));
                        }
                        // Only a resource or I/O ceiling truncates the
                        // analysis; a rejected candidate is a finding.
                        report_incomplete = analysis_incomplete(&e);
                        report_outcome = Some(InputStatus::Error);
                    }
                    crate::android::EntryStatus::Restored => {
                        s.unpacked += 1;
                        // Surface the engine's advisory findings. They never fail
                        // a restore, so they stay warnings on the same log/UI path.
                        report_validation = outcome.validation.clone();
                        if let Some(validation) = &report_validation {
                            if !suppress_file_lines {
                                for message in &validation.messages {
                                    eprintln!(
                                        "{} {}  {}",
                                        Palette::stderr().paint(Tone::Warning, "-"),
                                        rel.display(),
                                        message
                                    );
                                }
                            }
                            if let Some(log) = &log {
                                for message in &validation.messages {
                                    log.step(&format!("WARN {rel:?}: {message}"));
                                }
                            }
                        }
                        crate::ui::ok_label(
                            &bar,
                            suppress_file_lines,
                            &rel.display().to_string(),
                            "So",
                            &dest,
                        );
                        if let Some(log) = &log {
                            log.step(&format!("OK {rel:?} -> {dest:?} (Android SO)"));
                        }
                        if let Some(meta_dest) = outcome.embedded {
                            s.metadata += 1;
                            crate::ui::ok_label(
                                &bar,
                                suppress_file_lines,
                                &format!("{} (embedded metadata)", rel.display()),
                                "metadata",
                                &meta_dest,
                            );
                            if let Some(log) = &log {
                                log.step(&format!("META {rel:?} (embedded) -> {meta_dest:?}"));
                            }
                        }
                        report_outcome = Some(InputStatus::Ok);
                    }
                    crate::android::EntryStatus::NotTarget
                    | crate::android::EntryStatus::Unchanged => {
                        s.skipped += 1;
                        report_outcome = Some(InputStatus::Skipped);
                    }
                }
            }
            Ok(Err(e)) => {
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
                report_outcome = Some(InputStatus::Error);
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::Error::new(Coded::panic("", panic_payload(&panic)));
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!(
                        "ERR {rel:?}: panic during restore: {}",
                        panic_payload(&panic)
                    ));
                }
                report_outcome = Some(InputStatus::Error);
            }
        }
        if let Some(reporter) = reporter.as_deref_mut()
            && let Some(status) = report_outcome
        {
            let mut reported = android_library_input(&scoped.path, status, &dest, started);
            reported.analysis_incomplete = report_incomplete;
            apply_android_validation(&mut reported, report_validation.as_ref());
            reported.android_research = report_research;
            reporter.push(inspect_status_if_research(reported, research));
        }
        bar.inc(1);
    }
    // Loose sibling APKs that name the same package and version are one split
    // set. Their libraries run before their metadata because each package
    // restores its own libraries first and the shared cache collects modules
    // across the group. Bundles stay one package each.
    let package_groups =
        crate::android::loose_apk_groups_cached(&scan.android_packages, &mut android_cache);
    for group in &package_groups {
        if stop(&mut reporter) {
            break;
        }
        if group.len() > 1 {
            // A split set restores as one unit and reports each member.
            for package in group {
                started(&reporter, package);
            }
            s.packages += group.len();
            // Relative output paths are computed here, by the same helper the
            // rest of the driver uses: they must stay relative so joining them
            // under the output root cannot escape it.
            let rels: Vec<PathBuf> = group
                .iter()
                .map(|package| rel_in_tree(root, package).into_owned())
                .collect();
            let members: Vec<(&Path, &Path)> = group
                .iter()
                .map(|package| package.as_path())
                .zip(rels.iter().map(|rel| rel.as_path()))
                .collect();
            let out_root_owned = out_root.clone();
            let group_started = Instant::now();
            let result = senbei_engine::catch_unwind_quiet(|| {
                crate::android::restore_apk_group(
                    &members,
                    &out_root_owned,
                    &mut android_cache,
                    verbose_steps,
                )
            });
            let rel = rel_in_tree(root, &group[0]);
            match result {
                Ok(Ok(outcomes)) => {
                    // The summary and UI keep the flat split-set order; each
                    // split is additionally reported as its own container input,
                    // matched by the `<rel>::<entry>` label prefix.
                    if let Some(reporter) = reporter.as_deref_mut() {
                        for package in group {
                            let rel = rel_in_tree(root, package);
                            let prefix = format!("{}::", rel.display());
                            let entries: Vec<_> = outcomes
                                .iter()
                                .filter(|outcome| outcome.label.starts_with(&prefix))
                                .collect();
                            reporter.push(package_input(
                                package,
                                entries,
                                package_inventory(package, limits, research).as_ref(),
                                group_started,
                            ));
                        }
                    }
                    apply_package_outcomes(outcomes, &mut s, &bar, suppress_file_lines, &log);
                }
                Ok(Err(e)) => {
                    s.errors += 1;
                    crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                    if let Some(log) = &log {
                        log.step(&format!("ERR {rel:?}: {e:#}"));
                    }
                    // The failure belongs to the group, but the report is
                    // per-split: each member names the cause once, and the
                    // group is not counted again per restore phase.
                    if let Some(reporter) = reporter.as_deref_mut() {
                        for package in group {
                            let mut reported = failed_input(package, &e, group_started);
                            reported.android_research = crate::android::error_research(&e)
                                .and_then(|capture| match capture {
                                    crate::android::ResearchCapture::Library(report) => {
                                        Some(report.clone())
                                    }
                                    crate::android::ResearchCapture::Metadata(_) => None,
                                });
                            reporter.push(reported);
                        }
                    }
                }
                Err(panic) => {
                    let e = anyhow::Error::new(Coded::panic(
                        " during package restore",
                        panic_payload(&panic),
                    ));
                    s.errors += 1;
                    crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                    if let Some(log) = &log {
                        log.step(&format!("ERR {rel:?}: {e:#}"));
                    }
                    if let Some(reporter) = reporter.as_deref_mut() {
                        for package in group {
                            reporter.push(failed_input(package, &e, group_started));
                        }
                    }
                }
            }
            bar.inc(group.len() as u64);
            continue;
        }
        for package in group {
            if stop(&mut reporter) {
                break;
            }
            started(&reporter, package);
            let rel = rel_in_tree(root, package);
            s.packages += 1;
            let package_owned = package.clone();
            let rel_owned = rel.clone().into_owned();
            let out_root_owned = out_root.clone();
            let started = Instant::now();
            let result = senbei_engine::catch_unwind_quiet(|| {
                crate::android::restore_package_cached(
                    &package_owned,
                    &rel_owned,
                    &out_root_owned,
                    &mut android_cache,
                    verbose_steps,
                )
            });
            match result {
                Ok(Ok(outcomes)) => {
                    if let Some(reporter) = reporter.as_deref_mut() {
                        reporter.push(package_input(
                            package,
                            outcomes.iter().collect(),
                            package_inventory(package, limits, research).as_ref(),
                            started,
                        ));
                    }
                    apply_package_outcomes(outcomes, &mut s, &bar, suppress_file_lines, &log);
                }
                Ok(Err(e)) => {
                    s.errors += 1;
                    crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                    if let Some(log) = &log {
                        log.step(&format!("ERR {rel:?}: {e:#}"));
                    }
                    if let Some(reporter) = reporter.as_deref_mut() {
                        reporter.push(failed_input(package, &e, started));
                    }
                }
                Err(panic) => {
                    // A panic may leave a partial module recorded. Keeping the cache
                    // preserves successful dedup; a conflict still fails closed.
                    let e = anyhow::Error::new(Coded::panic("", panic_payload(&panic)));
                    s.errors += 1;
                    crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                    if let Some(log) = &log {
                        log.step(&format!(
                            "ERR {rel:?}: panic during package restore: {}",
                            panic_payload(&panic)
                        ));
                    }
                    if let Some(reporter) = reporter.as_deref_mut() {
                        reporter.push(failed_input(package, &e, started));
                    }
                }
            }
            bar.inc(1);
        }
    }

    // il2cpp metadata pass. A loose blob is paired only with the application
    // assigned when the tree was grouped. v24.1 with a missing or conflicting
    // module writes nothing. Other versions still restore when the application
    // has no conflicting module. The paired libraries are recorded on the log
    // line.
    for scoped in loose
        .iter()
        .filter(|scoped| metas.iter().any(|meta| meta == &scoped.path))
    {
        if stop(&mut reporter) {
            break;
        }
        started(&reporter, &scoped.path);
        let rel = rel_in_tree(root, &scoped.path);
        let dest = out_root.join(out_name(&rel));
        let meta_owned = scoped.path.clone();
        let dest_owned = dest.clone();
        let key = scoped.key.clone();
        let label = rel.display().to_string();
        let started = Instant::now();
        let result = senbei_engine::catch_unwind_quiet(|| {
            crate::android::restore_loose_metadata(
                &meta_owned,
                &dest_owned,
                &label,
                &key,
                verbose_steps,
                &mut android_cache,
            )
        });
        match result {
            Ok(Ok(report)) if report.remapped > 0 => {
                s.metadata += 1;
                crate::ui::metadata(&bar, suppress_file_lines, &rel, report.remapped, &dest);
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {rel:?} -> {dest:?}: v{} remapped {} method fields{}",
                        report.version,
                        report.remapped,
                        provenance_suffix(&report.provenance)
                    ));
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = metadata_input(&scoped.path, &report, Some(&dest), started);
                    reported.metadata_research = report.research.clone();
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            // Recognised metadata that needed no change (not -GMD-obfuscated):
            // leave it untouched and don't write a redundant copy.
            Ok(Ok(report)) => {
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {rel:?}: v{} already de-obfuscated{}",
                        report.version,
                        provenance_suffix(&report.provenance)
                    ));
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = metadata_input(&scoped.path, &report, None, started);
                    reported.metadata_research = report.research.clone();
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            Ok(Err(e)) => {
                // A metadata version we don't handle is NOT a run failure: the
                // game is simply not -GMD-obfuscated in a layout we know, the
                // file is left untouched, and the PE unpacks around it may be
                // fully successful. Count it as skipped (with a visible note),
                // matching the "anything that doesn't match is left untouched"
                // contract. Genuine corruption (Malformed) stays an error —
                // silently exiting 0 would let a failed de-obfuscation pass CI
                // while the il2cpp game assembly still crashes.
                let unsupported = unsupported_version(&e);
                if let Some(v) = unsupported {
                    s.skipped += 1;
                    if !suppress_file_lines {
                        eprintln!(
                            "{} {}  {}",
                            Palette::stderr().paint(Tone::Warning, "-"),
                            rel.display(),
                            Cli::MetadataUnsupportedLine { version: v }
                                .localize(senbei_i18n::current())
                        );
                    }
                    if let Some(log) = &log {
                        log.step(&format!(
                            "META SKIP {rel:?}: unsupported metadata version {v}"
                        ));
                    }
                } else {
                    s.errors += 1;
                    crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                    if let Some(log) = &log {
                        log.step(&format!("META ERR {rel:?}: {e:#}"));
                    }
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(metadata_failure_input(
                        &scoped.path,
                        &e,
                        unsupported,
                        started,
                    ));
                }
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::Error::new(Coded::panic(
                    " during de-obfuscation",
                    panic_payload(&panic),
                ));
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!(
                        "META ERR {rel:?}: panic during de-obfuscation: {}",
                        panic_payload(&panic)
                    ));
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(failed_input(&scoped.path, &e, started));
                }
            }
        }
    }

    bar.finish_and_clear();
    s.duration_ms = t0.elapsed().as_millis();
    if let Some(log) = &log {
        log.step(&format!("done in {} ms", s.duration_ms));
        log.step(&format!("summary: {}", s.line()));
    }
    Ok(s)
}

/// Single-file (PE or metadata) with the same log/header/footer/timing as folder mode.
///
/// Always returns `Ok(Summary)` for per-file unpack outcomes (including failures,
/// which set `errors: 1`) so callers always receive `duration_ms`. Fatal `Err`
/// only when the out dir / log cannot be created.
pub fn run_file_v(
    input: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
) -> anyhow::Result<Summary> {
    run_file_with_limits(
        input,
        out_dir,
        quiet,
        verbose,
        no_log,
        &senbei_engine::android::ResourceLimits::default(),
    )
}

/// Single-file mode with explicit Android archive and decoder ceilings.
pub fn run_file_with_limits(
    input: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    limits: &senbei_engine::android::ResourceLimits,
) -> anyhow::Result<Summary> {
    run_file_inner(input, out_dir, quiet, verbose, no_log, limits, None)
}

/// Single-file mode, additionally recording a per-input report.
///
/// Routing, output paths, and messages are those of
/// [`run_file_with_limits`]; the collector only observes.
pub fn run_file_reported(
    input: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    limits: &senbei_engine::android::ResourceLimits,
    report: &mut Collector,
) -> anyhow::Result<Summary> {
    run_file_inner(input, out_dir, quiet, verbose, no_log, limits, Some(report))
}

#[allow(clippy::too_many_arguments)]
fn run_file_inner(
    input: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    limits: &senbei_engine::android::ResourceLimits,
    reporter: Option<&mut Collector>,
) -> anyhow::Result<Summary> {
    observed(reporter, |reporter| {
        run_file_body(input, out_dir, quiet, verbose, no_log, limits, reporter)
    })
}

#[allow(clippy::too_many_arguments)]
fn run_file_body(
    input: &Path,
    out_dir: Option<&Path>,
    quiet: u8,
    verbose: bool,
    no_log: bool,
    limits: &senbei_engine::android::ResourceLimits,
    mut reporter: Option<&mut Collector>,
) -> anyhow::Result<Summary> {
    let t0 = std::time::Instant::now();
    let out_root = out_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_out_root_for_file(input));
    std::fs::create_dir_all(&out_root)?;

    let log = if no_log {
        None
    } else {
        let log = crate::logfile::Log::create(&out_root)?;
        log.step(&format!("Senbei {}", env!("CARGO_PKG_VERSION")));
        log.step(&format!(
            "started {}",
            crate::logfile::local_stamp_display()
        ));
        log.step(&format!("input {}", input.display()));
        log.step(&format!("out {}", out_root.display()));
        Some(log)
    };

    let name = out_name(Path::new(input.file_name().unwrap_or_default()));
    let dest = out_root.join(name);
    let mut s = Summary::default();
    // Research inspection runs this same driver and reads its results as
    // observations; everything else keeps the ordinary classification.
    let research = reporter
        .as_deref()
        .is_some_and(|reporter| reporter.mode() == Mode::Inspect);
    let verbose_steps = verbose_steps(verbose, quiet, &reporter);
    if let Some(observer) = reporter.as_deref().and_then(Collector::observer) {
        observer.scanned(1);
    }
    started(&reporter, input);

    let prefix = {
        use std::io::Read;
        let mut buf = vec![0u8; 8 * 1024];
        match std::fs::File::open(input).and_then(|mut f| f.read(&mut buf).map(|n| (buf, n))) {
            Ok((buf, n)) => {
                let mut b = buf;
                b.truncate(n);
                b
            }
            Err(_) => Vec::new(),
        }
    };
    let is_meta = senbei_metadata::is_metadata(&prefix);
    // Android single-file targets are routed by content: a protected AArch64
    // library probe needs the whole file (its payload section is found through
    // the section-header table at the end), while a package is a container
    // handled entry-by-entry. Anything else falls through to the PE pipeline.
    let is_android_so = crate::android::is_elf64_aarch64(&prefix)
        && crate::android::probe_so_file_with_limits(input, limits).unwrap_or(true);
    let is_android_package = !is_android_so && crate::android::is_app_package(input, &prefix);

    if is_meta {
        match deobfuscate_metadata_researched(input, &dest, verbose_steps, research, None) {
            Ok((report, layout, metadata_research)) if report.remapped > 0 => {
                s.metadata = 1;
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {:?} -> {:?}: v{} remapped {} method fields",
                        input, dest, report.version, report.remapped
                    ));
                }
                if quiet == 0 {
                    let palette = Palette::stdout();
                    let line = Cli::MetadataVersionLine {
                        version: palette.paint(Tone::Value, report.version).to_string(),
                        dest: palette.paint(Tone::Value, format!("{dest:?}")).to_string(),
                        remapped: palette.paint(Tone::Value, report.remapped).to_string(),
                    };
                    println!(
                        "{} {}",
                        palette.paint(Tone::Success, "✓"),
                        line.localize(senbei_i18n::current())
                    );
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported =
                        single_metadata_input(input, &report, layout, Some(&dest), research, t0);
                    reported.metadata_research = metadata_research;
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            Ok((report, layout, metadata_research)) => {
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {:?}: v{} already de-obfuscated",
                        input, report.version
                    ));
                }
                if quiet == 0 {
                    let lang = senbei_i18n::current();
                    let palette = Palette::stdout();
                    let version = Cli::MetadataAlreadyClean {
                        version: palette.paint(Tone::Value, report.version).to_string(),
                    };
                    println!(
                        "{} {}",
                        version.localize(lang),
                        palette.paint(Tone::Muted, Cli::MetadataNothingToDo.localize(lang))
                    );
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported =
                        single_metadata_input(input, &report, layout, None, research, t0);
                    reported.metadata_research = metadata_research;
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("META ERR {:?}: {e:#}", input));
                }
                // Level 1 quiet: banner/summary/duration only (match folder mode).
                if quiet == 0 {
                    crate::ui::print_anyhow(&e);
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let unsupported = unsupported_version(&e);
                    reporter.push(metadata_failure_input(input, &e, unsupported, t0));
                }
            }
        }
    } else if is_android_so {
        let restore = if research {
            crate::android::restore_so_file_researched(
                input,
                &dest,
                verbose_steps,
                limits,
                research,
            )
            .map(|restored| {
                (
                    restored.embedded_metadata,
                    restored.validation,
                    restored.research,
                )
            })
        } else {
            crate::android::restore_so_file_with_diagnostics(input, &dest, verbose_steps, limits)
                .map(|(embedded, validation)| (embedded, validation, None))
        };
        match restore {
            Ok((embedded, validation, android_research)) => {
                s.unpacked = 1;
                if let Some(log) = &log {
                    log.step(&format!("OK {:?} -> {:?} (Android SO)", input, dest));
                }
                if quiet == 0 {
                    let palette = Palette::stdout();
                    println!(
                        "{}  {}  ->  {}",
                        palette.paint(Tone::Success, "✓ So"),
                        palette.paint(Tone::Label, input.display()),
                        palette.paint(Tone::Value, dest.display())
                    );
                }
                match write_embedded_metadata(embedded, &dest) {
                    Ok(Some(meta_dest)) => {
                        s.metadata += 1;
                        if let Some(log) = &log {
                            log.step(&format!("META {:?} (embedded) -> {:?}", input, meta_dest));
                        }
                        if quiet == 0 {
                            let palette = Palette::stdout();
                            let line = Cli::EmbeddedMetadataLine {
                                input: palette.paint(Tone::Label, input.display()).to_string(),
                                dest: palette.paint(Tone::Value, meta_dest.display()).to_string(),
                            };
                            println!(
                                "{} {}",
                                palette.paint(Tone::Success, "✓"),
                                line.localize(senbei_i18n::current())
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        s.errors += 1;
                        if let Some(log) = &log {
                            log.step(&format!("ERR {:?}: embedded metadata: {e:#}", input));
                        }
                        if quiet == 0 {
                            crate::ui::print_error_about(Cli::EmbeddedMetadataFailed, &e);
                        }
                    }
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = android_library_input(input, InputStatus::Ok, &dest, t0);
                    apply_android_validation(&mut reported, validation.as_ref());
                    reported.android_research = android_research;
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    crate::ui::print_anyhow(&e);
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = android_library_input_with_error(
                        input,
                        InputStatus::Error,
                        &dest,
                        t0,
                        Some(&e),
                    );
                    // A restore that failed after extraction keeps what the
                    // extraction already reported.
                    reported.android_research =
                        crate::android::error_research(&e).and_then(|capture| match capture {
                            crate::android::ResearchCapture::Library(report) => {
                                Some(report.clone())
                            }
                            crate::android::ResearchCapture::Metadata(_) => None,
                        });
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
        }
    } else if is_android_package {
        s.packages = 1;
        let rel = PathBuf::from(input.file_name().unwrap_or_default());
        let mut seen = std::collections::HashSet::new();
        match crate::android::restore_package_with_limits_and_research(
            input,
            &rel,
            &out_root,
            &mut seen,
            verbose_steps,
            limits,
            research,
        ) {
            Ok(outcomes) => {
                let bar = crate::ui::progress(0, true);
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(package_input(
                        input,
                        outcomes.iter().collect(),
                        package_inventory(input, limits, research).as_ref(),
                        t0,
                    ));
                }
                apply_package_outcomes(outcomes, &mut s, &bar, quiet >= 1, &log);
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    crate::ui::print_anyhow(&e);
                }
                if let Some(reporter) = reporter {
                    reporter.push(failed_input(input, &e, t0));
                }
            }
        }
    } else {
        // A reporting run uses the profiled entry point so the report carries
        // the route that was actually selected; a research run keeps its
        // structural facts too. The unprofiled call is unchanged otherwise.
        let (profile, observed, result) = match reporter.is_some() {
            true => {
                let (profile, observed, result) =
                    unpack_one_researched(input, &dest, verbose_steps, research);
                (Some(profile), observed, result)
            }
            false => (None, None, unpack_one_v(input, &dest, verbose_steps)),
        };
        match result {
            Ok((kind, report)) => {
                s.unpacked = 1;
                if let Some(log) = &log {
                    log.step(&format!("OK {:?} -> {:?} ({kind:?})", input, dest));
                }
                if quiet == 0 {
                    let palette = Palette::stdout();
                    println!(
                        "{} -> {}",
                        palette.paint(Tone::Success, format!("✓ {kind:?}")),
                        palette.paint(Tone::Value, format!("{dest:?}"))
                    );
                }
                if !report.ok() {
                    s.suspect = 1;
                    if let Some(log) = &log {
                        log.step(&format!(
                            "SUSPECT {:?}: {}",
                            input,
                            report.issues.join("; ")
                        ));
                    }
                    if quiet == 0 {
                        let lang = senbei_i18n::current();
                        eprintln!(
                            "{}: {}",
                            Palette::stderr().paint(
                                Tone::Warning,
                                Cli::IntegrityFailedLikelyCrash.localize(lang)
                            ),
                            crate::ui::issues(&report, lang)
                        );
                    }
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = windows_input(input, &dest, kind, &report, profile, t0);
                    apply_windows_research(&mut reported, observed);
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    crate::ui::print_anyhow(&e);
                }
                if let Some(reporter) = reporter {
                    let mut reported = match profile {
                        Some(profile) => failed_input_with_profile(input, &e, profile, t0),
                        None => failed_input(input, &e, t0),
                    };
                    apply_windows_research(&mut reported, observed);
                    reporter.push(inspect_status_if_research(reported, research));
                }
            }
        }
    }

    s.duration_ms = t0.elapsed().as_millis();
    if let Some(log) = &log {
        log.step(&format!("done in {} ms", s.duration_ms));
        log.step(&format!("summary: {}", s.line()));
    }
    Ok(s)
}

/// Path of `p` relative to `root`, for mirroring into the output tree.
///
/// Falls back to just the file name when `p` is not under `root` (e.g. a
/// `\\?\`-prefixed root against plain candidate paths): `Path::join` with an
/// *absolute* path replaces the output root outright, which would write the
/// output back over the source tree instead of under `--out`.
fn rel_in_tree<'a>(root: &Path, p: &'a Path) -> std::borrow::Cow<'a, Path> {
    match p.strip_prefix(root) {
        Ok(rel) => std::borrow::Cow::Borrowed(rel),
        Err(_) => std::borrow::Cow::Owned(PathBuf::from(p.file_name().unwrap_or_default())),
    }
}

/// Insert `.unpack` before the last dot in the **file name**, preserving any
/// parent directories. If the file name has no dot, append `.unpack`.
///
/// The dot search is scoped to the file-name component only: a relative path
/// like `v1.2/launcher` (dotted directory, extension-less file) must become
/// `v1.2/launcher.unpack`, not `v1.unpack.2/launcher`.
pub fn out_name(input: &Path) -> PathBuf {
    let file = input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let renamed = match file.rfind('.') {
        Some(i) => format!("{}.unpack{}", &file[..i], &file[i..]),
        None => format!("{file}.unpack"),
    };
    match input.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(renamed),
        _ => PathBuf::from(renamed),
    }
}

fn provenance_suffix(sources: &[String]) -> String {
    if sources.is_empty() {
        String::new()
    } else {
        format!("; module 0x0C from {}", sources.join(", "))
    }
}

/// Extract a printable message from a caught panic payload.
fn panic_payload(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string payload>".to_string()
    }
}

/// If `e`'s chain contains [`senbei_metadata::Error::UnsupportedVersion`],
/// return the version. Used to apply the folder-mode "leave untouched, don't
/// fail the run" policy to metadata versions this build can't de-obfuscate.
fn unsupported_version(e: &anyhow::Error) -> Option<u32> {
    for cause in e.chain() {
        if let Some(senbei_metadata::Error::UnsupportedVersion(v)) =
            cause.downcast_ref::<senbei_metadata::Error>()
        {
            return Some(*v);
        }
    }
    None
}

/// De-obfuscate an il2cpp `global-metadata.dat` to `dest`.
///
/// CrackProof's `-GMD` option scrambles each `Il2CppMethodDefinition`'s token
/// into a sparse, original-metadata-style value; il2cpp expects the contiguous
/// per-module index it indexes its codegen tables with, so a statically-unpacked
/// il2cpp game assembly reads garbage and crashes during init. This rewrites
/// the tokens back to their canonical form (see [`senbei_metadata::deobfuscate`]).
///
/// The output is written only when something actually changed
/// (`report.remapped > 0`); an already-clean metadata is left untouched and no
/// redundant copy is produced. Returns the [`metadata::Report`] either way so
/// the caller can report what happened.
pub fn deobfuscate_metadata_to(
    input: &Path,
    dest: &Path,
    verbose: bool,
) -> anyhow::Result<senbei_metadata::Report> {
    deobfuscate_metadata_to_with_module(input, dest, verbose, None).map(|(report, _)| report)
}

fn deobfuscate_metadata_to_with_module(
    input: &Path,
    dest: &Path,
    verbose: bool,
    method_index_module: Option<&[u8]>,
) -> anyhow::Result<(senbei_metadata::Report, senbei_engine::LayoutKind)> {
    let (report, layout, _) =
        deobfuscate_metadata_researched(input, dest, verbose, false, method_index_module)?;
    Ok((report, layout))
}

/// [`deobfuscate_metadata_to_with_module`], optionally keeping what the
/// transform observed (tried seeds, discovery, its own report).
fn deobfuscate_metadata_researched(
    input: &Path,
    dest: &Path,
    verbose: bool,
    research: bool,
    method_index_module: Option<&[u8]>,
) -> anyhow::Result<(
    senbei_metadata::Report,
    senbei_engine::LayoutKind,
    Option<serde_json::Value>,
)> {
    let data = std::fs::read(input)?;
    // The Android seeded-permutation variant is tried first (it validates
    // every restored RID); the structural remap is the fallback and the
    // Windows path. The [`senbei_metadata::Error`] is preserved in the chain
    // (rather than stringified) so the folder driver can apply its
    // unsupported-version policy.
    let (out, report, layout, metadata_research) =
        crate::android::restore_metadata_with_module(&data, method_index_module, research)
            .map_err(|e| e.context(format!("{input:?}")))?;
    if report.remapped > 0 {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_atomic(dest, &out)?;
        if verbose {
            crate::ui::write_to(dest, true);
        }
    }
    Ok((report, layout, metadata_research))
}

/// Write an embedded metadata blob (unwrapped from a restored Android
/// library) next to the restored library. Returns the destination when a
/// blob was written.
fn write_embedded_metadata(
    embedded: Option<Vec<u8>>,
    so_dest: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(blob) = embedded else {
        return Ok(None);
    };
    let dest = crate::android::embedded_metadata_dest(so_dest);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(&dest, &blob)?;
    Ok(Some(dest))
}

/// Fold one package's per-entry outcomes into the run summary, UI, and log.
fn apply_package_outcomes(
    outcomes: Vec<crate::android::EntryOutcome>,
    s: &mut Summary,
    bar: &indicatif::ProgressBar,
    quiet: bool,
    log: &Option<crate::logfile::Log>,
) {
    use crate::android::{EntryKind, EntryStatus};
    for outcome in outcomes {
        match outcome.status {
            EntryStatus::Restored => {
                match outcome.kind {
                    EntryKind::So => {
                        s.unpacked += 1;
                        crate::ui::ok_label(bar, quiet, &outcome.label, "So", &outcome.dest);
                    }
                    EntryKind::Metadata { remapped } => {
                        s.metadata += 1;
                        crate::ui::metadata(
                            bar,
                            quiet,
                            Path::new(&outcome.label),
                            remapped,
                            &outcome.dest,
                        );
                    }
                    EntryKind::EmbeddedMetadata => {
                        s.metadata += 1;
                        crate::ui::ok_label(bar, quiet, &outcome.label, "metadata", &outcome.dest);
                    }
                }
                if let Some(log) = log {
                    log.step(&format!(
                        "OK {} -> {:?}{}",
                        outcome.label,
                        outcome.dest,
                        provenance_suffix(&outcome.provenance)
                    ));
                }
            }
            EntryStatus::Duplicate | EntryStatus::NotTarget | EntryStatus::Unchanged => {
                s.skipped += 1;
                if let Some(log) = log {
                    log.step(&format!("SKIP {} ({:?})", outcome.label, outcome.kind));
                }
            }
            EntryStatus::Failed(e) => {
                s.errors += 1;
                crate::ui::err(bar, quiet, Path::new(&outcome.label), &e);
                if let Some(log) = log {
                    log.step(&format!("ERR {}: {e:#}", outcome.label));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Inspect and dry-run drivers
// ---------------------------------------------------------------------------

/// Inspect `path`: run the real static recovery and report everything it saw.
///
/// Inspection is the research mode, so it runs the ordinary drivers — same
/// scan, same routing, same trial-and-validate layout selection, same Android
/// application context and deduplication — into a temporary directory that is
/// dropped afterwards. No output survives, no log is written, and the input
/// binary is never executed. The report therefore describes attempts that
/// really ran, plus the structural facts the engines published for them.
pub fn inspect_path(
    path: &Path,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
) -> anyhow::Result<Report> {
    let mut collector = Collector::new(Mode::Inspect);
    let workspace = tempfile::tempdir()?;
    let out_dir = workspace.path().to_path_buf();
    if path.is_dir() {
        run_folder_inner(
            path,
            Some(&out_dir),
            2,
            false,
            true,
            scan_all,
            limits,
            Some(&mut collector),
        )?;
    } else {
        run_file_inner(
            path,
            Some(&out_dir),
            2,
            false,
            true,
            limits,
            Some(&mut collector),
        )?;
    }
    Ok(collector.finish())
}

/// Restate one driver report as an inspection observation.
///
/// The drivers classify an input by what they did with it. Inspection asks a
/// different question — "what is this, and what happened when it was tried" —
/// so a recognised target stays `recognized` whether recovery succeeded,
/// failed, or found nothing to change. Only a genuine read or infrastructure
/// failure is an error, and a recovery failure is a research finding rather
/// than a failed inspection.
/// Restate a driver report as an inspection observation when the run is a
/// research inspection; leave an ordinary unpack report untouched.
fn inspect_status_if_research(input: InputReport, research: bool) -> InputReport {
    if research {
        inspect_status(input)
    } else {
        input
    }
}

/// Record what a research unpack observed on a Windows input report.
fn apply_windows_research(report: &mut InputReport, observed: Option<UnpackResearch>) {
    let Some(observed) = observed else {
        return;
    };
    report.source = Some(observed.source);
    if let Some(companion) = report.companion.as_mut() {
        // The sibling's identity, from the bytes the pipeline already read.
        companion.source = observed.companion;
    }
    report.research = observed.report;
    // The digest describes bytes that were produced and then dropped; the file
    // itself is never kept, which `Collector` states on the output stage.
    report.recovered = observed.recovered;
}

fn inspect_status(mut input: InputReport) -> InputReport {
    // A file that cannot be read was never inspected: that is a real failure,
    // not a finding about the protection.
    if read_prefix(Path::new(&input.path)).is_err() {
        input.status = InputStatus::Error;
        return input;
    }
    // A container is incomplete when any of its entries was.
    input.analysis_incomplete |= input.entries.iter().any(|entry| entry.analysis_incomplete);
    let recognition = input.profile.as_ref().map(|profile| profile.recognition);
    let container_target = input.entries.iter().any(|entry| {
        matches!(
            entry.status,
            EntryStatus::Restored
                | EntryStatus::Unchanged
                | EntryStatus::Duplicate
                | EntryStatus::Error
        )
    });
    let recognized = match recognition {
        Some(senbei_engine::RecognitionStatus::Recognized) => true,
        // A container has no single profile: any entry that was probed and
        // acted on says the container held a target.
        None => container_target,
        _ => false,
    };
    if input.analysis_incomplete {
        // The analysis stopped on an I/O or resource failure before it could
        // conclude anything. A known target does not make a truncated analysis
        // complete, so this stays an error with its reason.
        input.status = InputStatus::Error;
    } else if recognized {
        // A recovery that ran and failed is a finding about a real target, not
        // a failed inspection.
        input.status = InputStatus::Recognized;
    } else {
        // A plain non-target: the driver calls that an error because it could
        // not unpack it, but inspection only observed that there is no target.
        input.status = InputStatus::Skipped;
    }
    input
}

/// Whether a failure stopped the analysis before it could describe the input.
///
/// A candidate route that simply did not apply is a research finding. An I/O
/// failure, a resource ceiling, or a broken container means the analysis never
/// reached a conclusion, and calling that "recognized" would claim more than
/// was established. Classification is by error type, never by message text.
pub(crate) fn analysis_incomplete(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if cause.downcast_ref::<std::io::Error>().is_some() {
            return true;
        }
        if cause
            .downcast_ref::<senbei_engine::android::LimitExceeded>()
            .is_some()
        {
            return true;
        }
        // The Android engines wrap limits and I/O in their own error types;
        // their source chains are walked by `chain()` above, and the direct
        // variants are caught here.
        matches!(
            cause.downcast_ref::<senbei_engine::android::ExtractionError>(),
            Some(senbei_engine::android::ExtractionError::Io { .. })
                | Some(senbei_engine::android::ExtractionError::Limit(_))
        ) || matches!(
            cause.downcast_ref::<senbei_engine::android::RestoreError>(),
            Some(senbei_engine::android::RestoreError::Io { .. })
                | Some(senbei_engine::android::RestoreError::Limit(_))
        )
    })
}

fn read_prefix(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0_u8; 8 * 1024];
    let read = file.read(&mut buffer)?;
    buffer.truncate(read);
    Ok(buffer)
}

/// Run the real recovery and keep nothing.
///
/// The recovery path is the ordinary one — same routing, same trial-and-validate
/// layout selection, same Android staged restore — but every output goes to a
/// temporary directory that is dropped afterwards, and no run log is written.
/// The report therefore describes an attempt that really ran, while the caller's
/// filesystem is left untouched (apart from the Android engine's own temporary
/// workspace, which is always discarded).
pub fn dry_run_path(
    path: &Path,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
) -> anyhow::Result<Report> {
    let mut collector = Collector::new(Mode::DryRun);
    let workspace = tempfile::tempdir()?;
    let out_dir = workspace.path().to_path_buf();
    if path.is_dir() {
        run_folder_inner(
            path,
            Some(&out_dir),
            2,
            false,
            true,
            scan_all,
            limits,
            Some(&mut collector),
        )?;
    } else {
        run_file_inner(
            path,
            Some(&out_dir),
            2,
            false,
            true,
            limits,
            Some(&mut collector),
        )?;
    }
    Ok(collector.finish())
}

// ---------------------------------------------------------------------------
// Report construction
// ---------------------------------------------------------------------------

/// Metadata header identity for `path`, when the file has one.
pub(crate) fn identity_of(path: &Path) -> Option<senbei_metadata::MetadataIdentity> {
    let mut head = [0_u8; 8];
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    file.read_exact(&mut head).ok()?;
    senbei_metadata::identify(&head)
}

/// Unpack one file the way [`unpack_one_v`] does, keeping the route profile.
///
/// Output bytes and error values are those of [`unpack_one_v`]; only the
/// profile is additional. Reporting runs use this so the report names the
/// route the pipeline actually selected, the routes it rejected first, and the
/// static-check verdict for the bytes finally written.
pub fn unpack_one_profiled(
    input: &Path,
    dest: &Path,
    verbose: bool,
) -> (
    senbei_engine::ProtectionProfile,
    anyhow::Result<(senbei_engine::Kind, senbei_engine::IntegrityReport)>,
) {
    let (profile, _, result) = unpack_one_researched(input, dest, verbose, false);
    (profile, result)
}

/// What a reporting unpack observed from the bytes it already had in hand.
pub(crate) struct UnpackResearch {
    /// Identity of the physical input file, never of a synthetic spliced view.
    pub source: Digest,
    /// Identity of the `._` sibling whose bytes were read for pairing.
    pub companion: Option<Digest>,
    /// Structural research, kept only when the run asked for it.
    pub report: Option<crate::report::WindowsResearchReport>,
    /// Identity of the recovered image, which is discarded rather than written.
    pub recovered: Option<Digest>,
}

/// [`unpack_one_profiled`], optionally keeping the structural inspection of
/// both the protected input and the image recovery produced.
///
/// The recovery itself is the ordinary one and runs exactly once: the trace
/// sink only records what the pipeline publishes. Research mode inspects the
/// same bytes recovery used (the spliced view when a companion paired) and the
/// restored image before its bytes are dropped.
fn unpack_one_researched(
    input: &Path,
    dest: &Path,
    verbose: bool,
    research: bool,
) -> (
    senbei_engine::ProtectionProfile,
    Option<UnpackResearch>,
    anyhow::Result<(senbei_engine::Kind, senbei_engine::IntegrityReport)>,
) {
    // Read the stub and its `._` sibling exactly as the file entry point does.
    let (stub, companion) = match read_stub_and_companion(input) {
        Ok(pair) => pair,
        Err(error) => {
            let mut profile = observed_profile(input);
            profile.recovery = senbei_engine::RecoveryStatus::Blocked;
            profile.push_error(of_error(&error));
            return (profile, None, Err(error));
        }
    };
    // The bytes recovery will actually see. A companion that pairs replaces
    // the stub's payload region; anything else leaves the file as it is.
    let spliced = companion
        .as_deref()
        .and_then(|payload| crate::windows::splice_companion(&stub, payload));
    let (view, input_view) = match spliced.as_deref() {
        Some(view) => (view, crate::report::ResearchInputView::SplicedCompanion),
        None => (stub.as_slice(), crate::report::ResearchInputView::Original),
    };
    let inspected = research.then(|| senbei_engine::inspect_research(view));
    // Identity of the file as it sits on disk, before any splice, and of the
    // sibling whose bytes were read for pairing. Both hash bytes already in
    // memory: the report must never read a companion a second time.
    let source = Digest::of(&stub);
    let companion_digest = companion.as_deref().map(Digest::of);
    // The byte entry point owns the splice, companion overlays, and the check
    // over the image actually returned — the same steps as `unpack_one_v`.
    // The trace sink only observes, and only a research run asks for it.
    let (trace, (profile, recovered)) = if research {
        let (trace, outcome) = senbei_engine::with_research_trace(|| {
            crate::windows::unpack_bytes_profiled_v(&stub, companion.as_deref(), verbose)
        });
        (Some(trace), outcome)
    } else {
        (
            None,
            crate::windows::unpack_bytes_profiled_v(&stub, companion.as_deref(), verbose),
        )
    };
    let image = match recovered {
        Ok(image) => image,
        // The profile already records which candidates ran and why they failed.
        Err(error) => {
            let observed = Some(UnpackResearch {
                source,
                companion: companion_digest,
                report: match (inspected, trace) {
                    (Some(input), Some(trace)) => Some(crate::report::WindowsResearchReport {
                        input_view,
                        input,
                        restored: None,
                        trace,
                    }),
                    _ => None,
                },
                recovered: None,
            });
            return (profile, observed, Err(error.into()));
        }
    };
    // Inspect the post-overlay image now, while its bytes are still here, then
    // let them go: research inspection never keeps a recovered file.
    let observed = Some(UnpackResearch {
        source,
        companion: companion_digest,
        report: match (inspected, trace) {
            (Some(input), Some(trace)) => Some(crate::report::WindowsResearchReport {
                input_view,
                input,
                restored: Some(senbei_engine::inspect_research(&image.bytes)),
                trace,
            }),
            _ => None,
        },
        recovered: Some(Digest::of(&image.bytes)),
    });
    if let Some(parent) = dest.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return (profile, observed, Err(error.into()));
    }
    if let Err(error) = write_atomic(dest, &image.bytes) {
        return (profile, observed, Err(error.into()));
    }
    if verbose {
        crate::ui::write_to(dest, true);
    }
    (profile, observed, Ok((image.kind, image.integrity)))
}

/// The input's bytes and its `<input>._` companion payload, when one exists.
///
/// Mirrors the file entry point's companion discovery: a missing sibling is
/// simply absent, while an unreadable one is an error rather than a silent
/// mismatch.
/// The `<input>._` sibling when one exists and is readable.
///
/// `Ok(None)` means there is no sibling. `Err` means one exists but could not
/// be read — a real condition the caller must classify, not treat as absent.
fn read_optional_companion(input: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(path) = sibling_path(input) else {
        return Ok(None);
    };
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow::Error::from(error)
            .context(format!("couldn't read companion {}", path.display()))),
    }
}

fn read_stub_and_companion(input: &Path) -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let stub = std::fs::read(input)?;
    let Some(name) = input.file_name() else {
        return Ok((stub, None));
    };
    let mut sibling = name.to_os_string();
    sibling.push("._");
    let companion = input.with_file_name(sibling);
    match std::fs::read(&companion) {
        Ok(bytes) => Ok((stub, Some(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((stub, None)),
        Err(error) => Err(anyhow::Error::from(error)
            .context(format!("couldn't read companion {}", companion.display()))),
    }
}

/// `<input>._`, the companion payload path for `input`.
fn sibling_path(input: &Path) -> Option<PathBuf> {
    let name = input.file_name()?;
    let mut sibling = name.to_os_string();
    sibling.push("._");
    Some(input.with_file_name(sibling))
}

/// Outcome of looking for `<input>._`, with the bytes when there were any.
///
/// The bytes are kept so the report can name the sibling's identity without
/// reading it a second time; a `._` that exists but cannot be read is its own
/// state, never a mismatch.
pub(crate) enum CompanionProbe {
    Absent,
    Read(Vec<u8>),
    Unreadable(String),
}

pub(crate) fn probe_companion(input: &Path) -> CompanionProbe {
    let Some(path) = sibling_path(input) else {
        return CompanionProbe::Absent;
    };
    match std::fs::read(&path) {
        Ok(bytes) => CompanionProbe::Read(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CompanionProbe::Absent,
        // A directory, a lock, or a permission problem: the sibling is there,
        // but its bytes were never seen, so it must not be called a mismatch.
        Err(error) => CompanionProbe::Unreadable(format!("{error}")),
    }
}

/// Companion state for a run that only knows whether a payload was spliced.
///
/// `Spliced` means the pairing actually happened. Otherwise the sibling is
/// reported for what it is: unreadable if it could not be read, unmatched when
/// its bytes exist but do not pair with this stub, absent when there is none.
pub(crate) fn observed_companion_state(
    input: &Path,
    spliced: bool,
) -> (CompanionState, Option<Digest>, Option<String>) {
    if spliced {
        return (CompanionState::Spliced, None, None);
    }
    match probe_companion(input) {
        CompanionProbe::Absent => (CompanionState::Absent, None, None),
        CompanionProbe::Read(bytes) => (CompanionState::Unmatched, Some(Digest::of(&bytes)), None),
        CompanionProbe::Unreadable(reason) => (CompanionState::Unreadable, None, Some(reason)),
    }
}

/// What the `._` companion relationship is for `input`, observed on disk.
///
/// `source` is the identity of a sibling whose bytes were seen. `Unreadable`
/// carries no identity because none were: a digest of nothing would be a lie.
pub(crate) fn companion_report(
    input: &Path,
    state: CompanionState,
    source: Option<Digest>,
    unreadable: Option<String>,
) -> CompanionReport {
    let path = sibling_path(input);
    CompanionReport {
        state,
        path: match state {
            CompanionState::Absent => None,
            _ => path.map(|path| path.display().to_string()),
        },
        detail: match state {
            CompanionState::Unmatched => Some(Message::new(Msg::CompanionUnmatched)),
            CompanionState::Unreadable => Some(Message::new(match unreadable {
                Some(reason) => Msg::CompanionUnreadable { reason },
                None => Msg::CompanionUnreadableUnknown,
            })),
            _ => None,
        },
        source,
    }
}

/// Input report for a Windows PE whose outcome a profiled run reported.
fn windows_input(
    input: &Path,
    dest: &Path,
    kind: senbei_engine::Kind,
    report: &senbei_engine::IntegrityReport,
    profile: Option<senbei_engine::ProtectionProfile>,
    started: Instant,
) -> InputReport {
    let mut entry = InputReport::new(input, Role::Content);
    entry.status = if report.ok() {
        InputStatus::Ok
    } else {
        InputStatus::Suspect
    };
    let profile = profile.unwrap_or_else(|| recovered_profile(kind, report));
    entry.companion = crate::windows::is_pe_extension(input).then(|| {
        let (state, source, unreadable) =
            observed_companion_state(input, profile.observed.external_companion);
        companion_report(input, state, source, unreadable)
    });
    entry.profile = Some(profile);
    entry.outputs = vec![OutputFile::from_path(dest)];
    entry
        .stages
        .push(StageReport::new(Stage::Detection, StageStatus::Ok));
    entry.stages.push(
        StageReport::new(Stage::Recovery, StageStatus::Ok).timed(crate::report::now_ms(started)),
    );
    entry.stages.push(StageReport::new(
        Stage::StaticValidation,
        if report.ok() {
            StageStatus::Ok
        } else {
            StageStatus::Failed
        },
    ));
    entry.stages.push(
        StageReport::new(Stage::OutputWrite, StageStatus::Ok).detail(dest.display().to_string()),
    );
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

/// Profile for a successful Windows unpack when only the outcome is known.
///
/// Only used when a caller has no profiled result to hand. It states exactly
/// what was observed: the detected kind, the route that kind routes to, and the
/// final integrity verdict.
fn recovered_profile(
    kind: senbei_engine::Kind,
    report: &senbei_engine::IntegrityReport,
) -> senbei_engine::ProtectionProfile {
    use senbei_engine::{
        AttemptOutcome, LayoutAttempt, ProtectionEvidence, ProtectionProfile, RecognitionStatus,
        RecoveryStatus,
    };
    let mut profile =
        ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, Some(kind)));
    profile.recognition = RecognitionStatus::Recognized;
    profile.evidence = vec![ProtectionEvidence::HeaderMagic];
    profile.recovery = RecoveryStatus::Succeeded;
    profile.record_static_validation(report);
    let layout = match kind {
        senbei_engine::Kind::NativeDll | senbei_engine::Kind::ManagedDll => {
            senbei_engine::LayoutKind::Dll
        }
        _ => senbei_engine::LayoutKind::ExeStyle,
    };
    profile.selected = Some(layout);
    profile.candidates = vec![LayoutAttempt {
        layout,
        outcome: AttemptOutcome::Succeeded,
        warnings: profile.warnings.clone(),
        errors: profile.errors.clone(),
    }];
    profile
}

/// Input report for an input that failed before producing output.
///
/// The profile is rebuilt from the input's own header so the report says which
/// route failed and what was recognized, rather than only the error text. This
/// reads the header again — it is report construction, not a second pipeline
/// run, and the observed bytes are the same ones the pipeline saw.
fn failed_input(input: &Path, error: &anyhow::Error, started: Instant) -> InputReport {
    let mut entry = InputReport::new(input, Role::Content);
    entry.status = InputStatus::Error;
    entry.analysis_incomplete = analysis_incomplete(error);
    let detail = of_error(error);
    entry.error(detail.clone());
    entry.profile = Some(failure_profile(input, &detail));
    entry
        .stages
        .push(StageReport::new(Stage::Recovery, StageStatus::Failed).detail(detail));
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

/// Input report for a Windows PE whose profiled run failed.
///
/// The profile comes from the run itself, so it keeps every candidate that was
/// tried and the error that stopped each — no header re-read, no inference.
fn failed_input_with_profile(
    input: &Path,
    error: &anyhow::Error,
    profile: senbei_engine::ProtectionProfile,
    started: Instant,
) -> InputReport {
    let mut entry = InputReport::new(input, Role::Content);
    entry.status = InputStatus::Error;
    entry.analysis_incomplete = analysis_incomplete(error);
    let detail = of_error(error);
    entry.error(detail.clone());
    entry.companion = crate::windows::is_pe_extension(input).then(|| {
        let (state, source, unreadable) =
            observed_companion_state(input, profile.observed.external_companion);
        companion_report(input, state, source, unreadable)
    });
    entry.profile = Some(profile);
    entry
        .stages
        .push(StageReport::new(Stage::Recovery, StageStatus::Failed).detail(detail));
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

/// Best-effort observation of an input whose inspection failed.
///
/// Reads only what detection reads. Recognition and the routes that *would* be
/// tried are reported as planned; nothing is marked attempted.
fn observed_profile(input: &Path) -> senbei_engine::ProtectionProfile {
    use senbei_engine::{LayoutAttempt, ProtectionProfile, RecoveryStatus, ValidationStatus};
    let mut profile = match read_prefix(input) {
        Ok(prefix) if senbei_metadata::is_metadata(&prefix) => {
            crate::report::metadata_unchanged_profile(senbei_metadata::identify(&prefix))
        }
        Ok(_) if crate::windows::is_pe_extension(input) => match std::fs::read(input) {
            Ok(stub) => {
                let (bytes, spliced) = match read_optional_companion(input) {
                    Ok(Some(payload)) => match crate::windows::splice_companion(&stub, &payload) {
                        Some(spliced) => (spliced, true),
                        None => (stub, false),
                    },
                    _ => (stub, false),
                };
                let mut profile = senbei_engine::inspect_profile(&bytes);
                if spliced {
                    profile.record_companion_spliced();
                }
                profile
            }
            Err(_) => ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, None)),
        },
        Ok(prefix) if crate::android::is_elf64_aarch64(&prefix) => {
            ProtectionProfile::new(senbei_engine::ObservedTarget::android(None))
        }
        Ok(prefix) if crate::android::is_app_package(input, &prefix) => {
            ProtectionProfile::new(senbei_engine::ObservedTarget::android(None))
        }
        _ => ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, None)),
    };
    // Nothing was attempted: every planned route stays planned.
    for candidate in &mut profile.candidates {
        *candidate = LayoutAttempt::not_attempted(candidate.layout);
    }
    profile.selected = None;
    profile.recovery = RecoveryStatus::NotAttempted;
    profile.static_validation = ValidationStatus::NotRun;
    profile
}

/// Profile of an input whose recovery failed.
fn failure_profile(input: &Path, detail: &Message) -> senbei_engine::ProtectionProfile {
    use senbei_engine::{AttemptOutcome, LayoutKind, ProtectionProfile, RecoveryStatus};
    let Ok(prefix) = read_prefix(input) else {
        let mut profile =
            ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, None));
        profile.recovery = RecoveryStatus::Failed;
        profile.push_error(detail.clone());
        return profile;
    };
    if senbei_metadata::is_metadata(&prefix) {
        return crate::report::metadata_failed_profile(
            senbei_metadata::identify(&prefix),
            LayoutKind::MetadataStructural,
            detail,
        );
    }
    if crate::windows::is_pe_extension(input) {
        let mut profile = match crate::windows::read_unpacker_input(input) {
            Ok(unpacker_input) => {
                let spliced = unpacker_input.stub.is_some();
                let mut profile = senbei_engine::inspect_profile(&unpacker_input.bytes);
                if spliced {
                    profile.record_companion_spliced();
                }
                profile
            }
            // The input could not be read at all as a PE.
            Err(_) => ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, None)),
        };
        // The route that was tried is the one the pipeline would have used; a
        // spliced companion forces the EXE-style shell.
        let (layout, errors) = match profile
            .candidates
            .iter()
            .find(|candidate| candidate.outcome == AttemptOutcome::NotAttempted)
            .map(|candidate| candidate.layout)
        {
            Some(layout) => (layout, vec![detail.clone()]),
            None => (LayoutKind::ExeStyle, vec![detail.clone()]),
        };
        if let Some(attempt) = profile.attempt_mut(layout) {
            attempt.outcome = AttemptOutcome::Failed;
            attempt.errors = errors;
        } else {
            profile.candidates.push(senbei_engine::LayoutAttempt {
                layout,
                outcome: AttemptOutcome::Failed,
                warnings: Vec::new(),
                errors,
            });
        }
        profile.recovery = RecoveryStatus::Failed;
        profile.push_error(detail.clone());
        return profile;
    }
    if crate::android::is_elf64_aarch64(&prefix) {
        return crate::report::android_failed_profile(detail);
    }
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, None));
    profile.recovery = RecoveryStatus::Failed;
    profile.push_error(detail.clone());
    profile
}

/// Input report for a restored (or skipped) loose Android library.
pub(crate) fn android_library_input(
    input: &Path,
    status: InputStatus,
    dest: &Path,
    started: Instant,
) -> InputReport {
    android_library_input_with_error(input, status, dest, started, None)
}

/// [`android_library_input`], also recording whether the failure was a resource
/// or I/O ceiling rather than an ordinary candidate rejection.
fn android_library_input_with_error(
    input: &Path,
    status: InputStatus,
    dest: &Path,
    started: Instant,
    error: Option<&anyhow::Error>,
) -> InputReport {
    let mut entry = InputReport::new(input, Role::Content);
    entry.status = status;
    entry.analysis_incomplete = error.is_some_and(analysis_incomplete);
    // The failure profile below takes its detail from the first error.
    if let Some(error) = error {
        entry.error(of_error(error));
    }
    match status {
        InputStatus::Ok => {
            entry.profile = Some(crate::report::android_recovered_profile());
            entry.outputs = vec![OutputFile::from_path(dest)];
            entry.stages.push(
                StageReport::new(Stage::Recovery, StageStatus::Ok)
                    .timed(crate::report::now_ms(started)),
            );
        }
        InputStatus::Skipped => {
            entry
                .stages
                .push(StageReport::new(Stage::Recovery, StageStatus::Skipped));
        }
        _ => {
            let detail = entry
                .errors
                .first()
                .cloned()
                .unwrap_or_else(|| Message::raw(""));
            entry.profile = Some(crate::report::android_failed_profile(&detail));
            entry
                .stages
                .push(StageReport::new(Stage::Recovery, StageStatus::Failed));
        }
    }
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

/// Record a restore's validation verdict and advisory findings on a report.
///
/// `static_validation` becomes `clean` or `warnings`; diagnostics are warnings,
/// never errors, because the engine's own restore accepted these bytes.
fn apply_android_validation(
    report: &mut InputReport,
    validation: Option<&crate::android::ValidationDiagnostics>,
) {
    // No engine report is not a verdict: leave static_validation untouched.
    let Some(validation) = validation else {
        return;
    };
    let Some(profile) = report.profile.as_mut() else {
        return;
    };
    if profile.recovery != senbei_engine::RecoveryStatus::Succeeded {
        return;
    }
    profile.static_validation = if validation.is_clean() {
        senbei_engine::ValidationStatus::Clean
    } else {
        senbei_engine::ValidationStatus::Warnings
    };
    profile
        .warnings
        .extend(validation.messages.iter().cloned().map(Message::from));
    report
        .warnings
        .extend(validation.messages.iter().cloned().map(Message::from));
    // The stage itself succeeded — the restore validated the output. Findings
    // are carried as detail and warnings, not as a failed stage.
    let mut stage = StageReport::new(Stage::StaticValidation, StageStatus::Ok);
    if !validation.is_clean() {
        stage = stage.detail(validation.messages.join("; "));
    }
    report.stages.push(stage);
}

/// Profile for a metadata blob whose transform ran, validated, and needed no
/// change.
///
/// The route was really taken and the bytes really validated, so the attempt is
/// recorded — but a clean blob is no protection evidence, so recognition stays
/// `not_recognized` and no protection verdict is claimed. Without this an
/// inspection of an already-clean blob would say `not_attempted` while the
/// research section next to it showed the route and its report.
fn metadata_validated_unchanged_profile(
    identity: Option<senbei_metadata::MetadataIdentity>,
    route: senbei_engine::LayoutKind,
) -> senbei_engine::ProtectionProfile {
    use senbei_engine::{AttemptOutcome, LayoutAttempt, ProtectionProfile};
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::metadata(
        identity.map(|identity| identity.raw_version),
    ));
    profile.candidates = vec![LayoutAttempt {
        layout: route,
        outcome: AttemptOutcome::Succeeded,
        warnings: Vec::new(),
        errors: Vec::new(),
    }];
    profile.selected = Some(route);
    profile.recovery = senbei_engine::RecoveryStatus::Succeeded;
    profile.static_validation = senbei_engine::ValidationStatus::NotRun;
    profile.recognition = senbei_engine::RecognitionStatus::NotRecognized;
    profile
}

/// Input report for one loose il2cpp metadata blob.
fn metadata_input(
    input: &Path,
    report: &crate::android::LooseMetadataOutcome,
    dest: Option<&Path>,
    started: Instant,
) -> InputReport {
    let identity = identity_of(input);
    let mut entry = InputReport::new(input, Role::Content);
    entry.metadata = identity;
    entry.metadata_version = Some(report.version);
    entry.provenance = report.provenance.clone();
    if dest.is_some() {
        entry.status = InputStatus::Ok;
        entry.profile = Some(crate::report::metadata_recovered_profile(
            identity,
            report.layout,
        ));
        entry.outputs = dest
            .map(|dest| vec![OutputFile::from_path(dest)])
            .unwrap_or_default();
        entry.stages.push(
            StageReport::new(Stage::Recovery, StageStatus::Ok)
                .timed(crate::report::now_ms(started)),
        );
    } else {
        // Identified, valid, and already canonical: nothing to write. The
        // transform still ran and validated, so a research report may say so
        // even though the status stays "nothing needed".
        entry.status = InputStatus::Skipped;
        entry.profile = Some(match report.research {
            Some(_) => metadata_validated_unchanged_profile(identity, report.layout),
            None => crate::report::metadata_unchanged_profile(identity),
        });
        entry.stages.push(
            StageReport::new(Stage::Recovery, StageStatus::Skipped).detail(Msg::TransformNoop),
        );
    }
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

/// Input report for a single-file metadata run.
fn single_metadata_input(
    input: &Path,
    report: &senbei_metadata::Report,
    layout: senbei_engine::LayoutKind,
    dest: Option<&Path>,
    research: bool,
    started: Instant,
) -> InputReport {
    let identity = identity_of(input);
    let mut entry = InputReport::new(input, Role::Content);
    entry.metadata = identity;
    entry.metadata_version = Some(report.version);
    entry.status = if dest.is_some() {
        InputStatus::Ok
    } else {
        InputStatus::Skipped
    };
    entry.profile = Some(match (dest.is_some(), research) {
        (true, _) => crate::report::metadata_recovered_profile(identity, layout),
        // The transform ran and validated; only the rewrite was unnecessary.
        (false, true) => metadata_validated_unchanged_profile(identity, layout),
        (false, false) => crate::report::metadata_unchanged_profile(identity),
    });
    entry.outputs = dest
        .map(|dest| vec![OutputFile::from_path(dest)])
        .unwrap_or_default();
    entry.stages.push(
        StageReport::new(
            Stage::Recovery,
            if dest.is_some() {
                StageStatus::Ok
            } else {
                StageStatus::Skipped
            },
        )
        .timed(crate::report::now_ms(started)),
    );
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

/// Report for an il2cpp metadata input whose transform failed.
///
/// One rule for folder and single-file runs, in every mode: an unsupported
/// version was left untouched by design and is a skip; anything else is a real
/// failure of this input, with the transform's own reason preserved. Research
/// keeps the seeds and discovery the failing attempt produced.
fn metadata_failure_input(
    input: &Path,
    error: &anyhow::Error,
    unsupported: Option<u32>,
    started: Instant,
) -> InputReport {
    // `failed_input` already classified the typed error; an unsupported
    // version is a deliberate skip, not an incomplete analysis.
    let mut report = failed_input(input, error, started);
    if unsupported.is_some() {
        report.analysis_incomplete = false;
    }
    let identity = identity_of(input);
    report.metadata = identity;
    report.metadata_version = unsupported.or_else(|| identity.map(|identity| identity.raw_version));
    report.metadata_research =
        crate::android::error_research(error).and_then(|capture| match capture {
            crate::android::ResearchCapture::Metadata(value) => Some(value.clone()),
            crate::android::ResearchCapture::Library(_) => None,
        });
    if let Some(version) = unsupported {
        // Left untouched by design; not a failure of this run.
        report.status = InputStatus::Skipped;
        report.errors.clear();
        report.profile = Some(crate::report::metadata_unchanged_profile(identity));
        report.warning(Msg::MetadataLeftUntouched { version });
    } else {
        report.profile = Some(crate::report::metadata_failed_profile(
            identity,
            senbei_engine::LayoutKind::MetadataStructural,
            &of_error(error),
        ));
    }
    report
}

/// Membership of a package, read only for a research inspection.
///
/// This is a container listing (central directories and a bounded manifest
/// read), not a second restore: it never touches a protected entry's payload.
fn package_inventory(
    package: &Path,
    limits: &senbei_engine::android::ResourceLimits,
    research: bool,
) -> Option<crate::report::ContainerReport> {
    if !research {
        return None;
    }
    crate::android::inspect_package(package, limits).ok()
}

/// Input report for one app package, from the entries it produced.
///
/// `inventory` additionally lists what the container holds — its manifests and
/// the entries a restore would probe — kept apart from the entries that were
/// actually probed, so a membership list is never read as inspected content.
fn package_input(
    package: &Path,
    outcomes: Vec<&crate::android::EntryOutcome>,
    inventory: Option<&crate::report::ContainerReport>,
    started: Instant,
) -> InputReport {
    let mut entry = InputReport::new(package, Role::Container);
    entry.container = Some(match inventory {
        Some(inventory) => inventory.clone(),
        None => ContainerReport {
            kind: package
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.to_ascii_lowercase())
                .unwrap_or_default(),
            manifests: Vec::new(),
            entry_count: outcomes.len(),
            candidate_entries: outcomes
                .iter()
                .map(|outcome| outcome.label.clone())
                .collect(),
            nested_packages: Vec::new(),
        },
    });
    entry.entries = outcomes
        .iter()
        .map(|outcome| entry_report(outcome))
        .collect();
    // A container has no single profile; its validation verdict carries every
    // advisory finding a restored entry reported.
    let diagnostics: Vec<String> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome.status, crate::android::EntryStatus::Restored))
        .filter_map(|outcome| outcome.validation.as_ref())
        .flat_map(|validation| validation.messages.iter().cloned())
        .collect();
    if !diagnostics.is_empty() {
        entry
            .warnings
            .extend(diagnostics.iter().cloned().map(Message::from));
        entry.stages.push(
            StageReport::new(Stage::StaticValidation, StageStatus::Ok)
                .detail(diagnostics.join("; ")),
        );
    }
    // A container's analysis is incomplete when any entry's was: the
    // membership report may be truncated by the same ceiling.
    entry.analysis_incomplete = entry.entries.iter().any(|entry| entry.analysis_incomplete);
    entry.status = if entry
        .entries
        .iter()
        .any(|entry| entry.status == EntryStatus::Error)
    {
        InputStatus::Error
    } else if entry
        .entries
        .iter()
        .any(|entry| entry.status == EntryStatus::Restored)
    {
        InputStatus::Ok
    } else {
        InputStatus::Skipped
    };
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

fn entry_report(outcome: &crate::android::EntryOutcome) -> EntryReport {
    use crate::android::EntryKind as SourceKind;
    let (status, kind) = match &outcome.status {
        crate::android::EntryStatus::Restored => {
            (EntryStatus::Restored, Some(source_kind(outcome.kind)))
        }
        crate::android::EntryStatus::Duplicate => {
            (EntryStatus::Duplicate, Some(source_kind(outcome.kind)))
        }
        crate::android::EntryStatus::NotTarget => (EntryStatus::NotTarget, None),
        crate::android::EntryStatus::Unchanged => {
            (EntryStatus::Unchanged, Some(source_kind(outcome.kind)))
        }
        crate::android::EntryStatus::Failed(_) => {
            (EntryStatus::Error, Some(source_kind(outcome.kind)))
        }
    };
    let mut report = EntryReport::new(outcome.label.clone(), status);
    report.kind = kind;
    report.provenance = outcome.provenance.clone();
    report.layout = outcome.layout;
    report.metadata_version = outcome.metadata_version;
    report.android_research = outcome.research.clone();
    report.metadata_research = outcome.metadata_research.clone();
    if let SourceKind::Metadata { remapped } = outcome.kind {
        report.remapped = Some(remapped);
    }
    if status == EntryStatus::Restored {
        report.output = Some(OutputFile::from_path(&outcome.dest));
    }
    if let crate::android::EntryStatus::Failed(error) = &outcome.status {
        report.errors.push(of_error(error));
        // A resource or I/O ceiling stopped this entry before its structure
        // could be judged; a structural rejection is an observed finding.
        report.analysis_incomplete = analysis_incomplete(error);
    }
    // The engine's advisory findings for this entry's own output. Only a
    // restored entry has an output they could describe.
    if status == EntryStatus::Restored
        && let Some(validation) = &outcome.validation
    {
        report
            .warnings
            .extend(validation.messages.iter().cloned().map(Message::from));
    }
    report
}

fn source_kind(kind: crate::android::EntryKind) -> EntryKind {
    match kind {
        crate::android::EntryKind::So => EntryKind::SharedLibrary,
        crate::android::EntryKind::Metadata { .. }
        | crate::android::EntryKind::EmbeddedMetadata => EntryKind::Metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review regression: when the candidate path is not under `root` (e.g. a
    /// `\\?\`-prefixed root against plain walk paths), the output name must
    /// fall back to the bare file name — joining the absolute path would
    /// replace the output root and write back over the source tree.
    #[test]
    fn rel_in_tree_falls_back_to_file_name_outside_root() {
        let root = Path::new(r"D:\out-of-tree-root");
        let abs = Path::new(r"C:\game\bin\app.exe");
        let rel = rel_in_tree(root, abs);
        assert_eq!(rel.as_ref(), Path::new("app.exe"));

        // And the normal case still preserves the tree structure.
        let under = Path::new(r"D:\out-of-tree-root\bin\app.exe");
        let rel = rel_in_tree(root, under);
        assert_eq!(rel.as_ref(), Path::new(r"bin\app.exe"));
    }

    /// A restore's validation diagnostics reach the JSON report: the profile's
    /// `static_validation` becomes `warnings`, the findings appear as warnings,
    /// and a `static_validation` stage records them — while the input stays a
    /// success and its output is still listed.
    #[test]
    fn validation_diagnostics_reach_the_json_report() {
        use crate::android::ValidationDiagnostics;

        let started = Instant::now();
        let mut input = android_library_input(
            Path::new("lib/arm64-v8a/libil2cpp.so"),
            InputStatus::Ok,
            Path::new("out/libil2cpp.unpack.so"),
            started,
        );
        apply_android_validation(
            &mut input,
            Some(&ValidationDiagnostics {
                messages: vec!["a table a linker could not walk".to_owned()],
            }),
        );

        let mut collector = Collector::new(Mode::Unpack);
        collector.push(input);
        let value: serde_json::Value =
            serde_json::from_str(&collector.finish().to_json()).expect("valid report");

        let reported = &value["inputs"][0];
        assert_eq!(reported["status"], "ok");
        assert_eq!(reported["profile"]["recovery"], "succeeded");
        assert_eq!(reported["profile"]["static_validation"], "warnings");
        assert_eq!(
            reported["profile"]["warnings"][0],
            "a table a linker could not walk"
        );
        assert_eq!(reported["warnings"][0], "a table a linker could not walk");
        assert_eq!(reported["outputs"][0]["path"], "out/libil2cpp.unpack.so");
        // The advisory finding is a warning, never an error.
        assert!(reported["errors"].as_array().unwrap().is_empty());
        assert!(reported["profile"]["errors"].as_array().unwrap().is_empty());
        let stages: Vec<&str> = reported["stages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|stage| stage["stage"].as_str().unwrap())
            .collect();
        assert!(stages.contains(&"static_validation"), "{stages:?}");
    }

    /// No engine report means no verdict: a restore that reported none must not
    /// claim a clean static validation.
    #[test]
    fn missing_validation_report_is_not_a_clean_verdict() {
        let started = Instant::now();
        let mut input = android_library_input(
            Path::new("lib/arm64-v8a/libil2cpp.so"),
            InputStatus::Ok,
            Path::new("out/libil2cpp.unpack.so"),
            started,
        );
        apply_android_validation(&mut input, None);

        let mut collector = Collector::new(Mode::Unpack);
        collector.push(input);
        let value: serde_json::Value =
            serde_json::from_str(&collector.finish().to_json()).expect("valid report");
        assert_eq!(
            value["inputs"][0]["profile"]["static_validation"],
            "not_run"
        );
        assert!(
            value["inputs"][0]["warnings"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[cfg(test)]
mod research_tests {
    use super::*;
    use std::io::Write;

    /// Two splits that name the same package and version form one split set.
    /// A restore failure there belongs to the group, but each split still gets
    /// a report naming the cause — otherwise the JSON would say "no errors"
    /// and an inspection would exit 0 over a failed restore.
    #[test]
    fn a_failed_split_set_reports_an_error_for_every_split() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let manifest = |package: &str, version: u32| {
            format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                 <manifest package=\"{package}\" android:versionCode=\"{version}\"></manifest>\n"
            )
        };
        let write = |name: &str, entries: &[(&str, Vec<u8>)]| {
            let path = root.join(name);
            let file = std::fs::File::create(&path).unwrap();
            let mut archive = zip::ZipWriter::new(file);
            for (entry, data) in entries {
                archive
                    .start_file(
                        *entry,
                        zip::write::SimpleFileOptions::default()
                            .compression_method(zip::CompressionMethod::Stored),
                    )
                    .unwrap();
                archive.write_all(data).unwrap();
            }
            archive.finish().unwrap();
            path
        };
        // Same package and version: one split set. The library entry is larger
        // than the entry ceiling, so the group restore really fails.
        // The scan's size floor is applied before any content probe, so the
        // archives carry an asset that clears it.
        // Stored, not deflated: the scan's floor is the on-disk file size.
        let padding: Vec<u8> = (0..8 * 1024).map(|index| (index % 251) as u8).collect();
        let base = write(
            "base.apk",
            &[
                (
                    "AndroidManifest.xml",
                    manifest("com.example.split", 7).into_bytes(),
                ),
                ("assets/pad.bin", padding.clone()),
            ],
        );
        let config = write(
            "config.apk",
            &[
                (
                    "AndroidManifest.xml",
                    manifest("com.example.split", 7).into_bytes(),
                ),
                ("assets/pad.bin", padding),
                // Larger than the entry ceiling, so the group restore fails.
                ("lib/arm64-v8a/libil2cpp.so", vec![0xAA; 2048]),
            ],
        );

        let limits = senbei_engine::android::ResourceLimits {
            max_entry_bytes: 512,
            ..senbei_engine::android::ResourceLimits::default()
        };
        let mut collector = Collector::new(Mode::Inspect);
        run_folder_inner(
            root,
            Some(&td.path().join("out")),
            2,
            false,
            true,
            false,
            &limits,
            Some(&mut collector),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&collector.finish().to_json()).unwrap();
        let inputs = value["inputs"].as_array().unwrap();
        assert!(
            inputs.len() >= 2,
            "each split is reported separately: {value}"
        );
        // A resource ceiling is an honest failure, not a failed inspection of a
        // non-target: it is counted once per reported split, never twice for the
        // group's two restore phases.
        assert_eq!(
            value["summary"]["errors"], 2,
            "one error per split, counted exactly once: {value}"
        );
        for package in [&base, &config] {
            let reported = inputs
                .iter()
                .find(|input| input["path"] == package.display().to_string())
                .unwrap_or_else(|| panic!("{} must be reported: {value}", package.display()));
            assert_eq!(reported["status"], "error", "{reported}");
            assert!(
                !reported["errors"].as_array().unwrap().is_empty(),
                "the cause travels with the split: {reported}"
            );
        }
    }
}

#[cfg(test)]
mod single_package_research_tests {
    use super::*;
    use std::io::Write;

    /// A single package inspected on its own keeps the same per-entry engine
    /// report a folder run would: the research flag must reach its restore
    /// cache, not only the folder's shared one.
    #[test]
    fn a_single_package_inspection_keeps_its_entry_report() {
        let td = tempfile::tempdir().unwrap();
        let apk = td.path().join("app.apk");
        let mut metadata = 0xFAB1_1BAF_u32.to_le_bytes().to_vec();
        metadata.extend_from_slice(&31u32.to_le_bytes());
        metadata.resize(0x300, 0);
        // A plausible v31 header is not needed: the transform reports its own
        // failure, and a failing transform is exactly what carries research.
        let file = std::fs::File::create(&apk).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        archive.start_file("AndroidManifest.xml", options).unwrap();
        archive
            .write_all(
                b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
                  <manifest package=\"com.example.one\" android:versionCode=\"1\"></manifest>\n",
            )
            .unwrap();
        archive
            .start_file("assets/global-metadata.dat", options)
            .unwrap();
        archive.write_all(&metadata).unwrap();
        archive.start_file("assets/pad.bin", options).unwrap();
        archive
            .write_all(
                &(0..8 * 1024)
                    .map(|index| (index % 251) as u8)
                    .collect::<Vec<u8>>(),
            )
            .unwrap();
        archive.finish().unwrap();

        let report = inspect_path(
            &apk,
            false,
            &senbei_engine::android::ResourceLimits::default(),
        )
        .expect("inspection returns a report");
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        let input = &value["inputs"][0];
        assert_eq!(input["role"], "container");
        let entries = input["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "the metadata entry was probed: {input}");
        assert!(
            entries[0]["metadata_research"].is_object(),
            "a single package keeps the transform's research: {input}"
        );
    }
}

#[cfg(test)]
mod incomplete_analysis_tests {
    use super::*;

    fn limited() -> anyhow::Error {
        anyhow::Error::new(senbei_engine::android::LimitExceeded::Entry {
            requested: 4096,
            limit: 1024,
        })
    }

    /// A resource ceiling stops the analysis before it can conclude anything.
    /// A known target does not make that a complete inspection.
    #[test]
    fn a_resource_ceiling_keeps_inspection_incomplete() {
        let error = limited();
        assert!(analysis_incomplete(&error));
        // And it survives the Android engines' own wrappers.
        let wrapped = anyhow::Error::new(senbei_engine::android::ExtractionError::Limit(
            senbei_engine::android::LimitExceeded::Entry {
                requested: 4096,
                limit: 1024,
            },
        ));
        assert!(analysis_incomplete(&wrapped));
    }

    /// An ordinary rejected candidate is a finding: the analysis concluded that
    /// this layout does not apply.
    #[test]
    fn a_rejected_candidate_is_not_incomplete() {
        assert!(!analysis_incomplete(&anyhow::anyhow!(
            "stage5 marker not found — this build's layout is not supported"
        )));
        assert!(!analysis_incomplete(&anyhow::Error::new(
            senbei_engine::android::RestoreError::Invalid("not a linker-walkable image".to_owned())
        )));
    }

    /// The report restates a known target as recognized — unless the analysis
    /// stopped on a resource or I/O ceiling.
    #[test]
    fn an_incomplete_analysis_stays_an_error_even_for_a_known_target() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("libil2cpp.so");
        std::fs::write(&path, b"not really an ELF").unwrap();
        let mut input = InputReport::new(&path, Role::Content);
        input.status = InputStatus::Error;
        input.profile = Some(crate::report::android_failed_profile(&"limit".into()));
        input.analysis_incomplete = true;
        let reported = inspect_status(input);
        assert_eq!(reported.status, InputStatus::Error);
        assert!(reported.analysis_incomplete);

        // The same target without an incompleteness marker is a finding.
        let mut complete = InputReport::new(&path, Role::Content);
        complete.status = InputStatus::Error;
        complete.profile = Some(crate::report::android_failed_profile(
            &"layout rejected".into(),
        ));
        let reported = inspect_status(complete);
        assert_eq!(reported.status, InputStatus::Recognized);
        assert!(!reported.analysis_incomplete);
    }

    /// A loose library that failed keeps its error, in the report and as the
    /// failure profile's detail.
    #[test]
    fn a_failed_android_library_reports_its_error() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("libil2cpp.so");
        std::fs::write(&path, b"not really an ELF").unwrap();
        let error = anyhow::anyhow!("6 unresolved slots").context("restore protected library");
        let reported = android_library_input_with_error(
            &path,
            InputStatus::Error,
            &path,
            Instant::now(),
            Some(&error),
        );
        let texts: Vec<&str> = reported.errors.iter().map(Message::text).collect();
        assert_eq!(texts, ["restore protected library: 6 unresolved slots"]);
        let profile = reported.profile.expect("a failure profile");
        let detail: Vec<&str> = profile.errors.iter().map(Message::text).collect();
        assert_eq!(detail, texts);
    }

    /// A container whose entry hit a ceiling is incomplete as a whole.
    #[test]
    fn a_container_inherits_an_incomplete_entry() {
        let mut entry = EntryReport::new("app.apk::lib/arm64-v8a/libil2cpp.so", EntryStatus::Error);
        entry.analysis_incomplete = true;
        entry.errors.push("resource limit".into());
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("app.apk");
        std::fs::write(&path, b"PK").unwrap();
        let mut input = InputReport::new(&path, Role::Container);
        input.entries = vec![entry];
        let reported = inspect_status(input);
        assert_eq!(reported.status, InputStatus::Error);
        assert!(reported.analysis_incomplete);
    }
}
