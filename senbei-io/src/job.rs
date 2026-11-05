use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::atomic::write_atomic;
pub use crate::report::{Collector, Mode, REPORT_FORMAT_VERSION, Report};
use crate::report::{
    CompanionReport, CompanionState, ContainerReport, EntryKind, EntryReport, EntryStatus,
    InputReport, InputStatus, OutputFile, Role, Stage, StageReport, StageStatus,
};
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
    /// The summary line shared by CLI output and the log file.
    pub fn line(&self) -> String {
        let mut line = format!(
            "{} unpacked · {} skipped · {} errors · {} suspect · {} metadata",
            self.unpacked, self.skipped, self.errors, self.suspect, self.metadata
        );
        if self.packages > 0 {
            line.push_str(&format!(" · {} packages", self.packages));
        }
        line
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

/// Unpack all Crackproof-protected files under `root`, writing results into
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
pub fn error_report(mode: Mode, message: &str) -> Report {
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
    // Single merged directory walk: returns Crackproof unpack candidates, il2cpp
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
        eprintln!(
            "warning: {} file(s) could not be read during the scan and may be missed targets",
            scan_failed
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
    let verbose_steps = verbose && quiet == 0;
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
    if let Some(reporter) = reporter.as_deref_mut() {
        reporter.set_scan(crate::report::ScanReport {
            non_target_skipped: scan_stats.skipped,
            walk_errors: scan_stats.walk_errors,
            probe_errors: scan_stats.probe_errors,
        });
    }

    for input in candidates {
        let rel = rel_in_tree(root, input);
        let dest = out_root.join(out_name(&rel));
        let started = Instant::now();

        // Wrap in catch_unwind so a single bad file never aborts the folder run.
        // A reporting run goes through the profiled entry point so the report
        // carries the route the pipeline actually selected; an ordinary run
        // keeps the unchanged call.
        let profiled = reporter.is_some();
        let input_owned = input.clone();
        let dest_owned = dest.clone();
        let result = senbei_engine::catch_unwind_quiet(|| {
            if profiled {
                let (profile, result) =
                    unpack_one_profiled(&input_owned, &dest_owned, verbose_steps);
                (Some(profile), result)
            } else {
                (None, unpack_one_v(&input_owned, &dest_owned, verbose_steps))
            }
        });

        match result {
            Ok((profile, Ok((kind, report)))) => {
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
                    reporter.push(windows_input(input, &dest, kind, &report, profile, started));
                }
            }
            Ok((profile, Err(e))) => {
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(match profile {
                        Some(profile) => failed_input_with_profile(input, &e, profile, started),
                        None => failed_input(input, &e, started),
                    });
                }
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::anyhow!("unexpected panic: {}", panic_payload(&panic));
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
    let mut android_cache = crate::android::run_cache_with_limits(limits);
    let loose = crate::android::loose_scopes(&scan.android_so, metas);
    for scoped in loose.iter().filter(|scoped| {
        scan.android_so
            .iter()
            .any(|library| library == &scoped.path)
    }) {
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
        match result {
            Ok(Ok(outcome)) => match outcome.status {
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
                                eprintln!("- {}  {}", rel.display(), message);
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
                crate::android::EntryStatus::NotTarget | crate::android::EntryStatus::Unchanged => {
                    s.skipped += 1;
                    report_outcome = Some(InputStatus::Skipped);
                }
            },
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
                let e = anyhow::anyhow!("unexpected panic: {}", panic_payload(&panic));
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
            apply_android_validation(&mut reported, report_validation.as_ref());
            reporter.push(reported);
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
        if group.len() > 1 {
            s.packages += group.len();
            let group_owned = group.clone();
            let root_owned = root.to_path_buf();
            let out_root_owned = out_root.clone();
            let group_started = Instant::now();
            let result = senbei_engine::catch_unwind_quiet(|| {
                crate::android::restore_apk_group(
                    &group_owned,
                    &root_owned,
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
                            reporter.push(package_input(package, entries, group_started));
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
                }
                Err(panic) => {
                    let e = anyhow::anyhow!("unexpected panic: {}", panic_payload(&panic));
                    s.errors += 1;
                    crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                    if let Some(log) = &log {
                        log.step(&format!(
                            "ERR {rel:?}: panic during package restore: {}",
                            panic_payload(&panic)
                        ));
                    }
                }
            }
            bar.inc(group.len() as u64);
            continue;
        }
        for package in group {
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
                        reporter.push(package_input(package, outcomes.iter().collect(), started));
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
                    let e = anyhow::anyhow!("unexpected panic: {}", panic_payload(&panic));
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
                    reporter.push(metadata_input(&scoped.path, &report, Some(&dest), started));
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
                    reporter.push(metadata_input(&scoped.path, &report, None, started));
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
                            "- {}  unsupported metadata version {v}, left untouched",
                            rel.display()
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
                    let mut input = failed_input(&scoped.path, &e, started);
                    let identity = identity_of(&scoped.path);
                    input.metadata = identity;
                    input.metadata_version =
                        unsupported.or_else(|| identity.map(|identity| identity.raw_version));
                    if let Some(version) = unsupported {
                        // Left untouched by design; not a failure of this run.
                        input.status = InputStatus::Skipped;
                        input.errors.clear();
                        input.profile = Some(crate::report::metadata_unchanged_profile(identity));
                        input.warning(format!(
                            "unsupported metadata version {version}, left untouched"
                        ));
                    } else {
                        input.profile = Some(crate::report::metadata_failed_profile(
                            identity,
                            senbei_engine::LayoutKind::MetadataStructural,
                            &format!("{e:#}"),
                        ));
                    }
                    reporter.push(input);
                }
            }
            Err(panic) => {
                s.errors += 1;
                let e = anyhow::anyhow!(
                    "unexpected panic during de-obfuscation: {}",
                    panic_payload(&panic)
                );
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
        match deobfuscate_metadata_to_with_module(input, &dest, verbose && quiet == 0, None) {
            Ok((report, layout)) if report.remapped > 0 => {
                s.metadata = 1;
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {:?} -> {:?}: v{} remapped {} method fields",
                        input, dest, report.version, report.remapped
                    ));
                }
                if quiet == 0 {
                    println!(
                        "✓ metadata v{} -> {:?} ({} method fields remapped)",
                        report.version, dest, report.remapped
                    );
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(single_metadata_input(
                        input,
                        &report,
                        layout,
                        Some(&dest),
                        t0,
                    ));
                }
            }
            Ok((report, layout)) => {
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {:?}: v{} already de-obfuscated",
                        input, report.version
                    ));
                }
                if quiet == 0 {
                    println!(
                        "metadata v{}: already de-obfuscated, nothing to do",
                        report.version
                    );
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(single_metadata_input(input, &report, layout, None, t0));
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("META ERR {:?}: {e:#}", input));
                }
                // Level 1 quiet: banner/summary/duration only (match folder mode).
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut input_report = failed_input(input, &e, t0);
                    let identity = identity_of(input);
                    input_report.metadata = identity;
                    input_report.metadata_version = identity.map(|identity| identity.raw_version);
                    input_report.profile = Some(crate::report::metadata_failed_profile(
                        identity,
                        senbei_engine::LayoutKind::MetadataStructural,
                        &format!("{e:#}"),
                    ));
                    reporter.push(input_report);
                }
            }
        }
    } else if is_android_so {
        match crate::android::restore_so_file_with_diagnostics(
            input,
            &dest,
            verbose && quiet == 0,
            limits,
        ) {
            Ok((embedded, validation)) => {
                s.unpacked = 1;
                if let Some(log) = &log {
                    log.step(&format!("OK {:?} -> {:?} (Android SO)", input, dest));
                }
                if quiet == 0 {
                    println!("✓ So  {}  ->  {}", input.display(), dest.display());
                }
                match write_embedded_metadata(embedded, &dest) {
                    Ok(Some(meta_dest)) => {
                        s.metadata += 1;
                        if let Some(log) = &log {
                            log.step(&format!("META {:?} (embedded) -> {:?}", input, meta_dest));
                        }
                        if quiet == 0 {
                            println!(
                                "✓ metadata  {} (embedded)  ->  {}",
                                input.display(),
                                meta_dest.display()
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
                            eprintln!("error: embedded metadata: {e:#}");
                        }
                    }
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    let mut reported = android_library_input(input, InputStatus::Ok, &dest, t0);
                    apply_android_validation(&mut reported, validation.as_ref());
                    reporter.push(reported);
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(android_library_input(input, InputStatus::Error, &dest, t0));
                }
            }
        }
    } else if is_android_package {
        s.packages = 1;
        let rel = PathBuf::from(input.file_name().unwrap_or_default());
        let mut seen = std::collections::HashSet::new();
        match crate::android::restore_package_with_limits(
            input,
            &rel,
            &out_root,
            &mut seen,
            verbose && quiet == 0,
            limits,
        ) {
            Ok(outcomes) => {
                let bar = crate::ui::progress(0, true);
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(package_input(input, outcomes.iter().collect(), t0));
                }
                apply_package_outcomes(outcomes, &mut s, &bar, quiet >= 1, &log);
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
                if let Some(reporter) = reporter {
                    reporter.push(failed_input(input, &e, t0));
                }
            }
        }
    } else {
        // A reporting run uses the profiled entry point so the report carries
        // the route that was actually selected; the unprofiled call is
        // unchanged for every other run.
        let profiled = if reporter.is_some() {
            Some(unpack_one_profiled(input, &dest, verbose && quiet == 0))
        } else {
            None
        };
        let (profile, result) = match profiled {
            Some((profile, result)) => (Some(profile), result),
            None => (None, unpack_one_v(input, &dest, verbose && quiet == 0)),
        };
        match result {
            Ok((kind, report)) => {
                s.unpacked = 1;
                if let Some(log) = &log {
                    log.step(&format!("OK {:?} -> {:?} ({kind:?})", input, dest));
                }
                if quiet == 0 {
                    println!("✓ {:?} -> {:?}", kind, dest);
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
                        eprintln!(
                            "! integrity check failed (likely to crash at runtime): {}",
                            report.issues.join("; ")
                        );
                    }
                }
                if let Some(reporter) = reporter.as_deref_mut() {
                    reporter.push(windows_input(input, &dest, kind, &report, profile, t0));
                }
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
                if let Some(reporter) = reporter {
                    reporter.push(match profile {
                        Some(profile) => failed_input_with_profile(input, &e, profile, t0),
                        None => failed_input(input, &e, t0),
                    });
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
/// Crackproof's `-GMD` option scrambles each `Il2CppMethodDefinition`'s token
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
    let data = std::fs::read(input)?;
    // The Android seeded-permutation variant is tried first (it validates
    // every restored RID); the structural remap is the fallback and the
    // Windows path. The [`senbei_metadata::Error`] is preserved in the chain
    // (rather than stringified) so the folder driver can apply its
    // unsupported-version policy.
    let (out, report, layout) =
        crate::android::restore_metadata_bytes_with_module(&data, method_index_module)
            .map_err(|e| e.context(format!("{input:?}")))?;
    if report.remapped > 0 {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_atomic(dest, &out)?;
        if verbose {
            println!("Write to {}", dest.display());
        }
    }
    Ok((report, layout))
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

/// Inspect `path` without recovering or writing anything.
///
/// Reads only what detection needs: a short prefix per file, the protected
/// library probe for selected `.so` files, package manifests and central
/// directories, and the 8-byte il2cpp metadata header. No output, no log, and
/// no temporary file outside what a package inventory needs to read a nested
/// manifest. The report never claims recovery or a static-validation verdict.
pub fn inspect_path(
    path: &Path,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
) -> anyhow::Result<Report> {
    let mut collector = Collector::new(Mode::Inspect);
    if path.is_dir() {
        inspect_folder(path, scan_all, limits, &mut collector);
    } else {
        let started = Instant::now();
        match inspect_file(path, limits) {
            Ok(input) => collector.push(input),
            Err(error) => collector.push(inspect_failed_input(path, &error, started)),
        }
    }
    Ok(collector.finish())
}

fn inspect_folder(
    root: &Path,
    scan_all: bool,
    limits: &senbei_engine::android::ResourceLimits,
    collector: &mut Collector,
) {
    let scan = crate::scan::find_targets_with_limits(root, scan_all, limits);
    collector.set_scan(crate::report::ScanReport {
        non_target_skipped: scan.stats.skipped,
        walk_errors: scan.stats.walk_errors,
        probe_errors: scan.stats.probe_errors,
    });
    let mut inputs: Vec<&PathBuf> = Vec::new();
    inputs.extend(scan.crackproof.iter());
    inputs.extend(scan.metadata.iter());
    inputs.extend(scan.android_so.iter());
    inputs.extend(scan.android_packages.iter());
    for path in inputs {
        let started = Instant::now();
        match inspect_file(path, limits) {
            Ok(input) => collector.push(input),
            Err(error) => collector.push(inspect_failed_input(path, &error, started)),
        }
    }
}

/// Inspect one file, choosing the report from its content.
fn inspect_file(
    input: &Path,
    limits: &senbei_engine::android::ResourceLimits,
) -> anyhow::Result<InputReport> {
    let started = Instant::now();
    let prefix = read_prefix(input)?;
    if senbei_metadata::is_metadata(&prefix) {
        return Ok(inspect_metadata(input, &prefix, started));
    }
    if crate::android::is_app_package(input, &prefix) {
        return inspect_app_package(input, limits, started);
    }
    if crate::android::is_elf64_aarch64(&prefix) {
        return inspect_android_library(input, limits, started);
    }
    inspect_windows(input, started)
}

fn read_prefix(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0_u8; 8 * 1024];
    let read = file.read(&mut buffer)?;
    buffer.truncate(read);
    Ok(buffer)
}

/// Inspect a Windows input without recovering it.
///
/// The stub and its optional `._` sibling are read separately and independently:
/// inspection reports the pairing it observed and never turns a missing or
/// non-pairing sibling into a recovery failure. That matters because the file
/// entry point *does* refuse a companion-declaring stub without its payload —
/// correct for recovery, wrong for a description of what is on disk.
fn inspect_windows(input: &Path, started: Instant) -> anyhow::Result<InputReport> {
    // The stub's own bytes must be readable for inspection to say anything.
    // Failure here is a genuine read error and fails inspection.
    let stub = std::fs::read(input)?;
    let (companion, state) = if crate::windows::is_pe_extension(input) {
        match read_optional_companion(input) {
            // A sibling pairs only when its header matches this stub's payload
            // region; `splice_companion` is that exact test.
            Ok(Some(payload)) => {
                if crate::windows::splice_companion(&stub, &payload).is_some() {
                    (Some(payload), CompanionState::Spliced)
                } else {
                    // A sibling exists but is not this stub's payload.
                    (Some(payload), CompanionState::Unmatched)
                }
            }
            Ok(None) => (None, CompanionState::Absent),
            // A sibling exists but cannot be read. Inspection still describes
            // the stub; the unreadable sibling is reported, not raised.
            Err(_) => (None, CompanionState::Unreadable),
        }
    } else {
        (None, CompanionState::Absent)
    };

    // Inspect the bytes recovery would actually unpack: the spliced payload
    // when the pairing is real, otherwise the file as it sits on disk.
    let spliced_pair = match (state, companion.as_deref()) {
        (CompanionState::Spliced, Some(payload)) => {
            crate::windows::splice_companion(&stub, payload)
        }
        _ => None,
    };
    let inspected: &[u8] = spliced_pair.as_deref().unwrap_or(&stub);

    let mut profile = senbei_engine::inspect_profile(inspected);
    if spliced_pair.is_some() {
        // Evidence of a pairing that was actually performed, not of one that
        // was merely expected.
        profile.record_companion_spliced();
    }
    let mut report = InputReport::new(input, Role::Content);
    report.status = match profile.recognition {
        senbei_engine::RecognitionStatus::Recognized => InputStatus::Recognized,
        _ => InputStatus::Skipped,
    };
    report.companion =
        crate::windows::is_pe_extension(input).then(|| companion_report(input, state));
    // A sibling that does not pair, or cannot be read, describes the input —
    // neither is a failure of the inspection.
    if let Some(companion) = report.companion.as_mut() {
        match companion.state {
            CompanionState::Unmatched => {
                companion.detail =
                    Some("a sibling `._` exists but is not this stub's payload".to_owned());
            }
            CompanionState::Unreadable => {
                companion.detail = Some("the sibling `._` could not be read".to_owned());
            }
            _ => {}
        }
    }
    report.profile = Some(profile);
    report.stages = vec![
        StageReport::new(Stage::Detection, StageStatus::Ok).timed(crate::report::now_ms(started)),
        StageReport::new(Stage::Recovery, StageStatus::Skipped)
            .detail("inspection only: no recovery was run"),
    ];
    report.duration_ms = crate::report::now_ms(started);
    Ok(report)
}

/// Companion state for a run that only knows whether a payload was spliced.
///
/// `Spliced` means the pairing actually happened; otherwise any sibling on disk
/// was not this stub's payload.
fn observed_companion_state(input: &Path, spliced: bool) -> CompanionState {
    if spliced {
        return CompanionState::Spliced;
    }
    match sibling_path(input) {
        Some(path) if path.is_file() => CompanionState::Unmatched,
        _ => CompanionState::Absent,
    }
}

/// `<input>._`, the companion payload path for `input`.
fn sibling_path(input: &Path) -> Option<PathBuf> {
    let name = input.file_name()?;
    let mut sibling = name.to_os_string();
    sibling.push("._");
    Some(input.with_file_name(sibling))
}

/// What the `._` companion relationship is for `input`, observed on disk.
fn companion_report(input: &Path, state: CompanionState) -> CompanionReport {
    let path = sibling_path(input);
    CompanionReport {
        state,
        path: match state {
            CompanionState::Absent => None,
            _ => path.map(|path| path.display().to_string()),
        },
        detail: None,
    }
}

fn inspect_metadata(input: &Path, prefix: &[u8], started: Instant) -> InputReport {
    let mut report = InputReport::new(input, Role::Content);
    let identity = senbei_metadata::identify(prefix);
    report.metadata = identity;
    report.metadata_version = identity.map(|identity| identity.raw_version);
    // Header identification is a layout/capability fact, not a protection or
    // recovery verdict.
    report.status = InputStatus::Skipped;
    report.profile = Some(crate::report::metadata_unchanged_profile(identity));
    report.stages = vec![
        StageReport::new(Stage::Detection, StageStatus::Ok).timed(crate::report::now_ms(started)),
        StageReport::new(Stage::Recovery, StageStatus::Skipped)
            .detail("inspection only: no transform was run"),
    ];
    report.duration_ms = crate::report::now_ms(started);
    report
}

fn inspect_android_library(
    input: &Path,
    limits: &senbei_engine::android::ResourceLimits,
    started: Instant,
) -> anyhow::Result<InputReport> {
    let (profile, result) = crate::android::probe_so_profiled(input, limits)?;
    let mut report = InputReport::new(input, Role::Content);
    report.status = match (&profile.recognition, &result) {
        (senbei_engine::RecognitionStatus::Recognized, _) => InputStatus::Recognized,
        _ => InputStatus::Skipped,
    };
    if let Err(error) = &result {
        report.error(format!("{error:#}"));
        report.status = InputStatus::Error;
    }
    report.profile = Some(profile);
    report.stages = vec![
        StageReport::new(Stage::Detection, StageStatus::Ok).timed(crate::report::now_ms(started)),
        StageReport::new(Stage::Recovery, StageStatus::Skipped)
            .detail("inspection only: no restore was run"),
    ];
    report.duration_ms = crate::report::now_ms(started);
    Ok(report)
}

fn inspect_app_package(
    input: &Path,
    limits: &senbei_engine::android::ResourceLimits,
    started: Instant,
) -> anyhow::Result<InputReport> {
    let mut report = InputReport::new(input, Role::Container);
    let container = crate::android::inspect_package(input, limits)?;
    report.status = InputStatus::Skipped;
    report.container = Some(container);
    report.stages = vec![
        StageReport::new(Stage::ManifestInventory, StageStatus::Ok)
            .timed(crate::report::now_ms(started)),
        StageReport::new(Stage::EntryProbe, StageStatus::Skipped)
            .detail("inspection only: container entries were listed, not probed"),
    ];
    report.duration_ms = crate::report::now_ms(started);
    Ok(report)
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
    // Read the stub and its `._` sibling exactly as the file entry point does.
    let (stub, companion) = match read_stub_and_companion(input) {
        Ok(pair) => pair,
        Err(error) => {
            let mut profile = observed_profile(input);
            profile.recovery = senbei_engine::RecoveryStatus::Blocked;
            profile.push_error(format!("{error:#}"));
            return (profile, Err(error));
        }
    };
    // The byte entry point owns the splice, companion overlays, and the check
    // over the image actually returned — the same steps as `unpack_one_v`.
    let (profile, recovered) =
        crate::windows::unpack_bytes_profiled_v(&stub, companion.as_deref(), verbose);
    let image = match recovered {
        Ok(image) => image,
        // The profile already records which candidates ran and why they failed.
        Err(error) => return (profile, Err(error.into())),
    };
    if let Some(parent) = dest.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return (profile, Err(error.into()));
    }
    if let Err(error) = write_atomic(dest, &image.bytes) {
        return (profile, Err(error.into()));
    }
    if verbose {
        println!("Write to {}", dest.display());
    }
    (profile, Ok((image.kind, image.integrity)))
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
        companion_report(
            input,
            observed_companion_state(input, profile.observed.external_companion),
        )
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
    let detail = format!("{error:#}");
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
    let detail = format!("{error:#}");
    entry.error(detail.clone());
    entry.companion = crate::windows::is_pe_extension(input).then(|| {
        companion_report(
            input,
            observed_companion_state(input, profile.observed.external_companion),
        )
    });
    entry.profile = Some(profile);
    entry
        .stages
        .push(StageReport::new(Stage::Recovery, StageStatus::Failed).detail(detail));
    entry.duration_ms = crate::report::now_ms(started);
    entry
}

/// Input report for an input inspection could not read.
///
/// Inspection is detection only, so a read error must not be dressed up as a
/// failed recovery: no candidate is marked attempted, `recovery` stays
/// `not_attempted`, `static_validation` stays `not_run`, and no route is
/// selected. Whatever header evidence was obtainable is still reported.
fn inspect_failed_input(input: &Path, error: &anyhow::Error, started: Instant) -> InputReport {
    let mut entry = InputReport::new(input, Role::Content);
    entry.status = InputStatus::Error;
    let detail = format!("{error:#}");
    entry.error(detail.clone());
    let mut profile = observed_profile(input);
    profile.push_error(detail.clone());
    entry.profile = Some(profile);
    entry
        .stages
        .push(StageReport::new(Stage::Detection, StageStatus::Failed).detail(detail));
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
fn failure_profile(input: &Path, detail: &str) -> senbei_engine::ProtectionProfile {
    use senbei_engine::{AttemptOutcome, LayoutKind, ProtectionProfile, RecoveryStatus};
    let Ok(prefix) = read_prefix(input) else {
        let mut profile =
            ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, None));
        profile.recovery = RecoveryStatus::Failed;
        profile.push_error(detail.to_owned());
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
            Some(layout) => (layout, vec![detail.to_owned()]),
            None => (LayoutKind::ExeStyle, vec![detail.to_owned()]),
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
        profile.push_error(detail.to_owned());
        return profile;
    }
    if crate::android::is_elf64_aarch64(&prefix) {
        return crate::report::android_failed_profile(detail);
    }
    let mut profile = ProtectionProfile::new(senbei_engine::ObservedTarget::windows(None, None));
    profile.recovery = RecoveryStatus::Failed;
    profile.push_error(detail.to_owned());
    profile
}

/// Input report for a restored (or skipped) loose Android library.
fn android_library_input(
    input: &Path,
    status: InputStatus,
    dest: &Path,
    started: Instant,
) -> InputReport {
    let mut entry = InputReport::new(input, Role::Content);
    entry.status = status;
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
            let detail = entry.errors.first().cloned().unwrap_or_default();
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
    profile.warnings.extend(validation.messages.iter().cloned());
    report.warnings.extend(validation.messages.iter().cloned());
    // The stage itself succeeded — the restore validated the output. Findings
    // are carried as detail and warnings, not as a failed stage.
    let mut stage = StageReport::new(Stage::StaticValidation, StageStatus::Ok);
    if !validation.is_clean() {
        stage = stage.detail(validation.messages.join("; "));
    }
    report.stages.push(stage);
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
        // Identified, valid, and already canonical: nothing to restore.
        entry.status = InputStatus::Skipped;
        entry.profile = Some(crate::report::metadata_unchanged_profile(identity));
        entry
            .stages
            .push(StageReport::new(Stage::Recovery, StageStatus::Skipped));
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
    entry.profile = Some(if dest.is_some() {
        crate::report::metadata_recovered_profile(identity, layout)
    } else {
        crate::report::metadata_unchanged_profile(identity)
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

/// Input report for one app package, from the entries it produced.
fn package_input(
    package: &Path,
    outcomes: Vec<&crate::android::EntryOutcome>,
    started: Instant,
) -> InputReport {
    let mut entry = InputReport::new(package, Role::Container);
    entry.container = Some(ContainerReport {
        kind: package
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default(),
        // Inventory is only recorded by an explicit inspect run; a restore
        // reports what it actually produced.
        manifests: Vec::new(),
        entry_count: outcomes.len(),
        candidate_entries: outcomes
            .iter()
            .map(|outcome| outcome.label.clone())
            .collect(),
        nested_packages: Vec::new(),
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
        entry.warnings.extend(diagnostics.clone());
        entry.stages.push(
            StageReport::new(Stage::StaticValidation, StageStatus::Ok)
                .detail(diagnostics.join("; ")),
        );
    }
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
    if let SourceKind::Metadata { remapped } = outcome.kind {
        report.remapped = Some(remapped);
    }
    if status == EntryStatus::Restored {
        report.output = Some(OutputFile::from_path(&outcome.dest));
    }
    if let crate::android::EntryStatus::Failed(error) = &outcome.status {
        report.errors.push(format!("{error:#}"));
    }
    // The engine's advisory findings for this entry's own output. Only a
    // restored entry has an output they could describe.
    if status == EntryStatus::Restored
        && let Some(validation) = &outcome.validation
    {
        report.warnings.extend(validation.messages.iter().cloned());
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
