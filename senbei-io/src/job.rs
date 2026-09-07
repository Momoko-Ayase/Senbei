use std::path::{Path, PathBuf};

use crate::atomic::write_atomic;
pub use crate::windows::{
    UnpackedImage, unpack_bytes, unpack_bytes_force_exe, unpack_one, unpack_one_v,
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
    /// il2cpp `global-metadata.dat` files de-obfuscated (method tokens remapped),
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
    let scan = crate::scan::find_targets_opts(root, scan_all);
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

    // Silence the default panic hook's stderr spew during per-file processing.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // suppress "thread panicked" messages

    for input in candidates {
        let rel = rel_in_tree(root, input);
        let dest = out_root.join(out_name(&rel));

        // Wrap in catch_unwind so a single bad file never aborts the folder run.
        let input_owned = input.clone();
        let dest_owned = dest.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            unpack_one_v(&input_owned, &dest_owned, verbose_steps)
        }));

        match result {
            Ok(Ok((kind, report))) => {
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
            }
            Ok(Err(e)) => {
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
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
            }
        }
        bar.inc(1);
    }

    // Android pass: protected AArch64 libraries and app packages. Loose `.so`
    // files restore first so the cross-source dedup keeps them over a copy
    // inside a package (loose beats `.apk` beats `.apks`/`.xapk` bundle).
    let mut android_seen = std::collections::HashSet::new();
    // Hashing a protected library costs a full read, so only pay it when a
    // duplicate source can actually exist in this run.
    let android_dedup = scan.android_so.len() > 1 || !scan.android_packages.is_empty();
    for input in &scan.android_so {
        let rel = rel_in_tree(root, input);
        let dest = out_root.join(out_name(&rel));
        // Unreadable here is fine: the restore reports the same error.
        if android_dedup
            && let Ok(identity) = crate::android::file_content_identity(input)
            && !android_seen.insert(identity)
        {
            s.skipped += 1;
            if let Some(log) = &log {
                log.step(&format!("SKIP {rel:?}: duplicate of an earlier target"));
            }
            bar.inc(1);
            continue;
        }
        let input_owned = input.clone();
        let dest_owned = dest.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::android::restore_so_file(&input_owned, &dest_owned, verbose_steps)
        }));
        match result {
            Ok(Ok(embedded)) => {
                s.unpacked += 1;
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
                match write_embedded_metadata(embedded, &dest) {
                    Ok(Some(meta_dest)) => {
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
                    Ok(None) => {}
                    Err(e) => {
                        s.errors += 1;
                        crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                        if let Some(log) = &log {
                            log.step(&format!("ERR {rel:?}: embedded metadata: {e:#}"));
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
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
            }
        }
        bar.inc(1);
    }
    for package in &scan.android_packages {
        let rel = rel_in_tree(root, package);
        s.packages += 1;
        let package_owned = package.clone();
        let rel_owned = rel.clone().into_owned();
        let out_root_owned = out_root.clone();
        let mut seen_taken = std::mem::take(&mut android_seen);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let outcomes = crate::android::restore_package(
                &package_owned,
                &rel_owned,
                &out_root_owned,
                &mut seen_taken,
                verbose_steps,
            );
            (outcomes, seen_taken)
        }));
        match result {
            Ok((Ok(outcomes), seen_back)) => {
                android_seen = seen_back;
                apply_package_outcomes(outcomes, &mut s, &bar, suppress_file_lines, &log);
            }
            Ok((Err(e), seen_back)) => {
                android_seen = seen_back;
                s.errors += 1;
                crate::ui::err(&bar, suppress_file_lines, &rel, &e);
                if let Some(log) = &log {
                    log.step(&format!("ERR {rel:?}: {e:#}"));
                }
            }
            Err(panic) => {
                // The dedup set may be in an unknown state after a panic; a
                // re-scan costs a duplicate restore at worst, never corruption.
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
        bar.inc(1);
    }

    // il2cpp metadata pass. Crackproof's `-GMD` option obfuscates the method
    // tokens in `global-metadata.dat`; de-obfuscate any we find so the unpacked
    // il2cpp game assembly resolves methods instead of indexing its per-module
    // tables out of bounds (see [`senbei_metadata`]). This is additive to the
    // Crackproof module unpack above — the metadata blob is not itself a
    // Crackproof file.
    for meta in metas.iter() {
        let rel = rel_in_tree(root, meta);
        let dest = out_root.join(out_name(&rel));
        let meta_owned = meta.clone();
        let dest_owned = dest.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            deobfuscate_metadata_to(&meta_owned, &dest_owned, verbose_steps)
        }));
        match result {
            Ok(Ok(report)) if report.remapped > 0 => {
                s.metadata += 1;
                crate::ui::metadata(&bar, suppress_file_lines, &rel, report.remapped, &dest);
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {rel:?} -> {dest:?}: v{} remapped {} method tokens",
                        report.version, report.remapped
                    ));
                }
            }
            // Recognised metadata that needed no change (not -GMD-obfuscated):
            // leave it untouched and don't write a redundant copy.
            Ok(Ok(report)) => {
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {rel:?}: v{} already de-obfuscated",
                        report.version
                    ));
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
                if let Some(v) = unsupported_version(&e) {
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
            }
        }
    }

    // Restore the original panic hook.
    std::panic::set_hook(default_hook);

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
    let is_android_so =
        crate::android::is_elf64_aarch64(&prefix) && crate::android::is_protected_so_file(input);
    let is_android_package = !is_android_so && crate::android::is_app_package(input, &prefix);

    if is_meta {
        match deobfuscate_metadata_to(input, &dest, verbose && quiet == 0) {
            Ok(report) if report.remapped > 0 => {
                s.metadata = 1;
                if let Some(log) = &log {
                    log.step(&format!(
                        "META {:?} -> {:?}: v{} remapped {} method tokens",
                        input, dest, report.version, report.remapped
                    ));
                }
                if quiet == 0 {
                    println!(
                        "✓ metadata v{} -> {:?} ({} method tokens remapped)",
                        report.version, dest, report.remapped
                    );
                }
            }
            Ok(report) => {
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
            }
        }
    } else if is_android_so {
        match crate::android::restore_so_file(input, &dest, verbose && quiet == 0) {
            Ok(embedded) => {
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
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
                }
            }
        }
    } else if is_android_package {
        s.packages = 1;
        let rel = PathBuf::from(input.file_name().unwrap_or_default());
        let mut seen = std::collections::HashSet::new();
        match crate::android::restore_package(
            input,
            &rel,
            &out_root,
            &mut seen,
            verbose && quiet == 0,
        ) {
            Ok(outcomes) => {
                let bar = crate::ui::progress(0, true);
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
            }
        }
    } else {
        match unpack_one_v(input, &dest, verbose && quiet == 0) {
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
            }
            Err(e) => {
                s.errors = 1;
                if let Some(log) = &log {
                    log.step(&format!("ERR {:?}: {e:#}", input));
                }
                if quiet == 0 {
                    eprintln!("error: {e:#}");
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
    let data = std::fs::read(input)?;
    // The Android seeded-permutation variant is tried first (it validates
    // every restored RID); the structural remap is the fallback and the
    // Windows path. The [`senbei_metadata::Error`] is preserved in the chain
    // (rather than stringified) so the folder driver can apply its
    // unsupported-version policy.
    let (out, report) = crate::android::restore_metadata_bytes(&data)
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
    Ok(report)
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
                    log.step(&format!("OK {} -> {:?}", outcome.label, outcome.dest));
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
}
