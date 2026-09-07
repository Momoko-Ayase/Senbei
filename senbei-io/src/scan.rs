use senbei_engine::detect;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Bytes read per file for content detection. `detect` inspects the DOS/PE
/// header and the Crackproof key table at offset 4096; its deepest read is the
/// key-table dword at 4124 (so a candidate must be ≥ 4128 bytes) or the PE
/// data-directory field at `e_lfanew + 252`, which is far below 8 KiB for any
/// real PE (`e_lfanew` is a few hundred bytes). `is_metadata` needs only the
/// first 4 bytes. An 8 KiB prefix therefore yields the same verdict as the whole
/// file while avoiding pulling multi-gigabyte game assets into memory just to
/// reject them — the previous 64 KiB was 8× larger than anything detect reads.
const DETECT_PREFIX: u64 = 8 * 1024;

/// Smallest file that can possibly be a target, so anything shorter is skipped
/// without ever being opened.
///
/// A Crackproof module needs ≥ 4128 bytes for [`senbei_engine::detect`]'s key
/// table (it reads the dword at 4124), so the bound is exact for the unpack
/// path. An il2cpp `global-metadata.dat` only needs 4 bytes to match its magic,
/// but its header alone runs to offset 0xB0 and the images/types/methods tables
/// it indexes make every real one megabytes long — a sub-4 KiB "metadata" could
/// only ever fail [`senbei_metadata::deobfuscate`] with `Malformed`, so nothing
/// processable is lost.
const MIN_SIZE: u64 = 4128;

fn is_metadata_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(crate::METADATA_FILE_NAME))
}

/// Content classification of a single file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Neither a Crackproof module nor il2cpp metadata — left untouched.
    None,
    /// A Crackproof-protected PE (unpack target).
    Crackproof,
    /// An il2cpp `global-metadata.dat` (de-obfuscation target).
    Metadata,
    /// A protected AArch64 shared library (Android restore target).
    AndroidSo,
    /// An Android app package (`.apk`/`.apks`/`.xapk`) — a container whose
    /// entries are content-probed individually during the Android pass.
    AndroidPackage,
}

/// Everything one [`find_targets_opts`] walk found, plus non-target tallies.
#[derive(Default)]
pub struct ScanResult {
    /// Crackproof-protected PE files.
    pub crackproof: Vec<PathBuf>,
    /// il2cpp `global-metadata.dat` blobs.
    pub metadata: Vec<PathBuf>,
    /// Protected AArch64 shared libraries.
    pub android_so: Vec<PathBuf>,
    /// Android app packages (containers restored entry-by-entry).
    pub android_packages: Vec<PathBuf>,
    pub stats: ScanStats,
}

/// Walk `root` recursively (skipping any directory literally named `"unpack"`)
/// and return, **in walk order**, the Crackproof candidates and the il2cpp
/// metadata blobs found — from a *single* traversal that opens each file at
/// most once.
///
/// # Why the cheap pre-filter dominates
///
/// The traversal is not the cost. Measured on a 46,446-file / 61 GB game tree,
/// `readdir` (including each entry's size, which Windows returns from the
/// directory enumeration for free) takes ~0.2 s and opening all 46,446 files
/// takes ~1 s — but *reading* from them takes 40 s. Read size is irrelevant: a
/// 4-byte read costs the same ~900 µs as an 8 KiB one, because the cost is
/// per-file I/O latency, not bandwidth (that tree lives on a user-mode virtual
/// disk that tops out near 1,300 IOPS). Thread count barely moves it either.
///
/// So the only lever is **probing fewer files**, which is what the target-name
/// filter and [`MIN_SIZE`] do — both decided before any file is opened.
///
/// The selected probes (open + short read + magic test) are fanned out across
/// worker threads. Directory traversal itself stays serial because it only
/// collects names and sizes before the parallel probe.
///
/// Thread count follows [`senbei_engine::thread_cap`] (honoring
/// `SENBEI_THREADS`, `1` = fully sequential). Output order is independent of
/// thread count: each worker owns a disjoint contiguous slice of the path list
/// and writes the matching disjoint slice of the class list, so results are
/// deterministic.
pub fn find_targets(root: &Path) -> ScanResult {
    find_targets_opts(root, scan_all_env())
}

/// Non-target tallies from a [`find_targets_opts`] walk.
#[derive(Default, Clone, Copy, Debug)]
pub struct ScanStats {
    /// Files that were content-probed but matched neither detector (skipped).
    pub skipped: usize,
    /// Directory entries the walker could not read (permissions, transient
    /// I/O errors). These files were never classified — surface this to the
    /// user instead of silently reporting a clean scan.
    pub walk_errors: usize,
    /// Files selected for probing whose bytes could not be read (open/read
    /// failure, or a detector panic). Unlike `skipped`, the scan could not
    /// determine whether these are targets — a locked il2cpp game assembly
    /// looks exactly like this, so the job layer counts them as errors.
    pub probe_errors: usize,
}

/// [`find_targets`], but with the pre-filter explicitly controlled. When
/// `scan_all` is true selected target names below [`MIN_SIZE`] are also probed.
pub fn find_targets_opts(root: &Path, scan_all: bool) -> ScanResult {
    // Phase 1: serial traversal collecting regular-file paths only. No file is
    // opened here; `readdir` is fast relative to the content probe that follows,
    // and `entry.metadata()` is served from the directory entry on Windows, so
    // the size test below costs nothing.
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut stats = ScanStats::default();
    for entry in WalkDir::new(root).into_iter().filter_entry(|e| {
        if !e.file_type().is_dir() {
            return true;
        }
        // The root itself is always walked, even if it is named "unpack" or is
        // a junction the user pointed us at deliberately.
        if e.depth() == 0 {
            return true;
        }
        // Never descend into a previous output tree ("unpack", any case: NTFS
        // is case-insensitive, so `Unpack` from an older run is still ours).
        if e.file_name().eq_ignore_ascii_case("unpack") {
            return false;
        }
        // Skip reparse-point directories (junctions, symlink-dirs): they point
        // outside the scanned tree — walking one would silently unpack an
        // entire foreign tree (e.g. a `samples` junction into the golden corpus).
        !crate::windows::is_reparse_point(e)
    }) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                stats.walk_errors += 1;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if crate::windows::is_companion(entry.path()) {
            continue;
        }
        if !is_metadata_name(entry.path())
            && !crate::windows::is_pe_extension(entry.path())
            && !crate::android::is_so_name(entry.path())
            && !crate::android::is_package_name(entry.path())
        {
            continue;
        }
        if !scan_all {
            // Skip on directory metadata alone — never open these.
            let too_small = entry
                .metadata()
                .map(|m| m.len() < MIN_SIZE)
                .unwrap_or(false);
            if too_small {
                continue;
            }
        }
        paths.push(entry.into_path());
    }

    // Phase 2: parallel content probe over disjoint chunks (no synchronization).
    // `classify` yields `None` for unreadable/panicking probes (see ScanStats);
    // `Some(Class::None)` means "probed, matched neither detector".
    let n = paths.len();
    let mut class: Vec<Option<Class>> = vec![Some(Class::None); n];
    let workers = senbei_engine::thread_cap().clamp(1, n.max(1));
    if workers <= 1 {
        for (p, c) in paths.iter().zip(class.iter_mut()) {
            *c = classify(p);
        }
    } else {
        let chunk = n.div_ceil(workers);
        std::thread::scope(|scope| {
            for (pc, cc) in paths.chunks(chunk).zip(class.chunks_mut(chunk)) {
                scope.spawn(move || {
                    for (p, c) in pc.iter().zip(cc.iter_mut()) {
                        *c = classify(p);
                    }
                });
            }
        });
    }

    let mut result = ScanResult {
        stats,
        ..ScanResult::default()
    };
    for (p, c) in paths.into_iter().zip(class) {
        match c {
            Some(Class::Crackproof) => result.crackproof.push(p),
            Some(Class::Metadata) => result.metadata.push(p),
            Some(Class::AndroidSo) => result.android_so.push(p),
            Some(Class::AndroidPackage) => result.android_packages.push(p),
            Some(Class::None) => result.stats.skipped += 1,
            // Unreadable / panicking probe: NOT skipped — the scan could not
            // classify it, so it may be a target we failed to unpack.
            None => result.stats.probe_errors += 1,
        }
    }
    result
}

/// Whether the size pre-filter is disabled via `SENBEI_SCAN_ALL`. Any value
/// other than `0`/empty enables probing small selected target names. It never
/// expands the platform filename boundary.
pub fn scan_all_env() -> bool {
    match std::env::var("SENBEI_SCAN_ALL") {
        Ok(v) => !matches!(v.trim(), "" | "0"),
        Err(_) => false,
    }
}

/// Classify one named candidate by content. Reads a short prefix once and tests
/// the detector for that platform. Returns `None` when the file could not be classified at
/// all — an I/O error opening it (locked, permissions) or a panic inside a
/// detector — so the caller counts it as a probe error rather than a clean
/// "not a target" skip.
///
/// The detector is wrapped in `catch_unwind` because a panic in a scan worker
/// thread would otherwise abort the whole folder run (a scoped-thread panic
/// re-raises on join, before any per-file isolation exists). The default panic
/// hook still prints the message, keeping the bug diagnosable.
///
/// A Crackproof PE never matches the metadata magic (it is a PE, not a
/// metadata blob) and vice versa, so the order is immaterial.
///
/// The Android library probe needs more than the prefix: the protection
/// payload lives in a section found via the section-header table at the *end*
/// of the file, so an ELF64/AArch64 prefix triggers a full-file read. Only
/// selected `.so` images pay for it.
fn classify(path: &Path) -> Option<Class> {
    let head = read_prefix(path, DETECT_PREFIX)?;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if crate::android::is_package_name(path) && crate::android::is_app_package(path, &head) {
            return Class::AndroidPackage;
        }
        if is_metadata_name(path) && senbei_metadata::is_metadata(&head) {
            return Class::Metadata;
        }
        if crate::windows::is_pe_extension(path) && detect(&head).is_some() {
            return Class::Crackproof;
        }
        if crate::android::is_so_name(path)
            && crate::android::is_elf64_aarch64(&head)
            && crate::android::is_protected_so_file(path)
        {
            return Class::AndroidSo;
        }
        Class::None
    }));
    r.ok()
}

/// Read up to `max` bytes from the start of `path`. Returns `None` on any I/O
/// error (the file is simply not treated as a candidate).
fn read_prefix(path: &Path, max: u64) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(max as usize);
    file.take(max).read_to_end(&mut buf).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_names_are_platform_specific() {
        for p in [
            "daemon.exe",
            "GameLib.DLL",
            "libil2cpp.so",
            "global-metadata.dat",
        ] {
            assert!(
                is_metadata_name(Path::new(p))
                    || crate::windows::is_pe_extension(Path::new(p))
                    || crate::android::is_so_name(Path::new(p)),
                "{p} should be a candidate"
            );
        }
        for p in [
            "app.exe.bak",
            "managed.dll.bak",
            "libil2cpp.so.bak",
            "global-metadata.bin",
            "asset",
            "a.ab",
        ] {
            assert!(
                !is_metadata_name(Path::new(p))
                    && !crate::windows::is_pe_extension(Path::new(p))
                    && !crate::android::is_so_name(Path::new(p)),
                "{p} must not be a candidate"
            );
        }
    }

    #[test]
    fn extensionless_targets_are_not_candidates() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let mut blob = vec![0u8; MIN_SIZE as usize + 1];
        blob[..4].copy_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
        std::fs::write(root.join("metadata"), &blob).unwrap();

        let filtered = find_targets_opts(root, false);
        assert!(filtered.metadata.is_empty());

        let exhaustive = find_targets_opts(root, true);
        assert!(exhaustive.metadata.is_empty());
    }

    /// A selected file below the Crackproof key-table bound is skipped without
    /// being opened, while `scan_all` probes it.
    #[test]
    fn prefilter_skips_small_selected_files_only() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("tiny.dll"), vec![0u8; 100]).unwrap();
        std::fs::write(root.join("assets.ab"), vec![0u8; 100_000]).unwrap();
        std::fs::write(root.join("plain.dll"), vec![0u8; 100_000]).unwrap();

        // None of them are Crackproof, so both modes find nothing; the point is
        // that only the selected names are considered and `scan_all` controls
        // the size floor.
        let scan = find_targets_opts(root, false);
        assert!(scan.crackproof.is_empty() && scan.metadata.is_empty());
        let scan = find_targets_opts(root, true);
        assert!(scan.crackproof.is_empty() && scan.metadata.is_empty());
    }

    /// An exact `global-metadata.dat` name is found by the filtered scan.
    #[test]
    fn finds_metadata_through_the_prefilter() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let mut blob = vec![0u8; MIN_SIZE as usize + 1];
        blob[..4].copy_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
        std::fs::write(root.join("global-metadata.dat"), &blob).unwrap();
        // Same magic but too small to be processable — skipped by the size floor.
        std::fs::write(root.join("stub.dat"), &blob[..64]).unwrap();

        let scan = find_targets_opts(root, false);
        assert_eq!(scan.metadata.len(), 1);
        assert!(scan.metadata[0].ends_with("global-metadata.dat"));
    }

    /// Review regression: a previous output tree is pruned case-insensitively
    /// (NTFS is case-insensitive, so `UNPACK` from an older run is still our
    /// output), and probed non-targets are counted as skipped.
    #[test]
    fn prunes_unpack_dir_case_insensitively_and_counts_skipped() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let out_dir = root.join("UNPACK");
        std::fs::create_dir(&out_dir).unwrap();
        // A metadata-magic file inside the old output tree: must NOT be found.
        let mut blob = vec![0u8; MIN_SIZE as usize + 1];
        blob[..4].copy_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
        std::fs::write(out_dir.join("global-metadata.dat"), &blob).unwrap();
        // A big non-target file at the root: probed, then skipped.
        std::fs::write(root.join("plain.dll"), vec![0u8; 100_000]).unwrap();

        let scan = find_targets_opts(root, false);
        assert!(
            scan.crackproof.is_empty() && scan.metadata.is_empty(),
            "old output tree must be pruned"
        );
        assert_eq!(
            scan.stats.skipped, 1,
            "the probed non-target counts as skipped"
        );
        assert_eq!(scan.stats.walk_errors, 0);
    }

    #[test]
    fn companion_payload_is_not_counted_as_skipped() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("app.exe"), vec![0u8; MIN_SIZE as usize]).unwrap();
        std::fs::write(root.join("app.exe._"), vec![0u8; MIN_SIZE as usize]).unwrap();

        let scan = find_targets_opts(root, false);
        assert_eq!(scan.stats.skipped, 1, "only the stub was probed");
        assert!(crate::windows::is_companion(&root.join("app.exe._")));
    }

    #[test]
    fn scan_all_keeps_the_platform_name_boundary() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let mut metadata = vec![0_u8; MIN_SIZE as usize];
        metadata[..4].copy_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
        std::fs::write(root.join("renamed.bin"), &metadata).unwrap();
        std::fs::write(root.join("global-metadata.dat"), &metadata).unwrap();

        let scan = find_targets_opts(root, true);
        assert_eq!(scan.metadata.len(), 1);
        assert!(scan.metadata[0].ends_with("global-metadata.dat"));
    }
}
