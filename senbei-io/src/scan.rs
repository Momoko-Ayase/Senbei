use senbei_pe::detect;
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
/// A Crackproof module needs ≥ 4128 bytes for [`senbei_pe::detect`]'s key
/// table (it reads the dword at 4124), so the bound is exact for the unpack
/// path. An il2cpp `global-metadata.dat` only needs 4 bytes to match its magic,
/// but its header alone runs to offset 0xB0 and the images/types/methods tables
/// it indexes make every real one megabytes long — a sub-4 KiB "metadata" could
/// only ever fail [`senbei_metadata::deobfuscate`] with `Malformed`, so nothing
/// processable is lost.
const MIN_SIZE: u64 = 4128;

/// File extensions that are bulk data by construction and can never be a PE
/// image or an il2cpp metadata blob.
///
/// This is deliberately a **deny**-list, not an allow-list: the default is to
/// probe, so anything unrecognised is still opened. Targets are recognised by
/// content, not extension, and can carry arbitrary names — there is no closed
/// set of target extensions an allow-list of `exe`/`dll` could enumerate.
/// Only extensions that are bulk asset or text formats by construction appear
/// here.
///
/// Set `SENBEI_SCAN_ALL=1` (or pass `--scan-all`) to probe every file regardless.
const DENY_EXT: &[&str] = &[
    // Unity and other engine asset containers
    "ab",
    "bundle",
    "unity3d",
    "manifest",
    "resource",
    "ress",
    "assets",
    "sharedassets",
    // audio / video / image / font
    "acb",
    "awb",
    "usm",
    "wav",
    "ogg",
    "mp3",
    "mp4",
    "avi",
    "png",
    "jpg",
    "jpeg",
    "bmp",
    "gif",
    "tga",
    "dds",
    "svg",
    "ttf",
    "otf",
    // text, markup, config, logs
    "xml",
    "json",
    "txt",
    "csv",
    "md",
    "toml",
    "ini",
    "yml",
    "yaml",
    "log",
    "html",
    "htm",
    "css",
    "aspx",
    "browser",
    "config",
    "sig",
    "map",
    "pdb",
    // rhythm-game chart/score data
    "ma2",
    "sr",
];

/// Whether `path`'s extension is on [`DENY_EXT`]. Extensionless files are never
/// denied (they could be anything).
fn denied_ext(path: &Path) -> bool {
    let Some(ext) = path.extension() else {
        return false;
    };
    let Some(ext) = ext.to_str() else {
        return false;
    };
    // Extensions are ASCII in practice; compare case-insensitively without
    // allocating for the overwhelmingly common non-match.
    DENY_EXT
        .iter()
        .any(|d| d.len() == ext.len() && d.eq_ignore_ascii_case(ext))
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
/// So the only lever is **probing fewer files**, which is what [`MIN_SIZE`] and
/// [`DENY_EXT`] do — both decided from the free directory metadata, before any
/// file is opened. On that tree they cut 46,446 probes to 1,814 and the scan
/// from ~40 s to ~2 s while still finding every target.
///
/// The surviving probes (open + short read + magic test) are fanned out across
/// worker threads. Directory traversal itself stays serial (one cheap `readdir`
/// pass, no file opens) because it feeds the parallel probe.
///
/// Thread count follows [`crate::unpacker::parallel::thread_cap`] (honoring
/// `SENBEI_THREADS`, `1` = fully sequential). Output order is independent of
/// thread count: each worker owns a disjoint contiguous slice of the path list
/// and writes the matching disjoint slice of the class list, so results are
/// deterministic.
pub fn find_targets(root: &Path) -> (Vec<PathBuf>, Vec<PathBuf>, ScanStats) {
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
/// `scan_all` is true every regular file is probed, restoring the exhaustive
/// (and on asset-heavy trees, far slower) behavior.
pub fn find_targets_opts(root: &Path, scan_all: bool) -> (Vec<PathBuf>, Vec<PathBuf>, ScanStats) {
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
        !is_reparse_point(e)
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
        if !scan_all {
            // Skip on directory metadata alone — never open these.
            let too_small = entry
                .metadata()
                .map(|m| m.len() < MIN_SIZE)
                .unwrap_or(false);
            if too_small || denied_ext(entry.path()) {
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
    let workers = senbei_pe::thread_cap().clamp(1, n.max(1));
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

    let mut candidates = Vec::new();
    let mut metadata = Vec::new();
    for (p, c) in paths.into_iter().zip(class) {
        match c {
            Some(Class::Crackproof) => candidates.push(p),
            Some(Class::Metadata) => metadata.push(p),
            Some(Class::None) => stats.skipped += 1,
            // Unreadable / panicking probe: NOT skipped — the scan could not
            // classify it, so it may be a target we failed to unpack.
            None => stats.probe_errors += 1,
        }
    }
    (candidates, metadata, stats)
}

/// True if a walked directory entry is a reparse point (junction or symlink).
///
/// `DirEntry::file_type` only flags true symlinks; NTFS junctions report as
/// ordinary directories, so without this check the walker descends into them.
/// Off-Windows there are no junctions — symlink dirs are already excluded
/// because `follow_links` is off (their `file_type().is_dir()` is false).
#[cfg(windows)]
fn is_reparse_point(e: &walkdir::DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    e.metadata()
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_reparse_point(_e: &walkdir::DirEntry) -> bool {
    false
}

/// Whether the scan pre-filter is disabled via `SENBEI_SCAN_ALL`. Any value
/// other than `0`/empty turns exhaustive scanning on. The `--scan-all` flag is
/// ORed with this.
pub fn scan_all_env() -> bool {
    match std::env::var("SENBEI_SCAN_ALL") {
        Ok(v) => !matches!(v.trim(), "" | "0"),
        Err(_) => false,
    }
}

/// Classify one file by content. Reads a short prefix once and tests the
/// Crackproof detector first, then the il2cpp metadata magic. Returns `None`
/// when the file could not be classified at all — an I/O error opening it
/// (locked, permissions) or a panic inside a detector — so the caller counts
/// it as a probe error rather than a clean "not a target" skip.
///
/// The detector is wrapped in `catch_unwind` because a panic in a scan worker
/// thread would otherwise abort the whole folder run (a scoped-thread panic
/// re-raises on join, before any per-file isolation exists). The default panic
/// hook still prints the message, keeping the bug diagnosable.
///
/// A Crackproof PE never matches the metadata magic (it is a PE, not a
/// metadata blob) and vice versa, so the order is immaterial.
fn classify(path: &Path) -> Option<Class> {
    let head = read_prefix(path, DETECT_PREFIX)?;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if detect(&head).is_some() {
            Class::Crackproof
        } else if senbei_metadata::is_metadata(&head) {
            Class::Metadata
        } else {
            Class::None
        }
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
    fn denies_bulk_asset_extensions_case_insensitively() {
        for p in ["a.ab", "a.XML", "a.Acb", "a.ma2", "a.manifest", "a.PNG"] {
            assert!(denied_ext(Path::new(p)), "{p} should be denied");
        }
    }

    #[test]
    fn never_denies_what_a_target_can_be_named() {
        // Targets are recognised by content, not name — a protected module
        // can carry any extension, or none — so names like these must always
        // be probed. An allow-list would have skipped them.
        for p in [
            "app.exe.bak",
            "managed.dll.bak",
            "daemon.exe",
            "GameLib.dll",
            "global-metadata.dat",
            "noextension",
            "a.so",
            "a.bin",
        ] {
            assert!(!denied_ext(Path::new(p)), "{p} must still be probed");
        }
    }

    /// A file below the Crackproof key-table bound is skipped without being
    /// opened, but a large non-asset file is still probed.
    #[test]
    fn prefilter_skips_small_and_denied_files_only() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("tiny.dll"), vec![0u8; 100]).unwrap();
        std::fs::write(root.join("assets.ab"), vec![0u8; 100_000]).unwrap();
        std::fs::write(root.join("plain.dll"), vec![0u8; 100_000]).unwrap();

        // None of them are Crackproof, so both modes find nothing; the point is
        // that the filtered walk does not panic and honors `scan_all`.
        let (c, m, _) = find_targets_opts(root, false);
        assert!(c.is_empty() && m.is_empty());
        let (c, m, _) = find_targets_opts(root, true);
        assert!(c.is_empty() && m.is_empty());
    }

    /// An il2cpp metadata blob is found by the filtered scan: `.dat` is not on
    /// the deny-list and a real one is far above `MIN_SIZE`.
    #[test]
    fn finds_metadata_through_the_prefilter() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let mut blob = vec![0u8; MIN_SIZE as usize + 1];
        blob[..4].copy_from_slice(&0xFAB1_1BAFu32.to_le_bytes());
        std::fs::write(root.join("global-metadata.dat"), &blob).unwrap();
        // Same magic but too small to be processable — skipped by the size floor.
        std::fs::write(root.join("stub.dat"), &blob[..64]).unwrap();

        let (_, m, _) = find_targets_opts(root, false);
        assert_eq!(m.len(), 1);
        assert!(m[0].ends_with("global-metadata.dat"));
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

        let (c, m, stats) = find_targets_opts(root, false);
        assert!(
            c.is_empty() && m.is_empty(),
            "old output tree must be pruned"
        );
        assert_eq!(stats.skipped, 1, "the probed non-target counts as skipped");
        assert_eq!(stats.walk_errors, 0);
    }
}
