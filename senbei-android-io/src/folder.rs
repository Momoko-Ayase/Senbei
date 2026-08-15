use std::collections::BTreeSet;
use std::fs::{File, create_dir_all, read_dir};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::read::DeflateDecoder;
use senbei_android_engine::{ExtractOptions, extract_stage2, is_protected_libil2cpp};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};
use zip::ZipArchive;

use crate::{RestoreMetadataJob, RestoreSoJob, run_restore_metadata, run_restore_so};

const METADATA_NAME: &str = "global-metadata.dat";
const METADATA_SUFFIX: [&str; 6] = [
    "assets",
    "bin",
    "Data",
    "Managed",
    "Metadata",
    METADATA_NAME,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TargetKind {
    So,
    Metadata,
}

#[derive(Debug, Clone)]
struct Target {
    kind: TargetKind,
    source: PathBuf,
    destination: PathBuf,
    label: String,
    identity: String,
    source_priority: u8,
}

/// Summary of one folder-mode restoration run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderSummary {
    pub so_restored: usize,
    pub so_skipped: usize,
    pub metadata_restored: usize,
    pub metadata_skipped: usize,
    pub archives: usize,
}

/// Find protected Android targets below `root`, restore them, and write only
/// the clean files below `<root>/unpack`.
pub fn run_folder(root: &Path) -> Result<FolderSummary> {
    if !root.is_dir() {
        bail!("input must be a folder: `{}`", root.display());
    }
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("canonicalize input folder `{}`", root.display()))?;
    let output_root = root.join("unpack");
    create_dir_all(&output_root)
        .with_context(|| format!("create output folder `{}`", output_root.display()))?;

    let temporary = tempdir().context("create temporary archive workspace")?;
    let mut targets = Vec::new();
    let mut archives = BTreeSet::new();
    collect_targets(
        &root,
        &root,
        &output_root,
        &temporary,
        &mut targets,
        &mut archives,
    )?;
    targets = deduplicate_targets(targets);
    targets.sort_by(|left, right| left.destination.cmp(&right.destination));

    let mut summary = FolderSummary {
        so_restored: 0,
        so_skipped: 0,
        metadata_restored: 0,
        metadata_skipped: 0,
        archives: archives.len(),
    };
    let mut seen_destinations = BTreeSet::new();

    for target in targets {
        if !seen_destinations.insert(target.destination.clone()) {
            bail!(
                "duplicate target destination `{}`",
                target.destination.display()
            );
        }
        match target.kind {
            TargetKind::So => {
                if restore_so_target(&target, &temporary)? {
                    summary.so_restored += 1;
                } else {
                    summary.so_skipped += 1;
                }
            }
            TargetKind::Metadata => {
                if restore_metadata_target(&target)? {
                    summary.metadata_restored += 1;
                } else {
                    summary.metadata_skipped += 1;
                }
            }
        }
    }
    Ok(summary)
}

fn restore_so_target(target: &Target, temporary: &TempDir) -> Result<bool> {
    let data = std::fs::read(&target.source)
        .with_context(|| format!("read protected `{}`", target.label))?;
    if !is_protected_libil2cpp(&data) {
        bail!(
            "target is not a protected AArch64 libil2cpp ELF: `{}`",
            target.label
        );
    }
    let key = target.label.bytes().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(131).wrapping_add(u64::from(byte))
    });
    let stage2_dir = temporary.path().join(format!("stage2-{key:016x}"));
    let index = stage2_dir.join("index.json");
    if let Err(error) = extract_stage2(&ExtractOptions::with_defaults(
        target.source.clone(),
        stage2_dir,
    ))
    .with_context(|| format!("extract Stage 1/Stage 2 for `{}`", target.label))
    {
        eprintln!("skip SO `{}`: {error:#}", target.label);
        return Ok(false);
    }
    if let Err(error) = run_restore_so(&RestoreSoJob {
        input: target.source.clone(),
        output: target.destination.clone(),
        index: Some(index),
        report: None,
        dump_auxiliary: None,
        outer_only: false,
        preserve_entrypoint: false,
    })
    .with_context(|| format!("restore `{}`", target.label))
    {
        eprintln!("skip SO `{}`: {error:#}", target.label);
        return Ok(false);
    }
    Ok(true)
}

fn restore_metadata_target(target: &Target) -> Result<bool> {
    let input = std::fs::read(&target.source)
        .with_context(|| format!("read metadata `{}`", target.label))?;
    let discovery = senbei_android_metadata::discover_method_token_seeds(&input)
        .with_context(|| format!("inspect metadata `{}`", target.label))?;
    if discovery.version != 31 {
        return Ok(false);
    }
    if discovery.images.iter().all(|image| image.clean) {
        return Ok(false);
    }
    let seed = match discovery.seed_candidates.as_slice() {
        [] => senbei_android_metadata::DEFAULT_METHOD_TOKEN_SEED,
        [seed] => *seed,
        candidates => bail!(
            "metadata `{}` has ambiguous MethodDef seeds: {} candidates",
            target.label,
            candidates.len()
        ),
    };
    run_restore_metadata(&RestoreMetadataJob {
        input: target.source.clone(),
        output: target.destination.clone(),
        seed,
        report: None,
    })?;
    Ok(true)
}

fn collect_targets(
    root: &Path,
    current: &Path,
    output_root: &Path,
    temporary: &TempDir,
    targets: &mut Vec<Target>,
    archives: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let mut entries = read_dir(current)
        .with_context(|| format!("scan folder `{}`", current.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if entry.file_name().eq_ignore_ascii_case("unpack") {
                continue;
            }
            collect_targets(root, &path, output_root, temporary, targets, archives)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| anyhow::anyhow!("input path escaped root: `{}`", path.display()))?
            .to_path_buf();
        if is_so_path(&relative) {
            let bytes =
                std::fs::read(&path).with_context(|| format!("probe `{}`", path.display()))?;
            if is_protected_libil2cpp(&bytes) {
                targets.push(Target {
                    kind: TargetKind::So,
                    source: path,
                    destination: output_root.join(&relative),
                    label: relative.display().to_string(),
                    identity: content_identity(&bytes),
                    source_priority: 0,
                });
            }
        } else if is_metadata_path(&relative) {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("read metadata `{}`", path.display()))?;
            targets.push(Target {
                kind: TargetKind::Metadata,
                source: path,
                destination: output_root.join(&relative),
                label: relative.display().to_string(),
                identity: content_identity(&bytes),
                source_priority: 0,
            });
        } else if is_archive(&path) {
            extract_archive_targets(&path, &relative, output_root, temporary, targets, archives)?;
        }
    }
    Ok(())
}

fn is_archive(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("apk") || value.eq_ignore_ascii_case("apks")
        })
}

fn extract_archive_targets(
    archive_path: &Path,
    archive_relative: &Path,
    output_root: &Path,
    temporary: &TempDir,
    targets: &mut Vec<Target>,
    archives: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    archives.insert(archive_relative.to_path_buf());
    let is_apks = archive_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("apks"));
    let mut archive = ZipArchive::new(
        File::open(archive_path)
            .with_context(|| format!("open archive `{}`", archive_path.display()))?,
    )
    .with_context(|| format!("read archive `{}`", archive_path.display()))?;
    let mut nested = Vec::new();
    let mut direct = Vec::new();
    for index in 0..archive.len() {
        let (path, is_directory) = {
            let entry = archive.by_index(index)?;
            (entry.enclosed_name().map(PathBuf::from), entry.is_dir())
        };
        if is_directory {
            continue;
        }
        let Some(path) = path else {
            bail!(
                "archive entry has unsafe path in `{}`",
                archive_path.display()
            );
        };
        if is_apks
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("apk"))
        {
            nested.push((index, path));
        } else if !is_apks && (is_so_path(&path) || is_metadata_path(&path)) {
            direct.push((index, path));
        }
    }
    drop(archive);

    // Keep the archive suffix in the output directory name. An input tree may
    // already contain an extracted `base/` beside `base.apk`; dropping the
    // suffix would make those two independent targets collide.
    let archive_base = archive_relative.to_path_buf();
    for (index, path) in direct {
        let source =
            extract_entry_from_archive_path(archive_path, index, temporary, archive_relative)?;
        push_archive_target(
            output_root,
            targets,
            archive_base.clone(),
            path,
            source,
            archive_relative,
            if is_apks { 2 } else { 1 },
        )?;
    }
    for (index, nested_path) in nested {
        let nested_source =
            extract_entry_from_archive_path(archive_path, index, temporary, archive_relative)?;
        let nested_base = archive_base.join(nested_path.with_extension(""));
        extract_nested_apk(
            &nested_source,
            nested_base,
            archive_relative.join(&nested_path),
            output_root,
            temporary,
            targets,
        )?;
    }
    Ok(())
}

fn extract_nested_apk(
    apk_path: &Path,
    output_base: PathBuf,
    nested_label: PathBuf,
    output_root: &Path,
    temporary: &TempDir,
    targets: &mut Vec<Target>,
) -> Result<()> {
    let mut archive = ZipArchive::new(
        File::open(apk_path)
            .with_context(|| format!("open nested APK `{}`", apk_path.display()))?,
    )
    .with_context(|| format!("read nested APK `{}`", apk_path.display()))?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let (path, is_directory) = {
            let entry = archive.by_index(index)?;
            (entry.enclosed_name().map(PathBuf::from), entry.is_dir())
        };
        if is_directory {
            continue;
        }
        let Some(path) = path else {
            bail!(
                "nested APK entry has unsafe path in `{}`",
                apk_path.display()
            );
        };
        if is_so_path(&path) || is_metadata_path(&path) {
            entries.push((index, path));
        }
    }
    drop(archive);
    for (index, path) in entries {
        let source = extract_entry_from_archive_path(apk_path, index, temporary, &nested_label)?;
        push_archive_target(
            output_root,
            targets,
            output_base.clone(),
            path,
            source,
            &nested_label,
            2,
        )?;
    }
    Ok(())
}

fn push_archive_target(
    output_root: &Path,
    targets: &mut Vec<Target>,
    base: PathBuf,
    entry_path: PathBuf,
    source: PathBuf,
    archive_label: &Path,
    source_priority: u8,
) -> Result<()> {
    let kind = if is_so_path(&entry_path) {
        TargetKind::So
    } else {
        TargetKind::Metadata
    };
    let bytes = std::fs::read(&source)
        .with_context(|| format!("probe archive target `{}`", archive_label.display()))?;
    if kind == TargetKind::So && !is_protected_libil2cpp(&bytes) {
        return Ok(());
    }
    targets.push(Target {
        kind,
        source,
        destination: output_root.join(&base).join(&entry_path),
        label: format!("{}::{}", archive_label.display(), entry_path.display()),
        identity: content_identity(&bytes),
        source_priority,
    });
    Ok(())
}

fn is_so_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("so"))
}

fn is_metadata_path(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    components.len() >= METADATA_SUFFIX.len()
        && components[components.len() - METADATA_SUFFIX.len()..]
            .iter()
            .zip(METADATA_SUFFIX)
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
}

fn content_identity(data: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(data);
    format!("{:x}", digest.finalize())
}

fn deduplicate_targets(mut targets: Vec<Target>) -> Vec<Target> {
    targets.sort_by(|left, right| {
        (left.kind, &left.identity)
            .cmp(&(right.kind, &right.identity))
            .then_with(|| right.source_priority.cmp(&left.source_priority))
            .then_with(|| left.label.cmp(&right.label))
    });
    let mut seen = BTreeSet::new();
    targets
        .into_iter()
        .filter(|target| seen.insert((target.kind, target.identity.clone())))
        .collect()
}

fn extract_entry_from_archive_path(
    archive_path: &Path,
    index: usize,
    temporary: &TempDir,
    archive_label: &Path,
) -> Result<PathBuf> {
    let mut archive = ZipArchive::new(File::open(archive_path)?)?;
    extract_entry(&mut archive, index, temporary, archive_label)
}

fn extract_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    temporary: &TempDir,
    archive_label: &Path,
) -> Result<PathBuf> {
    let mut entry = archive.by_index_raw(index)?;
    let key = format!("{}-{index:08x}", archive_label.display());
    let destination = temporary.path().join(key.replace(['\\', '/'], "_"));
    let compressed_size = usize::try_from(entry.compressed_size())
        .map_err(|_| anyhow::anyhow!("archive entry compressed size exceeds usize"))?;
    let output_size = usize::try_from(entry.size())
        .map_err(|_| anyhow::anyhow!("archive entry size exceeds usize"))?;
    let mut compressed = vec![0_u8; compressed_size];
    entry.read_exact(&mut compressed).with_context(|| {
        format!(
            "read raw archive `{}` entry index {index}",
            archive_label.display()
        )
    })?;
    let mut output_data = Vec::with_capacity(output_size);
    match entry.compression() {
        zip::CompressionMethod::Stored => output_data.extend_from_slice(&compressed),
        zip::CompressionMethod::Deflated => {
            DeflateDecoder::new(compressed.as_slice())
                .read_to_end(&mut output_data)
                .with_context(|| {
                    format!(
                        "deflate archive `{}` entry index {index}",
                        archive_label.display()
                    )
                })?;
        }
        method => bail!(
            "unsupported compression method {method:?} in archive `{}` entry index {index}",
            archive_label.display()
        ),
    }
    if output_data.len() != output_size {
        bail!(
            "archive `{}` entry index {index} decompressed to 0x{:x}, expected 0x{:x}",
            archive_label.display(),
            output_data.len(),
            output_size
        );
    }
    let mut output = File::create(&destination)?;
    output.write_all(&output_data)?;
    Ok(destination)
}
