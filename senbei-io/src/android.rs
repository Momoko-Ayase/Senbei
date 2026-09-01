//! Android target orchestration: protected AArch64 shared libraries (`.so`),
//! app packages (`.apk` / `.apks` / `.xapk`), and the Android variant of the
//! il2cpp method-token obfuscation.
//!
//! The protection scheme hollows out an ELF64/AArch64 shared object and moves
//! the original bytes into an encrypted payload appended as a `SHT_LOUSER`
//! section; restoration extracts the stage-2 module set
//! ([`senbei_android_engine`]) and rebuilds the static image
//! ([`senbei_android_elf`]). Some il2cpp builds additionally embed their
//! metadata blob — XOR-wrapped, with no standalone `global-metadata.dat` in
//! the assets — inside the library's data section; after a successful restore
//! the blob is located by content and unwrapped
//! ([`senbei_android_metadata::extract_embedded_metadata`]).
//!
//! All functions in this module are native filesystem orchestration; the web
//! app (wasm) never touches them.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::read::DeflateDecoder;
use senbei_android_elf::{RestoreOptions, restore_libil2cpp};
use senbei_android_engine::{ExtractOptions, extract_stage2, is_protected_libil2cpp};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

/// File name of an il2cpp metadata blob (a platform-standard technology name).
pub const METADATA_FILE_NAME: &str = "global-metadata.dat";

/// Package extensions recognised as Android app packages. Packages are
/// *containers*: membership is decided by extension plus the zip magic, while
/// every file pulled out of one is still content-probed like a loose file.
const PACKAGE_EXTENSIONS: [&str; 3] = ["apk", "apks", "xapk"];

/// Whether `prefix` (the first bytes of a file) is an ELF64/AArch64 image.
/// Only those can be protected Android libraries, so the folder scan uses this
/// cheap check to decide when the full-file protection probe is worth its
/// read.
pub fn is_elf64_aarch64(prefix: &[u8]) -> bool {
    prefix.len() >= 20
        && prefix[0..4] == [0x7f, b'E', b'L', b'F']
        && prefix[4] == 2 // ELFCLASS64
        && prefix[5] == 1 // ELFDATA2LSB
        && u16::from_le_bytes([prefix[18], prefix[19]]) == 0xB7 // EM_AARCH64
}

/// Whether `path` is an Android app package: a recognised package extension
/// and the local-file-header zip magic in `prefix`.
pub fn is_app_package(path: &Path, prefix: &[u8]) -> bool {
    let is_package_ext = path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            PACKAGE_EXTENSIONS
                .iter()
                .any(|ext| value.eq_ignore_ascii_case(ext))
        });
    is_package_ext && prefix.starts_with(b"PK\x03\x04")
}

/// Probe a file on disk: true when it is a protected AArch64 library.
/// Reads the whole file (the payload section is found through the
/// section-header table at the end); call only after [`is_elf64_aarch64`]
/// has matched a prefix.
pub fn is_protected_so_file(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    is_elf64_aarch64(&bytes) && is_protected_libil2cpp(&bytes)
}

/// Restore one protected `.so` to `dest`.
///
/// The stage-2 module set is extracted into a temporary workspace (it is an
/// implementation detail of the two-phase restore, not user-facing output).
/// Returns the unwrapped embedded metadata blob when the restored image
/// carries one (see the module docs); the caller decides where to write it.
pub fn restore_so_file(input: &Path, dest: &Path, verbose: bool) -> Result<Option<Vec<u8>>> {
    let temporary = tempfile::tempdir().context("create stage-2 workspace")?;
    let stage2_dir = temporary.path().join("stage2");
    extract_stage2(&ExtractOptions::with_defaults(
        input.to_path_buf(),
        stage2_dir.clone(),
    ))
    .context("extract stage-1/stage-2 payload")?;
    restore_libil2cpp(&RestoreOptions {
        input: input.to_path_buf(),
        output: dest.to_path_buf(),
        index: stage2_dir.join("index.json"),
        dump_auxiliary: None,
        outer_only: false,
        preserve_entrypoint: false,
        verbose,
    })
    .context("restore protected library")?;
    let restored =
        std::fs::read(dest).with_context(|| format!("read restored `{}`", dest.display()))?;
    Ok(senbei_android_metadata::extract_embedded_metadata(
        &restored,
    ))
}

/// Content identity for cross-source deduplication: the same library may
/// appear loose in a tree, in its `.apk`, and again in an `.apks`/`.xapk`
/// bundle — restore it once, at the highest-priority source's destination.
pub fn content_identity(data: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(data);
    hex_digest(&digest.finalize())
}

/// Restore an il2cpp metadata blob (Android seeded permutation first, then the
/// structural remap used by the Windows builds).
///
/// The Android variant obfuscates MethodDef RIDs with a keyed five-round
/// permutation; the correct seed is recovered by intersecting per-image key
/// residues, and the restore *validates* every restored RID against its
/// canonical per-module index — so an unusable seed fails loudly and the
/// caller falls through to the structural remap, which targets the same
/// canonical form. Both paths are no-ops (`remapped == 0`) on an
/// already-clean blob.
pub fn restore_metadata_bytes(data: &[u8]) -> anyhow::Result<(Vec<u8>, senbei_metadata::Report)> {
    if let Ok(discovery) = senbei_android_metadata::discover_method_token_seeds(data)
        && discovery.version == 31
        && discovery.images.iter().any(|image| !image.clean)
    {
        let mut seeds = discovery.seed_candidates.clone();
        if seeds.is_empty() {
            seeds.push(senbei_android_metadata::DEFAULT_METHOD_TOKEN_SEED);
        }
        // Trial-and-validate: a wrong seed fails the restore's full-coverage
        // RID check, so ambiguous candidates cost one extra pass each and a
        // build with an unseeded permutation falls through to the structural
        // remap rather than producing a silently wrong file.
        for seed in seeds {
            if let Ok((out, report)) = senbei_android_metadata::restore_method_tokens(data, seed) {
                return Ok((
                    out,
                    senbei_metadata::Report {
                        version: report.version,
                        methods: report.methods,
                        remapped: report.changed_tokens,
                        modules: report.images_with_methods,
                    },
                ));
            }
        }
    }
    let (out, report) = senbei_metadata::deobfuscate(data).map_err(anyhow::Error::new)?;
    Ok((out, report))
}

/// What happened to one archive entry (or one loose Android target).
#[derive(Debug)]
pub struct EntryOutcome {
    /// Human-readable source label, e.g. `base.apk::lib/arm64-v8a/libil2cpp.so`.
    pub label: String,
    /// Where the restored bytes were written (meaningless unless `status` is
    /// `Restored`).
    pub dest: PathBuf,
    pub kind: EntryKind,
    pub status: EntryStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A protected shared library, restored.
    So,
    /// An il2cpp metadata blob, de-obfuscated (`remapped` tokens changed).
    Metadata { remapped: usize },
    /// A metadata blob unwrapped from a restored library's data section.
    EmbeddedMetadata,
}

#[derive(Debug)]
pub enum EntryStatus {
    Restored,
    /// Byte-identical content was already restored from a higher-priority
    /// source; no output written.
    Duplicate,
    /// Content-probed but not a target (unprotected library).
    NotTarget,
    /// A metadata blob whose tokens were already canonical; no copy written.
    Unchanged,
    /// Recognised as a target but the restore failed.
    Failed(anyhow::Error),
}

/// Restore every protected library and metadata blob inside one app package.
///
/// `rel` is the package's path relative to the scanned root (or its bare file
/// name in single-file mode); outputs mirror the package's internal layout
/// under `out_root/rel/`, with [`crate::job::out_name`] renaming. `seen`
/// carries content identities already restored from higher-priority sources
/// (loose files first, then `.apk`, then bundles) across the whole run.
pub fn restore_package(
    package: &Path,
    rel: &Path,
    out_root: &Path,
    seen: &mut HashSet<String>,
    verbose: bool,
) -> Result<Vec<EntryOutcome>> {
    let bundle = package
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("apks") || value.eq_ignore_ascii_case("xapk")
        });
    let mut archive = open_package(package)?;
    let temporary = tempfile::tempdir().context("create package workspace")?;
    let mut outcomes = Vec::new();

    let mut direct = Vec::new();
    let mut nested = Vec::new();
    for index in 0..archive.len() {
        let (name, is_dir) = {
            let entry = archive.by_index(index)?;
            (entry.enclosed_name(), entry.is_dir())
        };
        if is_dir {
            continue;
        }
        let Some(name) = name else {
            bail!("unsafe entry path in package `{}`", package.display());
        };
        if bundle {
            if name
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("apk"))
            {
                nested.push((index, name));
            }
        } else {
            direct.push((index, name));
        }
    }
    drop(archive);

    for (index, name) in direct {
        let label = format!("{}::{}", rel.display(), name.display());
        let dest = out_root.join(rel).join(crate::job::out_name(&name));
        let mut entry_outcomes =
            restore_package_entry(package, index, &label, &dest, &temporary, seen, verbose)
                .with_context(|| format!("extract `{label}`"))?;
        outcomes.append(&mut entry_outcomes);
    }
    for (index, name) in nested {
        let nested_label = rel.join(&name);
        let nested_path = extract_entry(package, index, &temporary, &nested_label)
            .with_context(|| format!("extract `{}`", nested_label.display()))?;
        let mut nested_archive = open_package(&nested_path)?;
        let mut entries = Vec::new();
        for nested_index in 0..nested_archive.len() {
            let (entry_name, is_dir) = {
                let entry = nested_archive.by_index(nested_index)?;
                (entry.enclosed_name(), entry.is_dir())
            };
            if !is_dir {
                let Some(entry_name) = entry_name else {
                    bail!("unsafe entry path in `{}`", nested_label.display());
                };
                entries.push((nested_index, entry_name));
            }
        }
        drop(nested_archive);
        // Keep the nested package's stem in the output layout so two splits
        // carrying same-named entries cannot collide.
        let base = rel.join(name.with_extension(""));
        for (nested_index, entry_name) in entries {
            let label = format!("{}::{}", nested_label.display(), entry_name.display());
            let dest = out_root.join(&base).join(crate::job::out_name(&entry_name));
            let mut entry_outcomes = restore_package_entry(
                &nested_path,
                nested_index,
                &label,
                &dest,
                &temporary,
                seen,
                verbose,
            )
            .with_context(|| format!("extract `{label}`"))?;
            outcomes.append(&mut entry_outcomes);
        }
    }
    Ok(outcomes)
}

/// Probe one extracted package entry and restore it when it is a target.
/// Returns one outcome per produced/consumed artifact: the entry itself, plus
/// an `EmbeddedMetadata` outcome when the restored library carried a blob.
fn restore_package_entry(
    package: &Path,
    index: usize,
    label: &str,
    dest: &Path,
    temporary: &tempfile::TempDir,
    seen: &mut HashSet<String>,
    verbose: bool,
) -> Result<Vec<EntryOutcome>> {
    let entry_path = extract_entry(package, index, temporary, Path::new(label))?;
    let data = std::fs::read(&entry_path).with_context(|| format!("read extracted `{label}`"))?;

    let is_so = is_elf64_aarch64(&data) && is_protected_libil2cpp(&data);
    let is_meta = !is_so && senbei_metadata::is_metadata(&data);
    let outcome = |kind, status| EntryOutcome {
        label: label.to_owned(),
        dest: dest.to_path_buf(),
        kind,
        status,
    };
    if !is_so && !is_meta {
        return Ok(vec![outcome(EntryKind::So, EntryStatus::NotTarget)]);
    }
    if !seen.insert(content_identity(&data)) {
        let kind = if is_so {
            EntryKind::So
        } else {
            EntryKind::Metadata { remapped: 0 }
        };
        return Ok(vec![outcome(kind, EntryStatus::Duplicate)]);
    }

    if is_so {
        return Ok(match restore_so_file(&entry_path, dest, verbose) {
            Ok(embedded) => {
                let mut outcomes = vec![outcome(EntryKind::So, EntryStatus::Restored)];
                if let Some(blob) = embedded {
                    let meta_dest = embedded_metadata_dest(dest);
                    let status = match write_metadata_blob(&meta_dest, &blob) {
                        Ok(()) => EntryStatus::Restored,
                        Err(error) => EntryStatus::Failed(error),
                    };
                    outcomes.push(EntryOutcome {
                        label: format!("{label} (embedded metadata)"),
                        dest: meta_dest,
                        kind: EntryKind::EmbeddedMetadata,
                        status,
                    });
                }
                outcomes
            }
            Err(error) => vec![outcome(EntryKind::So, EntryStatus::Failed(error))],
        });
    }

    // Metadata entry: write only when the restore actually changed tokens —
    // a clean blob needs no copy (same contract as loose metadata files).
    let kind_and_status = match restore_metadata_bytes(&data) {
        Ok((out, report)) if report.remapped > 0 => {
            let kind = EntryKind::Metadata {
                remapped: report.remapped,
            };
            match write_metadata_blob(dest, &out) {
                Ok(()) => (kind, EntryStatus::Restored),
                Err(error) => (kind, EntryStatus::Failed(error)),
            }
        }
        Ok(_) => (EntryKind::Metadata { remapped: 0 }, EntryStatus::Unchanged),
        Err(error) => (
            EntryKind::Metadata { remapped: 0 },
            EntryStatus::Failed(error),
        ),
    };
    Ok(vec![outcome(kind_and_status.0, kind_and_status.1)])
}

/// Output path for a metadata blob unwrapped from a restored library: next to
/// the library, under the standard file name (with the usual `.unpack` infix).
pub fn embedded_metadata_dest(restored_so: &Path) -> PathBuf {
    let dir = restored_so.parent().unwrap_or_else(|| Path::new("."));
    dir.join(crate::job::out_name(Path::new(METADATA_FILE_NAME)))
}

/// Write a metadata blob, creating the parent directory. The restore writes
/// its own output atomically; metadata blobs go through the job layer's
/// atomic write to share the mid-write failure semantics.
fn write_metadata_blob(dest: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create `{}`", parent.display()))?;
    }
    crate::job::write_atomic(dest, data)
        .map_err(anyhow::Error::from)
        .context("write metadata output")
}

fn open_package(path: &Path) -> Result<ZipArchive<std::fs::File>> {
    let file = std::fs::File::open(path).with_context(|| format!("open `{}`", path.display()))?;
    ZipArchive::new(file).with_context(|| format!("read package `{}`", path.display()))
}

/// Extract one package entry to the temporary workspace, streaming stored
/// entries and inflating deflated ones by hand so compression-method
/// surprises fail loudly instead of producing a truncated file.
fn extract_entry(
    package: &Path,
    index: usize,
    temporary: &tempfile::TempDir,
    label: &Path,
) -> Result<PathBuf> {
    let mut archive = open_package(package)?;
    let mut entry = archive.by_index_raw(index)?;
    let key = format!("{}-{index:08x}", label.display());
    // `:` appears in `package::entry` labels and is invalid in Windows file
    // names; sanitize every path-ish separator.
    let destination = temporary.path().join(key.replace(['\\', '/', ':'], "_"));
    let compressed_size = usize::try_from(entry.compressed_size())
        .map_err(|_| anyhow::anyhow!("entry compressed size exceeds usize"))?;
    let output_size =
        usize::try_from(entry.size()).map_err(|_| anyhow::anyhow!("entry size exceeds usize"))?;
    let mut compressed = vec![0_u8; compressed_size];
    entry.read_exact(&mut compressed)?;
    let mut output = Vec::with_capacity(output_size);
    match entry.compression() {
        zip::CompressionMethod::Stored => output.extend_from_slice(&compressed),
        zip::CompressionMethod::Deflated => {
            DeflateDecoder::new(compressed.as_slice()).read_to_end(&mut output)?;
        }
        method => bail!("unsupported compression method {method:?} in entry `{key}`"),
    }
    if output.len() != output_size {
        bail!(
            "entry `{key}` decompressed to 0x{:x}, expected 0x{output_size:x}",
            output.len()
        );
    }
    std::fs::write(&destination, &output)?;
    Ok(destination)
}
/// Lowercase hex of a digest output (sha2 0.11's `Array` no longer formats as
/// hex directly).
fn hex_digest(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
