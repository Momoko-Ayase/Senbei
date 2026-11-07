//! Android target orchestration: protected AArch64 shared libraries (`.so`),
//! app packages (`.apk` / `.apks` / `.xapk`), and the Android variant of the
//! il2cpp method-token/method-index obfuscation.
//!
//! The protection scheme hollows out an ELF64/AArch64 shared object and moves
//! the original bytes into an encrypted payload appended as a `SHT_LOUSER`
//! section; restoration extracts the stage-2 module set
//! ([`senbei_engine::android`]) and rebuilds the static image
//! ([`senbei_engine::android`]). Some il2cpp builds additionally embed their
//! metadata blob — XOR-wrapped, with no standalone `global-metadata.dat` in
//! the assets — inside the library's data section; after a successful restore
//! the blob is located by content and unwrapped
//! ([`senbei_metadata::android::extract_embedded_metadata`]).
//!
//! All functions in this module are native filesystem orchestration; the web
//! app (wasm) never touches them.

#[cfg(test)]
mod resource_tests;
#[cfg(test)]
mod tests;

mod archive_limits;
mod context;
mod manifest;

use context::LibraryRestorer;

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use memmap2::{Mmap, MmapOptions};
use senbei_crypto::hex_digest;
use senbei_engine::android::{ExtractOptions, extract_stage2_with_limits, is_protected_libil2cpp};
use senbei_engine::android::{ResourceLimits, RestoreOptions, restore_libil2cpp_with_limits};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

pub use crate::METADATA_FILE_NAME;
use crate::message::Coded;
use crate::report::{ContainerReport, ManifestReport};
use senbei_i18n::Msg;

/// Package extensions recognised as Android app packages. Packages are
/// *containers*: membership is decided by extension plus the ZIP magic, while
/// only `.so` and `global-metadata.dat` entries are read.
const PACKAGE_EXTENSIONS: [&str; 3] = ["apk", "apks", "xapk"];

pub(crate) fn is_package_name(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            PACKAGE_EXTENSIONS
                .iter()
                .any(|ext| value.eq_ignore_ascii_case(ext))
        })
}

pub(crate) fn is_so_name(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("so"))
}

pub(crate) fn is_android_entry_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(METADATA_FILE_NAME))
        || is_so_name(path)
}

/// Whether `prefix` (the first bytes of a file) is an ELF64/AArch64 image.
/// Only those can be protected Android libraries, so the folder scan uses this
/// cheap check to decide when the full-file protection probe is worth its
/// read.
pub fn is_elf64_aarch64(prefix: &[u8]) -> bool {
    senbei_elf::is_aarch64_prefix(prefix)
}

/// Whether `path` is an Android app package: a recognised package extension
/// and the local-file-header zip magic in `prefix`.
pub fn is_app_package(path: &Path, prefix: &[u8]) -> bool {
    is_package_name(path) && prefix.starts_with(b"PK\x03\x04")
}

/// Inventory an app package without restoring anything.
///
/// Reads the ZIP central directories and the bounded root manifests only; no
/// `.so` or `global-metadata.dat` entry is extracted, so this is a membership
/// report, not an inspection of protected content. Entries that a restore
/// *would* probe are listed by name.
pub fn inspect_package(package: &Path, limits: &ResourceLimits) -> Result<ContainerReport> {
    let kind = package
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let bundle = kind == "apks" || kind == "xapk";
    let mut budget = archive_limits::ArchiveBudget::from_limits(limits);
    let mut archive = budget.open_archive(package)?;
    let entry_count = archive.len();
    let mut manifests = Vec::new();
    let mut candidate_entries = Vec::new();
    let mut nested_packages = Vec::new();

    let mut nested_indices = Vec::new();
    for index in 0..archive.len() {
        let (name, is_dir) = {
            let entry = archive.by_index(index)?;
            (entry.enclosed_name(), entry.is_dir())
        };
        if is_dir {
            continue;
        }
        let Some(name) = name else {
            bail!(Coded::new(Msg::UnsafePackageEntry {
                package: package.display().to_string(),
            }));
        };
        if bundle {
            if name
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("apk"))
            {
                nested_indices.push(index);
                nested_packages.push(name.display().to_string());
            }
        } else if is_android_entry_name(&name) {
            candidate_entries.push(name.display().to_string());
        }
    }

    if !bundle {
        let inventory = context::inventory_manifest_package(
            &mut archive,
            package,
            package
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
            &package.display().to_string(),
            &mut budget,
        )?;
        manifests.push(manifest_report(&package.display().to_string(), &inventory));
        return Ok(ContainerReport {
            kind,
            manifests,
            entry_count,
            candidate_entries,
            nested_packages,
        });
    }

    // A bundle: each nested APK is its own package. Extract it to a temporary
    // file (no protected entry is read) so its manifest can name it.
    std::mem::drop(archive);
    let temporary = tempfile::tempdir().context("create inventory workspace")?;
    let mut budget = archive_limits::ArchiveBudget::from_limits(limits);
    let mut archive = budget.open_archive(package)?;
    for index in nested_indices {
        let name = {
            let entry = archive.by_index(index)?;
            entry.enclosed_name()
        };
        let Some(name) = name else {
            continue;
        };
        let path = extract_entry(&mut archive, index, &temporary, &name, &mut budget)
            .with_context(|| format!("extract `{}`", name.display()))?;
        let mut nested = budget.open_archive(&path)?;
        let inventory = context::inventory_manifest_package(
            &mut nested,
            &path,
            package,
            &name.display().to_string(),
            &mut budget,
        )?;
        manifests.push(manifest_report(&name.display().to_string(), &inventory));
        for nested_index in 0..nested.len() {
            let (entry_name, is_dir) = {
                let entry = nested.by_index(nested_index)?;
                (entry.enclosed_name(), entry.is_dir())
            };
            if is_dir {
                continue;
            }
            if let Some(entry_name) = entry_name
                && is_android_entry_name(&entry_name)
            {
                candidate_entries.push(format!("{}::{}", name.display(), entry_name.display()));
            }
        }
    }
    Ok(ContainerReport {
        kind,
        manifests,
        entry_count,
        candidate_entries,
        nested_packages,
    })
}

fn manifest_report(source: &str, inventory: &context::PackageInventory) -> ManifestReport {
    let (package, version) = match &inventory.key {
        context::AppKey::Manifest {
            package, version, ..
        } => (Some(package.clone()), Some(version.clone())),
        _ => (None, None),
    };
    ManifestReport {
        source: source.to_owned(),
        named: package.is_some() && version.is_some(),
        package,
        version,
    }
}

/// Structural diagnostics the restore engine reported for one output.
///
/// These are the cross-table findings from the engine's own validation pass
/// (see [`senbei_engine::android::RestoreReport`]). A restore that returns
/// success still validates; a finding here says a linker could not walk a table
/// in the bytes that were produced. It never fails a restore, so it is reported
/// as a warning, never as an error. Restorers that cannot report one leave the
/// field empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationDiagnostics {
    pub messages: Vec<String>,
}

impl ValidationDiagnostics {
    /// A completed validation with no findings.
    pub fn clean() -> Self {
        Self::default()
    }

    /// True when the validation ran and found nothing.
    pub fn is_clean(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Probe a file on disk: true when it is a protected AArch64 library.
/// Reads the whole file (the payload section is found through the
/// section-header table at the end); call only after [`is_elf64_aarch64`]
/// has matched a prefix.
pub fn is_protected_so_file(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let Ok(bytes) = map_read_only(&file, path) else {
        return false;
    };
    is_elf64_aarch64(&bytes) && is_protected_libil2cpp(&bytes)
}

pub(crate) fn probe_so_file_with_limits(
    path: &Path,
    limits: &senbei_engine::android::ResourceLimits,
) -> Result<bool> {
    let file = File::open(path).with_context(|| format!("open `{}`", path.display()))?;
    let bytes = map_read_only(&file, path)?;
    if !is_elf64_aarch64(&bytes) {
        return Ok(false);
    }
    senbei_engine::android::probe_libil2cpp_with_limits(&bytes, limits).map_err(Into::into)
}

pub fn file_content_identity(path: &Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    // SAFETY: the file remains open for the mapping lifetime and the mapping
    // is read-only.
    let bytes = unsafe { MmapOptions::new().map(&file)? };
    Ok(content_identity(&bytes))
}

/// Restore one protected `.so` to `dest`.
///
/// The stage-2 module set is extracted into a temporary workspace (it is an
/// implementation detail of the two-phase restore, not user-facing output).
/// Returns the unwrapped embedded metadata blob when the restored image
/// carries one (see the module docs); the caller decides where to write it.
///
/// Module `0x0C` recovered here belongs to this library's application. Callers
/// that restore more than one application must keep those modules apart; this
/// single-file entry point has only one application, so it keeps the module
/// only long enough to unwrap embedded metadata (which does not consume it).
pub(crate) fn restore_so_with_engine_limits(
    input: &Path,
    dest: &Path,
    verbose: bool,
    limits: &ResourceLimits,
    research: bool,
) -> Result<context::RestoredLibrary> {
    let temporary = tempfile::tempdir().context("create stage-2 workspace")?;
    let stage2_dir = temporary.path().join("stage2");
    let extraction = extract_stage2_with_limits(
        &ExtractOptions::with_defaults(input.to_path_buf(), stage2_dir.clone()),
        limits,
    )
    .context("extract stage-1/stage-2 payload")?;
    // The report the extraction just produced. Serialized once, only for
    // research runs; an ordinary run drops it with the rest of the workspace.
    let extraction_report = research.then(|| {
        report_value(
            &extraction,
            &[(input, "<input>"), (temporary.path(), "<workspace>")],
        )
    });
    // Every module 0x0C is collected. Two distinct images in one library are a
    // conflict for that library's application, not a last-writer-wins update.
    let mut modules = Vec::new();
    for module in extraction
        .module_registry
        .iter()
        .filter(|module| module.command_id == 0x0c)
    {
        let bytes = std::fs::read(stage2_dir.join(&module.image_path))
            .with_context(|| format!("read decoded module 0x0C `{}`", module.image_path))?;
        if modules
            .iter()
            .all(|(_, existing): &(_, Vec<u8>)| existing != &bytes)
        {
            modules.push((module.image_path.clone(), bytes));
        }
    }
    ensure!(
        modules.len() <= 1,
        "library `{}` contains {} distinct module 0x0C images",
        input.display(),
        modules.len()
    );
    let (module_image, method_index_module) = modules
        .pop()
        .map(|(image, bytes)| (Some(image), Some(bytes)))
        .unwrap_or((None, None));
    let report = restore_libil2cpp_with_limits(
        &RestoreOptions {
            input: input.to_path_buf(),
            output: dest.to_path_buf(),
            index: stage2_dir.join("index.json"),
            dump_auxiliary: None,
            outer_only: false,
            preserve_entrypoint: false,
            verbose,
        },
        limits,
    );
    // A restore that failed after extraction is still a research finding: the
    // extraction's seeds, records and modules are already known, and the
    // original failure travels with them so nothing is lost.
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            let restored = extraction_report
                .map(|extraction| crate::report::AndroidResearchReport {
                    extraction,
                    restoration: None,
                })
                .map(ResearchCapture::Library);
            return Err(capture(
                anyhow::Error::new(error).context("restore protected library"),
                restored,
            ));
        }
    };
    // The same restore's own report, serialized once for research output
    // before the validation diagnostics are taken out of it below.
    let restoration = research.then(|| {
        report_value(
            &report,
            &[
                (input, "<input>"),
                (dest, "<output>"),
                (temporary.path(), "<workspace>"),
            ],
        )
    });
    // Keep only the validation verdict this call already produced. Nothing is
    // re-read or re-validated: the diagnostics describe the bytes just written.
    let validation = Some(ValidationDiagnostics {
        messages: report.validation.diagnostics,
    });
    let restored_file =
        File::open(dest).with_context(|| format!("read restored `{}`", dest.display()))?;
    let restored = map_read_only(&restored_file, dest)?;
    Ok(context::RestoredLibrary {
        embedded_metadata: senbei_metadata::android::extract_embedded_metadata(&restored),
        method_index_module,
        module_image,
        validation,
        research: match (extraction_report, restoration) {
            (Some(extraction), restoration) => Some(crate::report::AndroidResearchReport {
                extraction,
                restoration,
            }),
            _ => None,
        },
    })
}

pub fn restore_so_file(input: &Path, dest: &Path, verbose: bool) -> Result<Option<Vec<u8>>> {
    restore_so_file_with_limits(input, dest, verbose, &ResourceLimits::default())
}

/// Restore a loose Android library with explicit resource ceilings.
pub fn restore_so_file_with_limits(
    input: &Path,
    dest: &Path,
    verbose: bool,
    limits: &ResourceLimits,
) -> Result<Option<Vec<u8>>> {
    Ok(restore_so_file_with_diagnostics(input, dest, verbose, limits)?.0)
}

/// [`restore_so_file_with_limits`], also returning the validation diagnostics
/// the engine reported for the image it just wrote.
///
/// The diagnostics come from that restore's own report; nothing is re-read or
/// re-validated. They are advisory and never fail the restore.
pub fn restore_so_file_with_diagnostics(
    input: &Path,
    dest: &Path,
    verbose: bool,
    limits: &ResourceLimits,
) -> Result<(Option<Vec<u8>>, Option<ValidationDiagnostics>)> {
    let restored = context::EngineRestorer::new(*limits, false).restore(input, dest, verbose)?;
    Ok((restored.embedded_metadata, restored.validation))
}

/// One single-file Android library restore.
pub(crate) struct ResearchedLibrary {
    pub embedded_metadata: Option<Vec<u8>>,
    /// Structural diagnostics for the image this restore wrote.
    pub validation: Option<ValidationDiagnostics>,
    /// The engines' own reports, kept only when research was requested.
    pub research: Option<crate::report::AndroidResearchReport>,
}

/// [`restore_so_file_with_diagnostics`], also keeping the engines' own reports
/// for research output. Nothing else changes: the same single restore runs.
pub(crate) fn restore_so_file_researched(
    input: &Path,
    dest: &Path,
    verbose: bool,
    limits: &ResourceLimits,
    research: bool,
) -> Result<ResearchedLibrary> {
    let restored = context::EngineRestorer::new(*limits, research).restore(input, dest, verbose)?;
    Ok(ResearchedLibrary {
        embedded_metadata: restored.embedded_metadata,
        validation: restored.validation,
        research: restored.research,
    })
}

/// Fresh run-scoped cache. Library hits reuse their module context; metadata hits
/// are keyed by encrypted bytes and the module that recovered them.
#[cfg(test)]
pub(crate) fn run_cache() -> context::AndroidRunCache {
    context::AndroidRunCache::default()
}

pub(crate) fn run_cache_with_limits(limits: &ResourceLimits) -> context::AndroidRunCache {
    context::AndroidRunCache::with_limits(limits)
}

/// The same cache, keeping the engines' reports for research output.
pub(crate) fn run_cache_for_research(limits: &ResourceLimits) -> context::AndroidRunCache {
    let mut cache = context::AndroidRunCache::with_limits(limits);
    cache.research = true;
    cache
}

/// Assign loose libraries and metadata to application contexts.
pub(crate) fn loose_scopes(
    libraries: &[PathBuf],
    metadata: &[PathBuf],
) -> Vec<context::ScopedInput> {
    context::group_loose_inputs(libraries, metadata)
}

/// One loose library restore, including the embedded metadata blob when the
/// rebuilt image carried one. `Duplicate` means an earlier successful restore
/// of the same encrypted bytes already populated this application.
#[derive(Debug)]
pub(crate) struct LooseLibraryOutcome {
    pub status: EntryStatus,
    /// Embedded metadata already written as part of this successful restore.
    pub embedded: Option<PathBuf>,
    /// Structural diagnostics from the restore that produced this output.
    /// `None` for duplicates, failures, and restorers without a report.
    pub validation: Option<ValidationDiagnostics>,
    /// The engines' own extraction and restoration reports, kept only for
    /// research inspection. `None` for every ordinary run.
    pub research: Option<crate::report::AndroidResearchReport>,
}

pub(crate) fn restore_loose_library(
    input: &Path,
    dest: &Path,
    label: &str,
    app: &context::AppKey,
    verbose: bool,
    cache: &mut context::AndroidRunCache,
) -> Result<LooseLibraryOutcome> {
    let limits = cache.limits;
    restore_loose_library_with(
        input,
        dest,
        label,
        app,
        verbose,
        cache,
        &mut context::EngineRestorer::new(limits, cache.research()),
    )
}

fn restore_loose_library_with<R: context::LibraryRestorer>(
    input: &Path,
    dest: &Path,
    label: &str,
    app: &context::AppKey,
    verbose: bool,
    cache: &mut context::AndroidRunCache,
    restorer: &mut R,
) -> Result<LooseLibraryOutcome> {
    let identity = file_content_identity(input).with_context(|| format!("hash `{label}`"))?;
    if let Some(cached) = cache.library(&identity).cloned() {
        // Same encrypted library. Record its module on this application and
        // write nothing: a duplicate has no output of its own.
        record_module(cache, app, &cached, label);
        return Ok(LooseLibraryOutcome {
            status: EntryStatus::Duplicate,
            embedded: None,
            validation: None,
            research: None,
        });
    }
    // A prior content-only success still needs context extraction. Restore it
    // in a private workspace, never over a destination that must stay untouched.
    let prior = cache.is_prior_success(&identity);
    let workspace = prior
        .then(tempfile::tempdir)
        .transpose()
        .context("create duplicate context workspace")?;
    let scratch = workspace
        .as_ref()
        .map(|directory| directory.path().join("restored.so"));
    let restore_dest = scratch.as_deref().unwrap_or(dest);
    match restorer.restore(input, restore_dest, verbose) {
        Ok(restored) => {
            // The library file is already at `dest`. Embedded metadata is part
            // of the same success: cache the module only after that write.
            let mut embedded = None;
            if !prior && let Some(blob) = &restored.embedded_metadata {
                let meta_dest = embedded_metadata_dest(dest);
                if let Err(error) = write_metadata_blob(&meta_dest, blob) {
                    return Ok(LooseLibraryOutcome {
                        status: EntryStatus::Failed(error),
                        embedded: None,
                        validation: None,
                        research: None,
                    });
                }
                embedded = Some(meta_dest);
            }
            let cached = context::CachedLibrary {
                method_index_module: restored.method_index_module,
                module_image: restored.module_image,
            };
            record_module(cache, app, &cached, label);
            cache.insert_library(identity, cached);
            Ok(LooseLibraryOutcome {
                status: if prior {
                    EntryStatus::Duplicate
                } else {
                    EntryStatus::Restored
                },
                embedded,
                // A duplicate restored only for its module context has no
                // output of its own, so it reports no diagnostics, and the
                // engine reports belong to the run that actually produced it.
                validation: if prior {
                    None
                } else {
                    restored.validation.clone()
                },
                research: if prior { None } else { restored.research },
            })
        }
        Err(error) => {
            // A restore that failed after extraction keeps the extraction's
            // own report; the error itself is unchanged.
            let research = match error_research(&error) {
                Some(ResearchCapture::Library(report)) => Some(report.clone()),
                _ => None,
            };
            Ok(LooseLibraryOutcome {
                status: EntryStatus::Failed(error),
                embedded: None,
                validation: None,
                research,
            })
        }
    }
}

/// Metadata restored under one application context, plus the libraries whose
/// module was paired with it.
#[derive(Debug)]
pub(crate) struct LooseMetadataOutcome {
    pub version: u32,
    pub remapped: usize,
    pub provenance: Vec<String>,
    /// Route the transform actually took (seeded, structural, or method-index).
    pub layout: senbei_engine::LayoutKind,
    /// Seeds tried, discovery, and the transform's own report. Only a research
    /// run keeps this.
    pub research: Option<serde_json::Value>,
}

pub(crate) fn restore_loose_metadata(
    input: &Path,
    dest: &Path,
    label: &str,
    app: &context::AppKey,
    verbose: bool,
    cache: &mut context::AndroidRunCache,
) -> Result<LooseMetadataOutcome> {
    let data = std::fs::read(input).with_context(|| format!("read `{label}`"))?;
    let version = metadata_version(&data);
    // Only raw v24 consumes module 0x0C. v29/v31/v39 and the structural path
    // must not fail, and must not record a module they did not use, when the
    // application's libraries disagree or have no module.
    let (module, provenance) = if version == Some(24) {
        let modules = cache.modules(app).cloned();
        match context::binding_module(modules.as_ref()) {
            Ok(module) => (
                module.map(|bytes| bytes.to_vec()),
                provenance_labels(&context::provenance_for(modules.as_ref(), None)),
            ),
            Err(ambiguity) => {
                let provenance = context::provenance_for(modules.as_ref(), Some(&ambiguity));
                bail!(provenance_error(&provenance, &ambiguity));
            }
        }
    } else {
        (None, Vec::new())
    };
    let module = module.as_deref();
    // Loose metadata retains one output per path, as before. Do not keep all
    // restored blobs in the folder cache just to avoid a repeated permutation.
    let (out, report, layout, research) =
        restore_metadata_with_module(&data, module, cache.research())
            .with_context(|| label.to_owned())?;
    if report.remapped > 0 {
        write_metadata_blob(dest, &out)?;
        if verbose {
            crate::ui::write_to(dest, false);
        }
    }
    Ok(LooseMetadataOutcome {
        version: report.version,
        remapped: report.remapped,
        provenance,
        layout,
        research,
    })
}

/// Group loose `.apk` files that are a split set: same parent directory and
/// the same manifest package name plus version. Bundles are never grouped
/// with anything. Order inside a group does not matter; the caller restores
/// every library in the group before any of its metadata.
#[cfg(test)]
pub(crate) fn loose_apk_groups(packages: &[PathBuf]) -> Vec<Vec<PathBuf>> {
    loose_apk_groups_cached(packages, &mut context::AndroidRunCache::default())
}

pub(crate) fn loose_apk_groups_cached(
    packages: &[PathBuf],
    cache: &mut context::AndroidRunCache,
) -> Vec<Vec<PathBuf>> {
    let mut groups: Vec<(context::AppKey, Vec<PathBuf>)> = Vec::new();
    let mut alone = Vec::new();
    for package in packages {
        let extension = package.extension().and_then(|value| value.to_str());
        let is_apk = extension.is_some_and(|value| value.eq_ignore_ascii_case("apk"));
        if !is_apk {
            alone.push(vec![package.clone()]);
            continue;
        }
        let key = apk_manifest_key(package, cache);
        if let Some(key) = key {
            if let Some((_, members)) = groups.iter_mut().find(|(existing, _)| existing == &key) {
                members.push(package.clone());
            } else {
                groups.push((key, vec![package.clone()]));
            }
        } else {
            alone.push(vec![package.clone()]);
        }
    }
    let mut grouped: Vec<_> = groups.into_iter().map(|(_, members)| members).collect();
    grouped.append(&mut alone);
    grouped
}

fn apk_manifest_key(
    package: &Path,
    cache: &mut context::AndroidRunCache,
) -> Option<context::AppKey> {
    let mut archive = cache.archive.open_archive(package).ok()?;
    let parent = package
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let inventory = context::inventory_manifest_package(
        &mut archive,
        package,
        parent,
        &package.display().to_string(),
        &mut cache.archive,
    )
    .ok()?;
    match inventory.key {
        context::AppKey::Manifest { .. } => Some(inventory.key),
        _ => None,
    }
}

/// Restore one package against the folder run's cache. Successful library
/// identities are published back through the cache itself; the public
/// [`restore_package`] wrapper remains for callers that only have a `HashSet`.
pub(crate) fn restore_package_cached(
    package: &Path,
    rel: &Path,
    out_root: &Path,
    cache: &mut context::AndroidRunCache,
    verbose: bool,
) -> Result<Vec<EntryOutcome>> {
    let limits = cache.limits;
    restore_package_with_restorer(
        package,
        rel,
        out_root,
        cache,
        verbose,
        &mut context::EngineRestorer::new(limits, cache.research()),
    )
}

/// One folder split-set: every library in the group, then every metadata blob.
/// A library-only pass records modules without writing metadata, so a metadata
/// blob in an earlier sibling cannot run before a library in a later one.
/// `members` pairs each package with the relative path its outputs live under.
///
/// The relative path is computed by the caller (see `job::rel_in_tree`) and is
/// always relative. This function never derives it: `Path::join` with an
/// absolute path discards the output root, so a fallback here could write
/// outside the caller's directory — unacceptable for a dry run or inspection,
/// whose whole contract is that it keeps nothing outside its own workspace.
pub(crate) fn restore_apk_group(
    members: &[(&Path, &Path)],
    out_root: &Path,
    cache: &mut context::AndroidRunCache,
    verbose: bool,
) -> Result<Vec<EntryOutcome>> {
    let limits = cache.limits;
    let mut outcomes = Vec::new();
    for (package, rel) in members {
        outcomes.extend(restore_package_pass(
            package,
            rel,
            out_root,
            cache,
            verbose,
            &mut context::EngineRestorer::new(limits, cache.research()),
            PackagePass::Libraries,
        )?);
    }
    for (package, rel) in members {
        outcomes.extend(restore_package_pass(
            package,
            rel,
            out_root,
            cache,
            verbose,
            &mut context::EngineRestorer::new(limits, cache.research()),
            PackagePass::Metadata,
        )?);
    }
    Ok(outcomes)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PackagePass {
    All,
    Libraries,
    Metadata,
}

/// Content identity for cross-source deduplication: the same library may
/// appear loose in a tree, in its `.apk`, and again in an `.apks`/`.xapk`
/// bundle — restore it once, at the highest-priority source's destination.
pub fn content_identity(data: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(data);
    hex_digest(&digest.finalize())
}

/// A failure that still carries what the attempt had already observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResearchCapture {
    /// Extraction ran and produced a report; the restoration after it failed.
    Library(crate::report::AndroidResearchReport),
    /// A metadata transform's seeds, discovery, and failure reason.
    Metadata(serde_json::Value),
}

/// A transform error that still carries what the attempt observed.
///
/// Research inspection wants the seeds it tried and the reason each failed even
/// when no output was produced. The error keeps its ordinary `anyhow` chain —
/// callers that do not care about research see exactly the same message.
#[derive(Debug)]
pub(crate) struct LossyError {
    inner: anyhow::Error,
    capture: ResearchCapture,
}

impl LossyError {
    pub(crate) fn new(inner: anyhow::Error, capture: ResearchCapture) -> Self {
        Self { inner, capture }
    }

    fn capture(&self) -> &ResearchCapture {
        &self.capture
    }
}

impl std::fmt::Display for LossyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl std::error::Error for LossyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Keep the whole wrapped chain reachable: callers classify the original
        // error (an unsupported version, a malformed blob) by walking it.
        Some(self.inner.as_ref())
    }
}

/// The research captured for a failure, if the error (or anything it wraps)
/// carries one.
pub(crate) fn error_research(error: &anyhow::Error) -> Option<&ResearchCapture> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<LossyError>())
        .map(LossyError::capture)
}

/// [`capture`] with the same rule, exposed to the module's tests so a failed
/// restore can be exercised without a protected fixture.
#[cfg(test)]
pub(crate) fn capture_for_tests(
    error: anyhow::Error,
    research: Option<ResearchCapture>,
) -> anyhow::Error {
    capture(error, research)
}

/// Wrap `error` with the capture, when there is one.
fn capture(error: anyhow::Error, capture: Option<ResearchCapture>) -> anyhow::Error {
    match capture {
        Some(capture) => LossyError::new(error, capture).into(),
        None => error,
    }
}

/// Serialize one engine report for research output.
///
/// The report is the engine's own, unchanged; only filesystem locations are
/// rewritten to logical labels. A research report outlives the run, and a
/// scratch path that no longer exists is noise — or worse, a misleading hint
/// about where an output was "kept".
fn report_value<T: serde::Serialize>(report: &T, labels: &[(&Path, &str)]) -> serde_json::Value {
    let mut value = serde_json::to_value(report).unwrap_or(serde_json::Value::Null);
    scrub_paths(&mut value, labels);
    value
}

fn scrub_paths(value: &mut serde_json::Value, labels: &[(&Path, &str)]) {
    // Longest location first: a nested path starts with its parent, and the
    // more specific label is the one that describes it.
    let mut rules: Vec<(String, &str)> = labels
        .iter()
        .map(|(path, label)| (path.display().to_string(), *label))
        .filter(|(rendered, _)| !rendered.is_empty())
        .collect();
    rules.sort_by_key(|(rendered, _)| std::cmp::Reverse(rendered.len()));
    scrub_value(value, &rules);
}

fn scrub_value(value: &mut serde_json::Value, rules: &[(String, &str)]) {
    match value {
        serde_json::Value::String(text) => {
            for (rendered, label) in rules {
                if text.contains(rendered.as_str()) {
                    *text = text.replace(rendered.as_str(), label);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scrub_value(item, rules);
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values_mut() {
                scrub_value(field, rules);
            }
        }
        _ => {}
    }
}

/// Restore an il2cpp metadata blob. Paired v24.1 Android packages use the
/// method-index profile recovered from module 0x0C; later Android layouts use
/// the seeded MethodDef RID permutation before falling back to the structural
/// remap used by the Windows builds.
///
/// The Android variant obfuscates MethodDef RIDs with a keyed five-round
/// permutation; the correct seed is recovered by intersecting per-image key
/// residues, and the restore *validates* every restored RID against its
/// canonical per-module index — so an unusable seed fails loudly and the
/// caller falls through to the structural remap, which targets the same
/// canonical form. Both paths are no-ops (`remapped == 0`) on an
/// already-clean blob.
pub fn restore_metadata_bytes(data: &[u8]) -> anyhow::Result<(Vec<u8>, senbei_metadata::Report)> {
    let (out, report, _route) = restore_metadata_bytes_with_module(data, None)?;
    Ok((out, report))
}

pub(crate) fn restore_metadata_bytes_with_module(
    data: &[u8],
    method_index_module: Option<&[u8]>,
) -> anyhow::Result<(Vec<u8>, senbei_metadata::Report, senbei_engine::LayoutKind)> {
    let (out, report, layout, _) = restore_metadata_with_module(data, method_index_module, false)?;
    Ok((out, report, layout))
}

/// [`restore_metadata_bytes_with_module`], optionally keeping the facts the
/// transform observed on the way.
///
/// The research value is produced by the same pass that does the work: the
/// seed candidates discovery found (or why it found none), the seeds actually
/// tried, and the transform's own report. Nothing is re-run for it, and it
/// survives a transform that fails — a failing trial is exactly what the
/// caller wants to see.
pub(crate) fn restore_metadata_with_module(
    data: &[u8],
    method_index_module: Option<&[u8]>,
    research: bool,
) -> anyhow::Result<(
    Vec<u8>,
    senbei_metadata::Report,
    senbei_engine::LayoutKind,
    Option<serde_json::Value>,
)> {
    use senbei_engine::LayoutKind;
    let version = data
        .get(4..8)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes);
    let mut facts = MetadataFacts {
        version,
        route: "method_indices",
        module_0c_sha256: method_index_module.map(content_identity),
        ..MetadataFacts::default()
    };
    // Keep what the attempt has seen so far, then wrap the failure with it.
    let fail = |facts: &mut MetadataFacts, error: anyhow::Error| -> anyhow::Error {
        facts.error = Some(format!("{error:#}"));
        let kept = research.then(|| facts.clone().into_value());
        capture(error, kept.map(ResearchCapture::Metadata))
    };

    if version == Some(24) {
        // v24.1 method indices come only from this application's module 0x0C.
        // Falling through to the structural remap would report "unsupported
        // version" and could be mistaken for a clean skip. No module is a
        // failed binding, not an unsupported layout.
        let Some(module) = method_index_module else {
            let error = anyhow::Error::new(Coded::new(Msg::NoModule0c));
            return Err(fail(&mut facts, error));
        };
        let (out, report) = senbei_metadata::android::restore_method_indices_v24_1(data, module)
            .map_err(anyhow::Error::new)
            .map_err(|error| fail(&mut facts, error))?;
        facts.version = Some(report.version);
        facts.report = Some(serde_json::json!({
            "version": report.version,
            "methods": report.methods,
            "active_methods": report.active_methods,
            "changed_indices": report.changed_indices,
            "exception_count": report.exception_count,
            "seed": report.seed,
        }));
        return Ok((
            out,
            senbei_metadata::Report {
                version: report.version,
                methods: report.methods,
                remapped: report.changed_indices,
                modules: 0,
            },
            LayoutKind::MetadataMethodIndices,
            research.then(|| facts.into_value()),
        ));
    }

    // Seed discovery is the only step that can say why a seeded restore was
    // never tried, so its own outcome is recorded for research. Whether the
    // seeded route runs at all is decided exactly as before.
    let mut seeded_layout = false;
    match senbei_metadata::android::discover_method_token_seeds(data) {
        Ok(found) if matches!(found.version, 29 | 31 | 39) => {
            seeded_layout = true;
            facts.seed_candidates = found.seed_candidates.clone();
            if research {
                facts.discovery = serde_json::to_value(&found).ok();
            }
        }
        Ok(_) => {}
        Err(error) => {
            if research {
                facts.discovery_error = Some(format!("{error}"));
            }
        }
    }
    if seeded_layout {
        let mut seeds = facts.seed_candidates.clone();
        if seeds.is_empty() {
            seeds.push(senbei_metadata::android::DEFAULT_METHOD_TOKEN_SEED);
        }
        // Trial-and-validate: a wrong seed fails the restore's full-coverage
        // RID check, so ambiguous candidates cost one extra pass each and a
        // build with an unseeded permutation falls through to the structural
        // remap rather than producing a silently wrong file.
        for seed in seeds {
            facts.tried_seeds.push(seed);
            if let Ok((out, report)) = senbei_metadata::android::restore_method_tokens(data, seed) {
                facts.route = "seeded";
                facts.version = Some(report.version);
                facts.report = Some(serde_json::json!({
                    "version": report.version,
                    "seed": report.seed,
                    "encryption_status": report.encryption_status,
                    "images": report.images,
                    "images_with_methods": report.images_with_methods,
                    "types": report.types,
                    "methods": report.methods,
                    "visited_methods": report.visited_methods,
                    "already_correct_before": report.already_correct_before,
                    "correct_after": report.correct_after,
                    "changed_tokens": report.changed_tokens,
                    "transformed_images": report.transformed_images,
                }));
                return Ok((
                    out,
                    senbei_metadata::Report {
                        version: report.version,
                        methods: report.methods,
                        remapped: report.changed_tokens,
                        modules: report.images_with_methods,
                    },
                    LayoutKind::MetadataSeeded,
                    research.then(|| facts.into_value()),
                ));
            }
        }
    }

    facts.route = "structural";
    let (out, report) = senbei_metadata::deobfuscate(data)
        .map_err(anyhow::Error::new)
        .map_err(|error| fail(&mut facts, error))?;
    facts.version = Some(report.version);
    facts.report = Some(serde_json::json!({
        "version": report.version,
        "methods": report.methods,
        "remapped": report.remapped,
        "modules": report.modules,
    }));
    Ok((
        out,
        report,
        LayoutKind::MetadataStructural,
        research.then(|| facts.into_value()),
    ))
}

/// What one metadata transform observed, independent of whether it succeeded.
#[derive(Debug, Clone, Default)]
struct MetadataFacts {
    route: &'static str,
    version: Option<u32>,
    /// Seeds the transform actually tried, in order.
    tried_seeds: Vec<u32>,
    /// Candidates seed discovery reported.
    seed_candidates: Vec<u32>,
    /// The discovery report, when it found a supported layout.
    discovery: Option<serde_json::Value>,
    /// Why seed discovery declined, when it did.
    discovery_error: Option<String>,
    /// The transform's own report.
    report: Option<serde_json::Value>,
    /// Identity of the module `0x0C` this transform bound to, when it had one.
    module_0c_sha256: Option<String>,
    /// Why the transform stopped, when it did.
    error: Option<String>,
}

impl MetadataFacts {
    fn into_value(self) -> serde_json::Value {
        serde_json::json!({
            "route": self.route,
            "version": self.version,
            "tried_seeds": self.tried_seeds,
            "seed_candidates": self.seed_candidates,
            "discovery": self.discovery,
            "discovery_error": self.discovery_error,
            "report": self.report,
            "module_0c_sha256": self.module_0c_sha256,
            "error": self.error,
        })
    }
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
    /// Libraries whose module `0x0C` was paired with this metadata entry.
    /// Empty for libraries and for metadata that had no paired module.
    pub provenance: Vec<String>,
    /// Route the transform took, for metadata entries only.
    pub layout: Option<senbei_engine::LayoutKind>,
    /// Raw il2cpp metadata version, for metadata entries only.
    pub metadata_version: Option<u32>,
    /// Structural diagnostics from the restore of this entry. `None` for
    /// metadata entries, duplicates, and restorers without a report.
    pub validation: Option<ValidationDiagnostics>,
    /// The engines' own reports for a library entry. Only a research run keeps
    /// them, and only for an entry that actually restored.
    pub research: Option<crate::report::AndroidResearchReport>,
    /// Seeds tried, discovery, and the transform report for a metadata entry.
    /// Only a research run keeps them, and they survive a failed transform.
    pub metadata_research: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A protected shared library, restored.
    So,
    /// An il2cpp metadata blob, de-obfuscated (`remapped` method fields changed).
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
    /// A metadata blob whose protected method fields were already canonical; no copy written.
    Unchanged,
    /// Recognised as a target but the restore failed.
    Failed(anyhow::Error),
}

struct PackageRestoreState<'a, R> {
    restorer: &'a mut R,
    cache: &'a mut context::AndroidRunCache,
    verbose: bool,
}

fn package_entry_priority(path: &Path) -> u8 {
    if is_so_name(path) { 0 } else { 1 }
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
    restore_package_with_limits(
        package,
        rel,
        out_root,
        seen,
        verbose,
        &ResourceLimits::default(),
    )
}

/// Restore one Android package with explicit archive and decoder ceilings.
pub fn restore_package_with_limits(
    package: &Path,
    rel: &Path,
    out_root: &Path,
    seen: &mut HashSet<String>,
    verbose: bool,
    limits: &ResourceLimits,
) -> Result<Vec<EntryOutcome>> {
    let limits = *limits;
    // `seen` is the public successful-content set shared with loose libraries.
    // Metadata recovery context does not fit in that set, so this wrapper keeps
    // a run-scoped cache and only publishes content identities of entries that
    // actually succeeded. A caller that passes identities restored by an earlier
    // package still skips those bytes; module context for metadata is rebuilt
    // inside this package (one package, or one manifest-scoped bundle, is one
    // application boundary).
    restore_package_with_limits_and_research(package, rel, out_root, seen, verbose, &limits, false)
}

/// [`restore_package_with_limits`], optionally keeping the engines' reports for
/// research output. One package is one application boundary either way.
pub(crate) fn restore_package_with_limits_and_research(
    package: &Path,
    rel: &Path,
    out_root: &Path,
    seen: &mut HashSet<String>,
    verbose: bool,
    limits: &ResourceLimits,
    research: bool,
) -> Result<Vec<EntryOutcome>> {
    let limits = *limits;
    let mut cache = context::AndroidRunCache::with_limits(&limits);
    cache.research = research;
    for identity in seen.iter().cloned() {
        cache.insert_prior_success(identity);
    }
    let research = cache.research();
    let outcomes = restore_package_with_restorer(
        package,
        rel,
        out_root,
        &mut cache,
        verbose,
        &mut context::EngineRestorer::new(limits, research),
    );
    // Publish successes even when the package returns `Err`. The caller's set
    // is only replaced after that, so a panic still leaves the old successes.
    let succeeded = cache.successful_content_identities();
    seen.clear();
    seen.extend(succeeded);
    outcomes
}

pub(crate) fn restore_package_with_restorer<R: context::LibraryRestorer>(
    package: &Path,
    rel: &Path,
    out_root: &Path,
    cache: &mut context::AndroidRunCache,
    verbose: bool,
    restorer: &mut R,
) -> Result<Vec<EntryOutcome>> {
    restore_package_pass(
        package,
        rel,
        out_root,
        cache,
        verbose,
        restorer,
        PackagePass::All,
    )
}

fn restore_package_pass<R: context::LibraryRestorer>(
    package: &Path,
    rel: &Path,
    out_root: &Path,
    cache: &mut context::AndroidRunCache,
    verbose: bool,
    restorer: &mut R,
    pass: PackagePass,
) -> Result<Vec<EntryOutcome>> {
    let bundle = package
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("apks") || value.eq_ignore_ascii_case("xapk")
        });
    let mut archive = cache.archive.open_archive(package)?;
    let temporary = tempfile::tempdir().context("create package workspace")?;
    let mut outcomes = Vec::new();
    let mut state = PackageRestoreState {
        restorer,
        cache,
        verbose,
    };

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
            bail!(Coded::new(Msg::UnsafePackageEntry {
                package: package.display().to_string(),
            }));
        };
        if bundle {
            if name
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("apk"))
            {
                nested.push((index, name));
            }
        } else if is_android_entry_name(&name) {
            direct.push((index, name));
        }
    }
    // One direct package is one application inside its own package set (the
    // package file). Its manifest names it by package plus version; without
    // both, the package is isolated. The ZIP file name is not a package id.
    // Inventory already walked this central directory; entry extraction below
    // reuses the same open and must not be charged as a second package.
    let direct_inventory = if direct.is_empty() {
        None
    } else {
        Some(context::inventory_manifest_package(
            &mut archive,
            package,
            package
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new(".")),
            &package.display().to_string(),
            &mut state.cache.archive,
        )?)
    };
    direct.retain(|(_, name)| match pass {
        PackagePass::Libraries => package_entry_priority(name) == 0,
        PackagePass::Metadata => package_entry_priority(name) == 1,
        PackagePass::All => true,
    });
    direct.sort_by_key(|(_, name)| package_entry_priority(name));
    if let Some(inventory) = direct_inventory {
        for (index, name) in direct {
            let label = format!("{}::{}", rel.display(), name.display());
            let dest = out_root.join(rel).join(crate::job::out_name(&name));
            let mut entry_outcomes = restore_package_entry(
                &mut archive,
                index,
                &label,
                &dest,
                &temporary,
                &inventory.key,
                &mut state,
            )
            .with_context(|| format!("extract `{label}`"))?;
            outcomes.append(&mut entry_outcomes);
        }
    }
    struct NestedPackage {
        label: PathBuf,
        path: PathBuf,
        base: PathBuf,
        app: context::AppKey,
        /// Manifest inventory, including the reopen key. Extraction opens
        /// `path` again; `inventory.archive` is not charged a second time.
        inventory: context::PackageInventory,
        entries: Vec<(usize, PathBuf)>,
    }

    let mut nested_packages = Vec::with_capacity(nested.len());
    for (index, name) in nested {
        state.cache.limits.check_depth(1)?;
        let nested_label = rel.join(&name);
        let nested_path = extract_entry(
            &mut archive,
            index,
            &temporary,
            &nested_label,
            &mut state.cache.archive,
        )
        .with_context(|| format!("extract `{}`", nested_label.display()))?;
        let mut nested_archive = state.cache.archive.open_archive(&nested_path)?;
        // Manifest first, before any library or metadata entry is chosen. Splits
        // that name the same package and version, inside this bundle only, share
        // one context. A split with no recognized package name or version is
        // isolated and cannot borrow a sibling's module. `nested_path` is the
        // reopen key: the central directory listed here is not charged again
        // when entries are extracted below.
        let inventory = context::inventory_manifest_package(
            &mut nested_archive,
            &nested_path,
            package,
            &nested_path.display().to_string(),
            &mut state.cache.archive,
        )?;
        let mut entries = Vec::new();
        for nested_index in 0..nested_archive.len() {
            let (entry_name, is_dir) = {
                let entry = nested_archive.by_index(nested_index)?;
                (entry.enclosed_name(), entry.is_dir())
            };
            if !is_dir {
                let Some(entry_name) = entry_name else {
                    bail!(Coded::new(Msg::UnsafeNestedEntry {
                        path: nested_label.display().to_string(),
                    }));
                };
                if is_android_entry_name(&entry_name) {
                    entries.push((nested_index, entry_name));
                }
            }
        }
        nested_packages.push(NestedPackage {
            label: nested_label,
            path: nested_path,
            base: rel.join(name.with_extension("")),
            app: inventory.key.clone(),
            inventory,
            entries,
        });
    }

    // A bundle can put libil2cpp.so in an ABI split while metadata stays in
    // base.apk. Splits of the same manifest package share one context. All of
    // that application's libraries are restored before its metadata, independent
    // of nested-APK order. Different package names never share a module.
    let mut app_order: Vec<context::AppKey> = Vec::new();
    for nested_package in &nested_packages {
        if !app_order.contains(&nested_package.app) {
            app_order.push(nested_package.app.clone());
        }
    }
    let priorities: &[u8] = match pass {
        PackagePass::Libraries => &[0],
        PackagePass::Metadata => &[1],
        PackagePass::All => &[0, 1],
    };
    for app in &app_order {
        for priority in priorities {
            for nested_package in nested_packages.iter().filter(|nested| &nested.app == app) {
                // Same file the inventory listed. Reopening is not a new package.
                debug_assert_eq!(
                    nested_package.inventory.archive.reopen_key,
                    nested_package.path
                );
                let mut nested_archive = state.cache.archive.open_archive(&nested_package.path)?;
                for (nested_index, entry_name) in nested_package
                    .entries
                    .iter()
                    .filter(|(_, entry_name)| package_entry_priority(entry_name) == *priority)
                {
                    let label = format!(
                        "{}::{}",
                        nested_package.label.display(),
                        entry_name.display()
                    );
                    let dest = out_root
                        .join(&nested_package.base)
                        .join(crate::job::out_name(entry_name));
                    let mut entry_outcomes = restore_package_entry(
                        &mut nested_archive,
                        *nested_index,
                        &label,
                        &dest,
                        &temporary,
                        app,
                        &mut state,
                    )
                    .with_context(|| format!("extract `{label}`"))?;
                    outcomes.append(&mut entry_outcomes);
                }
            }
        }
    }
    Ok(outcomes)
}

/// Probe one extracted package entry and restore it when it is a target.
/// Returns one outcome per produced/consumed artifact: the entry itself, plus
/// an `EmbeddedMetadata` outcome when the restored library carried a blob.
///
/// `app` is the application this entry was inventoried into. Libraries record
/// their module there; metadata reads it back and refuses a conflicting or
/// missing binding before writing.
fn restore_package_entry<R: Read + Seek, T: context::LibraryRestorer>(
    archive: &mut ZipArchive<R>,
    index: usize,
    label: &str,
    dest: &Path,
    temporary: &tempfile::TempDir,
    app: &context::AppKey,
    state: &mut PackageRestoreState<'_, T>,
) -> Result<Vec<EntryOutcome>> {
    let entry_path = extract_entry(
        archive,
        index,
        temporary,
        Path::new(label),
        &mut state.cache.archive,
    )?;
    let entry_file =
        File::open(&entry_path).with_context(|| format!("open extracted `{label}`"))?;
    let entry_data = map_read_only(&entry_file, &entry_path)?;

    let protected_override = state.restorer.protected_override(&entry_path);
    let is_so = protected_override.is_some()
        || (is_elf64_aarch64(&entry_data)
            && senbei_engine::android::probe_libil2cpp_with_limits(
                &entry_data,
                &state.cache.limits,
            )?);
    let is_meta = !is_so && senbei_metadata::is_metadata(&entry_data);
    let outcome = |kind, status, provenance: Vec<String>| EntryOutcome {
        label: label.to_owned(),
        dest: dest.to_path_buf(),
        kind,
        status,
        provenance,
        layout: None,
        metadata_version: None,
        validation: None,
        research: None,
        metadata_research: None,
    };
    if !is_so && !is_meta {
        return Ok(vec![outcome(
            EntryKind::So,
            EntryStatus::NotTarget,
            Vec::new(),
        )]);
    }
    let identity = content_identity(&entry_data);
    if is_so && state.cache.library(&identity).is_some() {
        if let Some(cached) = state.cache.library(&identity).cloned() {
            // Duplicate libraries still belong to the application that contains
            // them. The cached module is recorded here and no output is written.
            record_module(state.cache, app, &cached, label);
        }
        return Ok(vec![outcome(
            EntryKind::So,
            EntryStatus::Duplicate,
            Vec::new(),
        )]);
    }

    if is_so {
        drop(entry_data);
        drop(entry_file);
        let prior = state.cache.is_prior_success(&identity);
        let workspace = prior
            .then(|| tempfile::tempdir_in(temporary.path()))
            .transpose()
            .context("create duplicate context workspace")?;
        let scratch = workspace
            .as_ref()
            .map(|directory| directory.path().join("restored.so"));
        let restore_dest = scratch.as_deref().unwrap_or(dest);
        return Ok(
            match state
                .restorer
                .restore(&entry_path, restore_dest, state.verbose)
            {
                Ok(restored) => {
                    // A prior content-only success is restored only in the
                    // private workspace to recover its module context.
                    let mut outcomes = Vec::new();
                    let mut embedded_failed = None;
                    if !prior {
                        // The engine's own validation diagnostics for exactly
                        // these bytes; nothing is re-validated here.
                        let mut restored_outcome =
                            outcome(EntryKind::So, EntryStatus::Restored, Vec::new());
                        restored_outcome.validation = restored.validation.clone();
                        restored_outcome.research = restored.research.clone();
                        outcomes.push(restored_outcome);
                    }
                    if !prior && let Some(blob) = &restored.embedded_metadata {
                        let meta_dest = embedded_metadata_dest(dest);
                        match write_metadata_blob(&meta_dest, blob) {
                            Ok(()) => outcomes.push(EntryOutcome {
                                label: format!("{label} (embedded metadata)"),
                                dest: meta_dest,
                                kind: EntryKind::EmbeddedMetadata,
                                status: EntryStatus::Restored,
                                provenance: Vec::new(),
                                layout: None,
                                metadata_version: None,
                                validation: None,
                                research: None,
                                metadata_research: None,
                            }),
                            Err(error) => embedded_failed = Some(error),
                        }
                    }
                    if let Some(error) = embedded_failed {
                        vec![outcome(
                            EntryKind::So,
                            EntryStatus::Failed(error),
                            Vec::new(),
                        )]
                    } else {
                        let cached = context::CachedLibrary {
                            method_index_module: restored.method_index_module.clone(),
                            module_image: restored.module_image.clone(),
                        };
                        record_module(state.cache, app, &cached, label);
                        state.cache.insert_library(identity, cached);
                        if prior {
                            vec![outcome(EntryKind::So, EntryStatus::Duplicate, Vec::new())]
                        } else {
                            outcomes
                        }
                    }
                }
                Err(error) => {
                    // A restore that failed after extraction keeps what the
                    // extraction already reported, alongside the error.
                    let research = match error_research(&error) {
                        Some(ResearchCapture::Library(report)) => Some(report.clone()),
                        _ => None,
                    };
                    let mut failed = outcome(EntryKind::So, EntryStatus::Failed(error), Vec::new());
                    failed.research = research;
                    vec![failed]
                }
            },
        );
    }

    let version = metadata_version(&entry_data);
    // Module 0x0C is a v24.1 input only. Later layouts ignore it, so a missing
    // or conflicting module does not block them and is not listed as paired.
    let (module, provenance) = if version == Some(24) {
        let modules = state.cache.modules(app).cloned();
        match context::binding_module(modules.as_ref()) {
            Ok(module) => (
                module.map(|bytes| bytes.to_vec()),
                context::provenance_for(modules.as_ref(), None),
            ),
            Err(ambiguity) => {
                let provenance = context::provenance_for(modules.as_ref(), Some(&ambiguity));
                return Ok(vec![outcome(
                    EntryKind::Metadata { remapped: 0 },
                    EntryStatus::Failed(anyhow::Error::new(provenance_error(
                        &provenance,
                        &ambiguity,
                    ))),
                    provenance_labels(&provenance),
                )]);
            }
        }
    } else {
        (None, context::MetadataProvenance::default())
    };
    let module_bytes = module;
    let module = module_bytes.as_deref();
    let context_identity = context::metadata_context_identity(module);
    if let Some(cached) = state.cache.metadata(&identity, &context_identity).cloned() {
        // A repeated blob is not written again. The cached bytes stay available
        // for a *different* recovery context; this context already succeeded.
        let kind = match &cached {
            context::CachedMetadata::Unchanged => EntryKind::Metadata { remapped: 0 },
            context::CachedMetadata::Restored { remapped, .. } => EntryKind::Metadata {
                remapped: *remapped,
            },
        };
        let mut entry_outcome =
            outcome(kind, EntryStatus::Duplicate, provenance_labels(&provenance));
        entry_outcome.metadata_version = version;
        return Ok(vec![entry_outcome]);
    }

    // Metadata entry: write only when the restore actually changed protected
    // method fields — a clean blob needs no copy (same contract as loose files).
    // The binding was resolved before this write.
    let (kind, status, layout, metadata_research) =
        match restore_metadata_with_module(&entry_data, module, state.cache.research()) {
            Ok((out, report, layout, research)) if report.remapped > 0 => {
                let kind = EntryKind::Metadata {
                    remapped: report.remapped,
                };
                match write_metadata_blob(dest, &out) {
                    Ok(()) => {
                        state.cache.insert_metadata(
                            identity,
                            context_identity,
                            context::CachedMetadata::Restored {
                                remapped: report.remapped,
                            },
                        );
                        (kind, EntryStatus::Restored, Some(layout), research)
                    }
                    Err(error) => (kind, EntryStatus::Failed(error), Some(layout), research),
                }
            }
            // A blob that needed no change still reports the route that ran.
            Ok((_, _report, layout, research)) => {
                state.cache.insert_metadata(
                    identity,
                    context_identity,
                    context::CachedMetadata::Unchanged,
                );
                (
                    EntryKind::Metadata { remapped: 0 },
                    EntryStatus::Unchanged,
                    Some(layout),
                    research,
                )
            }
            Err(error) => {
                // The seeds it tried and the reason it stopped survive the failure.
                let research = error_research(&error).and_then(|capture| match capture {
                    ResearchCapture::Metadata(value) => Some(value.clone()),
                    ResearchCapture::Library(_) => None,
                });
                (
                    EntryKind::Metadata { remapped: 0 },
                    EntryStatus::Failed(error),
                    None,
                    research,
                )
            }
        };
    let mut entry_outcome = outcome(kind, status, provenance_labels(&provenance));
    entry_outcome.layout = layout;
    entry_outcome.metadata_version = version;
    entry_outcome.metadata_research = metadata_research;
    Ok(vec![entry_outcome])
}

fn record_module(
    cache: &mut context::AndroidRunCache,
    app: &context::AppKey,
    restored: &context::CachedLibrary,
    label: &str,
) {
    if let Some(module) = &restored.method_index_module {
        cache.modules_mut(app).record(
            module,
            context::ModuleSource {
                label: label.to_owned(),
                image: restored.module_image.clone(),
            },
        );
    }
}

fn metadata_version(data: &[u8]) -> Option<u32> {
    data.get(4..8)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
}

fn provenance_labels(provenance: &context::MetadataProvenance) -> Vec<String> {
    provenance
        .sources
        .iter()
        .map(|source| match &source.image {
            Some(image) => format!("{} ({image})", source.label),
            None => source.label.clone(),
        })
        .collect()
}

fn provenance_error(
    provenance: &context::MetadataProvenance,
    ambiguity: &context::ContextAmbiguity,
) -> Coded {
    let msg = match ambiguity {
        context::ContextAmbiguity::Missing => Msg::NoModule0c,
        context::ContextAmbiguity::Conflicting { .. } => Msg::AmbiguousModule0c,
    };
    let why = provenance
        .note
        .clone()
        .unwrap_or_else(|| "ambiguous module 0x0C binding".to_owned());
    if provenance.sources.is_empty() {
        return Coded::with_text(msg, why);
    }
    let sources = provenance
        .sources
        .iter()
        .map(|source| source.label.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Coded::with_text(msg, format!("{why}; modules from {sources}"))
}

/// Output path for a metadata blob unwrapped from a restored library: next to
/// the library, under the standard file name (with the usual `.unpack` infix).
pub fn embedded_metadata_dest(restored_so: &Path) -> PathBuf {
    let dir = restored_so.parent().unwrap_or_else(|| Path::new("."));
    dir.join(crate::job::out_name(Path::new(METADATA_FILE_NAME)))
}

/// Write a metadata blob, creating the parent directory. The restore writes
/// its own output atomically; metadata blobs use the shared orchestration
/// atomic writer to keep the same mid-write failure semantics.
fn write_metadata_blob(dest: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create `{}`", parent.display()))?;
    }
    crate::atomic::write_atomic(dest, data)
        .map_err(anyhow::Error::from)
        .context("write metadata output")
}

/// Stream one package entry to a temporary, seekable file. The Android engine
/// needs random access to ELF section tables, while the ZIP reader itself is
/// consumed directly without creating an in-memory compressed or decompressed
/// copy.
fn extract_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    temporary: &tempfile::TempDir,
    label: &Path,
    budget: &mut archive_limits::ArchiveBudget,
) -> Result<PathBuf> {
    let mut entry = archive.by_index(index)?;
    let output_size = entry.size();
    let mut file = tempfile::Builder::new()
        .prefix("entry-")
        .tempfile_in(temporary.path())?;
    {
        let mut output = BufWriter::new(file.as_file_mut());
        budget.copy_entry(
            &mut entry,
            &mut output,
            output_size,
            &label.display().to_string(),
        )?;
        output.flush()?;
    }
    // A failed copy drops the unique temporary immediately. Successful entries
    // remain seekable until the enclosing package workspace is dropped.
    file.into_temp_path()
        .keep()
        .context("retain extracted package entry")
}

fn map_read_only(file: &File, path: &Path) -> Result<Mmap> {
    // SAFETY: the file descriptor remains open for the returned mapping's
    // lifetime, and this mapping is read-only.
    unsafe { MmapOptions::new().map(file) }
        .with_context(|| format!("map extracted `{}`", path.display()))
}
