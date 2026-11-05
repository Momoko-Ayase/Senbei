//! Application-scoped module `0x0C` context for Android metadata recovery.
//!
//! One decoded module belongs to one application. Split APKs of that application
//! share it; unrelated games under the same scan do not. A metadata blob is
//! restored only after its application context is unambiguous, and the identity
//! of a successful restore includes that context: the same encrypted bytes can
//! decode differently under two module profiles.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

use anyhow::Result;

/// Where a decoded module `0x0C` image was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleSource {
    /// Protected library this module was recovered from (package label or path).
    pub label: String,
    /// Stage-2 image name inside that library, when the restorer reported one.
    pub image: Option<String>,
}

/// One application's collected module `0x0C` images.
///
/// Distinct byte profiles are kept. Duplicate libraries populate the same
/// context instead of replacing it, so a later game cannot win by being last.
#[derive(Debug, Default, Clone)]
pub(crate) struct ApplicationModules {
    profiles: BTreeMap<String, Vec<u8>>,
    sources: Vec<ModuleSource>,
}

impl ApplicationModules {
    pub(crate) fn record(&mut self, module: &[u8], source: ModuleSource) {
        let identity = crate::android::content_identity(module);
        self.profiles
            .entry(identity)
            .or_insert_with(|| module.to_vec());
        self.sources.push(source);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// The single module image, or `None` when this application recovered none
    /// or more than one distinct profile.
    pub(crate) fn unambiguous_module(&self) -> Option<&[u8]> {
        let mut values = self.profiles.values();
        let first = values.next()?;
        values.next().is_none().then_some(first.as_slice())
    }

    pub(crate) fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    pub(crate) fn sources(&self) -> &[ModuleSource] {
        &self.sources
    }
}

/// Why a metadata blob cannot be paired with exactly one module `0x0C`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContextAmbiguity {
    /// No library in this application yielded a module.
    Missing,
    /// Libraries in this application yielded more than one distinct module.
    Conflicting { profiles: usize },
}

/// Run-scoped cache of restored libraries and application module contexts.
///
/// The public package API still takes a content-identity set. This cache is
/// internal: a library hit reuses only its recovered module context, while a
/// metadata hit is keyed by recovery context as well as the encrypted bytes.
#[derive(Debug, Default)]
pub(crate) struct AndroidRunCache {
    pub(super) limits: senbei_engine::android::ResourceLimits,
    pub(super) archive: super::archive_limits::ArchiveBudget,
    apps: HashMap<AppKey, ApplicationModules>,
    /// Successfully restored protected libraries, keyed by encrypted content.
    libraries: HashMap<String, CachedLibrary>,
    /// Successfully handled metadata, keyed by encrypted content and context.
    metadata: HashMap<MetadataCacheKey, CachedMetadata>,
    /// Content identities already restored before this cache existed (the public
    /// `HashSet` contract). They skip a repeat of the same bytes but carry no
    /// module image, so they never become another application's profile.
    prior_success: std::collections::HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MetadataCacheKey {
    content: String,
    context: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CachedLibrary {
    /// Module `0x0C` from a library whose restore, including any embedded
    /// metadata write, succeeded. The restored image is not kept: a duplicate
    /// writes nothing.
    pub method_index_module: Option<Vec<u8>>,
    pub module_image: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum CachedMetadata {
    /// Successfully written package metadata. A duplicate does not write again.
    Restored { remapped: usize },
    /// The blob was already canonical under this context.
    Unchanged,
}

impl AndroidRunCache {
    pub(super) fn with_limits(limits: &senbei_engine::android::ResourceLimits) -> Self {
        Self {
            limits: *limits,
            archive: super::archive_limits::ArchiveBudget::from_limits(limits),
            ..Self::default()
        }
    }

    pub(crate) fn modules_mut(&mut self, key: &AppKey) -> &mut ApplicationModules {
        self.apps.entry(key.clone()).or_default()
    }

    pub(crate) fn modules(&self, key: &AppKey) -> Option<&ApplicationModules> {
        self.apps.get(key)
    }

    pub(crate) fn library(&self, content: &str) -> Option<&CachedLibrary> {
        self.libraries.get(content)
    }

    pub(crate) fn insert_prior_success(&mut self, content: String) {
        self.prior_success.insert(content);
    }

    pub(crate) fn is_prior_success(&self, content: &str) -> bool {
        self.prior_success.contains(content)
    }

    /// Content identities safe to publish back to the public successful-only set:
    /// prior successes plus libraries and metadata handled successfully here.
    /// Metadata identities are included because the public set still dedups a
    /// repeated blob inside one package call; cross-application recovery uses
    /// the context-keyed cache instead of this set.
    pub(crate) fn successful_content_identities(&self) -> Vec<String> {
        let mut identities: Vec<String> = self.prior_success.iter().cloned().collect();
        identities.extend(self.libraries.keys().cloned());
        identities.extend(self.metadata.keys().map(|key| key.content.clone()));
        identities.sort();
        identities.dedup();
        identities
    }

    pub(crate) fn insert_library(&mut self, content: String, cached: CachedLibrary) {
        self.libraries.entry(content).or_insert(cached);
    }

    pub(crate) fn metadata(&self, content: &str, context: &str) -> Option<&CachedMetadata> {
        self.metadata.get(&MetadataCacheKey {
            content: content.to_owned(),
            context: context.to_owned(),
        })
    }

    pub(crate) fn insert_metadata(
        &mut self,
        content: String,
        context: String,
        cached: CachedMetadata,
    ) {
        self.metadata
            .entry(MetadataCacheKey { content, context })
            .or_insert(cached);
    }
}

/// Identity of one Android application inside a folder run or one package set.
///
/// Constructed only from manifest package name **and** version, or the
/// conservative extracted `lib/<abi>/` + `assets/` boundary. The same package
/// name in a different version, or in a different bundle / loose tree, is a
/// different application. Scan-root names and ZIP entry names are never used
/// as a guess.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum AppKey {
    /// Manifest `package` plus `versionCode` (or `versionName` when the code is
    /// absent). `package_set` is the directory of the package file, or the
    /// bundle file itself, so the same name and version elsewhere do not merge.
    Manifest {
        package: String,
        version: String,
        package_set: PathBuf,
    },
    /// Parent of a real `lib/<abi>/` or `assets/` boundary.
    Extracted(PathBuf),
    /// No manifest and no extracted boundary. Isolated so it cannot see another
    /// application's modules. Not shared with any other unidentifiable input.
    Unidentifiable { source: String },
}

/// A metadata or library input assigned to one application context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopedInput {
    pub path: PathBuf,
    pub key: AppKey,
}

/// Group loose Android targets by application without crossing unrelated games.
///
/// A `lib/<abi>/` library and an `assets/` metadata blob share a context only
/// when both sit directly under the same application root. Anything else is
/// isolated. Order of `libraries` and `metadata` does not matter.
pub(crate) fn group_loose_inputs(libraries: &[PathBuf], metadata: &[PathBuf]) -> Vec<ScopedInput> {
    let mut scoped = Vec::with_capacity(libraries.len() + metadata.len());
    for path in libraries {
        scoped.push(ScopedInput {
            key: loose_library_key(path),
            path: path.clone(),
        });
    }
    for path in metadata {
        scoped.push(ScopedInput {
            key: loose_metadata_key(path),
            path: path.clone(),
        });
    }
    scoped.sort_by(|left, right| left.path.cmp(&right.path));
    scoped
}

fn loose_library_key(path: &Path) -> AppKey {
    extracted_app_root(path).map_or_else(
        || AppKey::Unidentifiable {
            source: path.to_string_lossy().into_owned(),
        },
        AppKey::Extracted,
    )
}

fn loose_metadata_key(path: &Path) -> AppKey {
    // `assets/bin/Data/Managed/Metadata/global-metadata.dat` and the shorter
    // `assets/bin/Data/Managed/global-metadata.dat` both end at `assets/`.
    assets_app_root(path).map_or_else(
        || AppKey::Unidentifiable {
            source: path.to_string_lossy().into_owned(),
        },
        AppKey::Extracted,
    )
}

/// Application root when `path` is `<root>/lib/<abi>/<library>.so`.
fn extracted_app_root(path: &Path) -> Option<PathBuf> {
    let mut components: Vec<Component<'_>> = path.components().collect();
    let file = components.pop()?;
    let abi = components.pop()?;
    let lib = components.pop()?;
    if !component_is(file, path.file_name()?.to_str()?) {
        return None;
    }
    // Compare components, not `Path::parent` display. A path joined from mixed
    // separators still yields `lib` and `<abi>` as two normal components.
    if !component_is(lib, "lib") || !matches!(abi, Component::Normal(_)) {
        return None;
    }
    let root: PathBuf = components.into_iter().collect();
    Some(if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root
    })
}

/// Application root when `path` is `<root>/assets/**/global-metadata.dat`.
fn assets_app_root(path: &Path) -> Option<PathBuf> {
    let mut components: Vec<Component<'_>> = path.components().collect();
    let name = components.pop()?;
    if !component_is(name, crate::METADATA_FILE_NAME) {
        return None;
    }
    let assets_at = components
        .iter()
        .rposition(|component| component_is(*component, "assets"))?;
    // `assets/global-metadata.dat` and `assets/**/global-metadata.dat` both
    // belong to the directory that contains `assets`.
    let root: PathBuf = components[..assets_at].iter().collect();
    Some(if root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        root
    })
}

fn component_eq(path: &Path, expected: &str) -> bool {
    // The final component must be exactly `expected`. `file_name` on a directory
    // path is that component; requiring the whole path to equal it would reject
    // every application root that is not a single path segment.
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

fn component_is(component: Component<'_>, expected: &str) -> bool {
    match component {
        Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(expected)),
        _ => false,
    }
}

/// One ZIP whose central directory was listed while naming an application.
///
/// `reopen_key` is the on-disk package (or extracted nested APK) to open again
/// when entries are restored. The resource budget charges this archive's
/// physical entry count on the first inventory pass only; reopening it for
/// entry extraction is not a second package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoriedArchive {
    pub reopen_key: PathBuf,
    /// Central-directory index of `AndroidManifest.xml`, when one was present.
    /// `None` means the manifest entry was absent and nothing was read.
    pub manifest_index: Option<usize>,
    /// Central-directory entry count observed by this inventory pass.
    pub entry_count: usize,
}

/// Inventory of one package (or nested split) that can name its application.
#[derive(Debug, Clone)]
pub(crate) struct PackageInventory {
    pub key: AppKey,
    /// True when `key` came from a parsed manifest `package` and version.
    /// Distinguishes a named package from an isolated one for a later report.
    #[allow(dead_code)]
    pub manifest_named: bool,
    /// Reopen handle for this archive. Entry extraction uses the already-open
    /// handle; this records the central directory that must be charged once.
    pub archive: InventoriedArchive,
}

/// Manifest-first application identity for one ZIP package.
///
/// Reads only a bounded root `AndroidManifest.xml` entry, supporting plain and
/// compiled XML. A missing, truncated, or unrecognized manifest isolates the
/// package instead of guessing from the ZIP filename. `package_set` is the
/// bundle or directory that owns this set of
/// splits — the same package name outside that boundary is a different app.
///
/// The returned [`InventoriedArchive`] is the reopen handle. Callers restore
/// entries from `archive.reopen_key` and must not treat that second open as a
/// newly discovered package.
pub(crate) fn inventory_manifest_package<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    reopen_key: &Path,
    package_set: &Path,
    isolate_as: &str,
    budget: &mut super::archive_limits::ArchiveBudget,
) -> Result<PackageInventory> {
    let entry_count = archive.len();
    let mut manifest_index = None;
    for index in 0..entry_count {
        let entry = archive.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        // Root manifest only. Nested paths and every other entry stay unread.
        if name.components().count() == 1 && component_eq(&name, "AndroidManifest.xml") {
            manifest_index = Some(index);
            break;
        }
    }
    let Some(index) = manifest_index else {
        return Ok(PackageInventory {
            key: AppKey::Unidentifiable {
                source: isolate_as.to_owned(),
            },
            manifest_named: false,
            archive: InventoriedArchive {
                reopen_key: reopen_key.to_path_buf(),
                manifest_index: None,
                entry_count,
            },
        });
    };
    let mut entry = archive.by_index(index)?;
    // The package and version attributes are in the root `<manifest` start tag.
    // Bound and charge this probe against the shared extraction budget. It
    // never opens assets or other entries. A manifest larger than the bound is
    // truncated and produces no identity rather than a partial guess.
    const MANIFEST_PROBE: usize = 4 * 1024 * 1024;
    let size = entry.size();
    let buffer = budget.read_probe(&mut entry, size, MANIFEST_PROBE, "AndroidManifest.xml")?;
    let truncated = size > MANIFEST_PROBE as u64;
    let named = super::manifest::identity(&buffer, truncated);
    Ok(PackageInventory {
        key: match &named {
            Some((package, version)) => AppKey::Manifest {
                package: package.clone(),
                version: version.clone(),
                package_set: package_set.to_path_buf(),
            },
            None => AppKey::Unidentifiable {
                source: isolate_as.to_owned(),
            },
        },
        manifest_named: named.is_some(),
        archive: InventoriedArchive {
            reopen_key: reopen_key.to_path_buf(),
            manifest_index: Some(index),
            entry_count,
        },
    })
}

/// Recovery-context identity mixed into metadata dedup.
///
/// Same encrypted bytes under two modules (or under "no module" versus a module)
/// must not collapse to one cached output.
pub(crate) fn metadata_context_identity(module: Option<&[u8]>) -> String {
    match module {
        Some(module) => format!("module:{}", crate::android::content_identity(module)),
        None => "module:none".to_owned(),
    }
}

/// Resolve the module a metadata blob may use, refusing an ambiguous context
/// before any output is written.
pub(crate) fn binding_module(
    modules: Option<&ApplicationModules>,
) -> std::result::Result<Option<&[u8]>, ContextAmbiguity> {
    let Some(modules) = modules else {
        return Ok(None);
    };
    if modules.is_empty() {
        return Err(ContextAmbiguity::Missing);
    }
    match modules.unambiguous_module() {
        Some(module) => Ok(Some(module)),
        None => Err(ContextAmbiguity::Conflicting {
            profiles: modules.profile_count(),
        }),
    }
}

/// Provenance recorded on a metadata outcome: every library that contributed
/// the module actually used, or the reason no module was bound.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct MetadataProvenance {
    pub sources: Vec<ModuleSource>,
    pub note: Option<String>,
}

pub(crate) fn provenance_for(
    modules: Option<&ApplicationModules>,
    ambiguity: Option<&ContextAmbiguity>,
) -> MetadataProvenance {
    match ambiguity {
        Some(ContextAmbiguity::Missing) => MetadataProvenance {
            sources: modules
                .map(|modules| modules.sources().to_vec())
                .unwrap_or_default(),
            note: Some("no module 0x0C in this application".to_owned()),
        },
        Some(ContextAmbiguity::Conflicting { profiles }) => MetadataProvenance {
            sources: modules
                .map(|modules| modules.sources().to_vec())
                .unwrap_or_default(),
            note: Some(format!(
                "ambiguous module 0x0C binding ({profiles} distinct profiles)"
            )),
        },
        None => MetadataProvenance {
            sources: modules
                .map(|modules| modules.sources().to_vec())
                .unwrap_or_default(),
            note: None,
        },
    }
}

/// What a library restore contributes to an application context.
#[derive(Debug, Clone)]
pub(crate) struct RestoredLibrary {
    pub embedded_metadata: Option<Vec<u8>>,
    pub method_index_module: Option<Vec<u8>>,
    pub module_image: Option<String>,
    /// Structural diagnostics from the engine's validation pass over the output
    /// it just wrote. `None` means the restorer produced no report at all (a
    /// test double, or an engine without a validation pass) — never that the
    /// output validated. `Some(empty)` is a completed, clean validation.
    pub validation: Option<super::ValidationDiagnostics>,
}

/// Injectable library restore. Tests supply a fake so application-context
/// behaviour does not need a protected ELF fixture. Production calls the
/// stage-2 extractor.
pub(crate) trait LibraryRestorer {
    fn restore(&mut self, input: &Path, dest: &Path, verbose: bool) -> Result<RestoredLibrary>;

    /// Bytes that should be treated as a protected library without the ELF
    /// probe. Production returns `None`; tests return the synthetic payload so
    /// a package entry can reach the restorer.
    fn protected_override(&mut self, _input: &Path) -> Option<Vec<u8>> {
        None
    }
}

/// Production restorer: stage-2 extract, ELF rebuild, embedded metadata unwrap.
#[derive(Default)]
pub(crate) struct EngineRestorer(pub(super) senbei_engine::android::ResourceLimits);

impl LibraryRestorer for EngineRestorer {
    fn restore(&mut self, input: &Path, dest: &Path, verbose: bool) -> Result<RestoredLibrary> {
        crate::android::restore_so_with_engine_limits(input, dest, verbose, &self.0)
    }
}
