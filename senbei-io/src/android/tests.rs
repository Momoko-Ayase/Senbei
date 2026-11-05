use super::*;
use crate::android::context::{self, AppKey, LibraryRestorer, RestoredLibrary};
use zip::write::SimpleFileOptions;

#[derive(Default)]
struct ScriptedRestorer {
    /// Encrypted library bytes -> module 0x0C profile.
    modules: Vec<(Vec<u8>, Vec<u8>)>,
    embedded: Option<Vec<u8>>,
}

impl LibraryRestorer for ScriptedRestorer {
    fn restore(
        &mut self,
        input: &Path,
        dest: &Path,
        _verbose: bool,
    ) -> anyhow::Result<RestoredLibrary> {
        let bytes = std::fs::read(input)?;
        let module = self
            .modules
            .iter()
            .find(|(library, _)| library == &bytes)
            .map(|(_, module)| module.clone())
            .ok_or_else(|| anyhow::anyhow!("no scripted module for library"))?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // The restored image is not an ELF; tests only check which metadata the
        // module recovered. A stable marker keeps duplicate reuse observable.
        std::fs::write(dest, b"restored")?;
        Ok(RestoredLibrary {
            embedded_metadata: self.embedded.clone(),
            method_index_module: Some(module),
            module_image: Some("module-0c.bin".to_owned()),
            // A scripted restore has no engine report behind it, so it claims
            // no validation verdict at all.
            validation: None,
        })
    }

    fn protected_override(&mut self, input: &Path) -> Option<Vec<u8>> {
        let bytes = std::fs::read(input).ok()?;
        self.modules
            .iter()
            .any(|(library, _)| library == &bytes)
            .then_some(bytes)
    }
}

/// A [`ScriptedRestorer`] that also reports validation diagnostics, as a real
/// engine restore does. Kept separate so the many existing scripted cases keep
/// meaning "no engine report".
struct DiagnosticRestorer {
    inner: ScriptedRestorer,
    diagnostics: Vec<String>,
}

impl LibraryRestorer for DiagnosticRestorer {
    fn restore(
        &mut self,
        input: &Path,
        dest: &Path,
        verbose: bool,
    ) -> anyhow::Result<RestoredLibrary> {
        let mut restored = self.inner.restore(input, dest, verbose)?;
        restored.validation = Some(ValidationDiagnostics {
            messages: self.diagnostics.clone(),
        });
        Ok(restored)
    }

    fn protected_override(&mut self, input: &Path) -> Option<Vec<u8>> {
        self.inner.protected_override(input)
    }
}

fn pair(seed: u32) -> (Vec<u8>, Vec<u8>) {
    // Local copy of the v24.1 fixture transform. Seeds 1..=5 and `0x77700DCC`
    // miss exactly `0..255` after the repeated high-half image, which is the
    // exception table written below. The metadata crate does not export this.
    const STRIDE: usize = 0x34;
    const INDEX_AT: usize = 0x14;
    fn transform(mut value: u32, count: u32, seed: u32) -> u32 {
        let key = seed % (count / 2) + count / 4;
        for _ in 0..5 {
            let mirror = count * 2 - 1;
            if value & 1 != 0 {
                value = mirror - value;
            }
            value >>= 1;
            if value >= count {
                value = mirror - value;
            }
            let adjusted = i64::from(value) - i64::from(key);
            value = if adjusted < 0 {
                (adjusted + i64::from(count)) as u32
            } else {
                adjusted as u32
            };
        }
        value
    }
    let active = 512_u32;
    let mut inverse = vec![u32::MAX; active as usize];
    for value in 0..active {
        inverse[transform(value, active, seed) as usize] = value;
    }
    let header = 0x100_usize;
    let methods = active as usize * STRIDE;
    let mut metadata = vec![0_u8; header + methods];
    metadata[0..4].copy_from_slice(&0xfab1_1baf_u32.to_le_bytes());
    metadata[4..8].copy_from_slice(&24_u32.to_le_bytes());
    metadata[0x30..0x34].copy_from_slice(&(header as u32).to_le_bytes());
    metadata[0x34..0x38].copy_from_slice(&(methods as u32).to_le_bytes());
    for method in 0..active as usize {
        let image = 256 + (method % 256) as u32;
        let protected = inverse[image as usize] as i32;
        let offset = header + method * STRIDE + INDEX_AT;
        metadata[offset..offset + 4].copy_from_slice(&protected.to_le_bytes());
    }
    let mut module = vec![0_u8; 0x1000];
    module[0x100..0x104].copy_from_slice(&seed.to_le_bytes());
    module[0x104..0x108].copy_from_slice(&24_u32.to_le_bytes());
    module[0x3f8..0x3fc].copy_from_slice(&1_u32.to_le_bytes());
    module[0x3fc..0x400].copy_from_slice(&(active - 1).to_le_bytes());
    for value in 0..256_u32 {
        let offset = 0x400 + value as usize * 4;
        module[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    (metadata, module)
}

fn restored_with(metadata: &[u8], module: &[u8]) -> Vec<u8> {
    match senbei_metadata::android::restore_method_indices_v24_1(metadata, module) {
        Ok((bytes, _)) => bytes,
        Err(error) => panic!("fixture restore failed: {error:?}"),
    }
}

fn manifest(package: &str, version: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<manifest package="{package}" android:versionCode="{version}">
</manifest>
"#
    )
}

fn library_bytes(marker: &[u8]) -> Vec<u8> {
    // Distinct from metadata magic so a mis-classified entry cannot take the
    // metadata path. The scripted restorer recognises these exact bytes.
    let mut bytes = b"SENBEI-SYNTHETIC-LIBRARY".to_vec();
    bytes.extend_from_slice(marker);
    bytes
}

fn metadata_fixture() -> Vec<u8> {
    let mut data = vec![0; 0x1a4];
    let mut put = |offset: usize, value: u32| {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    };
    put(0, 0xfab1_1baf);
    put(4, 31);
    put(0x30, 0x180);
    put(0x34, 0x24);
    put(0xa0, 0x128);
    put(0xa4, 0x58);
    put(0xa8, 0x100);
    put(0xac, 0x28);
    put(0x10c, 1);
    put(0x14c, 0);
    put(0x168, 1);
    put(0x198, 0x0600_1234);
    data
}

fn write_package(path: &Path, entries: &[(&str, &[u8])]) {
    let mut archive = zip::ZipWriter::new(File::create(path).unwrap());
    for (name, data) in entries {
        archive
            .start_file(*name, SimpleFileOptions::default())
            .unwrap();
        archive.write_all(data).unwrap();
    }
    archive.finish().unwrap();
}

#[test]
fn failed_metadata_output_does_not_poison_deduplication() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("app.apk");
    let out = temp.path().join("out");
    let data = metadata_fixture();
    write_package(
        &package,
        &[
            ("a/global-metadata.dat", &data),
            ("b/global-metadata.dat", &data),
            ("c/global-metadata.dat", &data),
        ],
    );
    std::fs::create_dir_all(out.join("app.apk")).unwrap();
    std::fs::write(out.join("app.apk/a"), b"blocks the output directory").unwrap();
    let mut seen = HashSet::new();
    let outcomes = restore_package(&package, Path::new("app.apk"), &out, &mut seen, false).unwrap();
    assert_eq!(outcomes.len(), 3);
    assert!(matches!(outcomes[0].status, EntryStatus::Failed(_)));
    assert!(matches!(outcomes[1].status, EntryStatus::Restored));
    assert!(matches!(outcomes[2].status, EntryStatus::Duplicate));
    assert_eq!(seen.len(), 1);
    let expected = restore_metadata_bytes(&data).unwrap().0;
    assert_eq!(std::fs::read(&outcomes[1].dest).unwrap(), expected);
    assert!(!outcomes[2].dest.exists());
}

#[test]
fn repeated_failed_metadata_is_retried() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("app.apk");
    let malformed = [0xaf, 0x1b, 0xb1, 0xfa, 31, 0, 0, 0];
    write_package(
        &package,
        &[
            ("a/global-metadata.dat", &malformed),
            ("b/global-metadata.dat", &malformed),
        ],
    );
    let mut seen = HashSet::new();
    let outcomes = restore_package(
        &package,
        Path::new("app.apk"),
        &temp.path().join("out"),
        &mut seen,
        false,
    )
    .unwrap();
    assert_eq!(outcomes.len(), 2);
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome.status, EntryStatus::Failed(_)))
    );
    assert!(seen.is_empty());
}

#[test]
fn unchanged_metadata_is_a_successful_deduplication_source() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("app.apk");
    let data = restore_metadata_bytes(&metadata_fixture()).unwrap().0;
    write_package(
        &package,
        &[
            ("a/global-metadata.dat", &data),
            ("b/global-metadata.dat", &data),
        ],
    );
    let mut seen = HashSet::new();
    let outcomes = restore_package(
        &package,
        Path::new("app.apk"),
        &temp.path().join("out"),
        &mut seen,
        false,
    )
    .unwrap();
    assert!(matches!(outcomes[0].status, EntryStatus::Unchanged));
    assert!(matches!(outcomes[1].status, EntryStatus::Duplicate));
    assert_eq!(seen.len(), 1);
    assert!(outcomes.iter().all(|outcome| !outcome.dest.exists()));
}

fn restore_scripted(
    package: &Path,
    rel: &Path,
    out: &Path,
    cache: &mut context::AndroidRunCache,
    restorer: &mut ScriptedRestorer,
) -> Vec<EntryOutcome> {
    restore_package_with_restorer(package, rel, out, cache, false, restorer).unwrap()
}

fn metadata_outcomes(outcomes: &[EntryOutcome]) -> Vec<&EntryOutcome> {
    outcomes
        .iter()
        .filter(|outcome| matches!(outcome.kind, EntryKind::Metadata { .. }))
        .collect()
}

#[test]
fn two_extracted_apps_do_not_share_module_context() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let (meta_a, module_a) = pair(1);
    let (meta_b, module_b) = pair(2);
    let lib_a = library_bytes(b"app-a");
    let lib_b = library_bytes(b"app-b");
    let app_a = root.join("games/alpha");
    let app_b = root.join("games/beta");
    std::fs::create_dir_all(app_a.join("lib/arm64-v8a")).unwrap();
    std::fs::create_dir_all(app_a.join("assets/bin/Data/Managed/Metadata")).unwrap();
    std::fs::create_dir_all(app_b.join("lib/arm64-v8a")).unwrap();
    std::fs::create_dir_all(app_b.join("assets/bin/Data/Managed/Metadata")).unwrap();
    let so_a = app_a.join("lib/arm64-v8a/libil2cpp.so");
    let so_b = app_b.join("lib/arm64-v8a/libil2cpp.so");
    let md_a = app_a.join("assets/bin/Data/Managed/Metadata/global-metadata.dat");
    let md_b = app_b.join("assets/bin/Data/Managed/Metadata/global-metadata.dat");
    std::fs::write(&so_a, &lib_a).unwrap();
    std::fs::write(&so_b, &lib_b).unwrap();
    std::fs::write(&md_a, &meta_a).unwrap();
    std::fs::write(&md_b, &meta_b).unwrap();

    let scoped = loose_scopes(&[so_b.clone(), so_a.clone()], &[md_a.clone(), md_b.clone()]);
    assert!(
        scoped
            .iter()
            .any(|item| item.path == so_a && item.key == AppKey::Extracted(app_a.clone())),
        "scopes: {:?}",
        scoped
            .iter()
            .map(|item| (item.path.display().to_string(), format!("{:?}", item.key)))
            .collect::<Vec<_>>()
    );
    assert!(
        scoped
            .iter()
            .any(|item| item.path == md_b && item.key == AppKey::Extracted(app_b.clone()))
    );

    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(lib_a, module_a.clone()), (lib_b, module_b.clone())],
    };
    let out = root.join("unpack");
    // Restore beta's library first. A last-writer cache would then poison alpha.
    for (library, app) in [(&so_b, &app_b), (&so_a, &app_a)] {
        let scoped = scoped.iter().find(|item| &item.path == library).unwrap();
        assert_eq!(&scoped.key, &AppKey::Extracted(app.clone()));
        let outcome = restore_loose_library_with(
            library,
            &out.join(library.file_name().unwrap()),
            &library.display().to_string(),
            &scoped.key,
            false,
            &mut cache,
            &mut restorer,
        )
        .unwrap();
        assert!(matches!(outcome.status, EntryStatus::Restored));
    }
    let restored_a = restore_loose_metadata(
        &md_a,
        &out.join("a.dat"),
        "alpha metadata",
        &AppKey::Extracted(app_a.clone()),
        false,
        &mut cache,
    )
    .unwrap_or_else(|error| panic!("alpha metadata: {error:#}; cache apps will not print"));
    let restored_b = restore_loose_metadata(
        &md_b,
        &out.join("b.dat"),
        "beta metadata",
        &AppKey::Extracted(app_b),
        false,
        &mut cache,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(out.join("a.dat")).unwrap(),
        restored_with(&meta_a, &module_a)
    );
    assert_eq!(
        std::fs::read(out.join("b.dat")).unwrap(),
        restored_with(&meta_b, &module_b)
    );
    assert!(
        senbei_metadata::android::restore_method_indices_v24_1(&meta_a, &module_b).is_err(),
        "beta's module must not restore alpha's metadata"
    );
    assert!(
        restored_a
            .provenance
            .iter()
            .any(|source| source.contains("alpha") || source.contains("libil2cpp"))
    );
    assert!(
        restored_b
            .provenance
            .iter()
            .all(|source| !source.contains("games/alpha") && !source.contains("games\\alpha"))
    );
}

#[test]
fn bundle_splits_share_context_independent_of_order() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, module) = pair(3);
    let library = library_bytes(b"split-lib");
    let manifest_xml = manifest("example.game", "123");
    let write = |name: &str, base_first: bool| {
        let path = temp.path().join(name);
        let base = (
            "base.apk",
            entries(&[
                ("AndroidManifest.xml", manifest_xml.as_bytes()),
                (
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                    &metadata,
                ),
            ]),
        );
        let split = (
            "split_config.arm64_v8a.apk",
            entries(&[
                ("AndroidManifest.xml", manifest_xml.as_bytes()),
                ("lib/arm64-v8a/libil2cpp.so", &library),
            ]),
        );
        let nested = if base_first {
            vec![base, split]
        } else {
            vec![split, base]
        };
        write_nested(&path, &nested);
        path
    };
    let mut cache_forward = run_cache();
    let mut cache_reverse = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(library.clone(), module.clone())],
    };
    let forward = write("forward.apks", true);
    let reverse = write("reverse.apks", false);
    let out_forward = temp.path().join("out-forward");
    let out_reverse = temp.path().join("out-reverse");
    let first = restore_scripted(
        &forward,
        Path::new("forward.apks"),
        &out_forward,
        &mut cache_forward,
        &mut restorer,
    );
    let second = restore_scripted(
        &reverse,
        Path::new("reverse.apks"),
        &out_reverse,
        &mut cache_reverse,
        &mut restorer,
    );
    let meta_first = metadata_outcomes(&first);
    let meta_second = metadata_outcomes(&second);
    assert_eq!(meta_first.len(), 1);
    assert_eq!(meta_second.len(), 1);
    assert!(matches!(meta_first[0].status, EntryStatus::Restored));
    assert!(matches!(meta_second[0].status, EntryStatus::Restored));
    let expected = restored_with(&metadata, &module);
    assert_eq!(std::fs::read(&meta_first[0].dest).unwrap(), expected);
    assert_eq!(std::fs::read(&meta_second[0].dest).unwrap(), expected);
    assert!(!meta_first[0].provenance.is_empty());
    assert!(!meta_second[0].provenance.is_empty());
}

#[test]
fn mixed_bundle_does_not_cross_package_identities() {
    let temp = tempfile::tempdir().unwrap();
    let (meta_a, module_a) = pair(1);
    let (meta_b, module_b) = pair(2);
    let lib_a = library_bytes(b"mix-a");
    let lib_b = library_bytes(b"mix-b");
    let package = temp.path().join("mixed.apks");
    write_nested(
        &package,
        &[
            (
                "first.apk",
                entries(&[
                    (
                        "AndroidManifest.xml",
                        manifest("example.one", "1").as_bytes(),
                    ),
                    ("lib/arm64-v8a/libil2cpp.so", &lib_a),
                    (
                        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        &meta_a,
                    ),
                ]),
            ),
            (
                "second.apk",
                entries(&[
                    (
                        "AndroidManifest.xml",
                        manifest("example.two", "1").as_bytes(),
                    ),
                    ("lib/arm64-v8a/libil2cpp.so", &lib_b),
                    (
                        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        &meta_b,
                    ),
                ]),
            ),
        ],
    );
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(lib_a, module_a.clone()), (lib_b, module_b.clone())],
    };
    let outcomes = restore_scripted(
        &package,
        Path::new("mixed.apks"),
        &temp.path().join("out"),
        &mut cache,
        &mut restorer,
    );
    let metas = metadata_outcomes(&outcomes);
    assert_eq!(metas.len(), 2);
    assert!(
        metas
            .iter()
            .all(|outcome| matches!(outcome.status, EntryStatus::Restored)),
        "outcomes: {:?}",
        metas
            .iter()
            .map(|outcome| {
                let status = match &outcome.status {
                    EntryStatus::Failed(error) => format!("failed: {error:#}"),
                    other => format!("{other:?}"),
                };
                (outcome.label.clone(), status, outcome.provenance.clone())
            })
            .collect::<Vec<_>>()
    );
    let bytes: Vec<_> = metas
        .iter()
        .map(|outcome| std::fs::read(&outcome.dest).unwrap())
        .collect();
    // Canonical method order does not depend on the seed, so both restored
    // blobs match their own module. Isolation is the provenance: each metadata
    // entry records only the library inside its own package.
    assert!(
        bytes
            .iter()
            .all(|item| item == &restored_with(&meta_a, &module_a)
                || item == &restored_with(&meta_b, &module_b))
    );
    assert!(metas.iter().all(|outcome| outcome.provenance.len() == 1));
    assert_ne!(metas[0].provenance, metas[1].provenance);
}

#[test]
fn duplicate_library_populates_the_owning_context() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, module) = pair(4);
    let library = library_bytes(b"dup-lib");
    let package = temp.path().join("dups.apk");
    let xml = manifest("example.dups", "9");
    write_package(
        &package,
        &[
            ("AndroidManifest.xml", xml.as_bytes()),
            ("lib/arm64-v8a/libil2cpp.so", &library),
            ("lib/armeabi-v7a/libil2cpp.so", &library),
            (
                "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                &metadata,
            ),
        ],
    );
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(library, module.clone())],
    };
    let outcomes = restore_scripted(
        &package,
        Path::new("dups.apk"),
        &temp.path().join("out"),
        &mut cache,
        &mut restorer,
    );
    let libraries: Vec<_> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome.kind, EntryKind::So))
        .collect();
    assert!(matches!(libraries[0].status, EntryStatus::Restored));
    assert!(matches!(libraries[1].status, EntryStatus::Duplicate));
    let meta = metadata_outcomes(&outcomes);
    assert_eq!(meta.len(), 1);
    assert!(matches!(meta[0].status, EntryStatus::Restored));
    assert_eq!(
        std::fs::read(&meta[0].dest).unwrap(),
        restored_with(&metadata, &module)
    );
    assert!(
        meta[0].provenance.len() >= 2,
        "both library copies must be recorded, got {:?}",
        meta[0].provenance
    );
}

#[test]
fn missing_module_writes_no_v24_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, module) = pair(5);
    let package = temp.path().join("bare.apk");
    write_package(
        &package,
        &[(
            "assets/bin/Data/Managed/Metadata/global-metadata.dat",
            metadata.as_slice(),
        )],
    );
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(library_bytes(b"unused"), module)],
    };
    let outcomes = restore_scripted(
        &package,
        Path::new("bare.apk"),
        &temp.path().join("out"),
        &mut cache,
        &mut restorer,
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome.status, EntryStatus::Failed(_)))
    );
    assert!(outcomes.iter().all(|outcome| !outcome.dest.exists()));
}

#[test]
fn conflicting_modules_write_no_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, module_a) = pair(1);
    let (_, module_b) = pair(2);
    let lib_a = library_bytes(b"conflict-a");
    let lib_b = library_bytes(b"conflict-b");
    let package = temp.path().join("conflict.apk");
    let xml = manifest("example.conflict", "1");
    write_package(
        &package,
        &[
            ("AndroidManifest.xml", xml.as_bytes()),
            ("lib/arm64-v8a/one.so", &lib_a),
            ("lib/arm64-v8a/two.so", &lib_b),
            (
                "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                &metadata,
            ),
        ],
    );
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(lib_a, module_a), (lib_b, module_b)],
    };
    let outcomes = restore_scripted(
        &package,
        Path::new("conflict.apk"),
        &temp.path().join("out"),
        &mut cache,
        &mut restorer,
    );
    let meta = metadata_outcomes(&outcomes);
    assert_eq!(meta.len(), 1);
    assert!(matches!(meta[0].status, EntryStatus::Failed(_)));
    assert!(!meta[0].dest.exists());
    assert!(meta[0].provenance.len() >= 2);
}

#[test]
fn same_metadata_bytes_cache_separately_per_module() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, module_a) = pair(3);
    // A second copy of the same module is still one profile. A different seed
    // that does not restore this metadata must not be substituted for it.
    let module_copy = module_a.clone();
    let (_other_metadata, other_module) = pair(4);
    let lib_a = library_bytes(b"cache-a");
    let lib_b = library_bytes(b"cache-b");
    let bundle = temp.path().join("same-bytes.apks");
    write_nested(
        &bundle,
        &[
            (
                "one.apk",
                entries(&[
                    (
                        "AndroidManifest.xml",
                        manifest("example.cache", "1").as_bytes(),
                    ),
                    ("lib/arm64-v8a/libil2cpp.so", &lib_a),
                    (
                        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        &metadata,
                    ),
                ]),
            ),
            (
                "two.apk",
                entries(&[
                    (
                        "AndroidManifest.xml",
                        manifest("example.cache", "2").as_bytes(),
                    ),
                    ("lib/arm64-v8a/libil2cpp.so", &lib_b),
                    (
                        "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                        &metadata,
                    ),
                ]),
            ),
        ],
    );
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(lib_a, module_copy), (lib_b, other_module)],
    };
    let outcomes = restore_scripted(
        &bundle,
        Path::new("same-bytes.apks"),
        &temp.path().join("out"),
        &mut cache,
        &mut restorer,
    );
    let metas = metadata_outcomes(&outcomes);
    assert_eq!(metas.len(), 2);
    // Version 1 has this metadata's module and restores. Version 2 has a
    // different module; the shared encrypted bytes must not reuse version 1's
    // output, and version 2 writes nothing.
    assert!(matches!(metas[0].status, EntryStatus::Restored));
    assert!(matches!(metas[1].status, EntryStatus::Failed(_)));
    assert_eq!(
        std::fs::read(&metas[0].dest).unwrap(),
        restored_with(&metadata, &module_a)
    );
    assert!(!metas[1].dest.exists());
    assert!(metas.iter().all(|outcome| outcome.provenance.len() == 1));
    assert_ne!(metas[0].provenance, metas[1].provenance);
}

#[test]
fn loose_metadata_outside_an_extracted_boundary_is_isolated() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, module) = pair(5);
    let library = library_bytes(b"loose-boundary");
    let app = temp.path().join("game");
    std::fs::create_dir_all(app.join("lib/arm64-v8a")).unwrap();
    let so = app.join("lib/arm64-v8a/libil2cpp.so");
    // Same scan root, but not under `<app>/assets/`. Must not borrow the module.
    let stray = temp.path().join("global-metadata.dat");
    std::fs::write(&so, &library).unwrap();
    std::fs::write(&stray, &metadata).unwrap();
    let scoped = loose_scopes(std::slice::from_ref(&so), std::slice::from_ref(&stray));
    let stray_key = scoped
        .iter()
        .find(|item| item.path == stray)
        .unwrap()
        .key
        .clone();
    assert!(matches!(stray_key, AppKey::Unidentifiable { .. }));
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(library, module)],
    };
    restore_loose_library_with(
        &so,
        &temp.path().join("out.so"),
        "library",
        &AppKey::Extracted(app),
        false,
        &mut cache,
        &mut restorer,
    )
    .unwrap();
    let error = restore_loose_metadata(
        &stray,
        &temp.path().join("out.dat"),
        "stray",
        &stray_key,
        false,
        &mut cache,
    )
    .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("no module 0x0C"),
        "unexpected error: {message}"
    );
    assert!(!temp.path().join("out.dat").exists());
}

type NestedEntries = Vec<(String, Vec<u8>)>;

fn entries(pairs: &[(&str, &[u8])]) -> NestedEntries {
    pairs
        .iter()
        .map(|(name, data)| ((*name).to_owned(), (*data).to_vec()))
        .collect()
}

fn write_nested(path: &Path, apks: &[(&str, NestedEntries)]) {
    let mut archive = zip::ZipWriter::new(File::create(path).unwrap());
    for (name, nested) in apks {
        let mut payload = Vec::new();
        {
            let mut inner = zip::ZipWriter::new(std::io::Cursor::new(&mut payload));
            for (entry, data) in nested {
                inner
                    .start_file(entry, SimpleFileOptions::default())
                    .unwrap();
                inner.write_all(data).unwrap();
            }
            inner.finish().unwrap();
        }
        archive
            .start_file(*name, SimpleFileOptions::default())
            .unwrap();
        archive.write_all(&payload).unwrap();
    }
    archive.finish().unwrap();
}

#[test]
fn duplicate_library_writes_no_output() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, module) = pair(1);
    let library = library_bytes(b"dup-output");
    let package = temp.path().join("once.apk");
    write_package(
        &package,
        &[
            (
                "AndroidManifest.xml",
                manifest("example.once", "1").as_bytes(),
            ),
            ("lib/arm64-v8a/libil2cpp.so", &library),
            ("lib/armeabi-v7a/libil2cpp.so", &library),
            (
                "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                &metadata,
            ),
        ],
    );
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(library, module)],
    };
    let outcomes = restore_scripted(
        &package,
        Path::new("once.apk"),
        &temp.path().join("out"),
        &mut cache,
        &mut restorer,
    );
    let libraries: Vec<_> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome.kind, EntryKind::So))
        .collect();
    assert!(matches!(libraries[0].status, EntryStatus::Restored));
    assert!(libraries[0].dest.exists());
    assert!(matches!(libraries[1].status, EntryStatus::Duplicate));
    assert!(
        !libraries[1].dest.exists(),
        "a duplicate library must not write {}",
        libraries[1].dest.display()
    );
}

#[test]
fn embedded_metadata_failure_is_retried() {
    let temp = tempfile::tempdir().unwrap();
    let library = library_bytes(b"embedded-retry");
    let package = temp.path().join("embed.apk");
    write_package(&package, &[("lib/arm64-v8a/libil2cpp.so", &library)]);
    let first_root = temp.path().join("first");
    let library_dest = first_root.join("embed.apk/lib/arm64-v8a/libil2cpp.unpack.so");
    let metadata_dest = embedded_metadata_dest(&library_dest);
    // Let the library write succeed, but prevent replacing its metadata file.
    std::fs::create_dir_all(&metadata_dest).unwrap();
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        modules: vec![(library.clone(), pair(1).1)],
        embedded: Some(b"embedded-blob".to_vec()),
    };
    let first = restore_scripted(
        &package,
        Path::new("embed.apk"),
        &first_root,
        &mut cache,
        &mut restorer,
    );
    assert!(
        first
            .iter()
            .any(|outcome| matches!(outcome.status, EntryStatus::Failed(_))),
        "embedded write must fail, got {first:?}"
    );
    assert!(cache.library(&content_identity(&library)).is_none());
    assert_eq!(std::fs::read(&library_dest).unwrap(), b"restored");
    assert!(metadata_dest.is_dir());
    let retry_root = temp.path().join("retry");
    let second = restore_scripted(
        &package,
        Path::new("embed.apk"),
        &retry_root,
        &mut cache,
        &mut restorer,
    );
    assert!(
        second
            .iter()
            .any(|outcome| matches!(outcome.status, EntryStatus::Restored))
    );
}

#[test]
fn content_only_duplicate_recovers_context_without_touching_existing_output() {
    let temp = tempfile::tempdir().unwrap();
    let library = library_bytes(b"prior-success");
    let (metadata, module) = pair(1);
    let package = temp.path().join("app.apk");
    write_package(
        &package,
        &[
            ("lib/arm64-v8a/libil2cpp.so", &library),
            ("assets/global-metadata.dat", &metadata),
        ],
    );
    let out = temp.path().join("out");
    let dest = out.join("app.apk/lib/arm64-v8a/libil2cpp.unpack.so");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, b"keep existing output").unwrap();
    let mut cache = run_cache();
    cache.insert_prior_success(content_identity(&library));
    let mut restorer = ScriptedRestorer {
        modules: vec![(library, module.clone())],
        embedded: None,
    };
    let outcomes = restore_scripted(
        &package,
        Path::new("app.apk"),
        &out,
        &mut cache,
        &mut restorer,
    );
    assert!(matches!(outcomes[0].status, EntryStatus::Duplicate));
    assert_eq!(std::fs::read(&dest).unwrap(), b"keep existing output");
    let meta = metadata_outcomes(&outcomes);
    assert!(matches!(meta[0].status, EntryStatus::Restored));
    assert_eq!(
        std::fs::read(&meta[0].dest).unwrap(),
        restored_with(&metadata, &module)
    );
}

#[test]
fn loose_embedded_metadata_reports_its_written_path() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("library.so");
    let library = library_bytes(b"loose-embedded");
    std::fs::write(&input, &library).unwrap();
    let dest = temp.path().join("out/library.unpack.so");
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        modules: vec![(library, pair(1).1)],
        embedded: Some(b"metadata".to_vec()),
    };
    let outcome = restore_loose_library_with(
        &input,
        &dest,
        "library.so",
        &AppKey::Unidentifiable {
            source: "one".to_owned(),
        },
        false,
        &mut cache,
        &mut restorer,
    )
    .unwrap();
    assert!(matches!(outcome.status, EntryStatus::Restored));
    assert_eq!(outcome.embedded, Some(embedded_metadata_dest(&dest)));
    assert_eq!(
        std::fs::read(outcome.embedded.unwrap()).unwrap(),
        b"metadata"
    );
}

#[test]
fn public_seen_survives_package_error() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing.apk");
    let mut seen = std::collections::HashSet::from(["already-restored".to_owned()]);
    let error = restore_package(
        &missing,
        Path::new("missing.apk"),
        &temp.path().join("out"),
        &mut seen,
        false,
    );
    assert!(error.is_err());
    assert!(
        seen.contains("already-restored"),
        "an error must not drop successes the caller already had: {seen:?}"
    );
}

#[test]
fn binary_manifest_splits_share_and_versions_do_not() {
    let temp = tempfile::tempdir().unwrap();
    let (metadata, _module) = pair(1);
    let library = library_bytes(b"axml-lib");
    let same = axml_manifest("example.axml", 7, None, None);
    let other = axml_manifest("example.axml", 8, None, None);
    let base = temp.path().join("base.apk");
    let split = temp.path().join("split.apk");
    let newer = temp.path().join("newer.apk");
    write_package(
        &base,
        &[
            ("AndroidManifest.xml", &same),
            (
                "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                &metadata,
            ),
        ],
    );
    write_package(
        &split,
        &[
            ("AndroidManifest.xml", &same),
            ("lib/arm64-v8a/libil2cpp.so", &library),
        ],
    );
    write_package(
        &newer,
        &[
            ("AndroidManifest.xml", &other),
            ("lib/arm64-v8a/libil2cpp.so", &library),
        ],
    );
    let groups = loose_apk_groups(&[newer.clone(), base.clone(), split.clone()]);
    let together = groups.iter().find(|group| group.contains(&base)).unwrap();
    assert!(together.contains(&split), "groups: {groups:?}");
    assert!(!together.contains(&newer), "groups: {groups:?}");
}

#[test]
fn truncated_binary_manifest_does_not_name_a_package() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("cut.apk");
    let mut truncated = axml_manifest("example.cut", 1, None, None);
    truncated.truncate(12);
    write_package(&package, &[("AndroidManifest.xml", &truncated)]);
    let groups = loose_apk_groups(std::slice::from_ref(&package));
    assert_eq!(groups, vec![vec![package]]);
}

#[test]
fn non_v24_metadata_ignores_conflicting_modules() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("later.apk");
    let lib_a = library_bytes(b"later-a");
    let lib_b = library_bytes(b"later-b");
    let metadata = metadata_fixture();
    write_package(
        &package,
        &[
            (
                "AndroidManifest.xml",
                manifest("example.later", "1").as_bytes(),
            ),
            ("lib/arm64-v8a/one.so", &lib_a),
            ("lib/arm64-v8a/two.so", &lib_b),
            (
                "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                &metadata,
            ),
        ],
    );
    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(lib_a, pair(1).1), (lib_b, pair(2).1)],
    };
    let outcomes = restore_scripted(
        &package,
        Path::new("later.apk"),
        &temp.path().join("out"),
        &mut cache,
        &mut restorer,
    );
    let meta = metadata_outcomes(&outcomes);
    assert_eq!(meta.len(), 1);
    assert!(
        matches!(
            meta[0].status,
            EntryStatus::Restored | EntryStatus::Unchanged
        ),
        "v31 must not be blocked by conflicting modules: {:?}",
        meta[0].status
    );
    assert!(
        meta[0].provenance.is_empty(),
        "a module that was not used must not be recorded: {:?}",
        meta[0].provenance
    );
}

#[test]
fn version_name_alone_does_not_merge_builds() {
    let temp = tempfile::tempdir().unwrap();
    let named = r#"<manifest package="example.same" android:versionName="1.0" android:versionCode="{code}"></manifest>"#;
    let first = temp.path().join("a.apk");
    let second = temp.path().join("b.apk");
    write_package(
        &first,
        &[(
            "AndroidManifest.xml",
            named.replace("{code}", "1").as_bytes(),
        )],
    );
    write_package(
        &second,
        &[(
            "AndroidManifest.xml",
            named.replace("{code}", "2").as_bytes(),
        )],
    );
    let groups = loose_apk_groups(&[first.clone(), second.clone()]);
    assert!(groups.iter().all(|group| group.len() == 1), "{groups:?}");
}

#[test]
fn direct_assets_metadata_shares_the_extracted_root() {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("game");
    std::fs::create_dir_all(app.join("lib/arm64-v8a")).unwrap();
    std::fs::create_dir_all(app.join("assets")).unwrap();
    let so = app.join("lib/arm64-v8a/libil2cpp.so");
    let meta = app.join("assets/global-metadata.dat");
    std::fs::write(&so, b"so").unwrap();
    std::fs::write(&meta, b"meta").unwrap();
    let scoped = loose_scopes(std::slice::from_ref(&so), std::slice::from_ref(&meta));
    assert_eq!(scoped[0].key, scoped[1].key);
    assert!(matches!(scoped[0].key, AppKey::Extracted(_)));
}

fn axml_manifest(
    package: &str,
    version_code: u32,
    major: Option<u32>,
    version_name: Option<&str>,
) -> Vec<u8> {
    let mut strings = vec![
        "manifest".to_owned(),
        "package".to_owned(),
        package.to_owned(),
        "versionCode".to_owned(),
    ];
    if major.is_some() {
        strings.push("versionCodeMajor".to_owned());
    }
    if let Some(version_name) = version_name {
        strings.push("versionName".to_owned());
        strings.push(version_name.to_owned());
    }
    let pool = axml_pool(&strings);
    let mut attributes = Vec::new();
    attributes.extend(axml_attr(1, 2, 0x03, 2));
    attributes.extend(axml_attr(3, 0xffff_ffff, 0x10, version_code));
    if let Some(major) = major {
        attributes.extend(axml_attr(4, 0xffff_ffff, 0x10, major));
    }
    if version_name.is_some() {
        let name_index = (strings.len() - 2) as u32;
        let value_index = (strings.len() - 1) as u32;
        attributes.extend(axml_attr(name_index, value_index, 0x03, value_index));
    }
    let attr_count = attributes.len() / 20;
    let mut element = Vec::new();
    element.extend(u16::to_le_bytes(0x0102));
    element.extend(u16::to_le_bytes(16));
    let element_size = 8 + 28 + attributes.len();
    element.extend(u32::to_le_bytes(element_size as u32));
    element.extend(u32::to_le_bytes(0));
    element.extend(u32::to_le_bytes(0xffff_ffff));
    element.extend(u32::to_le_bytes(0xffff_ffff));
    element.extend(u32::to_le_bytes(0));
    element.extend(u16::to_le_bytes(0x14)); // attribute start, from the node
    element.extend(u16::to_le_bytes(20));
    element.extend(u16::to_le_bytes(attr_count as u16));
    element.extend(u16::to_le_bytes(0));
    element.extend(u16::to_le_bytes(0));
    element.extend(u16::to_le_bytes(0));
    element.extend(attributes);
    let mut bytes = Vec::new();
    bytes.extend(u16::to_le_bytes(0x0003));
    bytes.extend(u16::to_le_bytes(8));
    bytes.extend(u32::to_le_bytes((8 + pool.len() + element.len()) as u32));
    bytes.extend(pool);
    bytes.extend(element);
    bytes
}

fn axml_pool(strings: &[String]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for value in strings {
        offsets.push(data.len() as u32);
        let units: Vec<u16> = value.encode_utf16().collect();
        data.extend(u16::to_le_bytes(units.len() as u16));
        for unit in units {
            data.extend(u16::to_le_bytes(unit));
        }
        data.extend(u16::to_le_bytes(0));
    }
    let mut chunk = Vec::new();
    chunk.extend(u16::to_le_bytes(0x0001));
    chunk.extend(u16::to_le_bytes(28));
    let size = 28 + strings.len() * 4 + data.len();
    chunk.extend(u32::to_le_bytes(size as u32));
    chunk.extend(u32::to_le_bytes(strings.len() as u32));
    chunk.extend(u32::to_le_bytes(0)); // style count
    chunk.extend(u32::to_le_bytes(0)); // flags
    chunk.extend(u32::to_le_bytes((28 + strings.len() * 4) as u32));
    chunk.extend(u32::to_le_bytes(0)); // styles start
    for offset in offsets {
        chunk.extend(u32::to_le_bytes(offset));
    }
    chunk.extend(data);
    chunk
}

fn axml_attr(name: u32, raw: u32, value_type: u8, data: u32) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend(u32::to_le_bytes(0xffff_ffff));
    record.extend(u32::to_le_bytes(name));
    record.extend(u32::to_le_bytes(raw));
    record.extend(u16::to_le_bytes(8));
    record.push(0);
    record.push(value_type);
    record.extend(u32::to_le_bytes(data));
    record
}

/// The engine's validation diagnostics travel from a restore into the entry
/// outcome a reporter reads, for loose libraries and package entries alike.
///
/// They are advisory: the restore still succeeds, the output is still written,
/// and nothing is re-validated or re-read to produce them.
#[test]
fn validation_diagnostics_reach_restored_outcomes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let finding = "dynamic symbol table is not referenced by a load segment";
    let library = library_bytes(b"diag");
    let app = root.join("app");
    std::fs::create_dir_all(app.join("lib/arm64-v8a")).unwrap();
    let so = app.join("lib/arm64-v8a/libil2cpp.so");
    std::fs::write(&so, &library).unwrap();

    let mut cache = run_cache();
    let mut restorer = DiagnosticRestorer {
        inner: ScriptedRestorer {
            embedded: None,
            modules: vec![(library, vec![0xAB; 16])],
        },
        diagnostics: vec![finding.to_owned()],
    };

    let scoped = loose_scopes(std::slice::from_ref(&so), &[]);
    let outcome = restore_loose_library_with(
        &so,
        &root.join("out.so"),
        "libil2cpp.so",
        &scoped[0].key,
        false,
        &mut cache,
        &mut restorer,
    )
    .unwrap();
    assert!(matches!(outcome.status, EntryStatus::Restored));
    assert_eq!(
        outcome.validation.as_ref().map(|v| v.messages.clone()),
        Some(vec![finding.to_owned()])
    );
    assert!(root.join("out.so").is_file(), "the output is still written");

    // Repeated bytes are a duplicate: no output of their own, so no verdict.
    let duplicate = restore_loose_library_with(
        &so,
        &root.join("out-duplicate.so"),
        "libil2cpp.so",
        &scoped[0].key,
        false,
        &mut cache,
        &mut restorer,
    )
    .unwrap();
    assert!(matches!(duplicate.status, EntryStatus::Duplicate));
    assert!(
        duplicate.validation.is_none(),
        "a duplicate restored only for its module context reports no verdict"
    );
}

/// A restorer with no engine report leaves the verdict empty instead of
/// claiming a clean validation it never performed.
#[test]
fn scripted_restore_claims_no_validation_verdict() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let library = library_bytes(b"no-report");
    let app = root.join("app");
    std::fs::create_dir_all(app.join("lib/arm64-v8a")).unwrap();
    let so = app.join("lib/arm64-v8a/libil2cpp.so");
    std::fs::write(&so, &library).unwrap();

    let mut cache = run_cache();
    let mut restorer = ScriptedRestorer {
        embedded: None,
        modules: vec![(library, vec![0xCD; 16])],
    };
    let scoped = loose_scopes(std::slice::from_ref(&so), &[]);
    let outcome = restore_loose_library_with(
        &so,
        &root.join("out.so"),
        "libil2cpp.so",
        &scoped[0].key,
        false,
        &mut cache,
        &mut restorer,
    )
    .unwrap();
    assert!(matches!(outcome.status, EntryStatus::Restored));
    assert!(
        outcome.validation.is_none(),
        "a restorer without a report must not claim a clean verdict"
    );
}
