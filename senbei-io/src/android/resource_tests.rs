use super::*;
use std::io::Cursor;
use zip::write::SimpleFileOptions;

fn package(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in entries {
        writer
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn compressed_entry_limit_leaves_no_restored_output() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("app.apk");
    std::fs::write(&input, package(&[("lib/test.so", &vec![0; 4096])])).unwrap();
    let limits = ResourceLimits {
        max_entry_bytes: 1024,
        ..ResourceLimits::default()
    };
    let out = temp.path().join("out");
    let error = restore_package_with_limits(
        &input,
        Path::new("app.apk"),
        &out,
        &mut HashSet::new(),
        false,
        &limits,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("extraction limit"));
    assert!(!out.exists());
}

#[test]
fn archive_bytes_are_cumulative_across_packages_in_a_folder_run() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first.apk");
    let second = temp.path().join("second.apk");
    let bytes = package(&[("lib/test.so", &vec![0; 400])]);
    std::fs::write(&first, &bytes).unwrap();
    std::fs::write(&second, &bytes).unwrap();
    let limits = ResourceLimits {
        max_entry_bytes: 1024,
        max_total_bytes: 600,
        ..ResourceLimits::default()
    };
    let mut cache = run_cache_with_limits(&limits);
    let out = temp.path().join("out");
    let first =
        restore_package_cached(&first, Path::new("first.apk"), &out, &mut cache, false).unwrap();
    assert!(matches!(first[0].status, EntryStatus::NotTarget));
    let error = restore_package_cached(&second, Path::new("second.apk"), &out, &mut cache, false)
        .unwrap_err();
    assert!(format!("{error:#}").contains("extraction limit"));
}

#[test]
fn nested_entries_share_the_outer_archive_count_budget() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bundle.apks");
    let nested = package(&[("lib/test.so", b"not an ELF")]);
    std::fs::write(&input, package(&[("base.apk", &nested)])).unwrap();
    let limits = ResourceLimits {
        max_entries: 1,
        ..ResourceLimits::default()
    };
    let error = restore_package_with_limits(
        &input,
        Path::new("bundle.apks"),
        &temp.path().join("out"),
        &mut HashSet::new(),
        false,
        &limits,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("entry limit"), "{error:#}");
}

#[test]
fn zero_depth_refuses_nested_apks_before_extracting_them() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("bundle.apks");
    std::fs::write(&input, package(&[("base.apk", b"not even a ZIP")])).unwrap();
    let limits = ResourceLimits {
        max_depth: 0,
        ..ResourceLimits::default()
    };
    let error = restore_package_with_limits(
        &input,
        Path::new("bundle.apks"),
        &temp.path().join("out"),
        &mut HashSet::new(),
        false,
        &limits,
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("nesting depth 1"),
        "{error:#}"
    );
}

#[test]
fn failed_entry_extraction_removes_its_partial_temporary() {
    let bytes = package(&[("lib/test.so", &vec![0; 4096])]);
    let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let mut budget = archive_limits::ArchiveBudget::from_limits(&ResourceLimits {
        max_entry_bytes: 1024,
        ..ResourceLimits::default()
    });
    assert!(
        extract_entry(
            &mut archive,
            0,
            &workspace,
            Path::new("app.apk::lib/test.so"),
            &mut budget
        )
        .is_err()
    );
    assert_eq!(std::fs::read_dir(workspace.path()).unwrap().count(), 0);
}
