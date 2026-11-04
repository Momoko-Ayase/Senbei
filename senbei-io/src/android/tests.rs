use super::*;
use zip::write::SimpleFileOptions;

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
