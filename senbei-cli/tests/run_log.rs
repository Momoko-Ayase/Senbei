use senbei_io::job;
use std::path::Path;

fn list_logs(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("senbei-") && n.ends_with(".log"))
                .unwrap_or(false)
        })
        .collect()
}

#[test]
fn run_file_no_log_creates_no_logfile() {
    let td = tempfile::tempdir().unwrap();
    let input = td.path().join("not_crackproof.bin");
    std::fs::write(&input, b"not a pe").unwrap();
    let out = td.path().join("out");
    let s = job::run_file_v(&input, Some(&out), 2, false, true).unwrap();
    assert_eq!(s.errors, 1);
    // With no_log, no senbei-*.log under out (even if the dir was created).
    assert!(list_logs(&out).is_empty());
}

#[test]
fn run_file_writes_log_under_out_with_header_footer() {
    let td = tempfile::tempdir().unwrap();
    let input = td.path().join("not_crackproof.bin");
    std::fs::write(&input, b"not a pe").unwrap();
    let out = td.path().join("out");
    let s = job::run_file_v(&input, Some(&out), 2, false, false).unwrap();
    assert_eq!(s.errors, 1);
    let logs = list_logs(&out);
    assert_eq!(logs.len(), 1, "expected one log under out, got {logs:?}");
    let text = std::fs::read_to_string(&logs[0]).unwrap();
    assert!(text.contains("Senbei "), "header version: {text}");
    assert!(text.contains("started "), "{text}");
    assert!(text.contains("input "), "{text}");
    assert!(text.contains("out "), "{text}");
    assert!(text.contains("ERR "), "{text}");
    assert!(text.contains("done in "), "{text}");
    assert!(text.contains("summary:"), "{text}");
}

#[test]
fn run_file_default_out_root_is_parent_unpack() {
    let td = tempfile::tempdir().unwrap();
    let input = td.path().join("not_crackproof.bin");
    std::fs::write(&input, b"not a pe").unwrap();
    let _ = job::run_file_v(&input, None, 2, false, false).unwrap();
    let unpack = td.path().join("unpack");
    assert!(unpack.is_dir());
    assert_eq!(list_logs(&unpack).len(), 1);
    // log must NOT be next to input's parent root without unpack
    assert!(list_logs(td.path()).is_empty());
}

#[test]
fn run_folder_log_lives_under_out_not_root() {
    let td = tempfile::tempdir().unwrap();
    // empty tree: 0 candidates still creates log under unpack
    let s = job::run_folder_v(td.path(), None, 2, false, false).unwrap();
    assert_eq!(s.unpacked, 0);
    let unpack = td.path().join("unpack");
    assert!(unpack.is_dir());
    assert_eq!(list_logs(&unpack).len(), 1);
    assert!(
        list_logs(td.path()).is_empty(),
        "log must not sit on input root"
    );
    let text = std::fs::read_to_string(&list_logs(&unpack)[0]).unwrap();
    assert!(text.contains("done in "));
    assert!(text.contains("summary:"));
}
