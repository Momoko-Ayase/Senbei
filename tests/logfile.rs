use senbei::logfile::{Log, local_stamp_compact, local_stamp_display};

#[test]
fn local_stamp_compact_matches_shape() {
    let s = local_stamp_compact();
    // YYYYMMDD-HHMMSS → 15 chars, digit groups around dash
    assert_eq!(s.len(), 15, "got {s}");
    assert_eq!(&s[8..9], "-");
    assert!(s.as_bytes().iter().enumerate().all(|(i, b)| {
        if i == 8 {
            *b == b'-'
        } else {
            b.is_ascii_digit()
        }
    }));
}

#[test]
fn local_stamp_display_matches_shape() {
    let s = local_stamp_display();
    // YYYY-MM-DD HH:MM:SS → 19 chars
    assert_eq!(s.len(), 19, "got {s}");
    assert_eq!(&s[4..5], "-");
    assert_eq!(&s[7..8], "-");
    assert_eq!(&s[10..11], " ");
    assert_eq!(&s[13..14], ":");
    assert_eq!(&s[16..17], ":");
}

#[test]
fn log_writes_timestamped_file_in_target_dir() {
    let td = tempfile::tempdir().unwrap();
    let log = Log::create(td.path()).unwrap();
    log.step("hello");
    let path = log.path().to_path_buf();
    drop(log);
    assert!(path.starts_with(td.path()));
    let name = path.file_name().unwrap().to_string_lossy();
    assert!(
        name.starts_with("senbei-") && name.ends_with(".log"),
        "unexpected log name: {name}"
    );
    // senbei-YYYYMMDD-HHMMSS.log
    let core = name.trim_start_matches("senbei-").trim_end_matches(".log");
    assert_eq!(core.len(), 15, "stamp in name: {name}");
    assert!(std::fs::read_to_string(&path).unwrap().contains("hello"));
}
