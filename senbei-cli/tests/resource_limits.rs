use std::process::Command;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_senbei"));
    command.args(["--no-pause", "--no-log"]);
    command
}

#[test]
fn help_lists_resource_limits_and_defaults() {
    let output = command().arg("--help").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for option in [
        "--max-entry-mib",
        "--max-total-mib",
        "--max-entries",
        "--max-depth",
    ] {
        assert!(text.contains(option), "missing {option}");
    }
    for value in ["2048", "8192", "100000", "32", "not a peak-RSS cap"] {
        assert!(text.contains(value), "missing {value}");
    }
}

#[test]
fn invalid_limits_exit_with_usage_error() {
    for option in [
        "--max-entry-mib",
        "--max-total-mib",
        "--max-entries",
        "--max-depth",
    ] {
        for value in [
            None,
            Some("-1"),
            Some("invalid"),
            Some("18446744073709551616"),
        ] {
            let mut command = command();
            command.arg(option);
            if let Some(value) = value {
                command.arg(value);
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(2), "{option} {value:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains(option));
        }
    }
}

#[test]
fn limits_compose_with_strict_and_quiet_modes() {
    let input = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let output = command()
        .arg(input.path())
        .arg("--out")
        .arg(out.path())
        .args([
            "--max-entry-mib",
            "1",
            "--max-total-mib",
            "2",
            "--max-entries",
            "1",
            "--max-depth",
            "0",
            "--strict-integrity",
            "-q",
            "-q",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn zip_entry_limit_rejects_before_central_directory_indexing() {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("large.apk");
    // A ZIP end record advertising two entries is enough to exercise the
    // preflight. Its directory is intentionally absent: the count limit must
    // reject it before the ZIP parser tries to read that directory.
    let mut bytes = b"PK\x03\x04".to_vec();
    let mut end = [0_u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[8..10].copy_from_slice(&2_u16.to_le_bytes());
    end[10..12].copy_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&end);
    std::fs::write(&package, bytes).unwrap();
    let output = command()
        .arg(&package)
        .arg("--out")
        .arg(temp.path().join("out"))
        .args(["--max-entries", "1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("entry limit"),
        "{output:?}"
    );
}
