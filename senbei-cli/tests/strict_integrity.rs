//! CLI behavior of `--strict-integrity`.
//!
//! The flag is off by default and only changes the exit status (see the unit
//! tests in `src/main.rs` for the errors-versus-suspect matrix). These tests
//! drive the binary: help text, flag parsing, the error exit, and the quiet
//! contract. The suspect-only exit policy is covered separately by unit tests
//! so these process tests do not depend on the optional protected corpus.

use std::path::Path;
use std::process::Command;

fn senbei() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_senbei"));
    command.env("SENBEI_LANG", "en");
    command
}

fn run(args: &[&str]) -> std::process::Output {
    senbei().args(args).output().expect("spawn senbei")
}

fn assert_silent(output: &std::process::Output) {
    assert!(
        output.stdout.is_empty() && output.stderr.is_empty(),
        "quiet>=2 must stay silent, stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_plain(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("plain.bin");
    std::fs::write(&path, b"not a protected image").unwrap();
    path
}

fn list_logs(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("senbei-") && name.ends_with(".log"))
        })
        .collect()
}

#[test]
fn help_documents_strict_integrity_behavior() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("--strict-integrity"));
    assert!(text.contains("--quiet"));
    assert!(text.contains("exit non-zero"));
    assert!(text.contains("suspect"));
    assert!(text.contains("Off by default"));
    assert!(text.contains("still written"));
    assert!(text.contains("exits 0 unless"));
    assert!(text.contains("a file errors"));
    assert!(text.contains("Quiet levels are unchanged"));
}

#[test]
fn short_help_and_version_ignore_the_flag_position() {
    let help = run(&["-h", "--strict-integrity"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--strict-integrity"));

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("Senbei "));
}

#[test]
fn unknown_flag_still_exits_2() {
    let output = run(&["--strict"]);
    assert_eq!(output.status.code(), Some(2));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("unknown option '--strict'"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("--strict-integrity"));
}

#[test]
fn missing_input_exits_2_with_the_flag() {
    let output = run(&["--strict-integrity", "--no-pause"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("--strict-integrity"));
}

#[test]
fn errors_exit_1_by_default_and_when_strict_and_write_nothing() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path());
    for extra in [None, Some("--strict-integrity")] {
        let out = td
            .path()
            .join(if extra.is_some() { "strict" } else { "default" });
        let mut args = vec![
            input.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--no-log",
            "--no-pause",
        ];
        if let Some(flag) = extra {
            args.push(flag);
        }
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            !out.join("plain.unpack.bin").exists(),
            "an error must not leave an artifact"
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("0 unpacked"));
        assert!(text.contains("1 errors"));
        assert!(text.contains("0 suspect"));
    }
}

#[test]
fn double_quiet_stays_silent_for_errors_in_both_modes() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path());
    let out = td.path().join("out");
    for extra in [None, Some("--strict-integrity")] {
        let mut args = vec![
            input.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--no-log",
            "--no-pause",
            "-q",
            "-q",
        ];
        if let Some(flag) = extra {
            args.push(flag);
        }
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1));
        assert_silent(&output);
    }
}

#[test]
fn single_quiet_keeps_the_summary_and_the_error() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path());
    let out = td.path().join("out");
    let output = run(&[
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--no-log",
        "--no-pause",
        "-q",
        "--strict-integrity",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // One -q only suppresses per-file lines. The banner and the summary still
    // print; that is the existing quiet contract and strict mode must not
    // change it.
    assert!(stdout.contains("Senbei "), "{stdout}");
    assert!(stdout.contains("1 errors"), "{stdout}");
    assert!(stdout.contains("0 suspect"), "{stdout}");
}

#[test]
fn strict_does_not_change_what_the_log_records() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path());
    let out = td.path().join("out");
    let output = run(&[
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--strict-integrity",
        "--no-pause",
        "-q",
        "-q",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_silent(&output);
    let logs = list_logs(&out);
    assert_eq!(logs.len(), 1);
    let text = std::fs::read_to_string(&logs[0]).unwrap();
    assert!(text.contains("summary:"));
    assert!(text.contains("1 errors"));
    assert!(text.contains("0 suspect"));
}
