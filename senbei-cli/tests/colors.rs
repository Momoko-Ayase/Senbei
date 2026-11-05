//! Terminal presentation is opt-in for pipes and never enters stored data.

#[path = "support/fixtures.rs"]
mod fixtures;

use std::path::Path;
use std::process::{Command, Output};

fn senbei() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_senbei"));
    command
        .arg("--no-pause")
        .env_remove("NO_COLOR")
        .env("TERM", "xterm-256color");
    command
}

fn fixture(root: &Path) -> std::path::PathBuf {
    let path = root.join("global-metadata.dat");
    std::fs::write(&path, fixtures::obfuscated_metadata()).unwrap();
    path
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("UTF-8 console output")
}

fn assert_plain(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!bytes.contains(&0x1b), "unexpected ANSI: {}", text(bytes));
        assert!(!text(bytes).to_ascii_lowercase().contains("\\u001b"));
    }
}

fn strip_styles(value: &str) -> String {
    let mut chars = value.chars();
    let mut plain = String::new();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            assert_eq!(chars.next(), Some('['));
            for code in chars.by_ref() {
                if code == 'm' {
                    break;
                }
                assert!(code.is_ascii_digit() || code == ';');
            }
        } else {
            plain.push(ch);
        }
    }
    plain
}

#[test]
fn inspect_colors_preserve_report_content() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(temp.path());
    let plain = senbei()
        .arg("inspect")
        .arg(&path)
        .args(["--color", "never"])
        .output()
        .unwrap();
    let colored = senbei()
        .arg("inspect")
        .arg(&path)
        .arg("--color=always")
        .output()
        .unwrap();
    assert!(plain.status.success());
    assert!(colored.status.success());
    assert_plain(&plain);
    assert!(colored.stdout.contains(&0x1b));
    assert!(colored.stderr.is_empty());
    let strip_time = |value: &str| {
        value
            .lines()
            .filter(|line| !line.ends_with(" ms"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        strip_time(&strip_styles(text(&colored.stdout))),
        strip_time(text(&plain.stdout))
    );
    assert!(text(&colored.stdout).contains("\x1b[32msucceeded\x1b[0m"));
    assert!(!temp.path().join("unpack").exists());
}

#[test]
fn ordinary_unpack_colors_results_but_not_saved_logs() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(temp.path());
    let out = temp.path().join("out");
    let output = senbei()
        .arg("unpack")
        .arg(&path)
        .arg("--out")
        .arg(&out)
        .args(["--color", "always"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(output.stdout.contains(&0x1b));
    assert!(text(&output.stdout).contains("\x1b[32m✓\x1b[0m"));
    assert!(out.join("global-metadata.unpack.dat").is_file());
    let logs: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|value| value == "log"))
        .collect();
    assert_eq!(logs.len(), 1);
    let log = std::fs::read_to_string(&logs[0]).unwrap();
    assert!(!log.contains('\x1b'));
    assert!(!log.contains("\\u001b"));
    assert!(log.contains("summary:"));
    assert!(log.contains("method fields"));
}

#[test]
fn folder_unpack_uses_the_same_palette_and_plain_logs() {
    let temp = tempfile::tempdir().unwrap();
    fixture(temp.path());
    let output = senbei()
        .arg("unpack")
        .arg(temp.path())
        .args(["--color=always", "--scan-all"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("\x1b[32m✓\x1b[0m"));
    assert!(text(&output.stdout).contains("metadata"));
    for entry in std::fs::read_dir(temp.path().join("unpack"))
        .unwrap()
        .flatten()
    {
        if entry.path().extension().is_some_and(|value| value == "log") {
            assert!(!std::fs::read(entry.path()).unwrap().contains(&0x1b));
        }
    }
}

#[test]
fn redirected_auto_and_never_are_plain_for_both_commands() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(temp.path());
    for operation in ["inspect", "unpack"] {
        for args in [vec![], vec!["--color", "auto"], vec!["--color=never"]] {
            let output = senbei()
                .arg(operation)
                .arg(&path)
                .args(args)
                .arg("--no-log")
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_plain(&output);
        }
    }
}

#[test]
fn explicit_color_overrides_no_color_and_dumb_terminal() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(temp.path());
    for operation in ["inspect", "unpack"] {
        let forced = senbei()
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .arg(operation)
            .arg(&path)
            .args(["--color=always", "--no-log"])
            .output()
            .unwrap();
        assert!(forced.status.success());
        assert!(forced.stdout.contains(&0x1b));
        let plain = senbei()
            .env("NO_COLOR", "1")
            .env("TERM", "dumb")
            .arg(operation)
            .arg(&path)
            .args(["--color=auto", "--no-log"])
            .output()
            .unwrap();
        assert!(plain.status.success());
        assert_plain(&plain);
    }
}

#[test]
fn json_stays_plain_even_with_forced_color_and_verbose() {
    let temp = tempfile::tempdir().unwrap();
    let path = fixture(temp.path());
    for operation in ["inspect", "unpack"] {
        let out = temp.path().join(format!("json-{operation}"));
        let mut command = senbei();
        command
            .arg(operation)
            .arg(&path)
            .args(["--json", "--verbose", "--color", "always"]);
        if operation == "unpack" {
            command.arg("--out").arg(&out);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{}", text(&output.stderr));
        assert_plain(&output);
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["inputs"][0]["profile"]["recovery"], "succeeded");
        if out.exists() {
            assert!(
                std::fs::read_dir(&out)
                    .unwrap()
                    .flatten()
                    .all(|entry| entry.path().extension().is_none_or(|value| value != "log"))
            );
        }
    }
}

#[test]
fn forced_color_diagnostics_use_stderr_and_quiet_still_wins() {
    let temp = tempfile::tempdir().unwrap();
    let invalid = temp.path().join("invalid.exe");
    std::fs::write(&invalid, b"not a protected image").unwrap();
    let failed = senbei()
        .arg(&invalid)
        .args(["--color=always", "--no-log"])
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1));
    assert!(text(&failed.stderr).contains("\x1b[31merror\x1b[0m"));
    for operation in ["inspect", "unpack"] {
        let output = senbei()
            .arg(operation)
            .arg(&invalid)
            .args(["--color=always", "--no-log", "-q", "-q"])
            .output()
            .unwrap();
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn invalid_color_arguments_are_usage_errors_and_help_explains_policy() {
    for args in [
        vec!["--color"],
        vec!["--color="],
        vec!["--color=bright"],
        vec!["--color", "bright"],
    ] {
        let output = senbei().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(text(&output.stderr).contains("--color requires auto, always, or never"));
        assert_plain(&output);
    }
    let help = senbei().arg("--help").output().unwrap();
    let help = text(&help.stdout);
    for fact in [
        "--color",
        "NO_COLOR",
        "TERM=dumb",
        "JSON and saved logs stay plain",
    ] {
        assert!(help.contains(fact), "missing {fact}: {help}");
    }
}
