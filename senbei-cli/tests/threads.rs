//! CLI worker-cap parsing and composition with report-only inspection.

use std::process::Command;

fn senbei() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_senbei"));
    command.env("SENBEI_LANG", "en");
    command
}

#[test]
fn rejects_missing_zero_negative_and_overflowing_caps() {
    for value in [
        "",
        "0",
        "-1",
        "+1",
        "1.5",
        "many",
        "999999999999999999999999999999",
    ] {
        let output = senbei()
            .args(["--threads", value, "--no-pause"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{value:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("--threads"));
    }
    assert_eq!(
        senbei().arg("--threads").output().unwrap().status.code(),
        Some(2)
    );
}

#[test]
fn composes_with_inspection_and_machine_output_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("plain.bin");
    std::fs::write(&input, b"not a protected image").unwrap();
    for cap in ["1", "4"] {
        let output = senbei()
            .env("SENBEI_THREADS", "invalid")
            .arg("inspect")
            .arg(&input)
            .args(["--threads", cap, "--json", "--no-pause"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["mode"], "inspect");
        assert_eq!(report["format_version"], 1);
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn help_describes_the_environment_override() {
    let output = senbei().arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--threads N"));
    assert!(help.contains("Overrides SENBEI_THREADS"));
    assert!(help.contains("sequential"));
}
