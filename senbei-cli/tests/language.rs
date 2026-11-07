//! The console follows SENBEI_LANG (or the system language); saved logs and
//! `--json` reports stay English in every language.

#[path = "support/fixtures.rs"]
mod fixtures;

use std::path::Path;
use std::process::Command;

use senbei_i18n::{Cli, Lang, Localize};

fn senbei(lang: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_senbei"));
    command.arg("--no-pause").env("SENBEI_LANG", lang);
    command
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("UTF-8 console output")
}

fn fixture(root: &Path) -> std::path::PathBuf {
    let path = root.join("global-metadata.dat");
    std::fs::write(&path, fixtures::obfuscated_metadata()).unwrap();
    path
}

fn without_timings(json: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(json).expect("one JSON document");
    fn strip(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.remove("duration_ms");
                map.values_mut().for_each(strip);
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut value);
    value.to_string()
}

#[test]
fn usage_errors_and_help_follow_the_language() {
    for lang in [Lang::ZhCn, Lang::ZhTw, Lang::Ja, Lang::Ko] {
        let output = senbei(lang.tag()).arg("--bogus").output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let expected = format!(
            "{}: {}",
            Cli::Error.localize(lang),
            Cli::UnknownOption {
                option: "--bogus".into()
            }
            .localize(lang)
        );
        assert!(text(&output.stderr).contains(&expected), "{lang:?}");
        assert!(text(&output.stdout).contains(&*Cli::HelpJson.localize(lang)));
        assert_ne!(
            Cli::HelpJson.localize(lang),
            Cli::HelpJson.localize(Lang::En),
            "{lang:?} is still English"
        );
    }
}

#[test]
fn an_unknown_language_falls_back_to_english() {
    for value in ["fr", "C", "x-unknown"] {
        let output = senbei(value).arg("--bogus").output().unwrap();
        assert!(
            text(&output.stderr).contains("error: unknown option '--bogus'"),
            "{value}"
        );
    }
}

#[test]
fn the_console_is_translated_while_logs_and_json_stay_english() {
    let temp = tempfile::tempdir().unwrap();
    let input = fixture(temp.path());
    let out = temp.path().join("out");
    let output = senbei("zh-CN")
        .arg(&input)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output.stderr));
    let summary = Cli::Summary {
        unpacked: "0".into(),
        skipped: "0".into(),
        errors: "0".into(),
        suspect: "0".into(),
        metadata: "1".into(),
    };
    let stdout = text(&output.stdout);
    assert!(stdout.contains(&*summary.localize(Lang::ZhCn)), "{stdout}");
    assert!(!stdout.contains("unpacked"), "{stdout}");

    let log = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|value| value == "log"))
        .expect("a run log");
    let log = std::fs::read_to_string(log).unwrap();
    assert!(
        log.contains("summary: 0 unpacked · 0 skipped · 0 errors · 0 suspect · 1 metadata"),
        "{log}"
    );

    let json = |lang: &str| {
        let output = senbei(lang)
            .args(["inspect", "--json"])
            .arg(&input)
            .output()
            .unwrap();
        assert!(output.status.success());
        without_timings(text(&output.stdout))
    };
    assert_eq!(json("ko"), json("en"));
}

#[test]
fn inspect_text_translates_summary_lines_but_keeps_values() {
    let temp = tempfile::tempdir().unwrap();
    let input = fixture(temp.path());
    let output = senbei("ja").arg("inspect").arg(&input).output().unwrap();
    assert!(output.status.success());
    let stdout = text(&output.stdout);
    let recovery = Cli::StaticRecovery {
        status: senbei_i18n::Term::Succeeded.localize(Lang::Ja).into_owned(),
    };
    assert!(stdout.contains(&*recovery.localize(Lang::Ja)), "{stdout}");
    assert!(!stdout.contains("static recovery"), "{stdout}");
    // Paths and the structural evidence are values, never translated.
    assert!(stdout.contains(&*input.display().to_string()), "{stdout}");
    assert!(stdout.contains("tried_seeds"), "{stdout}");
}
