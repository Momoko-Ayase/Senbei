//! CLI behaviour of `inspect`, `unpack`, `--json`, and `--dry-run`.
//!
//! These tests drive the binary against generated fixtures only: nothing here
//! needs the optional protected corpus, so they run everywhere. They pin the
//! three contracts the flags exist for:
//!
//! * `--json` writes one versioned document to stdout and nothing else.
//! * `inspect` writes no output, no log, and no temporary file, and never
//!   claims a route succeeded.
//! * `--dry-run` runs the real recovery and still leaves no ordinary output
//!   and no log behind.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[test]
fn unreadable_unpack_input_blocks_routes_instead_of_inventing_an_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("missing.dll");
    let dest = dir.path().join("unused.dll");
    let (profile, result) = senbei_io::job::unpack_one_profiled(&input, &dest, false);
    assert!(result.is_err());
    assert_eq!(profile.recovery, senbei_engine::RecoveryStatus::Blocked);
    assert_eq!(
        profile.static_validation,
        senbei_engine::ValidationStatus::NotRun
    );
    assert!(profile.candidates.is_empty());
    assert!(profile.selected.is_none());
    assert!(!dest.exists());
}

fn senbei() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_senbei"));
    command.arg("--no-pause");
    command
}

fn run(args: &[&str]) -> Output {
    senbei().args(args).output().expect("spawn senbei")
}

/// Every path below `root`, so a test can prove nothing appeared.
fn tree(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

fn parse_json(output: &Output) -> serde_json::Value {
    let text = String::from_utf8(output.stdout.clone()).expect("utf-8 stdout");
    serde_json::from_str(text.trim())
        .unwrap_or_else(|error| panic!("stdout was not one JSON document: {error}\n{text}"))
}

fn logs_below(root: &Path) -> Vec<PathBuf> {
    tree(root)
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("senbei-") && name.ends_with(".log"))
        })
        .collect()
}

/// The folder scan's size floor: a selected name below it is never opened, so
/// fixtures have to clear it to appear in a folder run.
const SCAN_FLOOR: usize = 4128;

fn write_plain(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let mut bytes = b"not a protected image at all".to_vec();
    bytes.resize(SCAN_FLOOR + 128, 0);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// A metadata header of the given version, without a real body. Identification
/// reads only the 8-byte header, so this is enough to exercise the capability
/// and unsupported-version paths.
fn write_metadata(dir: &Path, version: u32) -> PathBuf {
    let path = dir.join("global-metadata.dat");
    let mut bytes = 0xFAB1_1BAF_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.resize(SCAN_FLOOR + 128, 0);
    std::fs::write(&path, bytes).unwrap();
    path
}

// ---------------------------------------------------------------------------
// JSON purity
// ---------------------------------------------------------------------------

#[test]
fn json_inspect_writes_one_versioned_document_and_nothing_else() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path(), "plain.exe");
    let output = run(&["inspect", input.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(0));
    // No banner, no progress, no log path: stdout is the document alone.
    assert!(output.stderr.is_empty(), "stderr must be empty");
    let value = parse_json(&output);
    assert_eq!(value["format_version"], 1);
    assert_eq!(value["tool"]["name"], "senbei");
    assert_eq!(value["mode"], "inspect");
    assert!(value["inputs"].is_array());
    assert_eq!(value["inputs"][0]["path"], input.display().to_string());
    assert_eq!(value["inputs"][0]["status"], "skipped");
}

#[test]
fn json_unpack_reports_outputs_and_status() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path(), "plain.exe");
    let out = td.path().join("out");
    let output = run(&[
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--json",
    ]);
    assert!(output.stderr.is_empty(), "stderr must be empty");
    let value = parse_json(&output);
    assert_eq!(value["mode"], "unpack");
    // A non-target is a per-input error in unpack mode, and the document says so.
    assert_eq!(value["summary"]["errors"], 1);
    assert_eq!(value["inputs"][0]["status"], "error");
    assert!(
        !value["inputs"][0]["errors"].as_array().unwrap().is_empty(),
        "the failure reason must be in the report"
    );
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn json_error_status_is_reported_in_the_document() {
    let output = run(&["inspect", "Z:/definitely/not/here", "--json"]);
    assert_eq!(output.status.code(), Some(1));
    let value = parse_json(&output);
    assert_eq!(value["format_version"], 1);
    assert_eq!(value["summary"]["errors"], 1);
}

// ---------------------------------------------------------------------------
// Inspect writes nothing
// ---------------------------------------------------------------------------

#[test]
fn inspect_writes_no_output_no_log_and_no_temporary() {
    let td = tempfile::tempdir().unwrap();
    write_plain(td.path(), "plain.exe");
    write_metadata(td.path(), 31);
    let before = tree(td.path());

    let output = run(&["inspect", td.path().to_str().unwrap()]);
    assert!(output.status.success(), "inspect must succeed: {output:?}");
    assert_eq!(
        tree(td.path()),
        before,
        "inspect must not create, change, or remove anything"
    );
}

/// Inspection reports the real attempt but keeps nothing: no output file is
/// advertised, and a non-target never gets a route selected for it.
#[test]
fn inspect_keeps_nothing_and_claims_no_route_for_a_non_target() {
    let td = tempfile::tempdir().unwrap();
    write_plain(td.path(), "plain.exe");
    let output = run(&["inspect", td.path().to_str().unwrap(), "--json"]);
    let value = parse_json(&output);
    for input in value["inputs"].as_array().unwrap() {
        assert!(
            input["profile"]["selected"].is_null(),
            "a non-target selects no route: {input}"
        );
        assert_eq!(input["profile"]["recognition"], "not_recognized");
        assert_eq!(input["status"], "skipped");
        assert!(
            input["outputs"].as_array().unwrap().is_empty(),
            "inspect must not report outputs"
        );
        assert!(input["recovered"].is_null());
    }
    assert_eq!(value["summary"]["errors"], 0);
}

#[test]
fn inspect_reports_metadata_capability_without_a_protection_verdict() {
    let td = tempfile::tempdir().unwrap();
    write_metadata(td.path(), 31);
    let output = run(&["inspect", td.path().to_str().unwrap(), "--json"]);
    let value = parse_json(&output);
    let input = &value["inputs"][0];
    assert_eq!(input["metadata"]["raw_version"], 31);
    assert_eq!(input["metadata"]["layout"], "known");
    assert_eq!(input["metadata_version"], 31);
    // Identification is a header fact; it is never protection evidence.
    assert!(input["profile"]["evidence"].as_array().unwrap().is_empty());
}

#[test]
fn inspect_reports_an_unsupported_metadata_version_without_failing_the_run() {
    let td = tempfile::tempdir().unwrap();
    write_metadata(td.path(), 27);
    let output = run(&["inspect", td.path().to_str().unwrap(), "--json"]);
    assert!(output.status.success());
    let value = parse_json(&output);
    let input = &value["inputs"][0];
    assert_eq!(input["metadata_version"], 27);
    assert_eq!(input["metadata"]["layout"], "unverified");
    assert_eq!(input["status"], "skipped");
    assert_eq!(value["summary"]["errors"], 0);
}

// ---------------------------------------------------------------------------
// Dry run keeps nothing
// ---------------------------------------------------------------------------

#[test]
fn dry_run_writes_no_ordinary_output_and_no_log() {
    let td = tempfile::tempdir().unwrap();
    write_plain(td.path(), "plain.exe");
    write_metadata(td.path(), 31);
    let before = tree(td.path());

    let output = run(&["--dry-run", td.path().to_str().unwrap()]);
    assert!(
        logs_below(td.path()).is_empty(),
        "dry run must not write a log"
    );
    assert_eq!(
        tree(td.path()),
        before,
        "dry run must not leave outputs, logs, or temporaries behind"
    );
    assert!(
        !output.stdout.is_empty(),
        "a dry run still reports what it tried"
    );
}

#[test]
fn dry_run_json_describes_an_attempt_that_really_ran() {
    let td = tempfile::tempdir().unwrap();
    // A single file is always attempted, so the report shows a real failure
    // rather than the scan declining to select it.
    let input = write_plain(td.path(), "plain.exe");
    let output = run(&["--dry-run", input.to_str().unwrap(), "--json"]);
    let value = parse_json(&output);
    assert_eq!(value["mode"], "dry_run");
    let reported = &value["inputs"][0];
    assert_eq!(reported["path"], input.display().to_string());
    // The pipeline was really consulted: an unreadable-as-protected input is
    // reported as not recognized, with the reason recorded.
    assert_eq!(reported["profile"]["recognition"], "not_recognized");
    assert!(
        !reported["profile"]["errors"].as_array().unwrap().is_empty(),
        "the failure reason must be in the profile"
    );
    assert!(
        reported["outputs"].as_array().unwrap().is_empty(),
        "a dry run reports no output files"
    );
    assert_eq!(reported["status"], "error");
}

/// Only inspection keeps the research payloads; an ordinary unpack must not
/// serialize or clone them.
#[test]
fn unpack_and_dry_run_carry_no_research_payload() {
    let td = tempfile::tempdir().unwrap();
    let input = write_metadata(td.path(), 31);
    let out = td.path().join("out");
    let unpack = run(&[
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--json",
    ]);
    let dry_run = run(&["--dry-run", input.to_str().unwrap(), "--json"]);

    for output in [unpack, dry_run] {
        let value = parse_json(&output);
        for reported in value["inputs"].as_array().unwrap() {
            assert!(reported["research"].is_null(), "{reported}");
            assert!(reported["android_research"].is_null(), "{reported}");
            assert!(reported["metadata_research"].is_null(), "{reported}");
            assert!(reported["source"].is_null(), "{reported}");
        }
    }
}

#[test]
fn dry_run_refuses_an_output_directory() {
    let output = run(&["--dry-run", "--out", "out", "plain.exe"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--dry-run"));
}

// ---------------------------------------------------------------------------
// Backward compatibility
// ---------------------------------------------------------------------------

#[test]
fn legacy_positional_invocation_is_unchanged() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path(), "plain.exe");
    let out = td.path().join("out");

    let legacy = run(&[input.to_str().unwrap(), "--out", out.to_str().unwrap()]);
    assert_eq!(legacy.status.code(), Some(1), "a non-target is an error");
    let text = String::from_utf8_lossy(&legacy.stdout);
    assert!(text.starts_with("Senbei "), "banner is still printed");
    assert!(text.contains("0 unpacked"), "{text}");
    assert!(text.contains("done in "), "{text}");

    // The explicit alias behaves identically.
    let aliased = run(&[
        "unpack",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(aliased.status.code(), legacy.status.code());
}

#[test]
fn quiet_level_two_stays_silent() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path(), "plain.exe");
    let output = run(&[
        input.to_str().unwrap(),
        "--out",
        td.path().join("out").to_str().unwrap(),
        "-q",
        "-q",
        "--no-log",
    ]);
    assert!(output.stdout.is_empty(), "quiet>=2 stdout");
    assert!(output.stderr.is_empty(), "quiet>=2 stderr");
}

#[test]
fn inspect_help_is_documented() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for needle in ["inspect", "--json", "--dry-run", "unpack"] {
        assert!(text.contains(needle), "help must document {needle}");
    }
}

#[test]
fn inspect_rejects_writing_flags() {
    let output = run(&["inspect", "--json", "--out", "x"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "--out writes, inspect keeps nothing"
    );
    let output = run(&["inspect", "--dry-run", "x"]);
    assert_eq!(output.status.code(), Some(2));
}

/// Inspection runs the real static check, so `--strict-integrity` is a real
/// request about a real verdict rather than a contradiction.
#[test]
fn inspect_accepts_strict_integrity() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path(), "plain.exe");
    let output = run(&["inspect", input.to_str().unwrap(), "--strict-integrity"]);
    assert_ne!(output.status.code(), Some(2), "not a usage error");
}

// ---------------------------------------------------------------------------
// Containers and companions
// ---------------------------------------------------------------------------

/// A minimal plain-text `AndroidManifest.xml` the manifest reader accepts.
const MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app" android:versionCode="42" android:versionName="1.0">
</manifest>
"#;

/// CRC-32 (IEEE) as used by ZIP local and central headers.
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                0xEDB8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *slot = value;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc = table[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// A ZIP at `path` holding `entries` as **stored** (uncompressed) members.
///
/// Written by hand so the fixture needs no extra dependency: the point of the
/// test is the inventory, not the compressor.
fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let mut out: Vec<u8> = Vec::new();
    let mut directory: Vec<u8> = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let size = data.len() as u32;
        out.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        directory.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes()); // made by
        directory.extend_from_slice(&20u16.to_le_bytes()); // needed
        directory.extend_from_slice(&0u16.to_le_bytes()); // flags
        directory.extend_from_slice(&0u16.to_le_bytes()); // stored
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes()); // extra
        directory.extend_from_slice(&0u16.to_le_bytes()); // comment
        directory.extend_from_slice(&0u16.to_le_bytes()); // disk
        directory.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        directory.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
    }
    let directory_offset = out.len() as u32;
    let directory_size = directory.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // directory disk
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&directory_size.to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    std::fs::write(path, out).unwrap();
}

#[test]
fn inspect_reports_a_container_inventory_separately_from_its_entries() {
    let td = tempfile::tempdir().unwrap();
    let apk = td.path().join("base.apk");
    write_zip(
        &apk,
        &[
            ("AndroidManifest.xml", MANIFEST.as_bytes()),
            // A large asset: an inventory must not need to read it.
            ("assets/big.bin", &vec![0u8; 200_000]),
            ("lib/arm64-v8a/libil2cpp.so", b"\x7fELF-not-really"),
        ],
    );

    let output = run(&["inspect", apk.to_str().unwrap(), "--json"]);
    let value = parse_json(&output);
    let input = &value["inputs"][0];
    assert_eq!(input["role"], "container");
    assert_eq!(input["container"]["kind"], "apk");
    let manifests = input["container"]["manifests"].as_array().unwrap();
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0]["package"], "com.example.app");
    assert_eq!(manifests[0]["version"], "42");
    assert_eq!(manifests[0]["named"], true);
    // Inventory is membership: the entries a restore would probe, listed apart
    // from the entries that were actually probed (which have their own result).
    let candidates = input["container"]["candidate_entries"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].as_str().unwrap().ends_with("libil2cpp.so"));
    let entries = input["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "the candidate was probed: {input}");
    assert_eq!(entries[0]["status"], "not_target");
    assert!(input["outputs"].as_array().unwrap().is_empty());
    // The container itself has no single profile; its entries do the talking.
    assert!(input["profile"].is_null());
    assert_eq!(input["status"], "skipped");
}

/// A synthetic PE whose header key table carries the supported magic, so it is
/// detectable. No protected bytes are included: only the header layout.
fn fake_protected_pe() -> Vec<u8> {
    const MAGIC: u32 = 0x4E4E_4F4B;
    let mut bytes = vec![0u8; 0x2000];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    // IMAGE_FILE_HEADER.Characteristics: not a DLL.
    bytes[0x86..0x88].copy_from_slice(&0x0102u16.to_le_bytes());
    // Optional header magic (PE32+) and no CLR directory.
    bytes[0x98..0x9a].copy_from_slice(&0x20Bu16.to_le_bytes());
    // Header key table: keys[0] = cell[0]; keys[1] = keys[0] ^ cell[1].
    let cell0 = 0x1234_5678u32;
    let cell1 = cell0 ^ MAGIC;
    bytes[4096..4100].copy_from_slice(&cell0.to_le_bytes());
    bytes[4100..4104].copy_from_slice(&cell1.to_le_bytes());
    bytes
}

#[test]
fn inspect_reports_a_non_matching_companion_without_an_error() {
    let td = tempfile::tempdir().unwrap();
    let input = td.path().join("app.exe");
    std::fs::write(&input, fake_protected_pe()).unwrap();
    // A sibling `._` that cannot be this stub's payload.
    let mut companion = input.file_name().unwrap().to_os_string();
    companion.push("._");
    std::fs::write(input.with_file_name(companion), vec![0xFFu8; 32]).unwrap();

    let output = run(&["inspect", input.to_str().unwrap(), "--json"]);
    assert!(
        output.status.success(),
        "inspection does not fail on a bad pairing"
    );
    let value = parse_json(&output);
    let input = &value["inputs"][0];
    assert_eq!(input["profile"]["recognition"], "recognized");
    assert_eq!(input["companion"]["state"], "unmatched");
    assert!(input["companion"]["path"].is_string());
    assert_eq!(input["profile"]["observed"]["external_companion"], false);
    assert!(input["outputs"].as_array().unwrap().is_empty());
}

/// Inspection runs the real static recovery, so the report carries the attempt
/// and the structural evidence behind it — while still keeping nothing.
#[test]
fn inspect_reports_the_attempt_and_its_structural_evidence() {
    let td = tempfile::tempdir().unwrap();
    let input = td.path().join("app.exe");
    std::fs::write(&input, fake_protected_pe()).unwrap();
    let before = tree(td.path());

    let output = run(&["inspect", input.to_str().unwrap(), "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a failing trial is a finding"
    );
    let value = parse_json(&output);
    let reported = &value["inputs"][0];

    // Recognition is evidence about the input.
    assert_eq!(reported["status"], "recognized");
    assert_eq!(reported["profile"]["recognition"], "recognized");
    // The input identity is the physical file, and it was inspected as-is.
    assert!(reported["source"]["sha256"].is_string());
    assert_eq!(reported["source"]["size"], 0x2000);
    assert_eq!(reported["research"]["input_view"], "original");
    // The header structure the inspector decoded is there, not just a verdict:
    // the recognized magic and the decoded header words it came from.
    let protection = &reported["research"]["input"]["protection"];
    assert_eq!(protection["magic_recognized"], true);
    let words = protection["header_words"].as_array().unwrap();
    assert!(!words.is_empty(), "decoded header words are reported");
    assert!(
        words.iter().any(|word| word["semantic"] == "magic"),
        "each word names the field it decodes to: {protection}"
    );
    // The recovery really ran: a candidate was attempted and no route survived
    // this synthetic image, so nothing is selected.
    assert_ne!(reported["profile"]["recovery"], "not_attempted");
    assert!(reported["profile"]["selected"].is_null());
    // Nothing was kept.
    assert!(reported["outputs"].as_array().unwrap().is_empty());
    assert!(reported["recovered"].is_null());
    assert_eq!(
        tree(td.path()),
        before,
        "inspection must not create, change, or remove anything"
    );
    assert_eq!(value["summary"]["errors"], 0);
}

#[test]
fn unpack_reports_the_companion_state_it_actually_used() {
    let td = tempfile::tempdir().unwrap();
    let input = td.path().join("app.exe");
    std::fs::write(&input, fake_protected_pe()).unwrap();
    let out = td.path().join("out");
    let output = run(&[
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--json",
    ]);
    let value = parse_json(&output);
    let reported = &value["inputs"][0];
    // No companion was present, and the report says exactly that.
    assert_eq!(reported["companion"]["state"], "absent");
    assert!(reported["companion"]["path"].is_null());
    // The failure is recorded on the input, and the profile says which route ran.
    assert_eq!(reported["status"], "error");
    assert_eq!(reported["profile"]["recovery"], "failed");
    let candidates = reported["profile"]["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty(), "the attempted route is recorded");
    assert!(candidates.iter().any(|c| c["outcome"] == "failed"));
}

#[test]
fn a_relative_path_is_reported_verbatim() {
    let td = tempfile::tempdir().unwrap();
    write_plain(td.path(), "plain.exe");
    let output = Command::new(env!("CARGO_BIN_EXE_senbei"))
        .current_dir(td.path())
        .args(["--no-pause", "inspect", "plain.exe", "--json"])
        .output()
        .unwrap();
    let value = parse_json(&output);
    assert_eq!(value["inputs"][0]["path"], "plain.exe");
}

/// A resource ceiling on a real target is an incomplete analysis: the document
/// says so and the process exits 1. It is never "recognized, therefore fine".
#[test]
fn inspect_of_an_over_limit_target_is_incomplete_and_exits_one() {
    let td = tempfile::tempdir().unwrap();
    let apk = td.path().join("base.apk");
    // A protected-library candidate far larger than the 1 MiB entry ceiling.
    let large = vec![0x7Fu8; 2 * 1024 * 1024];
    write_zip(
        &apk,
        &[
            ("AndroidManifest.xml", MANIFEST.as_bytes()),
            ("lib/arm64-v8a/libil2cpp.so", &large),
        ],
    );

    let output = run(&[
        "inspect",
        apk.to_str().unwrap(),
        "--json",
        "--max-entry-mib",
        "1",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a truncated analysis is a failure: {output:?}"
    );
    let value = parse_json(&output);
    assert_eq!(value["summary"]["errors"], 1);
    let input = &value["inputs"][0];
    assert_eq!(input["status"], "error");
    assert_eq!(input["analysis_incomplete"], true);
    assert!(
        !input["errors"].as_array().unwrap().is_empty(),
        "the reason is on the report: {input}"
    );
    assert!(input["outputs"].as_array().unwrap().is_empty());
}

/// An unsupported layout is a research finding, not an incomplete analysis.
#[test]
fn inspect_of_an_unsupported_target_stays_a_finding() {
    let td = tempfile::tempdir().unwrap();
    let input = write_plain(td.path(), "plain.exe");
    let output = run(&["inspect", input.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let value = parse_json(&output);
    assert_eq!(value["summary"]["errors"], 0);
    let reported = &value["inputs"][0];
    assert_eq!(reported["analysis_incomplete"], false, "{reported}");
}
