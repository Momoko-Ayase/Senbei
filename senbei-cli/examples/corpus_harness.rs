//! Local, manifest-driven corpus harness.
//!
//! Run with an explicit manifest:
//!
//! ```text
//! cargo run --release --example corpus_harness -- --manifest corpus.json
//! cargo run --release --example corpus_harness -- --manifest corpus.json \
//!     --report target/corpus-report.json --commit <sha>
//! cargo run --release --example corpus_harness -- --emit-manifest ../samples \
//!     --android-app ../android/com.example.app --manifest-out target/corpus.json
//! ```
//!
//! Exit status is 0 only when every case passes. The report goes to stdout by
//! default; `--report` writes it atomically. Nothing is uploaded, no input or
//! golden is modified, and restored bytes live only in a temporary directory.
//!
//! The manifest schema is documented in `senbei-cli/tests/support/harness.rs`
//! (the `SCHEMA`/`Manifest`/`CaseSpec` types and the module header).

#[path = "../tests/support/harness.rs"]
mod harness;

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut manifest: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut commit: Option<String> = None;
    let mut emit_roots: Vec<PathBuf> = Vec::new();
    let mut android_apps: Vec<PathBuf> = Vec::new();
    let mut manifest_out: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "--manifest" => match args.next() {
                Some(value) => manifest = Some(PathBuf::from(value)),
                None => return usage("--manifest requires a path"),
            },
            "--report" => match args.next() {
                Some(value) => report = Some(PathBuf::from(value)),
                None => return usage("--report requires a path"),
            },
            "--commit" => match args.next() {
                Some(value) => commit = Some(value),
                None => return usage("--commit requires a value"),
            },
            "--emit-manifest" => match args.next() {
                Some(value) => emit_roots.push(PathBuf::from(value)),
                None => return usage("--emit-manifest requires a directory"),
            },
            "--android-app" => match args.next() {
                Some(value) => android_apps.push(PathBuf::from(value)),
                None => return usage("--android-app requires a directory"),
            },
            "--manifest-out" => match args.next() {
                Some(value) => manifest_out = Some(PathBuf::from(value)),
                None => return usage("--manifest-out requires a path"),
            },
            other => return usage(&format!("unknown argument {other:?}")),
        }
    }

    if !emit_roots.is_empty() || !android_apps.is_empty() {
        let Some(out) = manifest_out else {
            return usage("--emit-manifest/--android-app require --manifest-out");
        };
        match harness::emit_manifest(&emit_roots, &android_apps, &out) {
            Ok(count) => {
                println!("wrote {count} case(s) to {}", out.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(1)
            }
        }
    } else {
        let Some(manifest) = manifest else {
            return usage("--manifest is required");
        };
        let options = harness::RunOptions {
            commit,
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        };
        let report_data = harness::run(&manifest, &options);
        let text = match serde_json::to_string_pretty(&report_data) {
            Ok(text) => text,
            Err(error) => {
                eprintln!("error: serialize report: {error}");
                return ExitCode::from(1);
            }
        };
        if let Some(path) = report {
            if let Err(error) = harness::write_atomic(&path, text.as_bytes()) {
                eprintln!("error: write report {}: {error}", path.display());
                return ExitCode::from(1);
            }
        } else {
            println!("{text}");
        }
        if report_data.passed() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }
    }
}

fn usage(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    print_help();
    ExitCode::from(2)
}

fn print_help() {
    println!(
        "corpus_harness --manifest FILE [--report FILE] [--commit SHA]\n\
         corpus_harness --emit-manifest DIR [--emit-manifest DIR]... \
         [--android-app DIR]... --manifest-out FILE\n\
         \n\
         Explicit manifest cases only: no folder walk is performed unless an\n\
         android-app case supplies its app folder, and junctions are skipped."
    );
}
