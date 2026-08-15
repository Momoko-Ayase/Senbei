use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use senbei_android_io::run_folder;

fn main() -> std::process::ExitCode {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run(args: Vec<std::ffi::OsString>) -> Result<()> {
    let mut input = None;
    for value in args {
        if value == "-h" || value == "--help" {
            print_help();
            return Ok(());
        }
        if value == "-V" || value == "--version" {
            println!("senbei-android {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        if value.to_string_lossy().starts_with('-') {
            bail!("unknown option `{}`; use --help", value.to_string_lossy());
        }
        if input.is_some() {
            bail!("only one input folder is accepted");
        }
        input = Some(PathBuf::from(value));
    }
    let input = input.context("missing input folder; use --help for usage")?;
    if !input.is_dir() {
        bail!("input must be a folder: `{}`", input.display());
    }
    let summary = run_folder(&input)?;
    println!(
        "restored {} SO(s), skipped {} SO(s), restored {} metadata file(s), skipped {} metadata file(s), {} archive(s)",
        summary.so_restored,
        summary.so_skipped,
        summary.metadata_restored,
        summary.metadata_skipped,
        summary.archives
    );
    println!("output {}", input.join("unpack").display());
    Ok(())
}

fn print_help() {
    println!("senbei-android INPUT_FOLDER");
}
