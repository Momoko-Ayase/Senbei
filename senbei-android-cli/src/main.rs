use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use senbei_android_io::{RestoreMetadataJob, RestoreSoJob, run_restore_metadata, run_restore_so};

fn main() -> std::process::ExitCode {
    match run(std::env::args_os().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::from(1)
        }
    }
}

fn run(args: impl Iterator<Item = OsString>) -> Result<()> {
    let mut args = args.peekable();
    let Some(command) = args.next() else {
        print_help();
        bail!("missing command");
    };
    let command = command.to_string_lossy();
    match command.as_ref() {
        "restore-so" => restore_so(args.collect()),
        "restore-metadata" => restore_metadata(args.collect()),
        "-h" | "--help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" => {
            println!("senbei-android {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => bail!("unknown command `{command}`; use --help for usage"),
    }
}

fn restore_so(args: Vec<OsString>) -> Result<()> {
    let mut positional = Vec::new();
    let mut index = None;
    let mut report = None;
    let mut dump_auxiliary = None;
    let mut outer_only = false;
    let mut preserve_entrypoint = false;
    let mut cursor = 0;
    while cursor < args.len() {
        match args[cursor].to_string_lossy().as_ref() {
            "--index" => index = Some(option_path(&args, &mut cursor, "--index")?),
            "--report" => report = Some(option_path(&args, &mut cursor, "--report")?),
            "--dump-aux" => {
                dump_auxiliary = Some(option_path(&args, &mut cursor, "--dump-aux")?);
            }
            "--outer-only" => outer_only = true,
            "--preserve-entrypoint" => preserve_entrypoint = true,
            "-h" | "--help" => {
                print_so_help();
                return Ok(());
            }
            option if option.starts_with('-') => bail!("unknown restore-so option `{option}`"),
            _ => positional.push(PathBuf::from(&args[cursor])),
        }
        cursor += 1;
    }
    let [input, output] = positional.as_slice() else {
        bail!("restore-so requires INPUT and OUTPUT; use --help for usage");
    };
    let result = run_restore_so(&RestoreSoJob {
        input: input.clone(),
        output: output.clone(),
        index,
        report,
        dump_auxiliary,
        outer_only,
        preserve_entrypoint,
    })?;
    println!("Restored {} bytes to {}", result.output_size, result.output);
    println!("SHA-256 {}", result.output_sha256);
    Ok(())
}

fn restore_metadata(args: Vec<OsString>) -> Result<()> {
    let mut positional = Vec::new();
    let mut report = None;
    let mut seed = senbei_android_metadata::DEFAULT_METHOD_TOKEN_SEED;
    let mut cursor = 0;
    while cursor < args.len() {
        match args[cursor].to_string_lossy().as_ref() {
            "--seed" => {
                let value = option_string(&args, &mut cursor, "--seed")?;
                seed = parse_u32(&value).with_context(|| format!("invalid --seed `{value}`"))?;
            }
            "--report" => report = Some(option_path(&args, &mut cursor, "--report")?),
            "-h" | "--help" => {
                print_metadata_help();
                return Ok(());
            }
            option if option.starts_with('-') => {
                bail!("unknown restore-metadata option `{option}`");
            }
            _ => positional.push(PathBuf::from(&args[cursor])),
        }
        cursor += 1;
    }
    let [input, output] = positional.as_slice() else {
        bail!("restore-metadata requires INPUT and OUTPUT; use --help for usage");
    };
    let result = run_restore_metadata(&RestoreMetadataJob {
        input: input.clone(),
        output: output.clone(),
        seed,
        report,
    })?;
    println!(
        "Restored {}/{} MethodDef tokens ({} already canonical)",
        result.changed_tokens, result.methods, result.already_correct_before
    );
    Ok(())
}

fn option_path(args: &[OsString], cursor: &mut usize, name: &str) -> Result<PathBuf> {
    *cursor += 1;
    args.get(*cursor)
        .map(PathBuf::from)
        .with_context(|| format!("{name} requires a path"))
}

fn option_string(args: &[OsString], cursor: &mut usize, name: &str) -> Result<String> {
    *cursor += 1;
    args.get(*cursor)
        .map(|value| value.to_string_lossy().into_owned())
        .with_context(|| format!("{name} requires a value"))
}

fn parse_u32(value: &str) -> Result<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Ok(u32::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
    }
}

fn print_help() {
    println!("senbei-android {}", env!("CARGO_PKG_VERSION"));
    println!("Usage:");
    println!("  senbei-android restore-so INPUT OUTPUT [OPTIONS]");
    println!("  senbei-android restore-metadata INPUT OUTPUT [OPTIONS]");
    println!("  senbei-android --version");
}

fn print_so_help() {
    println!("senbei-android restore-so INPUT OUTPUT [OPTIONS]");
    println!("  --index FILE             Stage 2 module index.json");
    println!("  --report FILE            Write a JSON restoration report");
    println!("  --dump-aux FILE          Dump decoded auxiliary ELF data");
    println!("  --outer-only             Skip auxiliary ELF table materialization");
    println!("  --preserve-entrypoint    Keep the protector entrypoint");
}

fn print_metadata_help() {
    println!("senbei-android restore-metadata INPUT OUTPUT [OPTIONS]");
    println!("  --seed VALUE     Module 0x0C seed (decimal or 0x-prefixed hex)");
    println!("  --report FILE    Write a JSON restoration report");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex_seeds() {
        assert_eq!(parse_u32("42").unwrap(), 42);
        assert_eq!(parse_u32("0xA6FAE968").unwrap(), 0xa6fa_e968);
    }
}
