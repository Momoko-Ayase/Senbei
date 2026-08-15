use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use senbei_android_io::{
    ExtractStage2Job, RestoreMetadataJob, RestoreSoJob, run_extract_stage2, run_restore_metadata,
    run_restore_so,
};

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
        "discover-metadata" => discover_metadata(args.collect()),
        "extract-stage2" => extract_stage2(args.collect()),
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

fn discover_metadata(args: Vec<OsString>) -> Result<()> {
    let mut positional = Vec::new();
    for value in args {
        if value == "-h" || value == "--help" {
            println!("senbei-android discover-metadata INPUT");
            return Ok(());
        }
        if value.to_string_lossy().starts_with('-') {
            bail!(
                "unknown discover-metadata option `{}`",
                value.to_string_lossy()
            );
        }
        positional.push(PathBuf::from(value));
    }
    let [input] = positional.as_slice() else {
        bail!("discover-metadata requires INPUT; use --help for usage");
    };
    let data =
        std::fs::read(input).with_context(|| format!("read metadata `{}`", input.display()))?;
    let report = senbei_android_metadata::discover_method_token_seeds(&data)
        .with_context(|| format!("discover metadata seed `{}`", input.display()))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn extract_stage2(args: Vec<OsString>) -> Result<()> {
    let mut positional = Vec::new();
    let mut stage2_output = None;
    let mut outer_size = senbei_android_stage2::DEFAULT_OUTER_SIZE;
    let mut cipher_constant = senbei_android_stage2::DEFAULT_CIPHER_CONSTANT;
    let mut cursor = 0;
    while cursor < args.len() {
        match args[cursor].to_string_lossy().as_ref() {
            "--stage2-out" => {
                stage2_output = Some(option_path(&args, &mut cursor, "--stage2-out")?);
            }
            "--outer-size" => {
                let value = option_string(&args, &mut cursor, "--outer-size")?;
                outer_size = usize::try_from(parse_u64(&value)?)
                    .with_context(|| format!("invalid --outer-size `{value}`"))?;
            }
            "--cipher-constant" => {
                let value = option_string(&args, &mut cursor, "--cipher-constant")?;
                cipher_constant = parse_u32(&value)
                    .with_context(|| format!("invalid --cipher-constant `{value}`"))?;
            }
            "-h" | "--help" => {
                print_extract_help();
                return Ok(());
            }
            option if option.starts_with('-') => {
                bail!("unknown extract-stage2 option `{option}");
            }
            _ => positional.push(PathBuf::from(&args[cursor])),
        }
        cursor += 1;
    }
    let [input, output_dir] = positional.as_slice() else {
        bail!("extract-stage2 requires INPUT and OUTPUT_DIR; use --help for usage");
    };
    let mut job = ExtractStage2Job::new(input.clone(), output_dir.clone());
    job.stage2_output = stage2_output;
    job.outer_size = outer_size;
    job.cipher_constant = cipher_constant;
    let result = run_extract_stage2(&job)?;
    let module_images = result
        .module_registry
        .iter()
        .filter(|module| module.classification == "module_image")
        .count();
    println!(
        "Extracted {} streams, {} modules and {} compact artifacts",
        result.streams.len(),
        module_images,
        result.artifacts.len()
    );
    println!("Index {}", output_dir.join("index.json").display());
    Ok(())
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
        "Metadata status={} restored {}/{} MethodDef tokens ({} already canonical)",
        result.encryption_status,
        result.changed_tokens,
        result.methods,
        result.already_correct_before
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
    Ok(u32::try_from(parse_u64(value)?)?)
}

fn parse_u64(value: &str) -> Result<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse()?)
    }
}

fn print_help() {
    println!("senbei-android {}", env!("CARGO_PKG_VERSION"));
    println!("Usage:");
    println!("  senbei-android restore-so INPUT OUTPUT [OPTIONS]");
    println!("  senbei-android restore-metadata INPUT OUTPUT [OPTIONS]");
    println!("  senbei-android discover-metadata INPUT");
    println!("  senbei-android extract-stage2 INPUT OUTPUT_DIR [OPTIONS]");
    println!("  senbei-android --version");
}

fn print_extract_help() {
    println!("senbei-android extract-stage2 INPUT OUTPUT_DIR [OPTIONS]");
    println!("  --stage2-out FILE          Write the raw decrypted Stage 2 image");
    println!("  --outer-size VALUE         Stage 1 outer wrapper size (default 0x23C)");
    println!("  --cipher-constant VALUE    Stage 1 cipher constant (default 0xBF20165D)");
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
