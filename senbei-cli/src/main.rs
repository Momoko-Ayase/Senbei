use senbei_io::{job, pause, scan};
use std::path::Path;

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let mut path: Option<String> = None;
    let mut out: Option<String> = None;
    let mut quiet: u8 = 0;
    let mut no_pause = false;
    let mut no_log = false;
    let mut verbose = false;
    let mut scan_all = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_help();
                return std::process::ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("Senbei {}", env!("CARGO_PKG_VERSION"));
                return std::process::ExitCode::SUCCESS;
            }
            "-q" | "--quiet" => quiet = quiet.saturating_add(1),
            "-v" | "--verbose" => verbose = true,
            "--no-pause" => no_pause = true,
            "--no-log" => no_log = true,
            "--scan-all" => scan_all = true,
            "--out" => match args.next() {
                Some(v) if !v.starts_with('-') => out = Some(v),
                _ => {
                    eprintln!("error: --out requires a directory argument");
                    return std::process::ExitCode::from(2);
                }
            },
            other if other.starts_with('-') => {
                eprintln!("error: unknown option '{other}'");
                print_help();
                return std::process::ExitCode::from(2);
            }
            other => {
                if let Some(prev) = &path {
                    eprintln!("error: multiple input paths given ('{prev}' and '{other}')");
                    return std::process::ExitCode::from(2);
                }
                path = Some(other.to_string());
            }
        }
    }

    let code = match path {
        None => {
            print_help();
            2
        }
        Some(p) => {
            if quiet < 2 {
                println!("Senbei {}", env!("CARGO_PKG_VERSION"));
            }
            let p = Path::new(&p);
            let out_path = out.as_deref().map(Path::new);
            let result = if p.is_dir() {
                job::run_folder_opts(
                    p,
                    out_path,
                    quiet,
                    verbose,
                    no_log,
                    scan_all || scan::scan_all_env(),
                )
            } else {
                job::run_file_v(p, out_path, quiet, verbose, no_log)
            };
            match result {
                Ok(summary) => {
                    if quiet < 2 {
                        println!("{}", summary.line());
                        println!("done in {} ms", summary.duration_ms);
                    }
                    if summary.errors > 0 { 1 } else { 0 }
                }
                Err(error) => {
                    if quiet < 2 {
                        eprintln!("error: {error:#}");
                    }
                    1
                }
            }
        }
    };

    pause::maybe_pause(no_pause);
    std::process::ExitCode::from(code as u8)
}

fn print_help() {
    println!(
        "senbei <file|folder> [--out DIR] [-v|--verbose] [-q|--quiet]... [--scan-all] [--no-log] [--no-pause] [-V|--version] [-h|--help]"
    );
    println!(
        "  input        a Crackproof PE (.exe/.dll), an il2cpp global-metadata.dat,\n\
         \x20              a protected Android AArch64 library (.so), an Android app\n\
         \x20              package (.apk/.apks/.xapk), or a folder containing any of\n\
         \x20              these"
    );
    println!(
        "  --scan-all   probe every file in a folder, including ones the scan\n\
         \x20              pre-filter skips (under 4128 bytes, extensionless,\n\
         \x20              or a bulk-asset extension). Much slower on large trees."
    );
}
