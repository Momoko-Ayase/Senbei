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
    let mut strict_integrity = false;

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
            "--strict-integrity" => strict_integrity = true,
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
                    exit_code(&summary, strict_integrity)
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

/// Process status for a finished run.
///
/// Suspect outputs are still written. By default a suspect file is a warning
/// and the process stays successful; strict mode treats it like an error so a
/// caller can fail the run. An error fails the run either way.
fn exit_code(summary: &job::Summary, strict_integrity: bool) -> u8 {
    if summary.errors > 0 || (strict_integrity && summary.suspect > 0) {
        1
    } else {
        0
    }
}

fn print_help() {
    println!(
        "senbei <file|folder> [--out DIR] [-v|--verbose] [-q|--quiet]... [--scan-all] [--strict-integrity] [--no-log] [--no-pause] [-V|--version] [-h|--help]"
    );
    println!(
        "  input        a Crackproof PE (.exe/.dll), an il2cpp global-metadata.dat,\n\
         \x20              a protected Android AArch64 library (.so), an Android app\n\
         \x20              package (.apk/.apks/.xapk), or a folder containing any of\n\
         \x20              these"
    );
    println!(
        "  --scan-all   probe selected .exe/.dll/.so/metadata names below the\n\
         \x20              size floor; other filenames remain excluded."
    );
    println!(
        "  --strict-integrity\n\
         \x20              exit non-zero when any output fails the static integrity\n\
         \x20              check (a suspect) or a file errors. Off by default: a\n\
         \x20              suspect is still written and the process exits 0 unless\n\
         \x20              a file errors. Quiet levels are unchanged."
    );
}

#[cfg(test)]
mod strict_integrity {
    use super::exit_code;
    use senbei_io::job::Summary;

    fn summary(errors: usize, suspect: usize) -> Summary {
        Summary {
            errors,
            suspect,
            ..Summary::default()
        }
    }

    #[test]
    fn clean_run_exits_0_in_both_modes() {
        let summary = summary(0, 0);
        assert_eq!(exit_code(&summary, false), 0);
        assert_eq!(exit_code(&summary, true), 0);
    }

    #[test]
    fn errors_exit_1_whether_or_not_strict() {
        let summary = summary(2, 0);
        assert_eq!(exit_code(&summary, false), 1);
        assert_eq!(exit_code(&summary, true), 1);
    }

    #[test]
    fn suspect_exits_0_by_default_and_1_when_strict() {
        let summary = summary(0, 1);
        assert_eq!(exit_code(&summary, false), 0);
        assert_eq!(exit_code(&summary, true), 1);
    }

    #[test]
    fn errors_with_suspects_exit_1_in_both_modes() {
        let summary = summary(1, 3);
        assert_eq!(exit_code(&summary, false), 1);
        assert_eq!(exit_code(&summary, true), 1);
    }
}
