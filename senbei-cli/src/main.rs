use senbei_engine::android::ResourceLimits;
use senbei_io::{job, pause, scan};
use std::num::NonZeroUsize;
use std::path::Path;

fn main() -> std::process::ExitCode {
    let mut options = match Options::parse(std::env::args().skip(1)) {
        Ok(Outcome::Run(options)) => options,
        Ok(Outcome::Handled(code)) => return code,
        Err(message) => {
            eprintln!("error: {message}");
            return std::process::ExitCode::from(2);
        }
    };
    let code = match options.threads {
        Some(count) => senbei_engine::with_thread_cap(count, || execute(&mut options)),
        None => execute(&mut options),
    };
    if !options.machine {
        pause::maybe_pause(options.no_pause);
    }
    std::process::ExitCode::from(code)
}

/// Which operation the command line asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// Detection only. Writes nothing.
    Inspect,
    /// Recover and write outputs.
    Unpack,
}

struct Options {
    command: Command,
    path: String,
    out: Option<String>,
    quiet: u8,
    no_pause: bool,
    no_log: bool,
    verbose: bool,
    scan_all: bool,
    strict_integrity: bool,
    threads: Option<NonZeroUsize>,
    limits: ResourceLimits,
    /// Machine-readable output on stdout and nothing else.
    machine: bool,
    /// Run the real recovery but keep no ordinary output and no log.
    dry_run: bool,
}

enum Outcome {
    Run(Options),
    Handled(std::process::ExitCode),
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<Outcome, String> {
        let mut args = args.peekable();
        let mut command = Command::Unpack;
        let mut subcommand: Option<String> = None;
        let mut path: Option<String> = None;
        let mut out: Option<String> = None;
        let mut quiet: u8 = 0;
        let mut no_pause = false;
        let mut no_log = false;
        let mut verbose = false;
        let mut scan_all = false;
        let mut strict_integrity = false;
        let mut threads = None;
        let mut machine = false;
        let mut dry_run = false;
        let mut limits = ResourceLimits::default();

        while let Some(a) = args.next() {
            match a.as_str() {
                "-h" | "--help" => {
                    print_help();
                    return Ok(Outcome::Handled(std::process::ExitCode::SUCCESS));
                }
                "-V" | "--version" => {
                    println!("Senbei {}", env!("CARGO_PKG_VERSION"));
                    return Ok(Outcome::Handled(std::process::ExitCode::SUCCESS));
                }
                "-q" | "--quiet" => quiet = quiet.saturating_add(1),
                "-v" | "--verbose" => verbose = true,
                "--no-pause" => no_pause = true,
                "--no-log" => no_log = true,
                "--scan-all" => scan_all = true,
                "--strict-integrity" => strict_integrity = true,
                "--json" => machine = true,
                "--dry-run" => dry_run = true,
                "--threads" => threads = Some(parse_thread_cap(args.next().as_deref())?),
                flag
                @ ("--max-entry-mib" | "--max-total-mib" | "--max-entries" | "--max-depth") => {
                    set_resource_limit(&mut limits, flag, args.next().as_deref())?;
                }
                "--out" => match args.next() {
                    Some(v) if !v.starts_with('-') => out = Some(v),
                    _ => return Err("--out requires a directory argument".to_owned()),
                },
                other if other.starts_with('-') => {
                    print_help();
                    return Err(format!("unknown option '{other}'"));
                }
                // A subcommand is only a subcommand when it is the first
                // positional word. `senbei inspect` therefore means the
                // subcommand, while `senbei foo/inspect` is a path.
                other
                    if path.is_none()
                        && subcommand.is_none()
                        && matches!(other, "inspect" | "unpack") =>
                {
                    command = if other == "inspect" {
                        Command::Inspect
                    } else {
                        Command::Unpack
                    };
                    subcommand = Some(other.to_owned());
                }
                other => {
                    if let Some(prev) = &path {
                        return Err(format!(
                            "multiple input paths given ('{prev}' and '{other}')"
                        ));
                    }
                    path = Some(other.to_string());
                }
            }
        }

        let Some(path) = path else {
            // A subcommand with no path is a usage error; no arguments at all
            // still prints help and exits 2, as before.
            if let Some(subcommand) = subcommand {
                return Err(format!("'{subcommand}' requires an input path"));
            }
            print_help();
            return Ok(Outcome::Handled(std::process::ExitCode::from(2)));
        };

        // These combinations would silently mean different things, so they are
        // rejected rather than guessed at.
        if command == Command::Inspect {
            if dry_run {
                return Err("'inspect' writes nothing; drop --dry-run".to_owned());
            }
            if out.is_some() {
                return Err("'inspect' writes nothing; --out is not allowed".to_owned());
            }
            // `--strict-integrity` is meaningful: inspection runs the real
            // static check and reports its verdict.
        }
        if machine {
            // Machine output owns stdout; interleaved progress would corrupt it.
            quiet = quiet.max(1);
            no_log = true;
        }
        let dry_run = dry_run && command == Command::Unpack;
        if dry_run {
            // A dry run keeps nothing: no ordinary output directory, no log.
            if out.is_some() {
                return Err("--dry-run writes no output; --out is not allowed".to_owned());
            }
            no_log = true;
        }

        Ok(Outcome::Run(Options {
            command,
            path,
            out,
            quiet,
            no_pause,
            no_log,
            verbose,
            scan_all,
            strict_integrity,
            threads,
            limits,
            machine,
            dry_run,
        }))
    }
}

fn parse_thread_cap(value: Option<&str>) -> Result<NonZeroUsize, String> {
    value
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| "--threads requires a positive integer argument".to_owned())
}

/// Run the parsed command. Kept separate from argument parsing and the pause
/// prompt so the execution step can be wrapped on its own.
fn execute(options: &mut Options) -> u8 {
    let path = Path::new(&options.path);
    let scan_all = options.scan_all || scan::scan_all_env();
    match options.command {
        Command::Inspect => execute_inspect(options, path, scan_all),
        Command::Unpack if options.dry_run => execute_dry_run(options, path, scan_all),
        Command::Unpack => execute_unpack(options, path, scan_all),
    }
}

/// Inspection reports what the input is and what happened when it was tried;
/// only an input that could not be read makes it fail.
fn execute_inspect(options: &Options, path: &Path, scan_all: bool) -> u8 {
    match job::inspect_path(path, scan_all, &options.limits) {
        Ok(report) => {
            // A recovery that ran and produced a suspect image is exactly what
            // `--strict-integrity` asks about, so it applies here too.
            let code = report_exit_code(&report, options.strict_integrity);
            if options.machine {
                println!("{}", report.to_json());
            } else if options.quiet < 2 {
                print!("{}", report.render_text());
            }
            code
        }
        Err(error) => {
            if options.machine {
                let report = job::error_report(job::Mode::Inspect, &format!("{error:#}"));
                println!("{}", report.to_json());
            } else if options.quiet < 2 {
                eprintln!("error: {error:#}");
            }
            1
        }
    }
}

fn execute_dry_run(options: &Options, path: &Path, scan_all: bool) -> u8 {
    match job::dry_run_path(path, scan_all, &options.limits) {
        Ok(report) => {
            let code = report_exit_code(&report, options.strict_integrity);
            if options.machine {
                println!("{}", report.to_json());
            } else if options.quiet < 2 {
                print!("{}", report.render_text());
                println!("{}", report.summary_line());
            }
            code
        }
        Err(error) => {
            if options.machine {
                let report = job::error_report(job::Mode::DryRun, &format!("{error:#}"));
                println!("{}", report.to_json());
            } else if options.quiet < 2 {
                eprintln!("error: {error:#}");
            }
            1
        }
    }
}

fn execute_unpack(options: &Options, path: &Path, scan_all: bool) -> u8 {
    if options.quiet < 2 && !options.machine {
        println!("Senbei {}", env!("CARGO_PKG_VERSION"));
    }
    let out_path = options.out.as_deref().map(Path::new);
    // A machine run goes through the same drivers with an observer attached;
    // the observer never changes routing, output, or messages.
    let mut collector = job::Collector::new(job::Mode::Unpack);
    let result = if options.machine {
        if path.is_dir() {
            job::run_folder_reported(
                path,
                out_path,
                options.quiet,
                options.verbose,
                options.no_log,
                scan_all,
                &options.limits,
                &mut collector,
            )
        } else {
            job::run_file_reported(
                path,
                out_path,
                options.quiet,
                options.verbose,
                options.no_log,
                &options.limits,
                &mut collector,
            )
        }
    } else if path.is_dir() {
        job::run_folder_with_limits(
            path,
            out_path,
            options.quiet,
            options.verbose,
            options.no_log,
            scan_all,
            &options.limits,
        )
    } else {
        job::run_file_with_limits(
            path,
            out_path,
            options.quiet,
            options.verbose,
            options.no_log,
            &options.limits,
        )
    };

    match result {
        Ok(summary) => {
            if options.machine {
                println!("{}", collector.finish().to_json());
            } else if options.quiet < 2 {
                println!("{}", summary.line());
                println!("done in {} ms", summary.duration_ms);
            }
            exit_code(&summary, options.strict_integrity)
        }
        Err(error) => {
            if options.machine {
                let mut failed = collector;
                failed.push_error(format!("{error:#}"));
                println!("{}", failed.finish().to_json());
            } else if options.quiet < 2 {
                eprintln!("error: {error:#}");
            }
            1
        }
    }
}

/// Exit status from a report: the same policy as the summary-driven one.
fn report_exit_code(report: &job::Report, strict_integrity: bool) -> u8 {
    if report.summary.errors > 0 || (strict_integrity && report.summary.suspect > 0) {
        1
    } else {
        0
    }
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

fn set_resource_limit(
    limits: &mut ResourceLimits,
    flag: &str,
    value: Option<&str>,
) -> Result<(), String> {
    let invalid = || format!("{flag} requires an unsigned integer argument");
    let text = value
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(invalid)?;
    let value: u64 = text.parse().map_err(|_| invalid())?;
    if value == 0 && flag != "--max-depth" {
        return Err(format!("{flag} must be greater than zero"));
    }
    match flag {
        "--max-entry-mib" | "--max-total-mib" => {
            let bytes = value
                .checked_mul(1024 * 1024)
                .ok_or_else(|| format!("{flag} exceeds the supported byte range"))?;
            if flag == "--max-entry-mib" {
                limits.max_entry_bytes = bytes;
            } else {
                limits.max_total_bytes = bytes;
            }
        }
        "--max-entries" => limits.max_entries = usize::try_from(value).map_err(|_| invalid())?,
        "--max-depth" => limits.max_depth = usize::try_from(value).map_err(|_| invalid())?,
        _ => return Err(format!("unknown resource option '{flag}'")),
    }
    Ok(())
}

fn print_help() {
    println!(
        "senbei [inspect|unpack] <file|folder> [--out DIR] [-v|--verbose] [-q|--quiet]... [--json] [--dry-run] [--threads N] [--scan-all] [--strict-integrity] [--max-entry-mib N] [--max-total-mib N] [--max-entries N] [--max-depth N] [--no-log] [--no-pause] [-V|--version] [-h|--help]"
    );
    println!(
        "  <file|folder>\n\
         \x20              a Crackproof PE (.exe/.dll), an il2cpp global-metadata.dat,\n\
         \x20              a protected Android AArch64 library (.so), an Android app\n\
         \x20              package (.apk/.apks/.xapk), or a folder containing any of\n\
         \x20              these. The bare form is the same as 'unpack'."
    );
    println!(
        "  inspect PATH\n\
         \x20              run the real static recovery for research, and report\n\
         \x20              everything observed: recognition evidence, each route\n\
         \x20              tried and why it was rejected, the route selected, the\n\
         \x20              static check's verdict, and the engines' own structural\n\
         \x20              evidence (protected-header fields, seeds, module records,\n\
         \x20              restored-image facts). Nothing is kept: no output file,\n\
         \x20              no log, no temporary tree, and the input is never run."
    );
    println!("  unpack PATH  detection and recovery; writes outputs (the default).");
    println!(
        "  --json       write one versioned machine-readable report to stdout and\n\
         \x20              nothing else. Implies quiet and --no-log."
    );
    println!(
        "  --dry-run    run the real recovery but keep nothing: no output tree and\n\
         \x20              no log. Android extraction still uses its own temporary\n\
         \x20              workspace, which is discarded."
    );
    println!(
        "  --threads N  positive worker cap for this run. Overrides SENBEI_THREADS;\n\
         \x20              1 selects the sequential path. The environment is unchanged."
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
         \x20              a file errors. Quiet levels are unchanged.\n\
         \x20              With 'inspect', the check applies to the image actually\n\
         \x20              recovered for research; no output file is retained."
    );
    let defaults = ResourceLimits::default();
    println!(
        "  Android resource limits (MiB = 1048576 bytes):\n\
         \x20 --max-entry-mib N  single archive entry/decoded buffer/output (default {})\n\
         \x20 --max-total-mib N  cumulative archive bytes and per-engine task budget (default {})\n\
         \x20 --max-entries N    archive entries/stage-2 records (default {})\n\
         \x20 --max-depth N      nesting depth, root = 0 (default {})\n\
         \x20 Limits are checked before extraction/allocation; they are not a peak-RSS cap.",
        defaults.max_entry_bytes / (1024 * 1024),
        defaults.max_total_bytes / (1024 * 1024),
        defaults.max_entries,
        defaults.max_depth,
    );
    println!(
        "  Exit codes: 0 success, 1 a target failed (or a suspect with\n\
         \x20 --strict-integrity), 2 the command line was rejected."
    );
}

#[cfg(test)]
mod thread_options {
    use super::*;

    #[test]
    fn worker_cap_requires_a_positive_decimal_integer() {
        assert_eq!(parse_thread_cap(Some("1")).unwrap().get(), 1);
        assert_eq!(parse_thread_cap(Some("4")).unwrap().get(), 4);
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("-1"),
            Some("+1"),
            Some("1.5"),
            Some("many"),
            Some("999999999999999999999999999999"),
        ] {
            assert!(parse_thread_cap(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn caps_are_optional_and_work_with_both_commands() {
        for (args, expected) in [
            (vec!["x"], None),
            (vec!["unpack", "x", "--threads", "1"], Some(1)),
            (vec!["--threads", "4", "inspect", "x"], Some(4)),
        ] {
            let Outcome::Run(options) =
                Options::parse(args.into_iter().map(str::to_owned)).unwrap()
            else {
                panic!("expected a parsed command");
            };
            assert_eq!(options.threads.map(NonZeroUsize::get), expected);
        }
    }
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

#[cfg(test)]
mod resource_limits {
    use super::*;

    #[test]
    fn flags_override_only_the_selected_limit() {
        let mut limits = ResourceLimits::default();
        set_resource_limit(&mut limits, "--max-entry-mib", Some("4096")).unwrap();
        assert_eq!(limits.max_entry_bytes, 4096 * 1024 * 1024);
        assert_eq!(
            limits.max_total_bytes,
            ResourceLimits::default().max_total_bytes
        );
        set_resource_limit(&mut limits, "--max-total-mib", Some("16384")).unwrap();
        set_resource_limit(&mut limits, "--max-entries", Some("123")).unwrap();
        set_resource_limit(&mut limits, "--max-depth", Some("0")).unwrap();
        assert_eq!(limits.max_total_bytes, 16384 * 1024 * 1024);
        assert_eq!(limits.max_entries, 123);
        assert_eq!(limits.max_depth, 0);
    }

    #[test]
    fn invalid_and_overflowing_limits_are_usage_errors() {
        let mut limits = ResourceLimits::default();
        for flag in [
            "--max-entry-mib",
            "--max-total-mib",
            "--max-entries",
            "--max-depth",
        ] {
            for value in [
                None,
                Some(""),
                Some("-1"),
                Some("1.5"),
                Some("--no-log"),
                Some("18446744073709551616"),
            ] {
                assert!(
                    set_resource_limit(&mut limits, flag, value).is_err(),
                    "{flag} {value:?}"
                );
            }
        }
        for flag in ["--max-entry-mib", "--max-total-mib", "--max-entries"] {
            assert!(set_resource_limit(&mut limits, flag, Some("0")).is_err());
        }
        assert!(
            set_resource_limit(&mut limits, "--max-entry-mib", Some("18446744073709551615"))
                .is_err()
        );
        assert_eq!(limits, ResourceLimits::default());
    }
}

#[cfg(test)]
mod command_line {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        match Options::parse(args.iter().map(|arg| (*arg).to_string()))? {
            Outcome::Run(options) => Ok(options),
            Outcome::Handled(code) => Err(format!(
                "handled: {}",
                code == std::process::ExitCode::SUCCESS
            )),
        }
    }

    #[test]
    fn bare_path_is_an_unpack() {
        let options = parse(&["app.exe"]).unwrap();
        assert_eq!(options.command, Command::Unpack);
        assert_eq!(options.path, "app.exe");
        assert!(!options.dry_run);
        assert!(!options.machine);
    }

    #[test]
    fn legacy_flags_still_apply_around_a_bare_path() {
        let options = parse(&["app.exe", "--out", "o", "-q", "-v", "--no-log"]).unwrap();
        assert_eq!(options.path, "app.exe");
        assert_eq!(options.out.as_deref(), Some("o"));
        assert_eq!(options.quiet, 1);
        assert!(options.verbose);
        assert!(options.no_log);
    }

    #[test]
    fn explicit_subcommands_are_recognised() {
        assert_eq!(parse(&["inspect", "x"]).unwrap().command, Command::Inspect);
        assert_eq!(parse(&["unpack", "x"]).unwrap().command, Command::Unpack);
        // A directory literally named like a subcommand still works via path.
        assert_eq!(parse(&["./inspect"]).unwrap().path, "./inspect");
    }

    #[test]
    fn json_implies_quiet_and_no_log() {
        let options = parse(&["--json", "app.exe"]).unwrap();
        assert!(options.machine);
        assert!(options.quiet >= 1);
        assert!(options.no_log);
    }

    #[test]
    fn dry_run_refuses_an_output_directory() {
        assert!(parse(&["--dry-run", "--out", "o", "app.exe"]).is_err());
        let options = parse(&["--dry-run", "app.exe"]).unwrap();
        assert!(options.dry_run);
        assert!(options.no_log);
    }

    #[test]
    fn inspect_rejects_writing_flags() {
        assert!(parse(&["inspect", "--out", "o", "app.exe"]).is_err());
        assert!(parse(&["inspect", "--dry-run", "app.exe"]).is_err());
        assert_eq!(
            parse(&["inspect", "--json", "a"]).unwrap().command,
            Command::Inspect
        );
    }

    /// Inspection runs the real static check, so asking it to be strict about
    /// that verdict is meaningful, not contradictory.
    #[test]
    fn inspect_accepts_strict_integrity() {
        assert!(parse(&["inspect", "--strict-integrity", "app.exe"]).is_ok());
    }

    #[test]
    fn a_subcommand_without_a_path_is_a_usage_error() {
        assert!(parse(&["inspect"]).is_err());
        assert!(parse(&["unpack"]).is_err());
    }
}
