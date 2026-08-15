//! Filesystem orchestration for the Android restoration commands.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use senbei_android_elf::{RestoreOptions, RestoreReport, restore_libil2cpp};
use senbei_android_metadata::{DEFAULT_METHOD_TOKEN_SEED, Report as MetadataReport};
use serde::Serialize;
use tempfile::NamedTempFile;

/// Filesystem arguments for restoring one protected `libil2cpp.so`.
#[derive(Debug, Clone)]
pub struct RestoreSoJob {
    pub input: PathBuf,
    pub output: PathBuf,
    pub index: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub dump_auxiliary: Option<PathBuf>,
    pub outer_only: bool,
    pub preserve_entrypoint: bool,
}

/// Filesystem arguments for restoring one `global-metadata.dat`.
#[derive(Debug, Clone)]
pub struct RestoreMetadataJob {
    pub input: PathBuf,
    pub output: PathBuf,
    pub seed: u32,
    pub report: Option<PathBuf>,
}

impl RestoreMetadataJob {
    #[must_use]
    pub fn new(input: PathBuf, output: PathBuf) -> Self {
        Self {
            input,
            output,
            seed: DEFAULT_METHOD_TOKEN_SEED,
            report: None,
        }
    }
}

/// Infer the Stage 2 module index produced for `libil2cpp.so`.
#[must_use]
pub fn default_module_index(input: &Path) -> PathBuf {
    input
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("libil2cpp_stage2_modules")
        .join("index.json")
}

/// Run static SO restoration and optionally emit its JSON report.
pub fn run_restore_so(job: &RestoreSoJob) -> Result<RestoreReport> {
    refuse_in_place(&job.input, &job.output)?;
    let options = RestoreOptions {
        input: job.input.clone(),
        output: job.output.clone(),
        index: job
            .index
            .clone()
            .unwrap_or_else(|| default_module_index(&job.input)),
        dump_auxiliary: job.dump_auxiliary.clone(),
        outer_only: job.outer_only,
        preserve_entrypoint: job.preserve_entrypoint,
    };
    let result = restore_libil2cpp(&options).context("restore protected libil2cpp.so")?;
    if let Some(path) = &job.report {
        write_json_atomic(path, &result)?;
    }
    Ok(result)
}

/// Restore MethodDef tokens and atomically write the cleaned metadata.
pub fn run_restore_metadata(job: &RestoreMetadataJob) -> Result<MetadataReport> {
    refuse_in_place(&job.input, &job.output)?;
    let input =
        std::fs::read(&job.input).with_context(|| format!("read `{}`", job.input.display()))?;
    let (output, result) = senbei_android_metadata::restore_method_tokens(&input, job.seed)
        .with_context(|| format!("restore `{}`", job.input.display()))?;
    write_atomic(&job.output, &output)?;
    if let Some(path) = &job.report {
        write_json_atomic(path, &result)?;
    }
    Ok(result)
}

fn refuse_in_place(input: &Path, output: &Path) -> Result<()> {
    let input_absolute = absolute(input)?;
    let output_absolute = absolute(output)?;
    let same_existing_file =
        output.exists() && std::fs::canonicalize(input).ok() == std::fs::canonicalize(output).ok();
    if input_absolute == output_absolute || same_existing_file {
        bail!(
            "refusing to overwrite input in place: `{}`",
            input.display()
        );
    }
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("query current directory")?
            .join(path))
    }
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut data = serde_json::to_vec_pretty(value).context("serialize JSON report")?;
    data.push(b'\n');
    write_atomic(path, &data)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create output directory `{}`", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary file in `{}`", parent.display()))?;
    temporary
        .write_all(data)
        .and_then(|()| temporary.as_file().sync_all())
        .with_context(|| format!("write temporary output for `{}`", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace output `{}`", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_index_next_to_input() {
        assert_eq!(
            default_module_index(Path::new(r"C:\game\Native\libil2cpp.so")),
            PathBuf::from(r"C:\game\Native\libil2cpp_stage2_modules\index.json")
        );
    }

    #[test]
    fn metadata_job_uses_current_seed() {
        let job = RestoreMetadataJob::new(PathBuf::from("in"), PathBuf::from("out"));
        assert_eq!(job.seed, DEFAULT_METHOD_TOKEN_SEED);
    }
}
