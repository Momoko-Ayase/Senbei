use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};

use memmap2::MmapOptions;
use senbei_android_crypto::{Module9bConfig, decode_container};
use serde_json::to_vec_pretty;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::error::{Error, Result, invalid};
use crate::report::{
    ArtifactReport, DecoderReport, ExtractionReport, ModuleRegistryEntry, RecordReport,
    Stage1Report, StreamParent, StreamReport,
};
use crate::stage1::{
    DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE, SHT_LOUSER, Stage1Result, inspect,
};
use crate::stream::{DIRECT_FLAG, Record, parse_record_stream};

/// Inputs and output locations for one complete static Stage 2 extraction.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub input: PathBuf,
    pub output_dir: PathBuf,
    pub stage2_output: Option<PathBuf>,
    pub outer_size: usize,
    pub cipher_constant: u32,
}

impl ExtractOptions {
    #[must_use]
    pub fn with_defaults(input: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            input,
            output_dir,
            stage2_output: None,
            outer_size: DEFAULT_OUTER_SIZE,
            cipher_constant: DEFAULT_CIPHER_CONSTANT,
        }
    }
}

#[derive(Debug)]
struct LoadedModule {
    image: Vec<u8>,
    metadata: Option<Vec<u8>>,
    image_path: String,
    metadata_path: Option<String>,
    sha256: String,
    depth: usize,
    record_index: usize,
    command_id: u32,
    init_offset: u32,
    entry_offset: u32,
}

#[derive(Debug, Clone, Copy)]
struct ArtifactSpec<'a> {
    suffix: &'a str,
    kind: &'a str,
    classification: &'a str,
}

struct Extractor {
    output_dir: PathBuf,
    streams: Vec<StreamReport>,
    artifacts: Vec<ArtifactReport>,
    registry: BTreeMap<u32, LoadedModule>,
    seen_streams: HashSet<(u32, String)>,
}

pub fn extract_stage2(options: &ExtractOptions) -> Result<ExtractionReport> {
    let input_path = absolute(&options.input)?;
    let output_dir = absolute(&options.output_dir)?;
    if !input_path.is_file() {
        return invalid(format!(
            "protected ELF does not exist: {}",
            input_path.display()
        ));
    }
    if let Some(stage2_output) = &options.stage2_output {
        let stage2_output = absolute(stage2_output)?;
        if stage2_output == input_path {
            return invalid("refusing to overwrite the protected ELF with Stage 2 output");
        }
    }
    create_dir_all(&output_dir)
        .map_err(|source| Error::io("create Stage 2 output directory", &output_dir, source))?;

    let file = File::open(&input_path)
        .map_err(|source| Error::io("open protected ELF", &input_path, source))?;
    // SAFETY: the mapping is read-only, the file remains open for the mapping
    // lifetime, and extraction never mutates or truncates the source.
    let source = unsafe { MmapOptions::new().map(&file) }
        .map_err(|source| Error::io("map protected ELF", &input_path, source))?;
    let stage1 = inspect(
        &source,
        &input_path,
        options.outer_size,
        options.cipher_constant,
    )?;
    if let Some(stage2_output) = &options.stage2_output {
        write_atomic(&absolute(stage2_output)?, &stage1.plaintext)?;
    }

    let core_config =
        Module9bConfig::parse_embedded(&stage1.plaintext).map_err(Error::EmbeddedConfig)?;
    let bootstrap_end = stage1
        .remaining_file_offset
        .checked_add(stage1.remaining_size)
        .ok_or_else(|| Error::Invalid("Stage 2 bootstrap range overflow".to_owned()))?;
    let bootstrap = source
        .get(stage1.remaining_file_offset..bootstrap_end)
        .ok_or_else(|| Error::Invalid("Stage 2 bootstrap range is outside the ELF".to_owned()))?;
    let mut extractor = Extractor {
        output_dir: output_dir.clone(),
        streams: Vec::new(),
        artifacts: Vec::new(),
        registry: BTreeMap::new(),
        seen_streams: HashSet::new(),
    };
    extractor.extract_stream(
        bootstrap,
        0xe2,
        0,
        None,
        Some(stage1.remaining_file_offset),
        core_config,
    )?;

    let module_registry = extractor
        .registry
        .values()
        .map(|module| ModuleRegistryEntry {
            command_id: module.command_id,
            size: module.image.len(),
            sha256: module.sha256.clone(),
            depth: module.depth,
            record_index: module.record_index,
            image_path: module.image_path.clone(),
            metadata_path: module.metadata_path.clone(),
            init_offset: module.init_offset,
            entry_offset: module.entry_offset,
            classification: if module.metadata.is_some() {
                "module_image".to_owned()
            } else {
                "decoded_data".to_owned()
            },
        })
        .collect::<Vec<_>>();
    let report = ExtractionReport {
        format_version: 4,
        protected_elf: input_path.display().to_string(),
        output_dir: output_dir.display().to_string(),
        stage1: stage1_report(&stage1, options.outer_size),
        streams: extractor.streams,
        artifacts: extractor.artifacts,
        errors: Vec::new(),
        module_registry,
    };
    write_json_atomic(&output_dir.join("index.json"), &report)?;
    Ok(report)
}

impl Extractor {
    fn extract_stream(
        &mut self,
        stream: &[u8],
        stream_id: u32,
        depth: usize,
        parent: Option<StreamParent>,
        source_file_offset: Option<usize>,
        config: Module9bConfig,
    ) -> Result<()> {
        let digest = sha256(stream);
        if !self.seen_streams.insert((stream_id, digest.clone())) {
            return Ok(());
        }
        let (header, records, table_size) =
            parse_record_stream(stream, stream_id).map_err(|source| {
                Error::Invalid(format!(
                    "depth {depth} stream 0x{stream_id:02X} record table: {source}"
                ))
            })?;
        let mut stream_report = StreamReport {
            depth,
            stream_id,
            parent,
            source_file_offset,
            available_size: stream.len(),
            descriptor_table_size: table_size,
            encrypted_header_words: header.encrypted_words,
            decrypted_header_words: header.decrypted_words,
            record_state: header.record_state,
            sha256: digest,
            decoder: decoder_report(
                if depth == 0 {
                    "embedded_stage2"
                } else {
                    "decoded_interpreter"
                },
                (depth != 0).then_some(stream_id),
                &config,
            ),
            records: Vec::with_capacity(records.len()),
        };
        let mut direct_records = Vec::new();
        let mut modules_at_level = BTreeSet::new();

        for record in records {
            let mut result = record_report(record);
            let mut image_data = None;
            let mut metadata_data = None;

            if !record.direct() && record.image_size != 0 {
                let image_source = record_tail(stream, record.image_offset)?;
                let image = decode_container(image_source, &config, record.image_size as usize)
                    .map_err(|source| Error::RecordDecode {
                        depth,
                        stream_id,
                        record_index: record.index,
                        command_id: record.command_id,
                        part: "image decode",
                        source,
                    })?;
                let classification = if record.metadata_size != 0 {
                    "module_image"
                } else {
                    "decoded_data"
                };
                let artifact = self.write_artifact(
                    &record,
                    depth,
                    stream_id,
                    ArtifactSpec {
                        suffix: "module.bin",
                        kind: "decoded_container",
                        classification,
                    },
                    &image,
                )?;
                result.image = Some(artifact.clone());
                image_data = Some((image, artifact));
            }
            if record.metadata_size != 0 {
                let metadata_source = record_tail(stream, record.metadata_offset)?;
                let metadata =
                    decode_container(metadata_source, &config, record.metadata_size as usize)
                        .map_err(|source| Error::RecordDecode {
                            depth,
                            stream_id,
                            record_index: record.index,
                            command_id: record.command_id,
                            part: "metadata decode",
                            source,
                        })?;
                let artifact = self.write_artifact(
                    &record,
                    depth,
                    stream_id,
                    ArtifactSpec {
                        suffix: "metadata.bin",
                        kind: "decoded_metadata",
                        classification: "decoded_metadata",
                    },
                    &metadata,
                )?;
                result.metadata = Some(artifact.clone());
                metadata_data = Some((metadata, artifact));
            }
            if let Some((image, image_artifact)) = image_data {
                let (metadata, metadata_path) = if let Some((data, artifact)) = metadata_data {
                    (Some(data), Some(artifact.path))
                } else {
                    (None, None)
                };
                self.register_module(LoadedModule {
                    sha256: image_artifact.sha256.clone(),
                    image_path: image_artifact.path.clone(),
                    metadata_path,
                    image,
                    metadata,
                    depth,
                    record_index: record.index,
                    command_id: record.command_id,
                    init_offset: record.init_offset,
                    entry_offset: record.entry_offset,
                })?;
                modules_at_level.insert(record.command_id);
            }
            if record.direct() && record.image_size != 0 {
                direct_records.push((record, stream_report.records.len()));
            }
            stream_report.records.push(result);
        }

        let mut children = Vec::new();
        for (record, report_index) in direct_records {
            let next_stream_id = record.command_id.wrapping_sub(0x10);
            if modules_at_level.contains(&next_stream_id) {
                stream_report.records[report_index].nested_stream_id = Some(next_stream_id);
                children.push((record, next_stream_id));
                continue;
            }
            let direct_data = record_slice(stream, record.image_offset, record.image_size)?;
            let artifact = self.write_artifact(
                &record,
                depth,
                stream_id,
                ArtifactSpec {
                    suffix: "direct.bin",
                    kind: "direct",
                    classification: "direct_data",
                },
                direct_data,
            )?;
            stream_report.records[report_index].image = Some(artifact);
        }

        self.streams.push(stream_report);
        for (record, next_stream_id) in children {
            let child_data = record_slice(stream, record.image_offset, record.image_size)?;
            let parent = StreamParent {
                stream_id,
                record_index: record.index,
                command_id: record.command_id,
            };
            let interpreter = self.registry.get(&next_stream_id).ok_or_else(|| {
                Error::Invalid(format!(
                    "depth {depth} stream 0x{stream_id:02X} child 0x{next_stream_id:02X} has no interpreter module"
                ))
            })?;
            let interpreter_config =
                Module9bConfig::parse(&interpreter.image).map_err(|source| {
                    Error::InterpreterConfig {
                        depth: depth + 1,
                        stream_id: next_stream_id,
                        interpreter_id: next_stream_id,
                        source,
                    }
                })?;
            self.extract_stream(
                child_data,
                next_stream_id,
                depth + 1,
                Some(parent),
                None,
                interpreter_config,
            )?;
        }
        Ok(())
    }

    fn register_module(&mut self, module: LoadedModule) -> Result<()> {
        if let Some(previous) = self.registry.get(&module.command_id) {
            if previous.sha256 != module.sha256 {
                return invalid(format!(
                    "module 0x{:02X} produced conflicting images: {} and {}",
                    module.command_id, previous.sha256, module.sha256
                ));
            }
            return Ok(());
        }
        self.registry.insert(module.command_id, module);
        Ok(())
    }

    fn write_artifact(
        &mut self,
        record: &Record,
        depth: usize,
        stream_id: u32,
        spec: ArtifactSpec<'_>,
        data: &[u8],
    ) -> Result<ArtifactReport> {
        let digest = sha256(data);
        let filename = format!(
            "d{depth:02}_s{stream_id:02X}_r{:03}_id{:08X}_{}.{}",
            record.index,
            record.command_id,
            &digest[..12],
            spec.suffix
        );
        let path = self.output_dir.join(filename);
        write_atomic(&path, data)?;
        let artifact = ArtifactReport {
            kind: spec.kind.to_owned(),
            path: path
                .file_name()
                .ok_or_else(|| Error::Invalid("artifact path has no file name".to_owned()))?
                .to_string_lossy()
                .into_owned(),
            size: data.len(),
            sha256: digest,
            depth,
            stream_id,
            record_index: Some(record.index),
            command_id: Some(record.command_id),
            classification: spec.classification.to_owned(),
        };
        self.artifacts.push(artifact.clone());
        Ok(artifact)
    }
}

fn record_report(record: Record) -> RecordReport {
    RecordReport {
        index: record.index,
        command_id: record.command_id,
        flags: record.flags,
        image_offset: record.image_offset,
        image_size: record.image_size,
        metadata_offset: record.metadata_offset,
        metadata_size: record.metadata_size,
        id_copy: record.id_copy,
        entry_offset: record.entry_offset,
        init_offset: record.init_offset,
        direct: record.flags & DIRECT_FLAG != 0,
        extraction_status: "complete".to_owned(),
        image: None,
        metadata: None,
        nested_stream_id: None,
    }
}

fn decoder_report(
    kind: &str,
    interpreter_id: Option<u32>,
    config: &Module9bConfig,
) -> DecoderReport {
    DecoderReport {
        kind: kind.to_owned(),
        interpreter_id,
        header_seed: config.header_seed,
        container_seed: config.container_seed,
        schedule_offset: config.schedule_offset,
        aes_key_sha256: sha256(&config.aes_key),
        skip_aes: config.skip_aes,
    }
}

fn record_slice(stream: &[u8], offset: u32, size: u32) -> Result<&[u8]> {
    let offset = usize::try_from(offset)
        .map_err(|_| Error::Invalid("record payload offset exceeds usize".to_owned()))?;
    let size = usize::try_from(size)
        .map_err(|_| Error::Invalid("record payload size exceeds usize".to_owned()))?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::Invalid("record payload range overflows usize".to_owned()))?;
    stream.get(offset..end).ok_or_else(|| {
        Error::Invalid(format!(
            "record payload range 0x{offset:x}..0x{end:x} exceeds stream 0x{:x}",
            stream.len()
        ))
    })
}

fn record_tail(stream: &[u8], offset: u32) -> Result<&[u8]> {
    let offset = usize::try_from(offset)
        .map_err(|_| Error::Invalid("record container offset exceeds usize".to_owned()))?;
    stream.get(offset..).ok_or_else(|| {
        Error::Invalid(format!(
            "record container offset 0x{offset:x} exceeds stream 0x{:x}",
            stream.len()
        ))
    })
}

fn stage1_report(stage1: &Stage1Result, outer_size: usize) -> Stage1Report {
    Stage1Report {
        section_index: stage1.section_index,
        section_type: SHT_LOUSER,
        section_offset: stage1.section_offset,
        section_size: stage1.section_size,
        outer_size,
        header_offset: stage1.header_offset,
        header_key: stage1.header.key,
        payload_offset: stage1.header.payload_offset,
        payload_size: stage1.header.payload_size,
        payload_key: stage1.header.payload_key,
        entry_offset: stage1.header.entry_offset,
        protect_size: stage1.header.protect_size,
        stage2_file_offset: stage1.payload_file_offset,
        stage2_size: stage1.plaintext.len(),
        stage2_sha256: sha256(&stage1.plaintext),
        remaining_file_offset: stage1.remaining_file_offset,
        remaining_size: stage1.remaining_size,
    }
}

fn write_json_atomic(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_dir_all(parent)
        .map_err(|source| Error::io("create output directory", parent, source))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|source| Error::io("create temporary output", parent, source))?;
    temporary
        .write_all(data)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| Error::io("write temporary output", temporary.path(), source))?;
    temporary
        .persist(path)
        .map_err(|error| Error::io("replace output", path, error.error))?;
    Ok(())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|source| Error::io("query current directory", path, source))
    }
}

fn sha256(data: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(data);
    format!("{:x}", digest.finalize())
}
