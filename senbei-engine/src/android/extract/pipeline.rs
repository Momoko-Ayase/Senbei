use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use memmap2::MmapOptions;
use senbei_crypto::android::{Module9bConfig, decode_container_with_limit};

use crate::android::{ByteBudget, EntryBudget, ResourceLimits};
use serde_json::to_vec_pretty;

use super::super::common;
use super::error::{Error, Result, invalid};
use super::report::{
    ArtifactReport, DecoderReport, ExtractionReport, ModuleRegistryEntry, RecordReport,
    Stage1Report, StreamParent, StreamReport,
};
use super::stage1::{
    DEFAULT_CIPHER_CONSTANT, DEFAULT_OUTER_SIZE, SHT_LOUSER, Stage1Result, inspect,
};
use super::stream::{DIRECT_FLAG, Record, parse_record_stream};

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

struct DecodeBudget {
    limits: ResourceLimits,
    bytes: ByteBudget,
    records: EntryBudget,
    config: Module9bConfig,
}

struct Extractor {
    output_dir: PathBuf,
    streams: Vec<StreamReport>,
    artifacts: Vec<ArtifactReport>,
    registry: BTreeMap<u32, LoadedModule>,
    seen_streams: HashSet<(u32, String)>,
}

pub fn extract_stage2(options: &ExtractOptions) -> Result<ExtractionReport> {
    extract_stage2_with_limits(options, &ResourceLimits::default())
}

/// [`extract_stage2`] with explicit ceilings for decoded records and nesting.
///
/// `limits.max_entries` counts decoded stage-2 records. `limits.max_depth`
/// counts nested interpreter streams, with the bootstrap stream at depth 0.
/// `limits.max_entry_bytes` bounds each decoded container and its writers, and
/// `limits.max_total_bytes` sums those decoded payloads for this call. Neither
/// budget is a peak resident-memory measurement.
pub fn extract_stage2_with_limits(
    options: &ExtractOptions,
    limits: &ResourceLimits,
) -> Result<ExtractionReport> {
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
    std::fs::create_dir_all(&output_dir)
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
        // Stage 1 plaintext is the first thing this task retains. Its copy
        // is capped by both the single-entry ceiling and whatever remains of
        // the task total, which is the whole total at this point.
        Some(limits.max_entry_bytes.min(limits.max_total_bytes)),
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
    let mut budget = DecodeBudget {
        limits: *limits,
        bytes: ByteBudget::new(limits),
        records: EntryBudget::new(limits),
        config: core_config,
    };
    budget
        .bytes
        .charge(u64::try_from(stage1.plaintext.len()).unwrap_or(u64::MAX))?;
    extractor.extract_stream(
        bootstrap,
        0xe2,
        0,
        None,
        Some(stage1.remaining_file_offset),
        &mut budget,
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
        budget: &mut DecodeBudget,
    ) -> Result<()> {
        budget.limits.check_depth(depth)?;
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
                &budget.config,
            ),
            records: Vec::new(),
        };
        budget.records.charge(records.len())?;
        stream_report
            .records
            .try_reserve_exact(records.len())
            .map_err(|_| Error::Invalid("stage-2 record report reservation failed".to_owned()))?;
        let mut direct_records = Vec::new();
        let mut modules_at_level = BTreeSet::new();

        for record in records {
            let mut result = record_report(record);
            let mut image_data = None;
            let mut metadata_data = None;

            if !record.direct() && record.image_size != 0 {
                // Charge the declared size before the decoder reserves it.
                // A metadata-only record is charged below, on the same rule.
                budget.bytes.charge(u64::from(record.image_size))?;
                let image_source = record_tail(stream, record.image_offset)?;
                let image = decode_container_with_limit(
                    image_source,
                    &budget.config,
                    record.image_size as usize,
                    budget.limits.output_limit(),
                )
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
                budget.bytes.charge(u64::from(record.metadata_size))?;
                let metadata_source = record_tail(stream, record.metadata_offset)?;
                let metadata = decode_container_with_limit(
                    metadata_source,
                    &budget.config,
                    record.metadata_size as usize,
                    budget.limits.output_limit(),
                )
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
            budget.limits.check_depth(depth + 1)?;
            let parent_config = std::mem::replace(&mut budget.config, interpreter_config);
            self.extract_stream(
                child_data,
                next_stream_id,
                depth + 1,
                Some(parent),
                None,
                budget,
            )?;
            budget.config = parent_config;
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
    common::write_atomic(path, data)
        .map_err(|source| Error::io("write temporary output", path, source))
}

fn absolute(path: &Path) -> Result<PathBuf> {
    common::absolute(path).map_err(|source| Error::io("query current directory", path, source))
}

fn sha256(data: &[u8]) -> String {
    common::sha256(data)
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    use crate::android::LimitExceeded;

    fn config() -> Module9bConfig {
        Module9bConfig {
            header_seed: 0,
            container_seed: 0,
            aes_key: [0; 32],
            skip_aes: true,
            schedule_offset: 0,
        }
    }

    fn tight(entries: usize, depth: usize) -> ResourceLimits {
        ResourceLimits {
            max_entry_bytes: 1024,
            max_total_bytes: 1024,
            max_entries: entries,
            max_depth: depth,
        }
    }

    /// One direct record whose payload is `child`.
    ///
    /// The command is `stream_id + 0x10`, which is the id a nested stream uses
    /// for its interpreter. The payload begins immediately after the single
    /// descriptor, so parsing stops at that boundary.
    fn direct_stream(stream_id: u32, child: &[u8]) -> Vec<u8> {
        let key = stream_id.wrapping_mul(0x9d32_3cd7);
        let shift = stream_id & 7;
        let base = (key >> shift)
            .wrapping_add(0x5e72_7d74)
            .wrapping_add(key.wrapping_shl(stream_id & 0xb))
            .wrapping_add(0xf71e_3005);
        // record_state = plain1 + base, and plain1 is chosen so that state is
        // zero. That keeps the record cipher's index mask zero as well.
        let plain1 = 0_u32.wrapping_sub(base);
        let cipher0 =
            unmultiply(1_u32 ^ 0xebe8_1dba_u32.wrapping_add(base)).wrapping_sub(0xcbf0_c1d8);
        let cipher1 = unmultiply(plain1 ^ 0xebe8_1dba_u32.wrapping_mul(5).wrapping_add(base))
            .wrapping_sub(cipher0);
        let mut stream = Vec::new();
        stream.extend_from_slice(&cipher0.to_le_bytes());
        stream.extend_from_slice(&cipher1.to_le_bytes());
        // `command - 0x10` is the interpreter id a nested stream looks up.
        // Using `stream_id + 0x10` makes a lone record direct, because that
        // interpreter was not decoded from this same stream.
        let command = stream_id.wrapping_add(0x10);
        let words = [
            command,
            super::super::stream::DIRECT_FLAG,
            (8 + super::super::stream::RECORD_SIZE) as u32,
            child.len() as u32,
            0,
            0,
            command,
            0,
            0,
        ];
        stream.extend_from_slice(&encrypt_record(&words));
        stream.extend_from_slice(child);
        stream
    }

    fn encrypt_record(words: &[u32]) -> Vec<u8> {
        // Inverse of `decrypt_record` at record state zero: replay its
        // feedback from each ciphertext word, then undo the field multiply.
        let mut feedback = 0xf02f_7685_u32;
        let mut accumulator = 0x7993_4cf6_u32;
        let mut raw = vec![0_u8; super::super::stream::RECORD_SIZE];
        for (word_index, plain) in words.iter().copied().enumerate() {
            feedback = feedback.wrapping_mul(feedback);
            let mixed = plain
                .wrapping_sub(accumulator)
                .wrapping_add(0 >> ((word_index * 4 + 3) & 5));
            let cipher = unmultiply(mixed) ^ (feedback >> 3);
            raw[word_index * 4..word_index * 4 + 4].copy_from_slice(&cipher.to_le_bytes());
            accumulator = accumulator.wrapping_add(0xe64d_33d8);
            feedback = cipher;
        }
        raw
    }

    fn unmultiply(encoded: u32) -> u32 {
        let mut multiplier = 0xdc49_cd06_u32;
        let mut value = encoded;
        let mut result = 0_u32;
        while multiplier != 0 {
            if multiplier & 1 != 0 {
                result ^= value;
            }
            let carry = value >> 31;
            value = value.wrapping_shl(1);
            if carry != 0 {
                value ^= 0x5793_57eb;
            }
            multiplier >>= 1;
        }
        result
    }

    fn extractor() -> Extractor {
        Extractor {
            output_dir: PathBuf::from("."),
            streams: Vec::new(),
            artifacts: Vec::new(),
            registry: BTreeMap::new(),
            seen_streams: HashSet::new(),
        }
    }

    fn budget(entries: usize, depth: usize) -> DecodeBudget {
        let limits = tight(entries, depth);
        DecodeBudget {
            limits,
            bytes: ByteBudget::new(&limits),
            records: EntryBudget::new(&limits),
            config: config(),
        }
    }

    #[test]
    fn record_budget_rejects_one_past_the_ceiling_and_allows_the_boundary() {
        let stream = direct_stream(0xe2, &[0]);
        let error = extractor()
            .extract_stream(&stream, 0xe2, 0, None, None, &mut budget(0, 32))
            .expect_err("one record is already past a zero-record ceiling");
        assert!(
            matches!(
                error,
                Error::Limit(LimitExceeded::Entries {
                    requested: 1,
                    limit: 0
                })
            ),
            "unexpected error: {error}"
        );

        let directory = tempfile::tempdir().expect("temporary output directory");
        let mut at_ceiling = extractor();
        at_ceiling.output_dir = directory.path().to_path_buf();
        at_ceiling
            .extract_stream(&stream, 0xe2, 0, None, None, &mut budget(1, 0))
            .expect("one record at depth zero is the boundary");
    }

    #[test]
    fn nesting_one_past_the_ceiling_is_rejected_before_the_child_is_decoded() {
        let stream = direct_stream(0xe2, &[0]);
        let directory = tempfile::tempdir().expect("temporary output directory");
        let mut at_ceiling = extractor();
        at_ceiling.output_dir = directory.path().to_path_buf();
        at_ceiling
            .extract_stream(&stream, 0xe2, 32, None, None, &mut budget(1, 32))
            .expect("depth 32 is the nesting boundary");

        let error = extractor()
            .extract_stream(&stream, 0xe2, 33, None, None, &mut budget(1, 32))
            .expect_err("depth 33 is rejected before the stream is parsed");
        match &error {
            Error::Limit(limit) => assert_eq!(
                limit,
                &LimitExceeded::Depth {
                    requested: 33,
                    limit: 32
                }
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn decoded_payloads_share_one_task_budget() {
        let stream = direct_stream(0xe2, &[0]);
        let directory = tempfile::tempdir().expect("temporary output directory");
        let mut budget = budget(1, 0);
        budget.limits.max_total_bytes = 1;
        budget.bytes = ByteBudget::new(&budget.limits);
        // A direct record has no decoded container, so it does not charge the
        // byte budget. Seed the only allowed byte to prove the budget is the
        // one the caller passed in and is not reset per stream.
        budget.bytes.charge(1).unwrap();
        let mut extractor = extractor();
        extractor.output_dir = directory.path().to_path_buf();
        extractor
            .extract_stream(&stream, 0xe2, 0, None, None, &mut budget)
            .unwrap();
        assert_eq!(budget.bytes.used(), 1);
        assert!(budget.bytes.charge(1024).is_err());
    }
}
