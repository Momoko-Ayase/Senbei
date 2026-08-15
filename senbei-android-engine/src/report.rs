use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Stage1Report {
    pub section_index: usize,
    pub section_type: u32,
    pub section_offset: usize,
    pub section_size: usize,
    pub outer_size: usize,
    pub header_offset: usize,
    pub header_key: u32,
    pub payload_offset: u32,
    pub payload_size: u32,
    pub payload_key: u32,
    pub entry_offset: u32,
    pub protect_size: u32,
    pub stage2_file_offset: usize,
    pub stage2_size: usize,
    pub stage2_sha256: String,
    pub remaining_file_offset: usize,
    pub remaining_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecoderReport {
    pub kind: String,
    pub interpreter_id: Option<u32>,
    pub header_seed: u32,
    pub container_seed: u32,
    pub schedule_offset: usize,
    pub aes_key_sha256: String,
    pub skip_aes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactReport {
    pub kind: String,
    pub path: String,
    pub size: usize,
    pub sha256: String,
    pub depth: usize,
    pub stream_id: u32,
    pub record_index: Option<usize>,
    pub command_id: Option<u32>,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordReport {
    pub index: usize,
    pub command_id: u32,
    pub flags: u32,
    pub image_offset: u32,
    pub image_size: u32,
    pub metadata_offset: u32,
    pub metadata_size: u32,
    pub id_copy: u32,
    pub entry_offset: u32,
    pub init_offset: u32,
    pub direct: bool,
    pub extraction_status: String,
    pub image: Option<ArtifactReport>,
    pub metadata: Option<ArtifactReport>,
    pub nested_stream_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamParent {
    pub stream_id: u32,
    pub record_index: usize,
    pub command_id: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamReport {
    pub depth: usize,
    pub stream_id: u32,
    pub parent: Option<StreamParent>,
    pub source_file_offset: Option<usize>,
    pub available_size: usize,
    pub descriptor_table_size: usize,
    pub encrypted_header_words: [u32; 2],
    pub decrypted_header_words: [u32; 2],
    pub record_state: u32,
    pub sha256: String,
    pub decoder: DecoderReport,
    pub records: Vec<RecordReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleRegistryEntry {
    pub command_id: u32,
    pub size: usize,
    pub sha256: String,
    pub depth: usize,
    pub record_index: usize,
    pub image_path: String,
    pub metadata_path: Option<String>,
    pub init_offset: u32,
    pub entry_offset: u32,
    pub classification: String,
}

/// Machine-readable output of one complete static Stage 2 extraction.
#[derive(Debug, Clone, Serialize)]
pub struct ExtractionReport {
    pub format_version: u32,
    pub protected_elf: String,
    pub output_dir: String,
    pub stage1: Stage1Report,
    pub streams: Vec<StreamReport>,
    pub artifacts: Vec<ArtifactReport>,
    pub errors: Vec<String>,
    pub module_registry: Vec<ModuleRegistryEntry>,
}
