use std::path::{Path, PathBuf};

/// Stage 1 or Stage 2 extraction failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{action} `{path}`: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse ELF `{path}`: {source}")]
    Elf {
        path: PathBuf,
        #[source]
        source: goblin::error::Error,
    },
    #[error("serialize extraction index: {0}")]
    Json(#[from] serde_json::Error),
    #[error("embedded Stage 2 decoder configuration: {0}")]
    EmbeddedConfig(#[source] senbei_android_crypto::Error),
    #[error(
        "depth {depth} stream 0x{stream_id:02X} interpreter 0x{interpreter_id:02X} configuration: {source}"
    )]
    InterpreterConfig {
        depth: usize,
        stream_id: u32,
        interpreter_id: u32,
        #[source]
        source: senbei_android_crypto::Error,
    },
    #[error(
        "depth {depth} stream 0x{stream_id:02X} record {record_index} command 0x{command_id:02X} {part}: {source}"
    )]
    RecordDecode {
        depth: usize,
        stream_id: u32,
        record_index: usize,
        command_id: u32,
        part: &'static str,
        #[source]
        source: senbei_android_crypto::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

impl Error {
    pub(crate) fn io(action: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(message.into()))
}
