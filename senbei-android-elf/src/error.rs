use std::path::{Path, PathBuf};

/// ELF restoration failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{action} `{path}`: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse module index: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Crypto(#[from] senbei_android_crypto::Error),
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
