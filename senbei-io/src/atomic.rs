//! Shared atomic filesystem writes for native orchestration.

use std::path::{Path, PathBuf};

/// Write `bytes` through a sibling temporary file and replace `dest` only after
/// the complete write succeeds.
pub(crate) fn write_atomic(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut temporary_name = dest.as_os_str().to_os_string();
    temporary_name.push(".senbei-tmp");
    let temporary = PathBuf::from(temporary_name);
    let result = std::fs::write(&temporary, bytes).and_then(|()| std::fs::rename(&temporary, dest));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
