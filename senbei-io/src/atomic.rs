//! Shared atomic filesystem writes for native orchestration.

use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use tempfile::Builder;

/// Write `bytes` through a uniquely named temporary file in `dest`'s directory
/// and replace `dest` only after the complete write succeeds.
///
/// The temporary name is random, so concurrent writers of the same destination
/// do not share one sibling file. An existing `dest` is replaced. On any
/// failure the temporary file is removed and `dest` is left unchanged.
pub(crate) fn write_atomic(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = dest
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    // Same directory as `dest`: the final replace must stay on one filesystem.
    // The temporary is private to this call and is removed if persist is not
    // reached, or if persist fails.
    let mut temporary = Builder::new()
        .prefix(".senbei-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    // `persist` replaces an existing file and, on failure, hands the temporary
    // back. Drop deletes that file, so a failed replace cannot leave `dest`
    // half-written. Windows can refuse the replace while another handle still
    // has `dest` open (the file is mapped, or a concurrent replace has not
    // dropped its handle yet). Retry these refusals briefly; a persistent
    // permission or sharing failure still leaves the old destination intact.
    const ATTEMPTS: u32 = 8;
    let mut attempt = 0;
    loop {
        match temporary.persist(dest) {
            Ok(_) => return Ok(()),
            Err(error) if replace_in_progress(&error.error) && attempt + 1 < ATTEMPTS => {
                thread::sleep(Duration::from_millis(1 << attempt));
                attempt += 1;
                temporary = error.file;
            }
            Err(error) => return Err(error.error),
        }
    }
}

/// A replace refused because the destination is momentarily in use.
///
/// `ERROR_ACCESS_DENIED` (5) is what Windows returns when `MoveFileExW` cannot
/// replace a file another handle still has open. `ERROR_SHARING_VIOLATION`
/// (32) is the same condition reported through the sharing check. These codes
/// can also mean a permanent denial, so retries are bounded and never remove
/// the existing destination to force replacement.
fn replace_in_progress(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(5 | 32))
    }
    #[cfg(not(windows))]
    {
        let _ = error;
        false
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    fn stray_names(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .expect("read destination directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with(".senbei-") || name.ends_with(".senbei-tmp"))
            .collect()
    }

    #[test]
    fn writes_new_file_and_leaves_no_temporary() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("out.bin");

        write_atomic(&dest, b"payload").expect("write");

        assert_eq!(fs::read(&dest).unwrap(), b"payload");
        assert!(stray_names(dir.path()).is_empty());
    }

    #[test]
    fn overwrites_existing_destination() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("out.bin");
        fs::write(&dest, b"previous").expect("seed");

        write_atomic(&dest, b"replacement").expect("overwrite");

        assert_eq!(fs::read(&dest).unwrap(), b"replacement");
        assert!(stray_names(dir.path()).is_empty());
    }

    #[test]
    fn failure_leaves_existing_destination_and_no_temporary() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("out.bin");
        fs::create_dir(&dest).expect("destination directory");

        let error = write_atomic(&dest, b"replacement").expect_err("cannot replace a directory");

        assert_ne!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(dest.is_dir());
        assert!(stray_names(dir.path()).is_empty());
        assert!(
            stray_names(&dest).is_empty(),
            "temporary file was left inside the destination"
        );
    }

    #[test]
    fn missing_parent_writes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let parent = dir.path().join("missing");
        let dest = parent.join("out.bin");

        let error = write_atomic(&dest, b"payload").expect_err("missing parent");

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!parent.exists());
    }

    #[test]
    fn concurrent_writers_leave_one_complete_output() {
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = Arc::new(dir.path().join("out.bin"));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for id in 0..8u8 {
            let dest = Arc::clone(&dest);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                let payload = vec![id; 64 * 1024];
                write_atomic(&dest, &payload).expect("concurrent write");
                id
            }));
        }
        let ids: Vec<u8> = handles
            .into_iter()
            .map(|handle| handle.join().expect("writer thread"))
            .collect();

        let written = fs::read(dest.as_path()).expect("read destination");
        let writer = written[0];
        assert!(ids.contains(&writer));
        assert!(written.iter().all(|byte| *byte == writer));
        assert_eq!(written.len(), 64 * 1024);
        assert!(stray_names(dir.path()).is_empty());
    }

    #[test]
    fn distinct_temporary_names_survive_a_failed_replace() {
        // Two writers no longer share `<dest>.senbei-tmp`. Each temporary is
        // removed when its own replace fails, including when the destination
        // cannot be replaced at all.
        let dir = tempfile::tempdir().expect("temp dir");
        let dest = dir.path().join("out.bin");
        fs::create_dir(&dest).expect("destination directory");
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for payload in [b"first".as_slice(), b"second".as_slice()] {
            let dest = dest.clone();
            let barrier = Arc::clone(&barrier);
            let payload = payload.to_vec();
            handles.push(thread::spawn(move || {
                barrier.wait();
                write_atomic(&dest, &payload)
            }));
        }
        for handle in handles {
            handle
                .join()
                .expect("writer thread")
                .expect_err("directory destination");
        }
        assert!(dest.is_dir());
        assert!(stray_names(dir.path()).is_empty());
        assert!(stray_names(&dest).is_empty());
    }
}
