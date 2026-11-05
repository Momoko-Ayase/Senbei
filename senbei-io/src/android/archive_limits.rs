use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use senbei_engine::android::{LimitExceeded, ResourceLimits};
use zip::ZipArchive;

use anyhow::{Context, Result, bail};

#[derive(Clone, Copy)]
struct ArchiveInfo {
    entries: usize,
    directory_start: u64,
    directory_bytes: u64,
    end_record: u64,
    zip64_record: Option<u64>,
}

/// The ZIP library may retry an older end record when metadata is malformed.
/// During index construction, permit only the end records we preflighted and
/// keep central-header reads inside their declared region. Once indexing ends,
/// normal entry reads regain unrestricted seeking on the same file handle.
pub(super) struct ArchiveReader {
    file: File,
    info: ArchiveInfo,
    indexing: Arc<AtomicBool>,
    directory_started: bool,
}

fn invalid_metadata(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

impl Seek for ArchiveReader {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let position = self.file.seek(from)?;
        if !self.indexing.load(Ordering::Relaxed) {
            return Ok(position);
        }
        if matches!(from, SeekFrom::Start(_)) {
            let mut signature = [0_u8; 4];
            let read = self.file.read(&mut signature)?;
            self.file.seek(SeekFrom::Start(position))?;
            if read == 4
                && ((signature == *b"PK\x05\x06" && position != self.info.end_record)
                    || (signature == *b"PK\x06\x06" && Some(position) != self.info.zip64_record))
            {
                return Err(invalid_metadata(
                    "ZIP parser attempted an unverified end record",
                ));
            }
        }
        if position == self.info.directory_start {
            self.directory_started = true;
        }
        Ok(position)
    }
}

impl Read for ArchiveReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if !self.indexing.load(Ordering::Relaxed) || !self.directory_started {
            return self.file.read(buffer);
        }
        let position = self.file.stream_position()?;
        let directory_end = self.info.directory_start + self.info.directory_bytes;
        if position >= self.info.directory_start && position < directory_end {
            let count = (directory_end - position).min(buffer.len() as u64) as usize;
            return self.file.read(&mut buffer[..count]);
        }
        let trailer = self.info.zip64_record.unwrap_or(self.info.end_record);
        if position >= trailer {
            return self.file.read(buffer);
        }
        Err(invalid_metadata(
            "ZIP indexing crossed the verified metadata region",
        ))
    }
}

/// Cumulative extraction work for a run, including nested APKs. The budget is
/// charged for actual bytes read, even if a later write or restore fails.
#[derive(Debug)]
pub(super) struct ArchiveBudget {
    max_entry_bytes: u64,
    max_total_bytes: u64,
    max_entries: usize,
    bytes: u64,
    entries: usize,
    archives: HashMap<PathBuf, usize>,
}

impl Default for ArchiveBudget {
    fn default() -> Self {
        Self::from_limits(&ResourceLimits::default())
    }
}

impl ArchiveBudget {
    pub(super) fn from_limits(limits: &ResourceLimits) -> Self {
        Self::new(
            limits.max_entry_bytes,
            limits.max_total_bytes,
            limits.max_entries,
        )
    }

    fn new(max_entry_bytes: u64, max_total_bytes: u64, max_entries: usize) -> Self {
        Self {
            max_entry_bytes,
            max_total_bytes,
            max_entries,
            bytes: 0,
            entries: 0,
            archives: HashMap::new(),
        }
    }

    pub(super) fn open_archive(&mut self, path: &Path) -> Result<ZipArchive<ArchiveReader>> {
        let mut file = File::open(path).with_context(|| format!("open `{}`", path.display()))?;
        let info = inspect_archive(
            &mut file,
            self.max_entries,
            self.max_entry_bytes
                .min(self.max_total_bytes.saturating_sub(self.bytes)),
        )
        .with_context(|| format!("check package `{}`", path.display()))?;
        let count = info.entries;
        let trailer = info.zip64_record.unwrap_or(info.end_record);
        if info
            .directory_start
            .checked_add(info.directory_bytes)
            .is_none_or(|end| end > trailer)
            || (count as u64)
                .checked_mul(46)
                .is_none_or(|minimum| minimum > info.directory_bytes)
        {
            bail!("ZIP central directory range is inconsistent with its end record");
        }
        let previous = self.archives.get(path).copied().unwrap_or(0);
        if count > previous {
            self.register_entries(count - previous)?;
        }
        self.archives
            .insert(path.to_path_buf(), count.max(previous));
        let indexing = Arc::new(AtomicBool::new(true));
        let reader = ArchiveReader {
            file,
            info,
            indexing: indexing.clone(),
            directory_started: false,
        };
        let archive = ZipArchive::with_config(
            zip::read::Config {
                archive_offset: zip::read::ArchiveOffset::Known(0),
            },
            reader,
        )
        .with_context(|| format!("read package `{}`", path.display()))?;
        indexing.store(false, Ordering::Relaxed);
        if archive.len() > count {
            bail!("package central directory contains more entries than its end record");
        }
        Ok(archive)
    }

    pub(super) fn read_probe(
        &mut self,
        input: &mut impl Read,
        size: u64,
        maximum: usize,
        label: &str,
    ) -> Result<Vec<u8>> {
        if size > self.max_entry_bytes {
            return Err(anyhow::Error::new(LimitExceeded::Entry {
                requested: size,
                limit: self.max_entry_bytes,
            })
            .context(format!(
                "entry `{label}` exceeds extraction limit {}",
                self.max_entry_bytes
            )));
        }
        let length = size.min(maximum as u64);
        if length > self.max_total_bytes.saturating_sub(self.bytes) {
            return Err(anyhow::Error::new(LimitExceeded::Total {
                requested: self.bytes.saturating_add(length),
                adding: length,
                limit: self.max_total_bytes,
            })
            .context(format!(
                "manifest `{label}` exceeds the remaining extraction byte limit"
            )));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length as usize)
            .context("reserve manifest probe")?;
        self.copy_entry(&mut input.take(length), &mut bytes, length, label)?;
        Ok(bytes)
    }

    pub(super) fn register_entries(&mut self, entries: usize) -> Result<()> {
        let total = self
            .entries
            .checked_add(entries)
            .context("archive entry count overflow")?;
        if total > self.max_entries {
            return Err(anyhow::Error::new(LimitExceeded::Entries {
                requested: total,
                limit: self.max_entries,
            })
            .context(format!(
                "archive entry limit exceeded: {total} > {}",
                self.max_entries
            )));
        }
        self.entries = total;
        Ok(())
    }

    pub(super) fn copy_entry(
        &mut self,
        input: &mut impl Read,
        output: &mut impl Write,
        declared_size: u64,
        label: &str,
    ) -> Result<u64> {
        let remaining = self.max_total_bytes.saturating_sub(self.bytes);
        let allowance = self.max_entry_bytes.min(remaining);
        if declared_size > allowance {
            let exceeded = if declared_size > self.max_entry_bytes {
                LimitExceeded::Entry {
                    requested: declared_size,
                    limit: self.max_entry_bytes,
                }
            } else {
                LimitExceeded::Total {
                    requested: self.bytes.saturating_add(declared_size),
                    adding: declared_size,
                    limit: self.max_total_bytes,
                }
            };
            return Err(anyhow::Error::new(exceeded).context(format!(
                "entry `{label}` declares {declared_size} bytes, exceeding extraction limit {allowance}"
            )));
        }
        // The advertised size is a stricter ceiling when it is smaller than
        // the budget. A dishonest header must not buy extra decompression work.
        let limit = declared_size;
        let mut buffer = [0_u8; 64 * 1024];
        let mut written = 0_u64;
        loop {
            // Read at most one byte beyond the allowance to detect a dishonest
            // size header without decompressing the rest of the entry.
            let read_limit = (limit - written).saturating_add(1).min(buffer.len() as u64) as usize;
            let read = input.read(&mut buffer[..read_limit])?;
            if read == 0 {
                break;
            }
            let next = written
                .checked_add(read as u64)
                .context("decompressed entry size overflow")?;
            if next > limit {
                return Err(anyhow::Error::new(LimitExceeded::Entry {
                    requested: next,
                    limit,
                })
                .context(format!(
                    "entry `{label}` exceeds extraction limit {limit} while decompressing"
                )));
            }
            self.bytes = self
                .bytes
                .checked_add(read as u64)
                .context("extraction byte count overflow")?;
            output.write_all(&buffer[..read])?;
            written = next;
        }
        if written != declared_size {
            bail!("entry `{label}` decompressed to {written} bytes, expected {declared_size}");
        }
        Ok(written)
    }
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Read only the bounded end records before asking the ZIP library to allocate
/// its central-directory index. Both ordinary ZIP and ZIP64 are supported.
#[cfg(test)]
fn preflight_archive(
    file: &mut File,
    max_entries: usize,
    max_directory_bytes: u64,
) -> Result<usize> {
    Ok(inspect_archive(file, max_entries, max_directory_bytes)?.entries)
}

fn inspect_archive(
    file: &mut File,
    max_entries: usize,
    max_directory_bytes: u64,
) -> Result<ArchiveInfo> {
    let length = file.seek(SeekFrom::End(0))?;
    let tail_length = length.min(22 + u16::MAX as u64) as usize;
    let mut tail = vec![0_u8; tail_length];
    file.seek(SeekFrom::End(-(tail_length as i64)))?;
    file.read_exact(&mut tail)?;
    let end = (0..=tail.len().saturating_sub(22))
        .rev()
        .find(|&offset| {
            tail.get(offset..offset + 4) == Some(b"PK\x05\x06")
                && offset + 22 <= tail.len()
                && offset + 22 + word(&tail, offset + 20) as usize == tail.len()
        })
        .context("ZIP end record is missing or truncated")?;
    let record = &tail[end..end + 22];
    if word(record, 4) != 0 || word(record, 6) != 0 {
        bail!("multi-disk ZIP packages are unsupported");
    }
    let end_record = length - tail_length as u64 + end as u64;
    let mut zip64_record = None;
    let mut directory_start = u64::from(dword(record, 16));
    let mut entries = u64::from(word(record, 10));
    let mut directory_bytes = u64::from(dword(record, 12));
    if entries == u16::MAX as u64
        || directory_bytes == u32::MAX as u64
        || dword(record, 16) == u32::MAX
    {
        let absolute_end = length - tail_length as u64 + end as u64;
        let locator_offset = absolute_end
            .checked_sub(20)
            .context("ZIP64 locator is missing")?;
        file.seek(SeekFrom::Start(locator_offset))?;
        let mut locator = [0_u8; 20];
        file.read_exact(&mut locator)?;
        if &locator[..4] != b"PK\x06\x07" || dword(&locator, 4) != 0 || dword(&locator, 16) != 1 {
            bail!("invalid ZIP64 locator");
        }
        let record_offset = qword(&locator, 8);
        if record_offset
            .checked_add(56)
            .is_none_or(|end| end > locator_offset)
        {
            bail!("ZIP64 end record is outside the package");
        }
        file.seek(SeekFrom::Start(record_offset))?;
        let mut record = [0_u8; 56];
        file.read_exact(&mut record)?;
        if &record[..4] != b"PK\x06\x06"
            || qword(&record, 4) < 44
            || record_offset
                .checked_add(12)
                .and_then(|start| start.checked_add(qword(&record, 4)))
                .is_none_or(|end| end > locator_offset)
            || dword(&record, 16) != 0
            || dword(&record, 20) != 0
            || qword(&record, 24) != qword(&record, 32)
        {
            bail!("invalid ZIP64 end record");
        }
        if qword(&record, 4) > max_directory_bytes {
            return Err(anyhow::Error::new(LimitExceeded::Entry {
                requested: qword(&record, 4),
                limit: max_directory_bytes,
            })
            .context("ZIP64 metadata exceeds the directory memory limit"));
        }
        zip64_record = Some(record_offset);
        directory_start = qword(&record, 48);
        entries = qword(&record, 32);
        directory_bytes = qword(&record, 40);
    } else if word(record, 8) != word(record, 10) {
        bail!("inconsistent ZIP entry counts");
    }
    if entries > max_entries as u64 {
        return Err(anyhow::Error::new(LimitExceeded::Entries {
            requested: usize::try_from(entries).unwrap_or(usize::MAX),
            limit: max_entries,
        })
        .context(format!(
            "archive entry limit exceeded: {entries} > {max_entries}"
        )));
    }
    if directory_bytes > max_directory_bytes {
        return Err(anyhow::Error::new(LimitExceeded::Entry {
            requested: directory_bytes,
            limit: max_directory_bytes,
        })
        .context(format!(
            "ZIP directory size {directory_bytes} exceeds memory limit {max_directory_bytes}"
        )));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(ArchiveInfo {
        entries: usize::try_from(entries).context("ZIP entry count exceeds address space")?,
        directory_start,
        directory_bytes,
        end_record,
        zip64_record,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn entry_and_aggregate_limits_allow_exact_boundaries() {
        let mut budget = ArchiveBudget::new(4, 6, 3);
        budget.register_entries(3).unwrap();
        assert!(budget.register_entries(1).is_err());
        let mut output = Vec::new();
        budget
            .copy_entry(&mut Cursor::new(b"abcd"), &mut output, 4, "first")
            .unwrap();
        budget
            .copy_entry(&mut Cursor::new(b"ef"), &mut output, 2, "second")
            .unwrap();
        assert_eq!(output, b"abcdef");
        assert!(
            budget
                .copy_entry(&mut Cursor::new(b"g"), &mut output, 1, "third")
                .is_err()
        );
        assert_eq!(output, b"abcdef");
    }

    #[test]
    fn declared_and_actual_sizes_are_both_limited() {
        let mut budget = ArchiveBudget::new(4, 10, 10);
        let mut output = Vec::new();
        assert!(
            budget
                .copy_entry(&mut Cursor::new(b"abcde"), &mut output, 5, "large header")
                .is_err()
        );
        assert!(output.is_empty());
        assert!(
            budget
                .copy_entry(&mut Cursor::new(b"abcde"), &mut output, 4, "lying header")
                .is_err()
        );
        assert!(output.is_empty());
        assert!(
            budget
                .copy_entry(&mut Cursor::new(b"abc"), &mut output, 4, "short entry")
                .is_err()
        );
    }

    #[test]
    fn archive_ceilings_keep_typed_causes_and_context() {
        let mut budget = ArchiveBudget::new(4, 6, 1);
        budget.register_entries(1).unwrap();
        let error = budget.register_entries(1).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<LimitExceeded>(),
            Some(LimitExceeded::Entries { .. })
        ));
        assert!(format!("{error:#}").contains("entry limit"));

        let error = budget
            .read_probe(&mut Cursor::new(b"abcde"), 5, 5, "manifest")
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<LimitExceeded>(),
            Some(LimitExceeded::Entry { .. })
        ));
        let error = budget
            .copy_entry(&mut Cursor::new(b"abcde"), &mut Vec::new(), 5, "large")
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<LimitExceeded>(),
            Some(LimitExceeded::Entry { .. })
        ));
        assert!(format!("{error:#}").contains("extraction limit"));
        budget
            .copy_entry(&mut Cursor::new(b"abcd"), &mut Vec::new(), 4, "first")
            .unwrap();
        let error = budget
            .copy_entry(&mut Cursor::new(b"abc"), &mut Vec::new(), 3, "second")
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<LimitExceeded>(),
            Some(LimitExceeded::Total { .. })
        ));
        let error = budget
            .read_probe(&mut Cursor::new(b"abc"), 3, 3, "manifest")
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<LimitExceeded>(),
            Some(LimitExceeded::Total { .. })
        ));
    }

    #[test]
    fn failed_writes_still_consume_the_read_budget() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("blocked"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut budget = ArchiveBudget::new(4, 4, 10);
        assert!(
            budget
                .copy_entry(&mut Cursor::new(b"abcd"), &mut FailingWriter, 4, "first")
                .is_err()
        );
        assert!(
            budget
                .copy_entry(&mut Cursor::new(b"x"), &mut Vec::new(), 1, "retry")
                .is_err()
        );
    }

    fn end_record(entries: u16, directory_bytes: u32) -> [u8; 22] {
        let mut record = [0_u8; 22];
        record[..4].copy_from_slice(b"PK\x05\x06");
        record[8..10].copy_from_slice(&entries.to_le_bytes());
        record[10..12].copy_from_slice(&entries.to_le_bytes());
        record[12..16].copy_from_slice(&directory_bytes.to_le_bytes());
        record
    }

    #[test]
    fn preflight_rejects_large_counts_and_directory_before_indexing() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&end_record(50, 1000)).unwrap();
        let count_error = preflight_archive(&mut file, 49, 1000).unwrap_err();
        assert!(matches!(
            count_error.downcast_ref::<LimitExceeded>(),
            Some(LimitExceeded::Entries { .. })
        ));
        let size_error = preflight_archive(&mut file, 50, 999).unwrap_err();
        assert!(matches!(
            size_error.downcast_ref::<LimitExceeded>(),
            Some(LimitExceeded::Entry { .. })
        ));
        assert_eq!(preflight_archive(&mut file, 50, 1000).unwrap(), 50);
    }

    #[test]
    fn preflight_bounds_zip64_counts() {
        let mut bytes = [0_u8; 76];
        bytes[..4].copy_from_slice(b"PK\x06\x06");
        bytes[4..12].copy_from_slice(&44_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&100_001_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&100_001_u64.to_le_bytes());
        bytes[56..60].copy_from_slice(b"PK\x06\x07");
        bytes[72..76].copy_from_slice(&1_u32.to_le_bytes());
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        file.write_all(&end_record(u16::MAX, u32::MAX)).unwrap();
        assert!(preflight_archive(&mut file, 100_000, 1024).is_err());
        assert_eq!(
            preflight_archive(&mut file, 100_001, 1024).unwrap(),
            100_001
        );
    }

    #[test]
    fn reopening_an_archive_does_not_charge_its_entries_twice() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.apk");
        let second = temp.path().join("second.apk");
        for path in [&first, &second] {
            let mut writer = zip::ZipWriter::new(File::create(path).unwrap());
            writer
                .start_file("lib/test.so", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"payload").unwrap();
            writer.finish().unwrap();
        }
        let mut budget = ArchiveBudget::new(1024, 4096, 1);
        assert_eq!(budget.open_archive(&first).unwrap().len(), 1);
        assert_eq!(budget.open_archive(&first).unwrap().len(), 1);
        assert!(budget.open_archive(&second).is_err());
    }

    #[test]
    fn parser_cannot_retry_an_unverified_older_end_record() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("misleading.apk");
        let mut writer = zip::ZipWriter::new(File::create(&path).unwrap());
        for name in ["one.so", "two.so"] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"payload").unwrap();
        }
        let mut file = writer.finish().unwrap();
        // An invalid last record advertises a small archive. Without guarding
        // fallback, the ZIP parser retries the older, larger directory.
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(&end_record(1, 46)).unwrap();
        drop(file);
        let mut budget = ArchiveBudget::new(1024, 4096, 1);
        assert!(budget.open_archive(&path).is_err());
    }

    #[test]
    fn directory_indexing_respects_the_remaining_shared_budget() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("app.apk");
        let mut writer = zip::ZipWriter::new(File::create(&path).unwrap());
        writer
            .start_file("lib/test.so", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"payload").unwrap();
        writer.finish().unwrap();
        let mut budget = ArchiveBudget::new(1024, 1024, 10);
        budget
            .copy_entry(
                &mut Cursor::new(vec![0; 1024]),
                &mut std::io::sink(),
                1024,
                "earlier",
            )
            .unwrap();
        assert!(budget.open_archive(&path).is_err());
    }

    #[test]
    fn manifest_probe_shares_the_extraction_budget() {
        let mut budget = ArchiveBudget::new(10, 6, 10);
        assert_eq!(
            budget
                .read_probe(&mut Cursor::new(b"abcdefghi"), 9, 4, "manifest")
                .unwrap(),
            b"abcd"
        );
        assert!(
            budget
                .copy_entry(&mut Cursor::new(b"xyz"), &mut Vec::new(), 3, "library")
                .is_err()
        );
        assert!(
            budget
                .read_probe(&mut Cursor::new(b"abc"), 3, 3, "next manifest")
                .is_err()
        );
    }

    #[test]
    fn preflight_rejects_truncated_records() {
        for bytes in [&b""[..], &b"PK\x05\x06"[..], &b"not an archive"[..]] {
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(bytes).unwrap();
            assert!(preflight_archive(&mut file, 100, 1024).is_err());
        }
    }
}
