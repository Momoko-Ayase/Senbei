//! Bounded structural diagnostics for the CLR (COR20) metadata of a managed PE.
//!
//! A managed assembly reaches the CLR, not the native loader, so the loader
//! checks in the parent module do not describe it. The CLR first reads the
//! COR20 header, then the BSJB root, then the stream headers, and only then
//! the `#~` table stream. Each of those steps has a size or alignment the file
//! itself must satisfy; a stream whose header claims a range past the metadata
//! blob is rejected with `BadImageFormatException` before any IL runs.
//!
//! These are *structure* checks, not a guarantee that the assembly will load:
//! the metadata is not semantically validated (no table-column walk, no heap
//! contents, no signature decoding). They only detect regions the CLR could
//! not even enumerate — the signature of a `.text` pass that scribbled over
//! metadata the protector had copied through verbatim.
//!
//! All reads are bounds-checked and every loop is capped.

use super::rd_u32;
use crate::findings::Findings;

/// BSJB root: 4-byte signature, u16 major/minor, u32 reserved, u32 version
/// length, then the NUL-padded version string.
const BSJB_FIXED: u32 = 16;
/// A stream header is an offset, a size, and a NUL-terminated name that the
/// ECMA-335 layout pads to a 4-byte boundary.
const STREAM_HEADER_MIN: u32 = 8;
/// Real assemblies carry five streams (`#~`, `#Strings`, `#US`, `#GUID`,
/// `#Blob`, plus `#-` in unoptimized builds). The cap only stops a corrupt
/// stream count from walking past the metadata blob.
const MAX_STREAMS: u32 = 64;
const MAX_STREAM_NAME: u32 = 32;
/// `#~` fixed header: reserved u32, major u8, minor u8, heap sizes u8,
/// reserved u8, valid u64, sorted u64 — then one u32 row count per set bit.
const TABLES_HEADER: u32 = 24;
const TABLES_HEADER_SIZE: u32 = 24;
/// The widest table index in ECMA-335 II.22 is `#~` bit 44 (GenericParamConstraint).
const MAX_TABLE_BIT: u32 = 44;
/// Heap-size flag bits in the `#~` header.
const HEAP_STRING: u8 = 0x01;
const HEAP_GUID: u8 = 0x02;
const HEAP_BLOB: u8 = 0x04;

/// The metadata blob `[start, start+len)` inside the output file.
pub(super) struct Metadata<'a> {
    pub(super) data: &'a [u8],
    pub(super) start: usize,
    pub(super) len: usize,
}

impl Metadata<'_> {
    fn bytes(&self) -> &[u8] {
        self.data
            .get(self.start..self.start.saturating_add(self.len))
            .unwrap_or(&[])
    }

    fn u32(&self, offset: u32) -> Option<u32> {
        let local = self.data.get(self.start.checked_add(offset as usize)?..)?;
        rd_u32(local, 0)
    }

    fn u64(&self, offset: u32) -> Option<u64> {
        let bytes = self
            .bytes()
            .get(offset as usize..(offset as usize).checked_add(8)?)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    fn slice(&self, offset: u32, len: u32) -> Option<&[u8]> {
        let start = offset as usize;
        let end = start.checked_add(len as usize)?;
        if end > self.len {
            return None;
        }
        self.bytes().get(start..end)
    }
}

/// One declared metadata stream.
struct Stream<'a> {
    name: &'a [u8],
    offset: u32,
    size: u32,
}

/// Walk the BSJB header and every stream header, appending structural defects.
///
/// `out` receives one message per defect; an empty `out` means the CLR would
/// be able to enumerate every stream.
pub(super) fn collect(metadata: &Metadata<'_>, out: &mut Findings<'_>) {
    if metadata.slice(0, 4) != Some(b"BSJB") {
        // The parent module reports a missing signature as fatal; nothing
        // below can be parsed meaningfully.
        return;
    }
    let version_length = match metadata.u32(12) {
        Some(value) => value,
        None => {
            out.push("CLR metadata BSJB header is truncated".to_owned());
            return;
        }
    };
    // The version string is NUL-padded to a 4-byte boundary, followed by the
    // flags and stream-count words.
    let strings_at = BSJB_FIXED
        .checked_add(version_length)
        .and_then(|value| Some(value.checked_add(3)? & !3));
    let Some(flags_at) = strings_at else {
        out.push("CLR metadata version length overflows".to_owned());
        return;
    };
    // flags (u16) + stream count (u16) immediately follow the version string.
    let Some(trailer) = metadata.slice(flags_at, 4) else {
        out.push("CLR metadata version string runs past the metadata blob".to_owned());
        return;
    };
    let stream_count = u16::from_le_bytes([trailer[2], trailer[3]]);
    let Some(mut cursor) = flags_at.checked_add(4) else {
        out.push("CLR metadata stream table offset overflows".to_owned());
        return;
    };
    if u32::from(stream_count) > MAX_STREAMS {
        out.push(format!(
            "CLR metadata declares {stream_count} streams (more than {MAX_STREAMS})"
        ));
        return;
    }
    let mut streams: Vec<Stream<'_>> = Vec::with_capacity(stream_count as usize);
    for index in 0..u32::from(stream_count) {
        let Some(header) = metadata.slice(cursor, STREAM_HEADER_MIN) else {
            out.push(format!(
                "CLR metadata stream header {index} runs past the metadata blob"
            ));
            return;
        };
        let offset = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let name_at = cursor.saturating_add(STREAM_HEADER_MIN);
        let Some(name_len) = metadata
            .slice(name_at, 1)
            .and_then(|_| find_nul(metadata, name_at, MAX_STREAM_NAME))
        else {
            out.push(format!(
                "CLR metadata stream {index} name is unterminated within {MAX_STREAM_NAME} bytes"
            ));
            return;
        };
        let name = metadata.slice(name_at, name_len).unwrap_or_default();
        if name.is_empty() || !name.iter().all(|&byte| (0x20..0x7F).contains(&byte)) {
            out.push(format!(
                "CLR metadata stream {index} name is empty or not printable ASCII"
            ));
        }
        // Stream headers are 4-byte aligned; the name plus its NUL terminator
        // is padded out to the next boundary.
        let padded = name_len
            .checked_add(1)
            .and_then(|value| Some(value.checked_add(3)? & !3))
            .unwrap_or(name_len);
        cursor = name_at.saturating_add(padded);
        // The CLR rejects a stream whose declared range leaves the blob.
        let end = offset.checked_add(size);
        if end.is_none_or(|end| u64::from(end) > metadata.len as u64) {
            out.push(format!(
                "CLR metadata stream {} [0x{offset:X}..0x{:X}] extends past the metadata blob (0x{:X} bytes)",
                escape(name),
                offset.saturating_add(size),
                metadata.len
            ));
        }
        streams.push(Stream { name, offset, size });
    }

    // The CLR requires a tables stream and the heaps that stream's header
    // flags claim to reference.
    let tables = streams.iter().find(|stream| stream.name == b"#~");
    let unoptimized = streams.iter().find(|stream| stream.name == b"#-");
    let Some(tables) = tables.or(unoptimized) else {
        out.push("CLR metadata has neither a '#~' nor a '#-' tables stream".to_owned());
        return;
    };
    let heap = |name: &[u8]| streams.iter().any(|stream| stream.name == name);
    if !heap(b"#Strings") {
        out.push("CLR metadata has no '#Strings' heap".to_owned());
    }
    if !heap(b"#GUID") {
        out.push("CLR metadata has no '#GUID' heap".to_owned());
    }
    if !heap(b"#Blob") {
        out.push("CLR metadata has no '#Blob' heap".to_owned());
    }
    collect_tables(metadata, tables, out);
}

fn find_nul(metadata: &Metadata<'_>, offset: u32, limit: u32) -> Option<u32> {
    // The window is clamped to the blob: a name near the end must not be
    // reported as unterminated just because fewer than `limit` bytes remain.
    let start = offset as usize;
    let available = metadata.len.checked_sub(start)?;
    let window = metadata.slice(offset, u32::try_from(available.min(limit as usize)).ok()?)?;
    window
        .iter()
        .position(|&byte| byte == 0)
        .and_then(|index| u32::try_from(index).ok())
}

fn escape(name: &[u8]) -> String {
    name.iter()
        .map(|&byte| {
            if (0x20..0x7F).contains(&byte) {
                char::from(byte)
            } else {
                '.'
            }
        })
        .collect()
}

/// Validate the `#~` (or `#-`) tables stream header and its row-count array.
///
/// The columns themselves are not decoded: doing so would require the full
/// ECMA-335 schema and buys little, because a corrupted schema almost always
/// breaks one of the framing invariants below first.
fn collect_tables(metadata: &Metadata<'_>, tables: &Stream<'_>, out: &mut Findings<'_>) {
    let label = escape(tables.name);
    let Some(header) = metadata.slice(tables.offset, TABLES_HEADER) else {
        out.push(format!(
            "CLR '{label}' stream is shorter than its {TABLES_HEADER}-byte header"
        ));
        return;
    };
    if header[0..4] != [0, 0, 0, 0] {
        out.push(format!("CLR '{label}' header reserved field is not zero"));
    }
    let major = header[4];
    if major != 2 {
        out.push(format!(
            "CLR '{label}' table schema major version is {major} (expected 2)"
        ));
    }
    // The heap-size byte selects 2-byte vs 4-byte heap indices. Bit 0x40 is
    // reserved for an extra-data stream that the shipped runtimes do not use,
    // so only the three defined heap bits are checked here. The trailing
    // reserved byte is deliberately not checked: real optimized assemblies in
    // the wild carry values other than the ECMA-335 default of 1.
    let heap_sizes = header[6];
    if heap_sizes & !(HEAP_STRING | HEAP_GUID | HEAP_BLOB) != 0 {
        out.push(format!(
            "CLR '{label}' header heap-size flags 0x{heap_sizes:02X} set undefined bits"
        ));
    }
    let Some(valid) = metadata.u64(tables.offset.saturating_add(8)) else {
        out.push(format!("CLR '{label}' header valid mask is truncated"));
        return;
    };
    // Sorted is a *hint*: writers are free to set it for tables they did not
    // declare (and real assemblies do), so it is not checked against `valid`.
    if valid == 0 {
        out.push(format!("CLR '{label}' header declares no tables"));
    }
    let undefined = valid >> (MAX_TABLE_BIT + 1);
    if undefined != 0 {
        out.push(format!(
            "CLR '{label}' valid mask sets undefined table bits (0x{undefined:X})"
        ));
    }
    // One row count per set bit, in ascending table-bit order. A table may
    // legitimately be present with zero rows, so the counts themselves are not
    // inspected — only whether the stream is long enough to hold them.
    let row_tables = valid.count_ones();
    let rows_bytes = row_tables.saturating_mul(4);
    if metadata
        .slice(tables.offset.saturating_add(TABLES_HEADER_SIZE), rows_bytes)
        .is_none()
    {
        out.push(format!(
            "CLR '{label}' row-count array ({row_tables} tables) runs past the metadata blob"
        ));
    }
    // The tables stream itself must hold its header and row counts.
    if tables.size < TABLES_HEADER_SIZE.saturating_add(rows_bytes) {
        out.push(format!(
            "CLR '{label}' stream size 0x{:X} cannot hold {row_tables} row count(s)",
            tables.size
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Padded size of a NUL-terminated name, per the CLR's 4-byte alignment.
    fn padded_name(name: &[u8]) -> usize {
        (name.len() + 1 + 3) & !3
    }

    /// Header size of a BSJB blob carrying `streams` and this version string.
    fn header_size(version: &str, streams: &[&[u8]]) -> usize {
        16 + padded_name(version.as_bytes())
            + 4
            + streams
                .iter()
                .map(|name| 8 + padded_name(name))
                .sum::<usize>()
    }

    /// Build a BSJB blob. Stream bodies are appended by the caller at the
    /// offsets returned by [`header_size`]; `bodies` places them here so the
    /// stream table can name real ranges.
    fn bsjb(version: &str, bodies: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        let names: Vec<&[u8]> = bodies.iter().map(|(name, _)| *name).collect();
        let mut header = header_size(version, &names);
        let mut offsets = Vec::with_capacity(bodies.len());
        for (_, body) in bodies {
            offsets.push(header);
            header += body.len();
        }
        let mut blob = Vec::new();
        blob.extend_from_slice(b"BSJB");
        blob.extend_from_slice(&1_u16.to_le_bytes()); // major
        blob.extend_from_slice(&1_u16.to_le_bytes()); // minor
        blob.extend_from_slice(&0_u32.to_le_bytes()); // reserved
        let version_bytes = version.as_bytes();
        let padded = padded_name(version_bytes);
        blob.extend_from_slice(&(padded as u32).to_le_bytes());
        blob.extend_from_slice(version_bytes);
        blob.resize(blob.len() + (padded - version_bytes.len()), 0);
        blob.extend_from_slice(&0_u16.to_le_bytes()); // flags
        blob.extend_from_slice(&(bodies.len() as u16).to_le_bytes());
        for ((name, body), offset) in bodies.iter().zip(&offsets) {
            blob.extend_from_slice(&(*offset as u32).to_le_bytes());
            blob.extend_from_slice(&(body.len() as u32).to_le_bytes());
            let start = blob.len();
            blob.extend_from_slice(name);
            blob.push(0);
            blob.resize(start + padded_name(name), 0);
        }
        for (_, body) in bodies {
            blob.extend_from_slice(body);
        }
        blob
    }

    /// A `#~` stream body: reserved, major/minor/heaps/reserved, valid,
    /// sorted, then one row count per set bit.
    fn tables_body(valid: u64, rows: &[u32]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0, 2, 0, 0x05, 1];
        body.extend_from_slice(&valid.to_le_bytes());
        body.extend_from_slice(&0_u64.to_le_bytes());
        for row in rows {
            body.extend_from_slice(&row.to_le_bytes());
        }
        body
    }

    /// A minimal well-formed blob: the four streams the CLR requires, with a
    /// `#~` header describing one table with one row.
    fn well_formed() -> Vec<u8> {
        bsjb(
            "v4.0.30319",
            &[
                (b"#~", tables_body(1 << 0, &[1])),
                (b"#Strings", vec![0; 4]),
                (b"#GUID", vec![0; 16]),
                (b"#Blob", vec![0; 4]),
            ],
        )
    }

    #[test]
    fn well_formed_metadata_produces_no_findings() {
        let blob = well_formed();
        let metadata = Metadata {
            data: &blob,
            start: 0,
            len: blob.len(),
        };
        let mut out = Vec::new();
        collect(&metadata, &mut Findings::new(&mut out));
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn stream_whose_declared_range_leaves_the_blob_is_reported() {
        let mut blob = bsjb("v4.0.30319", &[(b"#~", tables_body(1 << 0, &[1]))]);
        // Rewrite the first stream header's offset to a range past the blob.
        let first_header = 16 + padded_name(b"v4.0.30319") + 4;
        blob[first_header..first_header + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        let metadata = Metadata {
            data: &blob,
            start: 0,
            len: blob.len(),
        };
        let mut out = Vec::new();
        collect(&metadata, &mut Findings::new(&mut out));
        assert!(
            out.iter()
                .any(|message| message.contains("extends past the metadata blob")),
            "{out:?}"
        );
    }

    #[test]
    fn missing_tables_stream_is_reported() {
        let blob = bsjb("v4.0.30319", &[(b"#Strings", vec![0; 4])]);
        let metadata = Metadata {
            data: &blob,
            start: 0,
            len: blob.len(),
        };
        let mut out = Vec::new();
        collect(&metadata, &mut Findings::new(&mut out));
        assert!(
            out.iter().any(|message| message.contains("tables stream")),
            "{out:?}"
        );
    }

    #[test]
    fn missing_heap_stream_is_reported() {
        let blob = bsjb(
            "v4.0.30319",
            &[
                (b"#~", tables_body(1 << 0, &[1])),
                (b"#Strings", vec![0; 4]),
            ],
        );
        let metadata = Metadata {
            data: &blob,
            start: 0,
            len: blob.len(),
        };
        let mut out = Vec::new();
        collect(&metadata, &mut Findings::new(&mut out));
        assert!(
            out.iter().any(|message| message.contains("'#GUID' heap")),
            "{out:?}"
        );
    }

    #[test]
    fn row_count_array_past_the_stream_is_reported() {
        // 18 present tables need 72 row-count bytes; the body declares four.
        let mut body = tables_body((1 << 18) - 1, &[1]);
        body.truncate(0x2C);
        let blob = bsjb("v4.0.30319", &[(b"#~", body)]);
        let metadata = Metadata {
            data: &blob,
            start: 0,
            len: blob.len(),
        };
        let mut out = Vec::new();
        collect(&metadata, &mut Findings::new(&mut out));
        assert!(
            out.iter()
                .any(|message| message.contains("row-count array")),
            "{out:?}"
        );
    }

    #[test]
    fn empty_metadata_is_reported_not_panicking() {
        let empty: [u8; 0] = [];
        let metadata = Metadata {
            data: &empty,
            start: 0,
            len: 0,
        };
        let mut out = Vec::new();
        collect(&metadata, &mut Findings::new(&mut out));
        assert!(
            out.is_empty(),
            "a missing BSJB signature is the parent module's finding, not this module's"
        );
    }
}
