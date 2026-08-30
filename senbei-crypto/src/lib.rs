//! Cryptographic, checksum, compression, and bytecode primitives.

pub mod bytecode;
pub mod crc32;
pub mod primitives;
mod tables;

/// Maximum buffer size accepted by allocation-sensitive transforms.
pub const MAX_IMAGE_SIZE: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferOperation {
    Read,
    CopySource,
    CopyDestination,
    ZeroFill,
}

impl std::fmt::Display for BufferOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::CopySource => "copy source",
            Self::CopyDestination => "copy destination",
            Self::ZeroFill => "zero-fill",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error(
        "{operation} range out of bounds (offset {offset}, size {size}, buffer length {buffer_len})"
    )]
    BufferRangeOutOfBounds {
        operation: BufferOperation,
        offset: usize,
        size: usize,
        buffer_len: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecompressionFailure {
    #[error("compressed source size {size} exceeds limit {max}")]
    SourceTooLarge { size: u32, max: u64 },
    #[error("Huffman code length {bits} is invalid")]
    InvalidCodeLength { bits: u8 },
    #[error("Huffman tree traversal exceeded 64 levels")]
    HuffmanTraversalLimit,
    #[error("pending length accumulator overflowed at {pending}")]
    PendingLengthOverflow { pending: u32 },
    #[error("output step {step} at byte {written} exceeds expected size {expected}")]
    OutputOverflow {
        written: u32,
        step: u32,
        expected: u32,
    },
    #[error("run-fill width {width} reads before output offset 0x{destination:08X}")]
    RunFillBeforeOutput { width: u32, destination: u32 },
    #[error("run-fill width {width} is unsupported")]
    InvalidRunFillWidth { width: u32 },
    #[error("back-reference distance {distance} exceeds {written} written bytes")]
    InvalidBackReference { distance: u32, written: u32 },
    #[error("Huffman symbol consumed no input and produced no output")]
    NoProgress,
    #[error(
        "output size mismatch (wrote {written}/{expected} bytes after consuming {consumed}/{source_size})"
    )]
    OutputSizeMismatch {
        written: u32,
        expected: u32,
        consumed: u32,
        source_size: u32,
    },
}
