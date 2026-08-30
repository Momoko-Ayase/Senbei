pub use senbei_crypto::{BufferOperation, DecompressionFailure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompressionStage {
    ExeStage3,
    ExeStage3Secondary,
    ExeStage4,
    ExeStage5,
    Pe32FourthStage,
    Pe32FifthStage,
    Pe32SeventhStage,
    DllCodeBlock1,
    DllCodeBlock2,
    DllCodeBlock3,
    DllCodeBlock4,
}

impl std::fmt::Display for DecompressionStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExeStage3 => "EXE stage3",
            Self::ExeStage3Secondary => "EXE secondary stage3",
            Self::ExeStage4 => "EXE stage4",
            Self::ExeStage5 => "EXE stage5",
            Self::Pe32FourthStage => "PE32 fourth stage",
            Self::Pe32FifthStage => "PE32 fifth stage",
            Self::Pe32SeventhStage => "PE32 seventh stage",
            Self::DllCodeBlock1 => "DLL code block 1",
            Self::DllCodeBlock2 => "DLL code block 2",
            Self::DllCodeBlock3 => "DLL code block 3",
            Self::DllCodeBlock4 => "DLL code block 4",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytecodeStage {
    ExeStage4,
    ExeStage5,
    Pe32CustomDecryptor,
    Pe32FileDecryptor,
    DllPrimaryDecryptor,
    DllSectionDecryptor,
}

impl std::fmt::Display for BytecodeStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExeStage4 => "EXE stage4",
            Self::ExeStage5 => "EXE stage5",
            Self::Pe32CustomDecryptor => "PE32 custom decryptor",
            Self::Pe32FileDecryptor => "PE32 file decryptor",
            Self::DllPrimaryDecryptor => "DLL primary decryptor",
            Self::DllSectionDecryptor => "DLL section decryptor",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionPipeline {
    ExePe32Plus,
    ExePe32,
    Dll,
}

impl std::fmt::Display for SectionPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ExePe32Plus => "PE32+ EXE",
            Self::ExePe32 => "PE32 EXE",
            Self::Dll => "DLL",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorTable {
    DllSectionBlocks,
    DllZeroFill,
}

impl std::fmt::Display for DescriptorTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DllSectionBlocks => "DLL section-block",
            Self::DllZeroFill => "DLL zero-fill",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UnpackError {
    #[error("input too short (need at least {required} bytes, got {actual})")]
    InputTooShort { actual: usize, required: usize },

    #[error("decrypted header magic mismatch (got 0x{found:08X})")]
    HeaderMagicMismatch { found: u32 },

    #[error("anchor field not found — corrupt data or wrong offset")]
    AnchorNotFound,

    #[error("stage1 descriptor not found near anchor 0x{anchor:08X}")]
    Stage1DescriptorNotFound { anchor: u32 },

    #[error("stage2 field not found — corrupt data or wrong offset")]
    Stage2NotFound,

    #[error("chk_src_start not found — corrupt data or wrong offset")]
    ChkSrcStartNotFound,

    #[error("table_start not found — corrupt data or wrong offset")]
    TableStartNotFound,

    #[error("{0} bytecode generation failed — corrupt data or wrong offset")]
    BytecodeGenerationFailed(BytecodeStage),

    #[error("stage5 marker not found — this build's layout is not supported by this unpacker")]
    Stage5MarkerNotFound,

    #[error("not a Crackproof-protected file")]
    NotCrackproof,

    #[error("invalid PE header offset {offset} for {input_len}-byte input")]
    InvalidPeOffset { offset: i64, input_len: usize },

    #[error("DLL pipeline requires PE32+ optional-header magic, got 0x{found:04X}")]
    UnsupportedDllPeMagic { found: u16 },

    #[error(
        "DLL primary descriptor address 0x{address:08X} is below layout base 0x{minimum:08X} or outside {image_len}-byte image"
    )]
    InvalidDllPrimaryDescriptor {
        address: u32,
        minimum: u32,
        image_len: usize,
    },

    #[error("invalid SizeOfImage {size}; expected 1..={max}")]
    InvalidImageSize { size: i64, max: u64 },

    #[error(
        "{operation} range out of bounds (offset {offset}, size {size}, buffer length {buffer_len})"
    )]
    BufferRangeOutOfBounds {
        operation: BufferOperation,
        offset: usize,
        size: usize,
        buffer_len: usize,
    },

    #[error(
        "EXE checksum descriptor at 0x{descriptor:08X} points outside input (offset {offset}, size {size}, input length {image_len})"
    )]
    ExeChecksumRangeOutOfBounds {
        descriptor: u32,
        offset: usize,
        size: usize,
        image_len: usize,
    },

    #[error(
        "{table} descriptor out of bounds (offset {offset}, size 16, image length {image_len})"
    )]
    DescriptorOutOfBounds {
        table: DescriptorTable,
        offset: usize,
        image_len: usize,
    },

    #[error("PE32 tbl not found — corrupt data or wrong offset")]
    Pe32TblNotFound,

    #[error("PE32 thirdStage decrypt failed — corrupt data or wrong offset")]
    Pe32ThirdStageFailed,

    #[error("PE32 customDecryptor not found in sevenStage")]
    Pe32CustomDecryptorNotFound,

    #[error("PE32 eighthStageKey not found")]
    Pe32EighthKeyNotFound,

    #[error("PE32 file LFSR not found in eighthStage")]
    Pe32FileLfsrNotFound,

    #[error("{stage} decompression failed: {reason}")]
    StageDecompressionFailed {
        stage: DecompressionStage,
        reason: DecompressionFailure,
    },

    #[error("{pipeline} section block {block} decompression failed")]
    SectionDecompressionFailed {
        pipeline: SectionPipeline,
        block: usize,
    },

    #[error("AES key schedule is outside the image at offset {offset}")]
    InvalidAesKeySchedule { offset: u32 },

    #[error("Huffman table is outside the image at offset {offset}")]
    InvalidHuffmanTable { offset: u32 },

    #[error("DLL pipeline failed: {dll}; EXE fallback failed: {exe}")]
    PipelineFallbackFailed {
        dll: Box<UnpackError>,
        exe: Box<UnpackError>,
    },

    #[error(
        "PE32 second-stage range is invalid (offset {offset}, size {size}, image length {image_len})"
    )]
    Pe32SecondStageRangeInvalid {
        offset: u32,
        size: u32,
        image_len: usize,
    },

    #[error("PE32 relocation-data descriptor not found")]
    Pe32RelocationDataNotFound,

    #[error("file decryptor candidate failed structural validation")]
    FileDecryptorValidationFailed,

    #[error("PE32 memory image could not be rebuilt as a file-layout PE")]
    Pe32OutputLayoutInvalid,

    #[error("internal panic at {file}:{line}:{column}: {message}")]
    InternalPanic {
        message: String,
        file: String,
        line: u32,
        column: u32,
    },
}

impl From<senbei_crypto::Error> for UnpackError {
    fn from(error: senbei_crypto::Error) -> Self {
        match error {
            senbei_crypto::Error::BufferRangeOutOfBounds {
                operation,
                offset,
                size,
                buffer_len,
            } => Self::BufferRangeOutOfBounds {
                operation,
                offset,
                size,
                buffer_len,
            },
        }
    }
}
