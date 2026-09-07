//! Cryptographic and compression primitives for the supported protection
//! formats.

pub mod android;
pub mod windows;

// Keep the historical flat paths available to downstream callers while the
// implementations themselves live under their platform boundary.
pub use windows::{BufferOperation, DecompressionFailure, Error, MAX_IMAGE_SIZE};
pub use windows::{bytecode, crc32, primitives};

/// Lowercase hexadecimal representation for digest and diagnostic bytes.
#[must_use]
pub fn hex_digest(data: &[u8]) -> String {
    let mut output = String::with_capacity(data.len() * 2);
    for byte in data {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
