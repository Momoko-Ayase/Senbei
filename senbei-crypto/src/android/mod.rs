//! Android container cryptography and decoding primitives.

mod protector;

pub use protector::{
    ContainerHeader, EncodedSegment, Error, HuffmanLzDecoder, Module9bConfig, ProtectedDescriptor,
    decode_container, gf32_mul_fixed, transform_segment,
};
