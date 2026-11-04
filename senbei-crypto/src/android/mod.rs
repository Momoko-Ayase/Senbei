//! Android container cryptography and decoding primitives.

mod protector;

pub use protector::{
    ContainerHeader, EncodedSegment, Error, HuffmanLzDecoder, Module9bConfig, OutputLimit,
    ProtectedDescriptor, decode_container, decode_container_with_limit, gf32_mul_fixed,
    transform_segment,
};
