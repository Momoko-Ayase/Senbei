//! Cryptographic and container primitives used by Senbei Android.

mod protector;

pub use protector::{
    ContainerHeader, EncodedSegment, Error, HuffmanLzDecoder, Module9bConfig, ProtectedDescriptor,
    decode_container, gf32_mul_fixed, transform_segment,
};
