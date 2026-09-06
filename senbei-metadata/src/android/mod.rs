//! Static IL2CPP metadata restoration interfaces.

mod embedded;
mod keystream;
mod method_tokens;

pub use embedded::{embedded_metadata_size, extract_embedded_metadata};
pub use method_tokens::{
    DEFAULT_METHOD_TOKEN_SEED, Error, ImageKeyDiscovery, Report, SeedDiscoveryReport,
    discover_method_token_seeds, restore_method_tokens,
};
