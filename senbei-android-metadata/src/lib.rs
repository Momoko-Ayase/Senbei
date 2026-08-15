//! Static IL2CPP metadata restoration interfaces.

mod method_tokens;

pub use method_tokens::{
    DEFAULT_METHOD_TOKEN_SEED, Error, ImageKeyDiscovery, Report, SeedDiscoveryReport,
    discover_method_token_seeds, restore_method_tokens,
};
