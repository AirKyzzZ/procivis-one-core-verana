pub mod blob_storage;
pub mod caching_loader;
pub mod credential_formatter;
pub mod data_type;
pub mod did_method;
mod disabled_provider;
pub mod issuance_protocol;
pub mod key_algorithm;
pub mod key_security_level;
pub mod key_storage;
pub mod presentation_formatter;
pub mod provider_directory;
pub mod remote_entity_storage;
pub mod revocation;
pub mod signer;
pub mod task;
pub mod trust_list_publisher;
pub mod trust_list_subscriber;
pub mod verification_protocol;
pub mod verifier;

/// Trait for provider implementations. Useful for core bootstrapping and decorating.
pub trait Provider {
    fn capabilities(&self) -> Option<serde_json::Value>;

    /// Whether the provider is enabled
    fn enabled(&self) -> bool {
        true
    }
}
