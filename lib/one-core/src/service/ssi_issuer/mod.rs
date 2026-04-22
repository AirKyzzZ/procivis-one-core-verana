use std::sync::Arc;

use crate::config::core_config;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::identifier_repository::IdentifierRepository;

pub mod dto;
pub mod error;
mod mapper;
pub mod service;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIIssuerService {
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    config: Arc<core_config::CoreConfig>,
    core_base_url: Option<String>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        config: Arc<core_config::CoreConfig>,
        core_base_url: Option<String>,
    ) -> Self {
        Self {
            credential_schema_repository,
            identifier_repository,
            issuance_protocol_provider,
            key_algorithm_provider,
            config,
            core_base_url,
        }
    }
}
