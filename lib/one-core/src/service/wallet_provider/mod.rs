use std::sync::Arc;

use crate::config::core_config;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::document_signer::provider::DocumentSignerProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::wallet_instance_repository::WalletInstanceRepository;

pub mod dto;
pub mod error;
pub mod service;
mod validator;

mod app_integrity;
mod mapper;
#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct WalletProviderService {
    organisation_repository: Arc<dyn OrganisationRepository>,
    wallet_instance_repository: Arc<dyn WalletInstanceRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    tx_manager: Arc<dyn TransactionManager>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    http_client: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    session_provider: Arc<dyn SessionProvider>,
    document_signer_provider: Arc<dyn DocumentSignerProvider>,
    base_url: Option<String>,
    config: Arc<core_config::CoreConfig>,
}

impl WalletProviderService {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository>,
        wallet_instance_repository: Arc<dyn WalletInstanceRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        tx_manager: Arc<dyn TransactionManager>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        http_client: Arc<dyn HttpClient>,
        clock: Arc<dyn Clock>,
        session_provider: Arc<dyn SessionProvider>,
        document_signer_provider: Arc<dyn DocumentSignerProvider>,
        config: Arc<core_config::CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            organisation_repository,
            wallet_instance_repository,
            identifier_repository,
            history_repository,
            trust_collection_repository,
            tx_manager,
            key_provider,
            key_algorithm_provider,
            revocation_method_provider,
            certificate_validator,
            http_client,
            config,
            base_url,
            clock,
            session_provider,
            document_signer_provider,
        }
    }
}
