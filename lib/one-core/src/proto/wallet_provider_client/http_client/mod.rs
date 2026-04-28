use std::sync::Arc;

use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::wallet_provider_metadata::WalletProviderMetadataCache;

pub(crate) mod dto;
pub mod provider;

pub struct HTTPWalletProviderClient {
    http_client: Arc<dyn HttpClient>,
    cache: Arc<dyn WalletProviderMetadataCache>,
}

impl HTTPWalletProviderClient {
    pub fn new(
        http_client: Arc<dyn HttpClient>,
        cache: Arc<dyn WalletProviderMetadataCache>,
    ) -> Self {
        Self { http_client, cache }
    }
}
