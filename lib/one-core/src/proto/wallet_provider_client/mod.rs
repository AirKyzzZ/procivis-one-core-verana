pub mod dto;
pub mod error;
pub mod http_client;

use dto::{IssueWalletAttestationResponse, MetadataTarget};
use error::WalletProviderClientError;
use shared_types::WalletInstanceId;

use crate::service::wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, IssueWalletUnitAttestationRequestDTO,
    RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO, WalletProviderMetadataResponseDTO,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletProviderClient: Send + Sync {
    async fn get_wallet_provider_metadata(
        &self,
        target: MetadataTarget,
    ) -> Result<WalletProviderMetadataResponseDTO, WalletProviderClientError>;

    async fn register(
        &self,
        wallet_provider_url: &str,
        request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, WalletProviderClientError>;

    async fn activate(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletInstanceId,
        request: ActivateWalletUnitRequestDTO,
    ) -> Result<(), WalletProviderClientError>;

    async fn issue_attestation(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletInstanceId,
        bearer_token: &str,
        request: IssueWalletUnitAttestationRequestDTO,
    ) -> Result<IssueWalletAttestationResponse, WalletProviderClientError>;
}
