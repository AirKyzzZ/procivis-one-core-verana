use shared_types::{HolderWalletInstanceId, KeyId, WalletInstanceAttestationId};

use super::error::DataLayerError;
use crate::model::wallet_instance_attestation::{
    UpdateWalletInstanceAttestationRequest, WalletInstanceAttestation,
    WalletInstanceAttestationRelations,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletInstanceAttestationRepository: Send + Sync + 'static {
    async fn create_wallet_instance_attestation(
        &self,
        wallet_unit_attestation: WalletInstanceAttestation,
    ) -> Result<WalletInstanceAttestationId, DataLayerError>;

    async fn get_wallet_instance_attestation_by_key_id(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<WalletInstanceAttestation>, DataLayerError>;

    async fn get_wallet_instance_attestations_by_holder_wallet_unit(
        &self,
        holder_wallet_unit_id: &HolderWalletInstanceId,
        relations: &WalletInstanceAttestationRelations,
    ) -> Result<Vec<WalletInstanceAttestation>, DataLayerError>;

    async fn update_wallet_attestation(
        &self,
        id: &WalletInstanceAttestationId,
        request: UpdateWalletInstanceAttestationRequest,
    ) -> Result<(), DataLayerError>;
}
