use shared_types::{WalletInstanceAttestedKeyId, WalletInstanceId};

use crate::model::wallet_instance_attested_key::{
    WalletInstanceAttestedKey, WalletInstanceAttestedKeyRelations,
    WalletInstanceAttestedKeyUpsertRequest,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletInstanceAttestedKeyRepository: Send + Sync {
    async fn create_attested_key(
        &self,
        request: WalletInstanceAttestedKey,
    ) -> Result<WalletInstanceAttestedKeyId, DataLayerError>;

    async fn update_attested_key(
        &self,
        request: WalletInstanceAttestedKey,
    ) -> Result<(), DataLayerError>;

    async fn upsert_attested_key(
        &self,
        request: WalletInstanceAttestedKeyUpsertRequest,
    ) -> Result<WalletInstanceAttestedKeyId, DataLayerError>;

    async fn get_attested_key(
        &self,
        id: &WalletInstanceAttestedKeyId,
        relations: &WalletInstanceAttestedKeyRelations,
    ) -> Result<Option<WalletInstanceAttestedKey>, DataLayerError>;

    async fn get_by_wallet_instance_id(
        &self,
        id: &WalletInstanceId,
        relations: &WalletInstanceAttestedKeyRelations,
    ) -> Result<Vec<WalletInstanceAttestedKey>, DataLayerError>;
}
