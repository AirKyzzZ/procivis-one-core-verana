use shared_types::HolderWalletInstanceId;

use crate::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, GetHolderWalletInstanceList, HolderWalletInstance,
    HolderWalletInstanceListQuery, HolderWalletInstanceRelations,
    UpdateHolderWalletInstanceRequest,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait HolderWalletInstanceRepository: Send + Sync {
    async fn create(
        &self,
        request: CreateHolderWalletInstanceRequest,
    ) -> Result<HolderWalletInstanceId, DataLayerError>;

    async fn get(
        &self,
        id: &HolderWalletInstanceId,
        relations: &HolderWalletInstanceRelations,
    ) -> Result<Option<HolderWalletInstance>, DataLayerError>;

    async fn update(
        &self,
        id: &HolderWalletInstanceId,
        request: UpdateHolderWalletInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn list(
        &self,
        query: HolderWalletInstanceListQuery,
    ) -> Result<GetHolderWalletInstanceList, DataLayerError>;

    async fn delete(&self, id: &HolderWalletInstanceId) -> Result<(), DataLayerError>;
}
