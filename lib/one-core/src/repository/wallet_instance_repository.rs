use shared_types::WalletInstanceId;

use super::error::DataLayerError;
use crate::model::wallet_instance::{
    GetWalletInstanceList, UpdateWalletInstanceRequest, WalletInstance, WalletInstanceListQuery,
    WalletInstanceRelations,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletInstanceRepository: Send + Sync {
    async fn create_wallet_instance(
        &self,
        request: WalletInstance,
    ) -> Result<WalletInstanceId, DataLayerError>;

    async fn get_wallet_instance(
        &self,
        id: &WalletInstanceId,
        relations: &WalletInstanceRelations,
    ) -> Result<Option<WalletInstance>, DataLayerError>;

    async fn get_wallet_instance_list(
        &self,
        query_params: WalletInstanceListQuery,
    ) -> Result<GetWalletInstanceList, DataLayerError>;

    async fn update_wallet_instance(
        &self,
        id: &WalletInstanceId,
        request: UpdateWalletInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete_wallet_instance(&self, id: &WalletInstanceId) -> Result<(), DataLayerError>;
}
