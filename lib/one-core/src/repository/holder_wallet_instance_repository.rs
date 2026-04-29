use shared_types::{HolderWalletInstanceId, OrganisationId};

use crate::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, GetHolderWalletInstanceList, HolderWalletInstance,
    HolderWalletInstanceListQuery, HolderWalletInstanceRelations,
    UpdateHolderWalletInstanceRequest,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait HolderWalletInstanceRepository: Send + Sync {
    async fn create_holder_wallet_instance(
        &self,
        request: CreateHolderWalletInstanceRequest,
    ) -> Result<HolderWalletInstanceId, DataLayerError>;

    async fn get_holder_wallet_instance(
        &self,
        id: &HolderWalletInstanceId,
        relations: &HolderWalletInstanceRelations,
    ) -> Result<Option<HolderWalletInstance>, DataLayerError>;

    async fn get_holder_wallet_instance_by_org_id(
        &self,
        organisation_id: &OrganisationId,
    ) -> Result<Option<HolderWalletInstance>, DataLayerError>;

    async fn update_holder_wallet_instance(
        &self,
        id: &HolderWalletInstanceId,
        request: UpdateHolderWalletInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn list_holder_wallet_instance(
        &self,
        query: HolderWalletInstanceListQuery,
    ) -> Result<GetHolderWalletInstanceList, DataLayerError>;
}
