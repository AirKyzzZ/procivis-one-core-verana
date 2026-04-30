use shared_types::VerifierInstanceId;

use crate::model::verifier_instance::{
    GetVerifierInstanceList, UpdateVerifierInstanceRequest, VerifierInstance,
    VerifierInstanceListQuery,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait VerifierInstanceRepository: Send + Sync {
    async fn create(&self, request: VerifierInstance)
    -> Result<VerifierInstanceId, DataLayerError>;

    async fn update(
        &self,
        id: &VerifierInstanceId,
        request: UpdateVerifierInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn get(
        &self,
        id: &VerifierInstanceId,
    ) -> Result<Option<VerifierInstance>, DataLayerError>;

    async fn list(
        &self,
        query: VerifierInstanceListQuery,
    ) -> Result<GetVerifierInstanceList, DataLayerError>;
}
