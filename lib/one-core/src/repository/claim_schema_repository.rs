use std::sync::Arc;

use shared_types::ClaimSchemaId;

use super::error::DataLayerError;
use crate::model::claim_schema::ClaimSchema;
use crate::model::relation::AsyncModelsLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ClaimSchemaRepository: Send + Sync {
    async fn get_claim_schema_list(
        &self,
        id: Vec<ClaimSchemaId>,
    ) -> Result<Vec<ClaimSchema>, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelsLoader<ClaimSchema> for Arc<dyn ClaimSchemaRepository> {
    async fn load(&self, ids: &[ClaimSchemaId]) -> Result<Vec<ClaimSchema>, DataLayerError> {
        self.get_claim_schema_list(ids.to_vec()).await
    }
}
