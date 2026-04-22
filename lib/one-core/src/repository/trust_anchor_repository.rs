use std::sync::Arc;

use shared_types::TrustAnchorId;

use super::error::DataLayerError;
use crate::model::relation::AsyncModelLoader;
use crate::model::trust_anchor::TrustAnchor;
use crate::service::trust_anchor::dto::{GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustAnchorRepository: Send + Sync {
    async fn create(&self, anchor: TrustAnchor) -> Result<TrustAnchorId, DataLayerError>;

    async fn get(&self, id: TrustAnchorId) -> Result<Option<TrustAnchor>, DataLayerError>;

    async fn list(
        &self,
        filters: ListTrustAnchorsQueryDTO,
    ) -> Result<GetTrustAnchorsResponseDTO, DataLayerError>;
    async fn delete(&self, id: TrustAnchorId) -> Result<(), DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<TrustAnchor> for Arc<dyn TrustAnchorRepository> {
    async fn load(&self, id: &TrustAnchorId) -> Result<TrustAnchor, DataLayerError> {
        self.get(*id)
            .await?
            .ok_or_else(|| DataLayerError::MissingRequiredRelation {
                relation: "trust-anchor",
                id: id.to_string(),
            })
    }
}
