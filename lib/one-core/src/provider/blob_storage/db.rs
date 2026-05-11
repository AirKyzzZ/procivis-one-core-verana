use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use shared_types::BlobId;

use super::BlobStorage;
use super::error::BlobStorageError;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::blob::{Blob, UpdateBlobRequest};
use crate::repository::blob_repository::BlobRepository;

#[derive(Provider)]
#[provider(skip_capabilities)]
pub struct RepositoryBlobStorage {
    pub blob_repository: Arc<dyn BlobRepository>,
}

#[async_trait]
impl BlobStorage for RepositoryBlobStorage {
    async fn create(&self, blob: Blob) -> Result<(), BlobStorageError> {
        Ok(self
            .blob_repository
            .create(blob)
            .await
            .error_while("creating blob")?)
    }

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, BlobStorageError> {
        Ok(self
            .blob_repository
            .get(id)
            .await
            .error_while("getting blob")?)
    }

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), BlobStorageError> {
        Ok(self
            .blob_repository
            .update(id, update)
            .await
            .error_while("updating blob")?)
    }

    async fn delete(&self, id: &BlobId) -> Result<(), BlobStorageError> {
        Ok(self
            .blob_repository
            .delete(id)
            .await
            .error_while("deleting blob")?)
    }

    async fn delete_many(&self, ids: &[BlobId]) -> Result<(), BlobStorageError> {
        Ok(self
            .blob_repository
            .delete_many(ids)
            .await
            .error_while("deleting blobs")?)
    }

    fn config_type(&self) -> BlobStorageType {
        BlobStorageType::Db
    }
}
