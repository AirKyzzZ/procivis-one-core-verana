use std::fmt::Display;
use std::sync::Arc;

use shared_types::BlobId;

use super::BlobStorage;
use super::error::BlobStorageError;
use crate::config::core_config::BlobStorageType;
use crate::model::blob::{Blob, UpdateBlobRequest};
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn BlobStorage {
    fn decorate(self: Arc<dyn BlobStorage>) -> Arc<dyn BlobStorage> {
        Arc::new(DisabledProvider::new(self))
    }
}

/// Functionality of disabled blob storage is limited to using existing entries, but not generate new ones.
#[async_trait::async_trait]
impl<T: BlobStorage + Display + ?Sized> BlobStorage for DisabledProvider<T> {
    async fn create(&self, _blob: Blob) -> Result<(), BlobStorageError> {
        self.disabled_error()
    }

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, BlobStorageError> {
        self.inner().get(id).await
    }

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), BlobStorageError> {
        self.inner().update(id, update).await
    }

    async fn delete(&self, id: &BlobId) -> Result<(), BlobStorageError> {
        self.inner().delete(id).await
    }

    async fn delete_many(&self, ids: &[BlobId]) -> Result<(), BlobStorageError> {
        self.inner().delete_many(ids).await
    }

    fn config_type(&self) -> BlobStorageType {
        self.inner().config_type()
    }
}
