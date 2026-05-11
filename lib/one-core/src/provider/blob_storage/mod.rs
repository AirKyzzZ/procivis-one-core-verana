use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use proc_macros::provider_mock;
use shared_types::BlobId;

use crate::config::core_config::BlobStorageType;
use crate::model::blob::{Blob, UpdateBlobRequest};
use crate::provider::Provider;
use crate::provider::blob_storage::error::BlobStorageError;

mod db;
mod decorators;
pub mod error;
pub mod provider;

#[provider_mock]
#[async_trait]
pub trait BlobStorage: Provider + Send + Sync {
    async fn create(&self, blob: Blob) -> Result<(), BlobStorageError>;

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, BlobStorageError>;

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), BlobStorageError>;

    async fn delete(&self, id: &BlobId) -> Result<(), BlobStorageError>;

    async fn delete_many(&self, ids: &[BlobId]) -> Result<(), BlobStorageError>;

    fn config_type(&self) -> BlobStorageType;
}

impl Display for dyn BlobStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blob storage `{}`", self.config_type())
    }
}
