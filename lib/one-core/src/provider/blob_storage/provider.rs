use std::sync::Arc;

use super::BlobStorage;
use super::db::RepositoryBlobStorage;
use crate::config::ConfigValidationError;
use crate::config::core_config::{BlobStorageFields, BlobStorageType, CoreConfig};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};
use crate::repository::blob_repository::BlobRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait BlobStorageProvider: Send + Sync {
    fn get_blob_storage(
        &self,
        r#type: BlobStorageType,
    ) -> Result<Arc<dyn BlobStorage>, NestedError>;
}

impl BlobStorageProvider
    for ProviderDirectory<BlobStorageType, BlobStorageFields, dyn BlobStorage>
{
    fn get_blob_storage(
        &self,
        r#type: BlobStorageType,
    ) -> Result<Arc<dyn BlobStorage>, NestedError> {
        self.provider(&r#type)
    }
}

pub(crate) fn blob_storage_provider_from_config(
    config: &mut CoreConfig,
    blob_repository: Arc<dyn BlobRepository>,
) -> Result<Arc<dyn BlobStorageProvider>, ConfigValidationError> {
    let initializer = move |r#type: &BlobStorageType, _field: &BlobStorageFields| {
        initialize_provider(r#type, blob_repository.clone())
    };
    let directory = ProviderDirectory::initialize(config.blob_storage.iter_mut(), initializer)
        .error_while("initializing blob storage providers")?;
    Ok(Arc::new(directory))
}

fn initialize_provider(
    r#type: &BlobStorageType,
    blob_repository: Arc<dyn BlobRepository>,
) -> Result<Arc<dyn BlobStorage>, InitializationError> {
    Ok(match r#type {
        BlobStorageType::Db => Arc::new(RepositoryBlobStorage { blob_repository }),
    })
}
