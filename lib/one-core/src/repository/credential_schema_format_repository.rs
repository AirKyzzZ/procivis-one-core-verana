use shared_types::{CredentialSchemaFormatId, CredentialSchemaId};

use super::error::DataLayerError;
use crate::model::credential_schema_format::CredentialSchemaFormat;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialSchemaFormatRepository: Send + Sync {
    async fn create_credential_schema_format(
        &self,
        request: CredentialSchemaFormat,
    ) -> Result<CredentialSchemaFormatId, DataLayerError>;

    async fn get_credential_schema_format(
        &self,
        id: &CredentialSchemaFormatId,
    ) -> Result<Option<CredentialSchemaFormat>, DataLayerError>;

    async fn list_by_credential_schema_id(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<Vec<CredentialSchemaFormat>, DataLayerError>;
}
