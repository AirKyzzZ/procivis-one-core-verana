use dcql::CredentialQueryId;
use shared_types::{EntityId, HistoryId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::proto::trust_information::dto::{TrustDetails, TrustInformation, TrustPurpose};

pub mod dto;
pub mod provider;

#[cfg(test)]
mod test;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait TrustInformationProvider: Send + Sync {
    async fn get_trust_information(
        &self,
        entity_id: EntityId,
    ) -> Result<Option<TrustInformation>, Error>;

    async fn get_trust_purpose(
        &self,
        entity_id: EntityId,
        query_id: &CredentialQueryId,
    ) -> Result<Option<TrustPurpose>, Error>;
    async fn get_trust_detail(&self, id: &EntityId) -> Result<Option<TrustDetails>, Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("History entry ({0}) of type {1:?}({2:?}) action {3:?} missing metadata")]
    MissingHistoryMetadata(
        HistoryId,
        HistoryEntityType,
        Option<EntityId>,
        HistoryAction,
    ),

    #[error("History entry metadata have unsupported type, got {0} expected {1}")]
    InvalidMetadataType(&'static str, &'static str),

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::MissingHistoryMetadata(_, _, _, _) => ErrorCode::BR_0426,
            Self::InvalidMetadataType(_, _) => ErrorCode::BR_0427,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
