pub mod dto;
pub mod provider;

#[cfg(test)]
mod test;

use shared_types::{CredentialId, EntityId, HistoryId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::history::HistoryAction;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::trust_information::dto::TrustInformationDTO;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::util::access_cert_parser::EtsiParsedAccessCert;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait TrustInformationProvider: Send + Sync {
    async fn get_trust_information_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Option<TrustInformationDTO>, Error>;

    async fn get_trust_detail(&self, id: &EntityId) -> Result<Option<TrustDetails>, Error>;
}

pub enum TrustDetails {
    Etsi {
        registration_certificate: JWTPayload<Payload>,
        access_certificate: EtsiParsedAccessCert,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("History entry ({0}) of type {1:?} missing metadata")]
    MissingHistoryMetadata(HistoryId, HistoryAction),

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
            Self::MissingHistoryMetadata(_, _) => ErrorCode::BR_0426,
            Self::InvalidMetadataType(_, _) => ErrorCode::BR_0427,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
