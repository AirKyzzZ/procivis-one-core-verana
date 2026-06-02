use shared_types::{
    BlobId, CredentialSchemaId, IdentifierId, KeyId, OrganisationId, ProofSchemaId,
    TrustListSubscriberId,
};

use crate::config::core_config::IdentifierType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum IdentifierServiceError {
    #[error("Identifier `{0}` not found")]
    NotFound(IdentifierId),
    #[error("Identifier type `{0}` disabled")]
    IdentifierTypeDisabled(IdentifierType),
    #[error(
        "DID, Key, Certificate or Certificate Authority must be specified when creating identifier"
    )]
    InvalidCreationInput,
    #[error("Remote identifier `{0}` already exists")]
    RemoteIdentifierAlreadyExists(IdentifierId),

    #[error("Organisation `{0}` not found")]
    MissingOrganisation(OrganisationId),
    #[error("Organisation `{0}` is deactivated")]
    OrganisationDeactivated(OrganisationId),
    #[error("Key `{0}` not found")]
    MissingKey(KeyId),
    #[error("Trust information blob `{0}` not found")]
    MissingTrustInformationBlob(BlobId),
    #[error("Invalid trust information: {0}")]
    InvalidTrustInformation(String),

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
    #[error("Missing trust list subscriber `{0}`")]
    MissingTrustListSubscriber(TrustListSubscriberId),
    #[error("Credential schema `{0}` not found")]
    CredentialSchemaNotFound(CredentialSchemaId),
    #[error("Proof schema `{0}` not found")]
    ProofSchemaNotFound(ProofSchemaId),
}

impl ErrorCodeMixin for IdentifierServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0207,
            Self::IdentifierTypeDisabled(_) => ErrorCode::BR_0227,
            Self::InvalidCreationInput => ErrorCode::BR_0206,
            Self::RemoteIdentifierAlreadyExists(_) => ErrorCode::BR_0240,
            Self::MissingOrganisation(_) => ErrorCode::BR_0088,
            Self::OrganisationDeactivated(_) => ErrorCode::BR_0241,
            Self::MissingKey(_) => ErrorCode::BR_0037,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::CredentialSchemaNotFound(_) => ErrorCode::BR_0413,
            Self::ProofSchemaNotFound(_) => ErrorCode::BR_0414,
            Self::Nested(nested) => nested.error_code(),
            Self::MissingTrustListSubscriber(_) => ErrorCode::BR_0388,
            Self::MissingTrustInformationBlob(_) => ErrorCode::BR_0415,
            Self::InvalidTrustInformation(_) => ErrorCode::BR_0416,
        }
    }
}
