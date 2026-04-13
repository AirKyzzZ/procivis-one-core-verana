use shared_types::{IdentifierId, OrganisationId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum OrganisationServiceError {
    #[error("Organisation `{0}` not found")]
    NotFound(OrganisationId),
    #[error("Organisation already exists")]
    AlreadyExists,

    #[error("Identifier does not belong to this organisation")]
    IdentifierOrganisationMismatch,
    #[error("Identifier `{0}` not found")]
    IdentifierNotFound(IdentifierId),
    #[error("Wallet provider is already associated to organisation `{0}`")]
    WalletProviderAlreadyAssociated(OrganisationId),
    #[error("Invalid parent organisation")]
    InvalidParentOrganisation,
    #[error("Parent organisation `{0}` not found")]
    ParentOrganisationNotFound(OrganisationId),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for OrganisationServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0088,
            Self::AlreadyExists => ErrorCode::BR_0023,
            Self::IdentifierOrganisationMismatch => ErrorCode::BR_0285,
            Self::IdentifierNotFound(_) => ErrorCode::BR_0207,
            Self::WalletProviderAlreadyAssociated(_) => ErrorCode::BR_0283,
            Self::InvalidParentOrganisation => ErrorCode::BR_0419,
            Self::ParentOrganisationNotFound(_) => ErrorCode::BR_0022,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
