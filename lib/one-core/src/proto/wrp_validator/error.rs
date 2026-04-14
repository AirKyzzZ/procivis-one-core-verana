use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum WRPValidatorError {
    #[error("Trust management disabled")]
    TrustManagementDisabled,

    #[error("Access certificate not trusted")]
    AccessCertificateNotTrusted,
    #[error("Registration certificate not trusted")]
    RegistrationCertificateNotTrusted,
    #[error("Invalid organisation identifier")]
    InvalidOrganisationIdentifier,
    #[error("Missing issuer")]
    MissingIssuer,

    #[error("URL parsing error: `{0}`")]
    URLParsing(#[from] url::ParseError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for WRPValidatorError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::TrustManagementDisabled => ErrorCode::BR_0412,
            Self::AccessCertificateNotTrusted | Self::RegistrationCertificateNotTrusted => {
                ErrorCode::BR_0410
            }
            Self::InvalidOrganisationIdentifier | Self::MissingIssuer => ErrorCode::BR_0416,
            Self::URLParsing(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
