use std::string::FromUtf8Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum WRPValidatorError {
    #[error("Access certificate not trusted")]
    AccessCertificateNotTrusted,
    #[error("Registration certificate not trusted")]
    RegistrationCertificateNotTrusted,
    #[error(
        "Registration certificate mismatch field: `{field_name}`: `{first_value}` != `{second_value}`"
    )]
    RegistrationCertificateMissmatch {
        field_name: String,
        first_value: String,
        second_value: String,
    },
    #[error("Credential issuer not trusted")]
    IssuerNotTrusted,
    #[error("Registry not trusted")]
    RegistryNotTrusted,
    #[error("Certificate revoked")]
    CertificateRevoked,
    #[error("Invalid organisation identifier")]
    InvalidOrganisationIdentifier,
    #[error("Invalid registry URL: `{0}`")]
    InvalidRegistryUrl(String),
    #[error("Missing registry key: `{0:?}`")]
    MissingRegistryKey(Option<String>),
    #[error("Missing signing details")]
    MissingSigningDetails,
    #[error("Invalid signing method: `{0}`")]
    InvalidSigningMethod(String),

    #[error("Missing issuer")]
    MissingIssuer,
    #[error("URL parsing error: `{0}`")]
    URLParsing(#[from] url::ParseError),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for WRPValidatorError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::AccessCertificateNotTrusted
            | Self::RegistrationCertificateNotTrusted
            | Self::IssuerNotTrusted
            | Self::RegistryNotTrusted
            | Self::CertificateRevoked => ErrorCode::BR_0410,
            Self::InvalidOrganisationIdentifier
            | Self::MissingSigningDetails
            | Self::MissingRegistryKey(_)
            | Self::MissingIssuer
            | Self::InvalidRegistryUrl(_)
            | Self::InvalidSigningMethod(_)
            | Self::RegistrationCertificateMissmatch { .. } => ErrorCode::BR_0224,
            Self::URLParsing(_) | Self::FromUtf8Error(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
