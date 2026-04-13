use std::string::FromUtf8Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum WRPValidatorError {
    #[error("Trust management disabled")]
    TrustManagementDisabled,

    #[error("Access certificate not trusted")]
    AccessCertificateNotTrusted,
    #[error("Registration certificate not trusted")]
    RegistrationCertificateNotTrusted,
    #[error("Registry not trusted")]
    RegistryNotTrusted,
    #[error("Invalid organisation identifier")]
    InvalidOrganisationIdentifier,
    #[error("Invalid registry URL: `{0}`")]
    InvalidRegistryUrl(String),
    #[error("Missing registry keys URL")]
    MissingRegistryKeysUrl,
    #[error("Missing registry key: `{0:?}`")]
    MissingRegistryKey(Option<String>),

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
            Self::TrustManagementDisabled => ErrorCode::BR_0412,
            Self::AccessCertificateNotTrusted
            | Self::RegistrationCertificateNotTrusted
            | Self::RegistryNotTrusted => ErrorCode::BR_0410,
            Self::InvalidOrganisationIdentifier
            | Self::MissingRegistryKeysUrl
            | Self::MissingRegistryKey(_)
            | Self::MissingIssuer
            | Self::InvalidRegistryUrl(_) => ErrorCode::BR_0224,
            Self::URLParsing(_) | Self::FromUtf8Error(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
