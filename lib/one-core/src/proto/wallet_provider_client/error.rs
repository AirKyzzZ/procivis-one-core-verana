use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::wallet_instance::WalletProviderType;

#[derive(Debug, Error)]
pub enum WalletProviderClientError {
    #[error("Integrity check required")]
    IntegrityCheckRequired,
    #[error("Integrity check not required")]
    IntegrityCheckNotRequired,

    #[error("Unknown provider type: `{0}`")]
    UnsupportedType(WalletProviderType),

    #[error("URL error: `{0}`")]
    URLError(#[from] url::ParseError),
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for WalletProviderClientError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::IntegrityCheckRequired => ErrorCode::BR_0280,
            Self::IntegrityCheckNotRequired => ErrorCode::BR_0281,
            Self::UnsupportedType(_) | Self::URLError(_) | Self::JsonError(_) | Self::Nested(_) => {
                ErrorCode::BR_0264
            }
        }
    }
}
