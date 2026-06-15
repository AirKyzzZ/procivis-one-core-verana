use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum QesError {
    #[error("Document signer `{0}` not found")]
    ProviderNotFound(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for QesError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::ProviderNotFound(_) => ErrorCode::BR_0445,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
