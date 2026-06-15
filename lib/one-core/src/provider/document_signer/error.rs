use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum DocumentSignerError {
    #[error("Document is not a valid PDF")]
    InvalidDocument,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for DocumentSignerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidDocument => ErrorCode::BR_0444,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
