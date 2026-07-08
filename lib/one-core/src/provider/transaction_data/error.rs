use thiserror::Error;

use crate::config::core_config::FormatType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum TransactionDataError {
    #[error("failed to parse transaction data: {0}")]
    Parsing(#[from] serde_json::Error),
    #[error("encoding error: {0}")]
    Encoding(#[from] ct_codecs::Error),
    #[error("unsupported transaction data type `{0}`")]
    UnsupportedType(String),
    #[error("no supported transaction data hash algorithm among `{0}`")]
    UnsupportedHashAlgorithm(String),
    #[error("hashing error: {0}")]
    Hashing(#[from] one_crypto::HasherError),
    #[error("transaction data not supported for credential format `{0}`")]
    UnsupportedCredentialFormat(FormatType),
    #[error("invalid transaction data object `{0}`")]
    InvalidTransactionData(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TransactionDataError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Parsing(_)
            | Self::Encoding(_)
            | Self::UnsupportedType(_)
            | Self::UnsupportedHashAlgorithm(_)
            | Self::Hashing(_)
            | Self::UnsupportedCredentialFormat(_)
            | Self::InvalidTransactionData(_) => ErrorCode::BR_0458,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
