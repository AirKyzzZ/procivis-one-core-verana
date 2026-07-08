use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use indexmap::IndexMap;
use one_crypto::{CryptoProvider, Hasher};
use proc_macros::Provider;
use shared_types::TransactionDataType;
use standardized_types::csc::transaction_data::{
    QES_APPROVAL_KB_JWT_CLAIM, QES_APPROVAL_MDOC_ELEMENT, QES_APPROVAL_MDOC_NAMESPACE,
    QES_APPROVAL_TRANSACTION_DATA_TYPE, QesApprovalRequest,
};
use standardized_types::iana;

use crate::config::core_config::FormatType;
use crate::provider::provider_directory::InitializationError;
use crate::provider::transaction_data::error::TransactionDataError;
use crate::provider::transaction_data::{
    ProcessedTransactionData, TransactionData, TransactionDataCapabilities,
    TransactionDataDisplayParams, TransactionDataMetadata, TransactionDataParams,
    decode_transaction_data,
};

#[cfg(test)]
mod test;

#[derive(Provider)]
pub struct QesApprovalTransactionData {
    config_id: TransactionDataType,
    params: TransactionDataParams,
    crypto: Arc<dyn CryptoProvider>,
}

impl QesApprovalTransactionData {
    pub fn new(
        config_id: TransactionDataType,
        params: serde_json::Value,
        crypto: Arc<dyn CryptoProvider>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            params,
            crypto,
        })
    }

    fn hasher(
        &self,
        algorithm: iana::HashAlgorithm,
    ) -> Result<Arc<dyn Hasher>, TransactionDataError> {
        let algorithm = algorithm.to_string();
        self.crypto
            .get_hasher(&algorithm)
            .map_err(|_| TransactionDataError::UnsupportedHashAlgorithm(algorithm))
    }
}

#[async_trait]
impl TransactionData for QesApprovalTransactionData {
    fn validate_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<TransactionDataMetadata, TransactionDataError> {
        let request: QesApprovalRequest = decode_transaction_data(transaction_data)?;

        if request.credential_ids.is_empty() {
            return Err(TransactionDataError::InvalidTransactionData(
                "credential_ids must not be empty".to_string(),
            ));
        }

        if request.credential_id.is_none() && request.signature_qualifier.is_none() {
            return Err(TransactionDataError::InvalidTransactionData(
                "at least one of credentialID and signatureQualifier must be present".to_string(),
            ));
        }

        self.hasher(request.hash_algorithm.into())?;

        Ok(TransactionDataMetadata {
            credential_ids: request.credential_ids.into_iter().map(Into::into).collect(),
        })
    }

    async fn process_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
    ) -> Result<ProcessedTransactionData, TransactionDataError> {
        let request: QesApprovalRequest = decode_transaction_data(transaction_data)?;

        match format {
            // data model bindings section 7.2.1.2: hash the base64url-encoded
            // transaction data as received, using the hashAlgorithmOID algorithm
            FormatType::SdJwtVc => {
                let qes_approval = self
                    .hasher(request.hash_algorithm.into())?
                    .hash_base64(transaction_data.as_bytes())?;

                Ok(ProcessedTransactionData::KbJwtClaims(
                    serde_json::Map::from_iter([(
                        QES_APPROVAL_KB_JWT_CLAIM.to_string(),
                        qes_approval.into(),
                    )]),
                ))
            }
            // data model bindings section 7.2.1.1: the mdoc encoding pins SHA-256
            // regardless of the requested hashAlgorithmOID, hashed over the
            // base64url-decoded transaction data and represented as a raw byte string
            FormatType::Mdoc => {
                let decoded = Base64UrlSafeNoPadding::decode_to_vec(transaction_data, None)?;
                let digest = self.hasher(iana::HashAlgorithm::Sha256)?.hash(&decoded)?;

                Ok(ProcessedTransactionData::DeviceSignedElements(
                    IndexMap::from([(
                        QES_APPROVAL_MDOC_NAMESPACE.to_string(),
                        IndexMap::from([(
                            QES_APPROVAL_MDOC_ELEMENT.to_string(),
                            ciborium::Value::Bytes(digest),
                        )]),
                    )]),
                ))
            }
            other => Err(TransactionDataError::UnsupportedCredentialFormat(other)),
        }
    }

    fn get_capabilities(&self) -> TransactionDataCapabilities {
        TransactionDataCapabilities {
            transaction_data_types: vec![QES_APPROVAL_TRANSACTION_DATA_TYPE.to_string()],
            formats: vec![FormatType::SdJwtVc, FormatType::Mdoc],
        }
    }

    fn config_name(&self) -> &TransactionDataType {
        &self.config_id
    }

    fn display_params(&self) -> &TransactionDataDisplayParams {
        &self.params.transaction_data_display_params
    }
}
