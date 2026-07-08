pub(crate) mod decorators;
pub mod error;
pub(crate) mod provider;
pub(crate) mod qes_approval;

use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use dcql::CredentialQueryId;
use error::TransactionDataError;
use proc_macros::provider_mock;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json_path::JsonPath;
use shared_types::TransactionDataType;

use crate::config::core_config::FormatType;
use crate::provider::Provider;
use crate::provider::presentation_formatter::mso_mdoc::model::DeviceNamespaces;

pub(crate) fn decode_transaction_data<T: DeserializeOwned>(
    transaction_data: &str,
) -> Result<T, TransactionDataError> {
    let data = Base64UrlSafeNoPadding::decode_to_vec(transaction_data, None)?;
    Ok(serde_json::from_slice(&data)?)
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransactionDataMetadata {
    pub credential_ids: Vec<CredentialQueryId>,
}

/// Format-specific representation of processed transaction data, to be merged into the
/// presentation response.
#[derive(Clone, Debug, PartialEq)]
pub enum ProcessedTransactionData {
    /// Top-level claims for the SD-JWT VC Key Binding JWT
    KbJwtClaims(serde_json::Map<String, serde_json::Value>),
    /// Data elements for the mdoc `DeviceSigned` structure
    DeviceSignedElements(DeviceNamespaces),
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDataCapabilities {
    transaction_data_types: Vec<String>,
    /// Credential formats the transaction data can be bound to
    formats: Vec<FormatType>,
}

// Private params
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransactionDataParams {
    pub(crate) transaction_data_display_params: Vec<TransactionDataDisplayParam>,
}

#[derive(Deserialize, Debug)]
pub struct TransactionDataDisplayParam {
    path: JsonPath,
    display: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransactionDataDisplayValue {
    pub display: String,
    pub values: Vec<serde_json::Value>,
}

/// The `transaction_data` arguments are base64url-encoded OpenID4VP `transaction_data` entries.
#[provider_mock]
#[async_trait]
pub trait TransactionData: Provider + Send + Sync {
    fn validate_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<TransactionDataMetadata, TransactionDataError>;
    /// Type-specific processing of an approved transaction; returns the fields to be
    /// merged into the presentation response of the credential authorizing it.
    async fn process_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
    ) -> Result<ProcessedTransactionData, TransactionDataError>;
    fn get_capabilities(&self) -> TransactionDataCapabilities;
    fn config_name(&self) -> &TransactionDataType;
    fn display_params(&self) -> &[TransactionDataDisplayParam];

    fn get_display_data(
        &self,
        transaction_data: &str,
    ) -> Result<Vec<TransactionDataDisplayValue>, TransactionDataError> {
        let transaction_data: serde_json::Value = decode_transaction_data(transaction_data)?;

        Ok(self
            .display_params()
            .iter()
            .map(|param| TransactionDataDisplayValue {
                display: param.display.clone(),
                values: param
                    .path
                    .query(&transaction_data)
                    .all()
                    .into_iter()
                    .cloned()
                    .collect(),
            })
            .collect())
    }
}

impl Display for dyn TransactionData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction data type `{}`", self.config_name())
    }
}
