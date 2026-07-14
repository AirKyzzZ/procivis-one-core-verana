use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use dcql::CredentialQueryId;
use error::TransactionDataError;
use proc_macros::provider_mock;
use processed_transaction_data::ProcessedTransactionData;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json_path::JsonPath;
use shared_types::TransactionDataType;

use crate::config::core_config::FormatType;
use crate::provider::Provider;
use crate::provider::presentation_formatter::model::PresentedTransactionData;

pub(crate) mod decorators;
pub mod error;
pub(crate) mod processed_transaction_data;
pub(crate) mod provider;
pub(crate) mod qes_approval;

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

/// Outcome of checking presented evidence against a `transaction_data` entry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionDataAuthorization {
    Authorized,
    NotAuthorized,
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
    pub(crate) transaction_data_display_params: TransactionDataDisplayParams,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDataDisplayParams {
    /// Selects the displayed entries within the transaction data
    group_path: JsonPath,
    /// Selects an entry's title, relative to `group_path`
    title_path: JsonPath,
    /// An entry's attributes, relative to `group_path`
    attributes: Vec<TransactionDataDisplayParam>,
}

#[derive(Deserialize, Debug)]
pub struct TransactionDataDisplayParam {
    path: JsonPath,
    display: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransactionDataDisplayValue {
    pub title: String,
    pub attributes: Vec<TransactionDataDisplayAttribute>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransactionDataDisplayAttribute {
    pub key: String,
    pub value: String,
}

/// The `transaction_data` arguments are base64url-encoded OpenID4VP `transaction_data` entries.
#[provider_mock]
#[async_trait]
pub trait TransactionData: Provider + Send + Sync {
    /// Composes a `transaction_data` entry from verifier-provided type-specific content,
    /// validates it and returns it base64url-encoded for use in the authorization request.
    fn prepare_transaction_data(
        &self,
        credential_ids: Vec<CredentialQueryId>,
        data: Option<serde_json::Value>,
    ) -> Result<String, TransactionDataError>;
    fn validate_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<TransactionDataMetadata, TransactionDataError>;
    /// Holder-side processing of an approved transaction; returns the fields to be
    /// merged into the presentation response of the credential authorizing it.
    /// May have side effects, e.g. calling out to external signing APIs.
    async fn process_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
    ) -> Result<ProcessedTransactionData, TransactionDataError>;
    /// Verifier-side check whether the evidence presented by the holder authorizes this
    /// transaction data entry. Must not trigger the side effects of
    /// [`process_transaction_data`](Self::process_transaction_data).
    /// Evidence not matching the entry is [`TransactionDataAuthorization::NotAuthorized`],
    /// never an error; errors always denote a failure to perform the check.
    async fn verify_transaction_data(
        &self,
        transaction_data: &str,
        format: FormatType,
        presented: &PresentedTransactionData,
    ) -> Result<TransactionDataAuthorization, TransactionDataError>;
    fn get_capabilities(&self) -> TransactionDataCapabilities;
    fn config_name(&self) -> &TransactionDataType;
    fn display_params(&self) -> &TransactionDataDisplayParams;

    /// Grouped key-value data for displaying the transaction to the user
    fn get_display_data(
        &self,
        transaction_data: &str,
    ) -> Result<Vec<TransactionDataDisplayValue>, TransactionDataError> {
        let transaction_data: serde_json::Value = decode_transaction_data(transaction_data)?;
        let params = self.display_params();

        Ok(params
            .group_path
            .query(&transaction_data)
            .all()
            .into_iter()
            .map(|group| TransactionDataDisplayValue {
                title: params
                    .title_path
                    .query(group)
                    .first()
                    .and_then(|title| title.as_str())
                    .unwrap_or_default()
                    .to_string(),
                attributes: params
                    .attributes
                    .iter()
                    .flat_map(|param| {
                        let values = param
                            .path
                            .query(group)
                            .all()
                            .into_iter()
                            .filter_map(transaction_data_value_display);

                        values.map(|value| TransactionDataDisplayAttribute {
                            key: param.display.clone(),
                            value,
                        })
                    })
                    .collect(),
            })
            .collect())
    }
}

fn transaction_data_value_display(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.to_owned()),
        serde_json::Value::Null => Some("null".to_string()),
        serde_json::Value::Bool(value) => Some(format!("{value}")),
        serde_json::Value::Number(value) => Some(format!("{value}")),
        other => {
            tracing::warn!("Non-primitive display value: `{other}`");
            None
        }
    }
}

impl Display for dyn TransactionData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction data type `{}`", self.config_name())
    }
}
