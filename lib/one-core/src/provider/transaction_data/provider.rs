use std::sync::Arc;

use one_crypto::CryptoProvider;
use shared_types::TransactionDataType;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, TransactionDataProviderType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::provider::provider_directory::ProviderDirectory;
use crate::provider::transaction_data::decorators::CapabilityChecked;
use crate::provider::transaction_data::error::TransactionDataError;
use crate::provider::transaction_data::qes_approval::QesApprovalTransactionData;
use crate::provider::transaction_data::{TransactionData, decode_transaction_data};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait TransactionDataProvider: Send + Sync {
    fn get_transaction_data(
        &self,
        transaction_data: &str,
    ) -> Result<Arc<dyn TransactionData>, NestedError>;
}

impl TransactionDataProvider
    for ProviderDirectory<
        TransactionDataType,
        Fields<TransactionDataProviderType>,
        dyn TransactionData,
    >
{
    fn get_transaction_data(
        &self,
        // base64url-encoded transaction data
        transaction_data: &str,
    ) -> Result<Arc<dyn TransactionData>, NestedError> {
        let as_value: serde_json::Value =
            decode_transaction_data(transaction_data).error_while("decoding transaction data")?;
        let transaction_data_type = as_value
            .get("type")
            .and_then(|t| t.as_str())
            .ok_or(TransactionDataError::InvalidTransactionData(
                "missing or invalid 'type' field".to_string(),
            ))
            .error_while("reading transaction data type")?;

        let (_, provider) = self
            .iter()
            .find(|(_, provider)| {
                provider
                    .get_capabilities()
                    .transaction_data_types
                    .iter()
                    .any(|supported| supported == transaction_data_type)
            })
            .ok_or(TransactionDataError::UnsupportedType(
                transaction_data_type.to_string(),
            ))
            .error_while("resolving transaction data provider")?;

        Ok(provider.clone())
    }
}

pub(crate) fn transaction_data_provider_from_config(
    config: &mut CoreConfig,
    crypto: Arc<dyn CryptoProvider>,
) -> Result<Arc<dyn TransactionDataProvider>, ConfigValidationError> {
    let directory = ProviderDirectory::initialize(
        config.transaction_data_provider.iter_mut(),
        |name: &TransactionDataType, fields: &Fields<TransactionDataProviderType>| {
            let provider: Arc<dyn TransactionData> = match fields.r#type {
                TransactionDataProviderType::QesApproval => {
                    Arc::new(QesApprovalTransactionData::new(
                        name.clone(),
                        fields.merge_fields(),
                        crypto.clone(),
                    )?)
                }
            };
            let provider: Arc<dyn TransactionData> = Arc::new(CapabilityChecked(provider));

            Ok(provider)
        },
    )
    .error_while("initializing transaction data provider")?;

    Ok(Arc::new(directory))
}
