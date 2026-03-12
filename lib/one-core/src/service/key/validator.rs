use std::str::FromStr;

use crate::config::core_config::KeyAlgorithmType;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::key::error::KeyServiceError;

pub(super) fn validate_generate_request(
    key_type: &str,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), KeyServiceError> {
    let key_type = KeyAlgorithmType::from_str(key_type)
        .map_err(|err| KeyServiceError::InvalidKeyAlgorithm(err.to_string()))?;
    let provider = key_algorithm_provider
        .key_algorithm_from_type(key_type)
        .ok_or(KeyServiceError::UnsupportedKeyType { key_type })?;
    if !provider.enabled() {
        return Err(KeyServiceError::InvalidKeyAlgorithm(format!(
            "{provider} is disabled"
        )));
    }
    Ok(())
}
