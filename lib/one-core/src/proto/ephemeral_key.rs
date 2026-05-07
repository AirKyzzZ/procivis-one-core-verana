use std::sync::Arc;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::provider::credential_formatter::model::{AuthenticationFn, SignatureProvider};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::model::GeneratedKey;

/// In-memory (temporary) key implementing the `SignatureProvider` trait
pub(crate) struct EphemeralKey {
    key: GeneratedKey,
    key_algorithm: Arc<dyn KeyAlgorithm>,
}

impl EphemeralKey {
    pub(crate) fn new(key_algorithm: Arc<dyn KeyAlgorithm>) -> Result<Self, KeyAlgorithmError> {
        Ok(Self {
            key: key_algorithm
                .generate_key()
                .error_while("generating ephemeral key")?,
            key_algorithm,
        })
    }

    pub(crate) fn key_handle(&self) -> &KeyHandle {
        &self.key.key
    }
}

#[async_trait::async_trait]
impl SignatureProvider for EphemeralKey {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(self.key.key.sign(message).await.error_while("signing")?)
    }

    fn get_key_id(&self) -> Option<String> {
        None
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        Ok(self.key_algorithm.algorithm_type())
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok(self.key_algorithm.issuance_jose_alg_id())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.key.public.to_owned()
    }
}

impl From<EphemeralKey> for AuthenticationFn {
    fn from(value: EphemeralKey) -> Self {
        Box::new(value)
    }
}
