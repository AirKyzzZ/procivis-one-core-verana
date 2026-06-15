use one_crypto::utilities;
use secrecy::{ExposeSecret, SecretSlice};

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ErrorCodeMixinExt;
use crate::model::key::KeyModelError;
use crate::provider::credential_formatter::model::SignatureProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmError;

/// [`SignatureProvider`] that signs with HMAC-SHA256 (JOSE `HS256`), keyed by a
/// shared secret. Used wherever a symmetric JWT is minted (OID4VCI nonces, the
/// SIGN8 CSC `account_token`, …).
pub(crate) struct HS256Signer {
    signing_key: SecretSlice<u8>,
}

impl HS256Signer {
    pub(crate) fn new(signing_key: SecretSlice<u8>) -> Self {
        Self { signing_key }
    }
}

#[async_trait::async_trait]
impl SignatureProvider for HS256Signer {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(utilities::create_hmac(
            self.signing_key.expose_secret(),
            message,
        )?)
    }

    fn get_key_id(&self) -> Option<String> {
        None
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        Err(
            KeyModelError::UnsupportedKeyAlgorithmType("HS256".to_string())
                .error_while("getting key algorithm type")
                .into(),
        )
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok("HS256".to_string())
    }

    fn get_public_key(&self) -> Vec<u8> {
        Default::default()
    }
}
