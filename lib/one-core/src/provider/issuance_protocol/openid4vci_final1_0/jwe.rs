use one_crypto::jwe::Header;
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwe::CompressionAlgorithm;
use standardized_types::jwk::PublicJwk;

use crate::error::ContextWithErrorCode;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};

pub(crate) async fn build_jwe(
    payload: &[u8],
    issuer_key: PublicJwk,
    encryption_algorithm: EncryptionAlgorithm,
    compression: Option<CompressionAlgorithm>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<String, IssuanceProtocolError> {
    let ParsedKey { algorithm_type, .. } = key_algorithm_provider
        .parse_jwk(&issuer_key)
        .error_while("Parsing JWK")?;
    let algorithm = key_algorithm_provider.key_algorithm_from_type(algorithm_type)?;

    let private_key = algorithm
        .generate_key()
        .error_while("Generating encryption key")?;
    let key_agreement = private_key
        .key
        .key_agreement()
        .ok_or(IssuanceProtocolError::Failed(
            "Key agreement not set".to_string(),
        ))?;
    let shared_secret = key_agreement
        .private()
        .ok_or(IssuanceProtocolError::Failed(
            "Private key not set".to_string(),
        ))?
        .shared_secret(&issuer_key)
        .await?;
    let local_jwk = key_agreement
        .public()
        .as_jwk()
        .error_while("Generating local JWK")?;

    Ok(one_crypto::jwe::build_jwe(
        payload,
        Header {
            key_id: issuer_key.kid().map(String::from),
            zip: compression,
            partyuinfo_data: None,
            partyvinfo_data: None,
        },
        shared_secret,
        local_jwk,
        encryption_algorithm,
    )?)
}
