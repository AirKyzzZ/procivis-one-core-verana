use anyhow::anyhow;
use one_crypto::jwe::Header;
use standardized_types::jwa::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, PublicJwk};
use standardized_types::openid4vp::ClientMetadata;

use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::provider::verification_protocol::openid4vp::model::JwePayload;

pub(crate) async fn build_jwe(
    payload: JwePayload,
    verifier_key: PublicJwk,
    holder_nonce: &str,
    nonce: &str, // nonce from the authorization request object
    encryption_algorithm: EncryptionAlgorithm,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> anyhow::Result<String> {
    let payload = payload.try_into_json()?;
    let ParsedKey { algorithm_type, .. } = key_algorithm_provider.parse_jwk(&verifier_key)?;
    let algorithm = key_algorithm_provider
        .key_algorithm_from_type(algorithm_type)
        .map_err(|_| anyhow!("Algorithm not found"))?;

    let private_key = algorithm.generate_key()?;
    let key_agreement = private_key
        .key
        .key_agreement()
        .ok_or(anyhow!("Key agreement not set"))?;
    let shared_secret = key_agreement
        .private()
        .ok_or(anyhow!("Private key not set"))?
        .shared_secret(&verifier_key)
        .await?;
    let local_jwk = key_agreement.public().as_jwk().map_err(|e| anyhow!(e))?;

    Ok(one_crypto::jwe::build_jwe(
        &payload,
        Header {
            key_id: verifier_key.kid().map(String::from),
            zip: None,
            partyuinfo_data: Some(holder_nonce.as_bytes().to_vec()),
            partyvinfo_data: Some(nonce.as_bytes().to_vec()),
        },
        shared_secret,
        local_jwk,
        encryption_algorithm,
    )?)
}

pub(crate) fn encryption_key_from_metadata(
    metadata: ClientMetadata,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Option<PublicJwk> {
    let jwks = metadata.jwks;

    let is_usable_for_encryption = |key: &PublicJwk| -> bool {
        // Per RFC 7517 §4.2, `use` is OPTIONAL. When absent, the key's algorithm
        // or capabilities determine its purpose. Only reject keys explicitly
        // marked for a non-encryption use (e.g. "sig").
        match key.r#use() {
            Some(r#use) => *r#use == JwkUse::Encryption,
            None => true,
        }
    };

    let supports_key_agreement = |key: &PublicJwk| -> bool {
        key_algorithm_provider
            .parse_jwk(key)
            .is_ok_and(|parsed_key| parsed_key.key.key_agreement().is_some())
    };

    jwks.into_iter()
        .flat_map(|jwk| jwk.keys)
        .find(|key| is_usable_for_encryption(key) && supports_key_agreement(key))
}
