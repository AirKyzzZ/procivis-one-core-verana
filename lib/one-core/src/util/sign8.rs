use ct_codecs::{Base64UrlSafe, Encoder};
use one_crypto::utilities::generate_random_bytes;
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::hmac::HS256Signer;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::oauth_client::Pkce;
use crate::service::error::ServiceError;

/// SIGN8's gateway rejects requests without a `User-Agent`, reqwest sends none by default.
pub(crate) const USER_AGENT: &str = "procivis-one-core";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AccountTokenClaims {
    azp: String,
}

/// SIGN8-proprietary gateway-auth token (not part of CSC); the CSC client forwards it.
pub(crate) async fn build_account_token(
    account_id: &str,
    client_id: &str,
    client_secret: &SecretString,
    now: OffsetDateTime,
) -> Result<String, NestedError> {
    let payload = JWTPayload::<AccountTokenClaims> {
        subject: Some(account_id.to_owned()),
        issued_at: Some(now),
        jwt_id: Some(Uuid::new_v4().to_string()),
        custom: AccountTokenClaims {
            azp: client_id.to_owned(),
        },
        ..Default::default()
    };

    let signing_key =
        SecretSlice::from(Sha256::digest(client_secret.expose_secret().as_bytes()).to_vec());

    Jwt::new("JWT".to_string(), "HS256".to_string(), None, None, payload)
        .tokenize(Some(&HS256Signer::new(signing_key)))
        .await
        .error_while("creating account token")
}

#[derive(Debug)]
pub(crate) struct AuthorizationTls {
    pub code: String,
    pub code_verifier: String,
}

#[derive(Deserialize)]
pub(crate) struct CodeResponseRestDTO {
    pub code: String,
}

pub(crate) struct AuthorizeTlsRequest<'a> {
    pub oauth_url: &'a str,
    pub redirect_url: &'a str,
    pub credential_id: &'a str,
    pub client_id: &'a str,
    pub account_token: &'a str,
}

pub(crate) async fn authorize_tls(
    client: &dyn HttpClient,
    request: AuthorizeTlsRequest<'_>,
) -> Result<AuthorizationTls, NestedError> {
    let pkce = Pkce::generate()
        .map_err(|e| ServiceError::MappingError(e.to_string()))
        .error_while("creating pkce challenge")?;
    let random_hash: [u8; 32] = generate_random_bytes();
    let encoded = Base64UrlSafe::encode_to_string(random_hash)
        .map_err(|e| ServiceError::MappingError(e.to_string()))
        .error_while("Base64 encoding hashes challenge")?;
    let token: CodeResponseRestDTO = async {
        client
            .post(&format!("{}/oauth2/authorize_tls", request.oauth_url))
            .header("User-Agent", USER_AGENT)
            .form([
                ("scope", "credential"),
                ("account_token", request.account_token),
                ("response_type", "code"),
                ("client_id", request.client_id),
                ("redirect_uri", request.redirect_url),
                ("code_challenge", &pkce.challenge),
                ("credentialID", request.credential_id),
                ("numSignatures", "1"),
                ("hashes", &encoded),
                ("hashAlgorithmOID", "2.16.840.1.101.3.4.2.1"),
            ])?
            .send()
            .await?
            .error_for_status()?
            .json()
    }
    .await
    .error_while("authorize tls request")?;
    Ok(AuthorizationTls {
        code: token.code,
        code_verifier: pkce.verifier,
    })
}
