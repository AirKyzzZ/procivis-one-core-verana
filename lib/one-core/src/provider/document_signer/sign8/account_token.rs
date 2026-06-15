use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, NestedError};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::hmac::HS256Signer;
use crate::proto::jwt::model::JWTPayload;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AccountTokenClaims {
    azp: String,
}

/// SIGN8-proprietary gateway-auth token (not part of CSC); the CSC client forwards it.
pub(super) async fn build_account_token(
    account_id: &str,
    client_id: &str,
    client_secret: &str,
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

    let signing_key = SecretSlice::from(Sha256::digest(client_secret.as_bytes()).to_vec());

    Jwt::new("JWT".to_string(), "HS256".to_string(), None, None, payload)
        .tokenize(Some(&HS256Signer::new(signing_key)))
        .await
        .error_while("creating account token")
}
