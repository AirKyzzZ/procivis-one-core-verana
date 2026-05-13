use serde::Deserialize;
use shared_types::SerializedCredential;
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;

use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OAuthAuthorizationServerMetadata, OAuthCodeChallengeMethod, OpenID4VCIIssuerMetadataResponseDTO,
};

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCICredentialResponseDTO {
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,

    pub credentials: Option<Vec<OpenID4VCICredentialResponseEntryDTO>>,
    pub transaction_id: Option<String>,
    pub interval: Option<u64>,
    pub notification_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OpenID4VCICredentialResponseEntryDTO {
    pub credential: SerializedCredential,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OAuthAuthorizationServerMetadataResponseDTO {
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<TokenEndpointAuthMethod>,
    pub challenge_endpoint: Option<String>,
    pub client_attestation_signing_alg_values_supported: Option<Vec<String>>,
    pub client_attestation_pop_signing_alg_values_supported: Option<Vec<String>>,
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,
}

impl From<OAuthAuthorizationServerMetadata> for OAuthAuthorizationServerMetadataResponseDTO {
    fn from(value: OAuthAuthorizationServerMetadata) -> Self {
        Self {
            issuer: value.issuer.to_string(),
            authorization_endpoint: value.authorization_endpoint.map(|url| url.to_string()),
            token_endpoint: value.token_endpoint.map(|url| url.to_string()),
            pushed_authorization_request_endpoint: value
                .pushed_authorization_request_endpoint
                .map(|url| url.to_string()),
            code_challenge_methods_supported: value
                .code_challenge_methods_supported
                .into_iter()
                .map(|method| match method {
                    OAuthCodeChallengeMethod::Plain => "plain".to_string(),
                    OAuthCodeChallengeMethod::S256 => "S256".to_string(),
                })
                .collect(),
            jwks_uri: value.jwks_uri,
            scopes_supported: value.scopes_supported,
            response_types_supported: value.response_types_supported,
            grant_types_supported: value.grant_types_supported,
            token_endpoint_auth_methods_supported: value.token_endpoint_auth_methods_supported,
            challenge_endpoint: value.challenge_endpoint.map(|url| url.to_string()),
            client_attestation_signing_alg_values_supported: value
                .client_attestation_signing_alg_values_supported,
            client_attestation_pop_signing_alg_values_supported: value
                .client_attestation_pop_signing_alg_values_supported,
            dpop_signing_alg_values_supported: value.dpop_signing_alg_values_supported,
        }
    }
}

#[derive(Clone, Debug)]
pub enum OID4VCIFinal1_0IssuerMetadataResponseTypeEnum {
    Model,
    Jwt,
}

#[derive(Clone, Debug)]
pub enum OID4VCIFinal1_0IssuerMetadataResponseEnum {
    Model(Box<OpenID4VCIIssuerMetadataResponseDTO>),
    Jwt(String),
}
