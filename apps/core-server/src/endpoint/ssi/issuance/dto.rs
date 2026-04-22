use proc_macros::options_not_nullable;
use serde::Serialize;
use standardized_types::jwk::PublicJwk;
use utoipa::ToSchema;

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SdJwtVcIssuerMetadataRestDTO {
    pub issuer: String,
    pub jwks_uri: Option<String>,
    pub jwks: Option<SdJwtVcIssuerMetadataJwksRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SdJwtVcIssuerMetadataJwksRestDTO {
    pub keys: Vec<PublicJwk>,
}
