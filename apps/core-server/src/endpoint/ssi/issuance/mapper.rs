use one_core::service::ssi_issuer::dto::{SdJwtVcIssuerMetadata, SdJwtVcIssuerMetadataJwks};

use crate::endpoint::ssi::issuance::dto::{
    SdJwtVcIssuerMetadataJwksRestDTO, SdJwtVcIssuerMetadataRestDTO,
};

impl From<SdJwtVcIssuerMetadata> for SdJwtVcIssuerMetadataRestDTO {
    fn from(o: SdJwtVcIssuerMetadata) -> Self {
        let (jwks, jwks_uri) = match o.jwks {
            SdJwtVcIssuerMetadataJwks::Jwks(jwks) => {
                (Some(SdJwtVcIssuerMetadataJwksRestDTO { keys: jwks }), None)
            }
            SdJwtVcIssuerMetadataJwks::JwksUri(jwks_uri) => (None, Some(jwks_uri)),
        };
        Self {
            issuer: o.issuer,
            jwks_uri,
            jwks,
        }
    }
}
