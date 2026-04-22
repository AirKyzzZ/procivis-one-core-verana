use shared_types::{CredentialId, CredentialSchemaId, IdentifierId};

use super::OID4VCIFinal1_0SwiyuService;
use crate::error::ContextWithErrorCode;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialRequestDTO, OpenID4VCIFinal1CredentialOfferDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCINonceResponseDTO,
    OpenID4VCINotificationRequestDTO, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
};
use crate::service::oid4vci_final1_0::dto::{
    OAuthAuthorizationServerMetadataResponseDTO, OpenID4VCICredentialResponseDTO,
};
use crate::service::oid4vci_final1_0::error::OID4VCIFinal1_0ServiceError;

impl OID4VCIFinal1_0SwiyuService {
    pub async fn oauth_authorization_server(
        &self,
        protocol_id: &str,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OAuthAuthorizationServerMetadataResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .oauth_authorization_server(protocol_id, identifier_id, credential_schema_id)
            .await
    }
    pub async fn get_issuer_metadata(
        &self,
        protocol_id: &str,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, OID4VCIFinal1_0ServiceError> {
        let issuance_protocol = self.protocol_provider.get_protocol(protocol_id).ok_or(
            OID4VCIFinal1_0ServiceError::MappingError("issuance protocol not found".to_string()),
        )?;

        let issuer_identifier = self.inner.get_issuer_identifier(identifier_id).await?;

        issuance_protocol
            .issuer_metadata(protocol_id, credential_schema_id, &issuer_identifier)
            .await
            .error_while("getting issuer metadata")
            .map_err(Into::into)
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<OpenID4VCIFinal1CredentialOfferDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .get_credential_offer(credential_schema_id, credential_id)
            .await
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
    ) -> Result<OpenID4VCITokenResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .create_token(
                credential_schema_id,
                request,
                oauth_client_attestation,
                oauth_client_attestation_pop,
            )
            .await
    }

    pub async fn create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .create_credential(credential_schema_id, access_token, request)
            .await
    }

    pub async fn generate_nonce(
        &self,
        protocol_id: &str,
    ) -> Result<OpenID4VCINonceResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner.generate_nonce(protocol_id).await
    }

    pub async fn handle_notification(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCINotificationRequestDTO,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        self.inner
            .handle_notification(credential_schema_id, access_token, request)
            .await
    }
}
