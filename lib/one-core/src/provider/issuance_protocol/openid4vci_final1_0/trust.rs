use shared_types::{CredentialId, OrganisationId};
use url::Url;
use uuid::Uuid;

use super::model::EtsiIssuerInfoResponseDTO;
use super::{
    AccessCertificateResult, OpenID4VCICredentialConfigurationData, OpenID4VCIFinal1_0,
    OpenID4VCIIssuerMetadataResponseDTO,
};
use crate::clock::now_utc;
use crate::error::ContextWithErrorCode;
use crate::model::blob::{Blob, BlobType};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};
use crate::proto::session_provider::SessionExt;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::signer::registration_certificate;
use crate::service::error::MissingProviderError;

pub(super) struct TrustInfo {
    pub registration_certificate: Option<String>,
    pub national_registry_data: Option<String>,
    pub relying_party_name: String,
}

impl OpenID4VCIFinal1_0 {
    pub(super) async fn validate_trust(
        &self,
        credential_config: &OpenID4VCICredentialConfigurationData,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        organisation_id: OrganisationId,
        access_certificate: &AccessCertificateResult,
    ) -> Result<TrustInfo, IssuanceProtocolError> {
        Ok(if issuer_metadata.issuer_info.is_empty() {
            let (national_registry_data, relying_party_name) = self
                .validate_credential_config_trust_against_registry(
                    credential_config,
                    &access_certificate.relying_party_id,
                    access_certificate.registry_url.as_ref().ok_or(
                        IssuanceProtocolError::InvalidRequest("Missing registry URL".to_string()),
                    )?,
                    organisation_id,
                )
                .await?;

            TrustInfo {
                registration_certificate: None,
                national_registry_data: Some(national_registry_data),
                relying_party_name,
            }
        } else {
            let (registration_certificate, relying_party_name) = self
                .validate_credential_config_trust_with_registration_certificate(
                    credential_config,
                    &issuer_metadata.issuer_info,
                    &access_certificate.relying_party_id,
                    organisation_id,
                )
                .await?;

            TrustInfo {
                registration_certificate: Some(registration_certificate),
                national_registry_data: None,
                relying_party_name,
            }
        })
    }

    async fn validate_credential_config_trust_against_registry(
        &self,
        credential_config: &OpenID4VCICredentialConfigurationData,
        relying_party_id: &str,
        registry_url: &Url,
        organisation_id: OrganisationId,
    ) -> Result<(String, String), IssuanceProtocolError> {
        let info = self
            .wrp_validator
            .fetch_from_registry(
                relying_party_id,
                registry_url,
                Some(organisation_id),
                self.params.trust_ecosystem_leeway,
            )
            .await
            .error_while("fetching from WRP registry")?;

        if !info
            .payload
            .custom
            .data
            .provides_attestations
            .iter()
            .any(|attestation| {
                credential_config_matches_reg_cert_attestation(
                    credential_config,
                    &attestation.to_owned().into(),
                )
            })
        {
            return Err(IssuanceProtocolError::DisallowedCredentialConfiguration);
        };

        Ok((
            info.jwt,
            info.payload.custom.data.trade_name.unwrap_or_default(),
        ))
    }

    async fn validate_credential_config_trust_with_registration_certificate(
        &self,
        credential_config: &OpenID4VCICredentialConfigurationData,
        issuer_info: &[EtsiIssuerInfoResponseDTO],
        expected_relying_party_id: &str,
        organisation_id: OrganisationId,
    ) -> Result<(String, String), IssuanceProtocolError> {
        for reg_cert in issuer_info {
            if let Some(relying_party_name) = self
                .credential_config_matches_reg_cert(
                    credential_config,
                    reg_cert,
                    expected_relying_party_id,
                    organisation_id,
                )
                .await
            {
                return Ok((reg_cert.data.to_owned(), relying_party_name));
            }
        }

        Err(IssuanceProtocolError::DisallowedCredentialConfiguration)
    }

    async fn credential_config_matches_reg_cert(
        &self,
        credential_config: &OpenID4VCICredentialConfigurationData,
        issuer_info: &EtsiIssuerInfoResponseDTO,
        expected_relying_party_id: &str,
        organisation_id: OrganisationId,
    ) -> Option<String> {
        let Ok(reg_cert) = self
            .wrp_validator
            .validate_registration_certificate(
                &issuer_info.data,
                expected_relying_party_id,
                Some(organisation_id),
                self.params.trust_ecosystem_leeway,
            )
            .await
        else {
            return None;
        };

        let provides_attestations = reg_cert.payload.custom.provides_attestations?;

        if provides_attestations.iter().any(|attestation| {
            credential_config_matches_reg_cert_attestation(credential_config, attestation)
        }) {
            Some(reg_cert.payload.custom.name)
        } else {
            None
        }
    }

    pub(super) async fn store_trust_history_event(
        &self,
        action: HistoryAction,
        credential_id: CredentialId,
        organisation_id: OrganisationId,
        blob_content: Option<String>,
        metadata: Option<HistoryMetadata>,
    ) -> Result<(), IssuanceProtocolError> {
        let metadata_blob_id = if let Some(blob_content) = blob_content {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)
                .await
                .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
                .error_while("getting blob storage")?;

            let blob = Blob::new(blob_content, BlobType::HistoryMetadata);

            let blob_id = blob.id;
            blob_storage
                .create(blob)
                .await
                .error_while("creating history metadata blob")?;
            Some(blob_id)
        } else {
            None
        };

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                action,
                name: Default::default(),
                target: None,
                source: HistorySource::Core,
                entity_id: Some(credential_id.into()),
                entity_type: HistoryEntityType::Credential,
                metadata,
                metadata_blob_id,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("storing history")?;

        Ok(())
    }
}

fn credential_config_matches_reg_cert_attestation(
    credential_config: &OpenID4VCICredentialConfigurationData,
    reg_cert_attestation: &registration_certificate::model::Credential,
) -> bool {
    if credential_config.format != reg_cert_attestation.format.to_string() {
        return false;
    }

    match &reg_cert_attestation.meta {
        dcql::CredentialMeta::MsoMdoc { doctype_value } => credential_config
            .doctype
            .as_ref()
            .is_some_and(|doctype| doctype == doctype_value),
        dcql::CredentialMeta::SdJwtVc { vct_values } => credential_config
            .vct
            .as_ref()
            .is_some_and(|vct| vct_values.contains(vct)),
        dcql::CredentialMeta::W3cVc { type_values } => credential_config
            .credential_definition
            .as_ref()
            .is_some_and(|credential_definition| {
                // TODO: support context expansion
                type_values.iter().any(|types| {
                    credential_definition
                        .r#type
                        .iter()
                        .all(|r#type| types.contains(r#type))
                })
            }),
    }
}
