use shared_types::{CredentialId, OrganisationId, SerializedCredential};
use url::Url;
use uuid::Uuid;

use super::model::{EtsiIssuerInfoResponseDTO, HolderInteractionData};
use super::{
    AccessCertificateResult, OpenID4VCICredentialConfigurationData, OpenID4VCIFinal1_0,
    OpenID4VCIIssuerMetadataResponseDTO,
};
use crate::clock::now_utc;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::blob::{Blob, BlobType};
use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    TrustResolutionMetadata, TrustResolutionResult, WalletRelyingPartyMetadata,
};
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::verana_trust::VeranaTrustVerdict;
use crate::proto::session_provider::SessionExt;
use crate::proto::wrp_validator::model::TrustMode;
use crate::proto::wrp_validator::{QUALIFIED_EAA_CATEGORY, credential_category};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Features, IdentifierDetails, X5References};
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::signer::registration_certificate;

pub(super) struct TrustInfo {
    pub registration_certificate: Option<String>,
    pub national_registry_data: Option<String>,
    pub relying_party_name: String,
}

impl OpenID4VCIFinal1_0 {
    #[expect(clippy::too_many_arguments)]
    pub(super) async fn resolve_credential_issuer_trust(
        &self,
        credential: &Credential,
        issuer_certificate: Option<&Certificate>,
        serialized: Option<&SerializedCredential>,
        schema: &CredentialSchema,
        formatter: &dyn CredentialFormatter,
        access_certificate_trust: TrustResolutionResult,
        organisation_id: OrganisationId,
    ) -> TrustResolutionResult {
        let namespaced = formatter_requires_namespaces(formatter);
        let is_qeaa = credential
            .claims
            .as_deref()
            .and_then(|claims| credential_category(claims, namespaced))
            == Some(QUALIFIED_EAA_CATEGORY);

        if is_qeaa {
            return self
                .resolve_qeaa_issuer_trust(serialized, schema, formatter, organisation_id)
                .await;
        }

        if access_certificate_trust == TrustResolutionResult::Trusted
            && let Err(err) = self
                .wrp_validator
                .validate_credential_issuer(
                    issuer_certificate.map(|certificate| certificate.chain.as_str()),
                    schema,
                    None,
                    X5References::default(),
                    organisation_id,
                )
                .await
        {
            tracing::info!(%err, "Credential issuer trust not verified");
            return TrustResolutionResult::Untrusted;
        }
        access_certificate_trust
    }

    async fn resolve_qeaa_issuer_trust(
        &self,
        serialized: Option<&SerializedCredential>,
        schema: &CredentialSchema,
        formatter: &dyn CredentialFormatter,
        organisation_id: OrganisationId,
    ) -> TrustResolutionResult {
        let Some(serialized) = serialized else {
            tracing::info!("Missing serialized QEAA credential for issuer trust resolution");
            return TrustResolutionResult::Untrusted;
        };
        let issuer = match formatter
            .extract_credentials_unverified(serialized, Some(schema))
            .await
        {
            Ok(detail) => detail.issuer,
            Err(err) => {
                tracing::info!(%err, "Failed to extract QEAA issuer for trust resolution");
                return TrustResolutionResult::Untrusted;
            }
        };
        let (chain, x5_references) = match &issuer {
            IdentifierDetails::Certificate(certificate) => {
                (Some(certificate.chain.as_str()), certificate.x5_references)
            }
            _ => (None, X5References::default()),
        };
        match self
            .wrp_validator
            .validate_credential_issuer(
                chain,
                schema,
                Some(QUALIFIED_EAA_CATEGORY),
                x5_references,
                organisation_id,
            )
            .await
        {
            Ok(_) => TrustResolutionResult::Trusted,
            Err(err) => {
                tracing::info!(%err, "QEAA issuer trust not verified");
                TrustResolutionResult::Untrusted
            }
        }
    }

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
                .get_blob_storage(BlobStorageType::Db)?;

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

    #[expect(clippy::too_many_arguments)]
    pub(super) async fn validate_batch_refresh_trust(
        &self,
        interaction_data: &HolderInteractionData,
        organisation: &Organisation,
        interaction: &Interaction,
        schema: &CredentialSchema,
        batch_parent_id: CredentialId,
        credential: &Credential,
        serialized: Option<&SerializedCredential>,
        formatter: &dyn CredentialFormatter,
    ) -> Result<(), IssuanceProtocolError> {
        if interaction_data.trust_mode == TrustMode::Disabled {
            return Ok(());
        }

        let namespaced = formatter_requires_namespaces(formatter);
        if credential
            .claims
            .as_deref()
            .and_then(|claims| credential_category(claims, namespaced))
            == Some(QUALIFIED_EAA_CATEGORY)
        {
            let mut trust_resolution = self
                .resolve_qeaa_issuer_trust(serialized, schema, formatter, organisation.id)
                .await;
            let verana = self.resolve_verana_issuer_trust(credential, schema).await?;
            if let Some(verana) = &verana {
                trust_resolution = if verana.verdict.is_positive() {
                    TrustResolutionResult::Trusted
                } else {
                    TrustResolutionResult::Untrusted
                };
            }
            return self
                .store_trust_resolved_event(
                    batch_parent_id,
                    organisation.id,
                    trust_resolution,
                    verana,
                )
                .await;
        }

        let verana = self.resolve_verana_issuer_trust(credential, schema).await?;
        match batch_refresh_path(
            interaction_data.trust_resolution,
            verana.as_ref().map(|summary| summary.verdict),
        ) {
            BatchRefreshPath::Store(result) => {
                return self
                    .store_trust_resolved_event(batch_parent_id, organisation.id, result, verana)
                    .await;
            }
            BatchRefreshPath::Skip => return Ok(()),
            BatchRefreshPath::ValidateNative => {}
        }

        let issuer_certificate_chain = credential
            .issuer_certificate
            .as_ref()
            .map(|certificate| certificate.chain.as_str());
        let mut trust_resolution = TrustResolutionResult::Trusted;

        let relying_party_id =
            interaction_data
                .relying_party_id
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "Missing relying party id on trusted interaction {}",
                    interaction.id
                )))?;
        if let Some(reg_cert) = interaction_data.registration_certificate.as_ref()
            && let Err(err) = self
                .wrp_validator
                .validate_registration_certificate(
                    reg_cert,
                    relying_party_id,
                    Some(organisation.id),
                    self.params.trust_ecosystem_leeway,
                )
                .await
        {
            tracing::debug!(%err, "Registration certificate no longer trusted, rechecking using national registry");
            let registry_url = interaction_data.national_registry_url.as_ref().ok_or(
                IssuanceProtocolError::Failed(format!(
                    "Missing registry URL on trusted interaction {}",
                    interaction.id
                )),
            )?;
            let result = self
                .wrp_validator
                .fetch_from_registry(
                    relying_party_id,
                    registry_url,
                    Some(organisation.id),
                    self.params.trust_ecosystem_leeway,
                )
                .await;
            match result {
                Ok(info) => {
                    self.store_trust_history_event(
                        HistoryAction::WrpNrReceived,
                        batch_parent_id,
                        organisation.id,
                        Some(info.jwt),
                        Some(HistoryMetadata::WalletRelyingParty(
                            WalletRelyingPartyMetadata {
                                name: info.payload.custom.data.trade_name.unwrap_or_default(),
                                ..Default::default()
                            },
                        )),
                    )
                    .await?;
                }
                Err(err) => {
                    tracing::info!(%err, "Failed to fetch trust information from national registry");
                    trust_resolution = TrustResolutionResult::Untrusted;
                }
            }
        }

        if trust_resolution == TrustResolutionResult::Trusted
            && let Err(err) = self
                .wrp_validator
                .validate_credential_issuer(
                    issuer_certificate_chain,
                    schema,
                    None,
                    Default::default(),
                    organisation.id,
                )
                .await
        {
            tracing::info!(%err, "Credential issuer trust not verified");
            trust_resolution = TrustResolutionResult::Untrusted;
        }

        self.store_trust_resolved_event(batch_parent_id, organisation.id, trust_resolution, None)
            .await
    }

    async fn store_trust_resolved_event(
        &self,
        target: CredentialId,
        organisation_id: OrganisationId,
        trust_resolution: TrustResolutionResult,
        verana: Option<crate::model::verana_trust::VeranaTrustSummary>,
    ) -> Result<(), IssuanceProtocolError> {
        self.store_trust_history_event(
            HistoryAction::TrustResolved,
            target,
            organisation_id,
            None,
            Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                result: trust_resolution,
                verana,
            })),
        )
        .await
    }
}

#[derive(Debug, Eq, PartialEq)]
enum BatchRefreshPath {
    Store(TrustResolutionResult),
    ValidateNative,
    Skip,
}

fn batch_refresh_path(
    native_resolution: TrustResolutionResult,
    verana_verdict: Option<VeranaTrustVerdict>,
) -> BatchRefreshPath {
    match verana_verdict {
        Some(VeranaTrustVerdict::TrustedAuthorized) => {
            BatchRefreshPath::Store(TrustResolutionResult::Trusted)
        }
        Some(_) => BatchRefreshPath::Store(TrustResolutionResult::Untrusted),
        None if native_resolution == TrustResolutionResult::Trusted => {
            BatchRefreshPath::ValidateNative
        }
        None => BatchRefreshPath::Skip,
    }
}

#[cfg(test)]
mod refresh_test {
    use super::{BatchRefreshPath, batch_refresh_path};
    use crate::model::history::TrustResolutionResult;
    use crate::model::verana_trust::VeranaTrustVerdict;

    #[test]
    fn verana_refresh_is_stored_even_when_native_trust_was_not_positive() {
        for verdict in [
            VeranaTrustVerdict::Unauthorized,
            VeranaTrustVerdict::Unavailable,
        ] {
            assert_eq!(
                batch_refresh_path(TrustResolutionResult::Untrusted, Some(verdict)),
                BatchRefreshPath::Store(TrustResolutionResult::Untrusted)
            );
        }

        assert_eq!(
            batch_refresh_path(
                TrustResolutionResult::Untrusted,
                Some(VeranaTrustVerdict::TrustedAuthorized),
            ),
            BatchRefreshPath::Store(TrustResolutionResult::Trusted)
        );
    }

    #[test]
    fn native_refresh_behavior_is_preserved_without_verana() {
        assert_eq!(
            batch_refresh_path(TrustResolutionResult::Trusted, None),
            BatchRefreshPath::ValidateNative
        );
        assert_eq!(
            batch_refresh_path(TrustResolutionResult::Untrusted, None),
            BatchRefreshPath::Skip
        );
    }
}

fn formatter_requires_namespaces(formatter: &dyn CredentialFormatter) -> bool {
    formatter
        .get_capabilities()
        .features
        .contains(&Features::RequiresNamespaces)
}

fn credential_config_matches_reg_cert_attestation(
    credential_config: &OpenID4VCICredentialConfigurationData,
    reg_cert_attestation: &registration_certificate::model::Credential,
) -> bool {
    if credential_config.format != reg_cert_attestation.format.dcql_format() {
        return false;
    }

    match &reg_cert_attestation.format {
        dcql::CredentialFormat::MsoMdoc(meta) => credential_config
            .doctype
            .as_ref()
            .is_some_and(|doctype| doctype == &meta.doctype_value),
        dcql::CredentialFormat::SdJwt(meta) => credential_config
            .vct
            .as_ref()
            .is_some_and(|vct| meta.vct_values.contains(vct)),
        dcql::CredentialFormat::JwtVc(meta)
        | dcql::CredentialFormat::W3cSdJwt(meta)
        | dcql::CredentialFormat::LdpVc(meta) => credential_config
            .credential_definition
            .as_ref()
            .is_some_and(|credential_definition| {
                // TODO: support context expansion
                meta.type_values.iter().any(|types| {
                    credential_definition
                        .r#type
                        .iter()
                        .all(|r#type| types.contains(r#type))
                })
            }),
    }
}
