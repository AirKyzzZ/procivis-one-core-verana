use std::collections::HashMap;

use dcql::DcqlQuery;
use one_dto_mapper::convert_inner;
use shared_types::{OrganisationId, ProofId};
use standardized_types::etsi_119_602::MultiLangString;
use url::Url;
use uuid::Uuid;

use super::OpenID4VPFinal1_0;
use super::mappers::credential_query_matches_reg_cert_credential;
use super::model::{AuthorizationRequest, VerifierInfoAttestation};
use crate::error::ContextWithErrorCode;
use crate::model::blob::{Blob, BlobType};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    TrustResolutionMetadata, TrustResolutionResult, WalletRelyingPartyMetadata,
};
use crate::proto::session_provider::SessionExt;
use crate::proto::wrp_validator::model::{AccessCertificateResult, IntendedUse, TrustMode};
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::signer::registration_certificate;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::service::error::MissingProviderError;

impl OpenID4VPFinal1_0 {
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub(super) async fn handle_trust(
        &self,
        verifier_details: Option<&IdentifierDetails>,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        authorization_request: &AuthorizationRequest,
    ) -> Result<(), VerificationProtocolError> {
        let trust_result = self
            .perform_trust_resolution(
                verifier_details,
                proof_id,
                organisation_id,
                authorization_request,
            )
            .await?;

        self.store_trust_history_event(
            HistoryAction::TrustResolved,
            proof_id,
            organisation_id,
            None,
            Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                result: trust_result,
            })),
        )
        .await?;

        Ok(())
    }

    async fn perform_trust_resolution(
        &self,
        verifier_details: Option<&IdentifierDetails>,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        authorization_request: &AuthorizationRequest,
    ) -> Result<TrustResolutionResult, VerificationProtocolError> {
        let trust_mode = self
            .wrp_validator
            .wallet_trust_mode(organisation_id)
            .await
            .error_while("checking trust mode")?;

        if trust_mode == TrustMode::Disabled {
            tracing::debug!("Trust ecosystem disabled");
            return Ok(TrustResolutionResult::Unknown);
        }

        // trust ecosystem does not support other identifiers than certificates
        let Some(IdentifierDetails::Certificate(access_certificate)) = verifier_details else {
            tracing::debug!(
                "Unsupported or missing verifier identifier type: {:?}",
                verifier_details.map(|detail| detail.identifier_type())
            );
            if trust_mode == TrustMode::TrustMandatory {
                return Err(VerificationProtocolError::Untrusted);
            }
            return Ok(TrustResolutionResult::Untrusted);
        };

        let access_certificate_trust = match self
            .validate_access_certificate(access_certificate, proof_id, organisation_id)
            .await
        {
            Ok(trusted) => trusted,
            Err(err) => {
                if trust_mode == TrustMode::TrustMandatory {
                    return Err(err);
                }

                tracing::info!(%err, "Access certificate validation failed");
                return Ok(TrustResolutionResult::Untrusted);
            }
        };

        let relying_party_id = &access_certificate_trust.relying_party_id;
        let dcql_query = authorization_request.dcql_query.as_ref().ok_or(
            VerificationProtocolError::InvalidRequest("missing dcql_query".to_string()),
        )?;

        let reg_cert_result = if authorization_request.verifier_info.is_empty() {
            let registry_url = access_certificate_trust.registry_url.as_ref().ok_or(
                VerificationProtocolError::InvalidRequest("missing registry URL".to_string()),
            )?;

            self.validate_against_registry_info(
                &access_certificate_trust.relying_party_id,
                registry_url,
                dcql_query,
                proof_id,
                organisation_id,
            )
            .await
        } else {
            // check query against registration certificates
            self.validate_registration_certificates(
                &authorization_request.verifier_info,
                dcql_query,
                relying_party_id,
                proof_id,
                organisation_id,
            )
            .await
        };

        if let Err(err) = reg_cert_result {
            if trust_mode == TrustMode::TrustMandatory {
                return Err(err);
            }

            tracing::info!(%err, "Registration certificate validation failed");
            return Ok(TrustResolutionResult::Untrusted);
        }

        tracing::debug!("Trust validated");
        Ok(TrustResolutionResult::Trusted)
    }

    async fn validate_access_certificate(
        &self,
        certificate: &CertificateDetails,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<AccessCertificateResult, VerificationProtocolError> {
        let result = self
            .wrp_validator
            .validate_access_certificate(&certificate.chain, Some(organisation_id))
            .await
            .error_while("validating access certificate")?;

        self.store_trust_history_event(
            HistoryAction::WrpAcReceived,
            proof_id,
            organisation_id,
            Some(certificate.chain.to_owned()),
            None,
        )
        .await?;

        Ok(result)
    }

    async fn validate_registration_certificates(
        &self,
        verifier_info: &[VerifierInfoAttestation],
        dcql_query: &DcqlQuery,
        expected_rp_id: &str,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<(), VerificationProtocolError> {
        #[derive(Clone)]
        struct RefCertCredentialInfo<'a> {
            credential_def: registration_certificate::model::Credential,
            reg_cert: &'a VerifierInfoAttestation,
            purpose: Vec<registration_certificate::model::MultiLangString>,
            relying_party_name: String,
        }

        let mut allowed_credentials: HashMap<
            Option<dcql::CredentialQueryId>,
            Vec<RefCertCredentialInfo>,
        > = HashMap::new();
        for reg_cert in verifier_info {
            if let Ok(trusted) = self
                .wrp_validator
                .validate_registration_certificate(
                    &reg_cert.data,
                    expected_rp_id,
                    Some(organisation_id),
                    self.params.holder.trust_ecosystems_leeway,
                )
                .await
                .inspect_err(|err| {
                    tracing::warn!(%err, "Provided registration certificate validation failure");
                })
                && let (Some(credentials), Some(purpose)) = (
                    trusted.payload.custom.credentials,
                    trusted.payload.custom.purpose,
                )
            {
                let creds_with_reg_cert: Vec<_> = credentials
                    .into_iter()
                    .map(|credential_def| RefCertCredentialInfo {
                        credential_def,
                        reg_cert,
                        purpose: purpose.to_owned(),
                        relying_party_name: trusted.payload.custom.name.to_owned(),
                    })
                    .collect();

                if reg_cert.credential_ids.is_empty() {
                    allowed_credentials
                        .entry(None)
                        .or_default()
                        .extend(creds_with_reg_cert);
                } else {
                    for credential_id in &reg_cert.credential_ids {
                        allowed_credentials
                            .entry(Some(credential_id.to_owned()))
                            .or_default()
                            .extend(creds_with_reg_cert.to_owned());
                    }
                }
            }
        }

        struct RegCertInfo {
            relying_party_name: String,
            purpose: HashMap<dcql::CredentialQueryId, Vec<MultiLangString>>,
        }
        let mut used_reg_certs: HashMap<String, RegCertInfo> = HashMap::new();
        for credential_query in &dcql_query.credentials {
            let empty = vec![];
            let mut related_reg_cert_credentials = allowed_credentials
                .get(&None)
                .unwrap_or(&empty)
                .iter()
                .chain(
                    allowed_credentials
                        .get(&Some(credential_query.id.to_owned()))
                        .unwrap_or(&empty),
                );

            let Some(RefCertCredentialInfo {
                reg_cert,
                purpose,
                relying_party_name,
                ..
            }) = related_reg_cert_credentials.find(
                |RefCertCredentialInfo { credential_def, .. }| {
                    credential_query_matches_reg_cert_credential(credential_query, credential_def)
                },
            )
            else {
                return Err(VerificationProtocolError::DisallowedQuery(
                    credential_query.id.to_owned(),
                ));
            };

            used_reg_certs
                .entry(reg_cert.data.to_owned())
                .or_insert(RegCertInfo {
                    relying_party_name: relying_party_name.to_owned(),
                    purpose: Default::default(),
                })
                .purpose
                .insert(
                    credential_query.id.to_owned(),
                    convert_inner(purpose.to_owned()),
                );
        }

        for (
            used_reg_cert,
            RegCertInfo {
                relying_party_name,
                purpose,
            },
        ) in used_reg_certs
        {
            self.store_trust_history_event(
                HistoryAction::WrpRcReceived,
                proof_id,
                organisation_id,
                Some(used_reg_cert),
                Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        name: relying_party_name,
                        purpose,
                    },
                )),
            )
            .await?;
        }

        Ok(())
    }

    async fn validate_against_registry_info(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        dcql_query: &DcqlQuery,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<(), VerificationProtocolError> {
        let info = self
            .wrp_validator
            .fetch_from_registry(
                relying_party_id,
                registry_url,
                Some(organisation_id),
                self.params.holder.trust_ecosystems_leeway,
            )
            .await
            .error_while("fetching from WRP registry")?;

        let mut purpose: HashMap<dcql::CredentialQueryId, Vec<MultiLangString>> =
            Default::default();
        for credential_query in &dcql_query.credentials {
            let Some(applied_purpose) = find_matching_intended_use(
                credential_query,
                &info.payload.custom.data.intended_use,
            ) else {
                return Err(VerificationProtocolError::DisallowedQuery(
                    credential_query.id.to_owned(),
                ));
            };

            purpose.insert(credential_query.id.to_owned(), applied_purpose);
        }

        self.store_trust_history_event(
            HistoryAction::WrpNrReceived,
            proof_id,
            organisation_id,
            Some(info.jwt),
            Some(HistoryMetadata::WalletRelyingParty(
                WalletRelyingPartyMetadata {
                    name: info.payload.custom.data.trade_name.unwrap_or_default(),
                    purpose,
                },
            )),
        )
        .await?;

        Ok(())
    }

    async fn store_trust_history_event(
        &self,
        action: HistoryAction,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        blob_content: Option<String>,
        metadata: Option<HistoryMetadata>,
    ) -> Result<(), VerificationProtocolError> {
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
                created_date: crate::clock::now_utc(),
                action,
                name: Default::default(),
                target: None,
                source: HistorySource::Core,
                entity_id: Some(proof_id.into()),
                entity_type: HistoryEntityType::Proof,
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

fn find_matching_intended_use(
    credential_query: &dcql::CredentialQuery,
    among_uses: &[IntendedUse],
) -> Option<Vec<MultiLangString>> {
    for intended_use in among_uses {
        if intended_use.credential.iter().any(|c| {
            credential_query_matches_reg_cert_credential(credential_query, &c.clone().into())
        }) {
            return Some(convert_inner(intended_use.purpose.to_owned()));
        }
    }
    None
}
