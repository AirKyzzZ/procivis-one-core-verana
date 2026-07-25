use std::collections::HashMap;
use std::sync::Arc;

use dcql::{ClaimValue, DcqlQuery, PathSegment};
use one_dto_mapper::convert_inner;
use shared_types::{OrganisationId, ProofId};
use standardized_types::etsi_119_602::MultiLangString;
use time::Duration;
use url::Url;
use uuid::Uuid;

use super::{HolderTrustResolver, HolderTrustResolverError};
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::blob::{Blob, BlobType};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    TrustResolutionMetadata, TrustResolutionResult, WalletRelyingPartyMetadata,
};
use crate::model::verana_trust::{VeranaTrustRole, VeranaTrustSummary, VerifierTrustProvenance};
use crate::proto::holder_trust_resolver::mapper::credential_query_matches_reg_cert_credential;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::proto::verana_trust::VeranaTrustResolver;
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::model::{AccessCertificateResult, IntendedUse, TrustMode};
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::signer::registration_certificate;
use crate::provider::verification_protocol::openid4vp::final1_0::model::VerifierInfoAttestation;
use crate::repository::history_repository::HistoryRepository;

pub(crate) struct HolderTrustResolverProto {
    history_repository: Arc<dyn HistoryRepository>,
    wrp_validator: Arc<dyn WRPValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    verana_trust_resolver: Option<Arc<VeranaTrustResolver>>,
}

impl HolderTrustResolverProto {
    pub(crate) fn new(
        history_repository: Arc<dyn HistoryRepository>,
        wrp_validator: Arc<dyn WRPValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        verana_trust_resolver: Option<Arc<VeranaTrustResolver>>,
    ) -> Self {
        Self {
            history_repository,
            wrp_validator,
            blob_storage_provider,
            session_provider,
            verana_trust_resolver,
        }
    }
}

#[async_trait::async_trait]
impl HolderTrustResolver for HolderTrustResolverProto {
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    async fn resolve_verification_trust<'a>(
        &self,
        verifier_details: Option<&'a IdentifierDetails>,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        dcql_query: &DcqlQuery,
        verifier_info: &[VerifierInfoAttestation],
        leeway: Duration,
        provenance: VerifierTrustProvenance,
    ) -> Result<(), HolderTrustResolverError> {
        let (trust_result, verana) = self
            .perform_trust_resolution(
                verifier_details,
                proof_id,
                organisation_id,
                dcql_query,
                verifier_info,
                leeway,
                provenance,
            )
            .await?;

        self.store_trust_history_event(
            HistoryAction::TrustResolved,
            proof_id,
            organisation_id,
            None,
            Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                result: trust_result,
                verana,
            })),
        )
        .await?;

        Ok(())
    }
}

impl HolderTrustResolverProto {
    async fn perform_trust_resolution(
        &self,
        verifier_details: Option<&IdentifierDetails>,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        dcql_query: &DcqlQuery,
        verifier_info: &[VerifierInfoAttestation],
        leeway: Duration,
        provenance: VerifierTrustProvenance,
    ) -> Result<(TrustResolutionResult, Option<VeranaTrustSummary>), HolderTrustResolverError> {
        let trust_mode = self
            .wrp_validator
            .wallet_trust_mode(organisation_id)
            .await
            .error_while("checking trust mode")?;

        if !verana_resolution_enabled(trust_mode) {
            tracing::debug!("Trust ecosystem disabled");
            return Ok((TrustResolutionResult::Unknown, None));
        }

        let schemas = verana_presentation_schema_ids(dcql_query)
            .map_err(|error| HolderTrustResolverError::InvalidRequest(error.to_string()))?;
        let verana = if let Some(resolver) = &self.verana_trust_resolver {
            match (provenance, verifier_details) {
                (VerifierTrustProvenance::DidSignedRequest, Some(IdentifierDetails::Did(did))) => {
                    let did = did.to_string();
                    Some(
                        resolver
                            .resolve_summary(VeranaTrustRole::Verifier, &did, schemas.clone())
                            .await,
                    )
                }
                _ => Some(
                    resolver.unsupported_summary(
                        VeranaTrustRole::Verifier,
                        verifier_details
                            .and_then(IdentifierDetails::did_value)
                            .map(|did| did.to_string())
                            .as_deref(),
                        schemas,
                        match provenance {
                            VerifierTrustProvenance::DidSignedRequest => "DID_MISSING",
                            VerifierTrustProvenance::VerifierAttestation => {
                                "VERIFIER_ATTESTATION_PROVENANCE"
                            }
                            VerifierTrustProvenance::RedirectUri => "REDIRECT_URI_PROVENANCE",
                            VerifierTrustProvenance::X509 => "X509_PROVENANCE",
                            VerifierTrustProvenance::Proximity => "PROXIMITY_PROVENANCE",
                        },
                    ),
                ),
            }
        } else {
            None
        };

        if provenance.allows_verana_positive()
            && let Some(verana) = &verana
        {
            if verana.verdict.is_positive() {
                return Ok((TrustResolutionResult::Trusted, Some(verana.clone())));
            }
            if trust_mode == TrustMode::TrustMandatory {
                return Err(HolderTrustResolverError::Untrusted);
            }
            return Ok((TrustResolutionResult::Untrusted, Some(verana.clone())));
        }

        // trust ecosystem does not support other identifiers than certificates
        let Some(IdentifierDetails::Certificate(access_certificate)) = verifier_details else {
            tracing::debug!(
                "Unsupported or missing verifier identifier type: {:?}",
                verifier_details.map(|detail| detail.identifier_type())
            );
            if trust_mode == TrustMode::TrustMandatory {
                return Err(HolderTrustResolverError::Untrusted);
            }
            return Ok((TrustResolutionResult::Untrusted, verana));
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
                return Ok((TrustResolutionResult::Untrusted, verana));
            }
        };

        let reg_cert_result = if verifier_info.is_empty() {
            let registry_url = access_certificate_trust.registry_url.as_ref().ok_or(
                HolderTrustResolverError::InvalidRequest("missing registry URL".to_string()),
            )?;

            self.validate_against_registry_info(
                &access_certificate_trust.relying_party_id,
                registry_url,
                dcql_query,
                proof_id,
                organisation_id,
                leeway,
            )
            .await
        } else {
            // check query against registration certificates
            self.validate_registration_certificates(
                verifier_info,
                dcql_query,
                &access_certificate_trust.relying_party_id,
                proof_id,
                organisation_id,
                leeway,
            )
            .await
        };

        if let Err(err) = reg_cert_result {
            if trust_mode == TrustMode::TrustMandatory {
                return Err(err);
            }

            tracing::info!(%err, "Registration certificate validation failed");
            return Ok((TrustResolutionResult::Untrusted, verana));
        }

        tracing::debug!("Trust validated");
        Ok((TrustResolutionResult::Trusted, verana))
    }

    async fn validate_access_certificate(
        &self,
        certificate: &CertificateDetails,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<AccessCertificateResult, HolderTrustResolverError> {
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
        leeway: Duration,
    ) -> Result<(), HolderTrustResolverError> {
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
        let mut last_reg_cert_jwt: Option<registration_certificate::model::Payload> = None;
        for reg_cert in verifier_info {
            let trusted = match self
                .wrp_validator
                .validate_registration_certificate(
                    &reg_cert.data,
                    expected_rp_id,
                    Some(organisation_id),
                    leeway,
                )
                .await
            {
                Ok(trusted) => trusted,
                Err(err) => {
                    tracing::warn!(%err, "Provided registration certificate validation failure");
                    continue;
                }
            };

            if let Some(last_reg_cert) = &last_reg_cert_jwt
                && let Err(err) = self
                    .wrp_validator
                    .validate_registration_certificates_consistency(
                        last_reg_cert,
                        &trusted.payload.custom,
                    )
            {
                tracing::warn!(%err, "validating registration certificates similarity");
                continue;
            }
            last_reg_cert_jwt = Some(trusted.payload.custom.clone());

            let (Some(credentials), Some(purpose)) = (
                trusted.payload.custom.credentials,
                trusted.payload.custom.purpose,
            ) else {
                continue;
            };

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
                return Err(HolderTrustResolverError::DisallowedQuery(
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
        leeway: Duration,
    ) -> Result<(), HolderTrustResolverError> {
        let info = self
            .wrp_validator
            .fetch_from_registry(
                relying_party_id,
                registry_url,
                Some(organisation_id),
                leeway,
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
                return Err(HolderTrustResolverError::DisallowedQuery(
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
    ) -> Result<(), HolderTrustResolverError> {
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

fn verana_resolution_enabled(trust_mode: TrustMode) -> bool {
    trust_mode != TrustMode::Disabled
}

fn verana_presentation_schema_ids(dcql_query: &DcqlQuery) -> Result<Vec<String>, dcql::DcqlError> {
    let mut schemas = std::collections::BTreeSet::new();
    for filter in dcql_query.credential_filters()?.into_values().flatten() {
        let mut signed_schema_binding = Vec::new();
        for claim in filter.claims.iter().filter(|claim| {
            claim.required
                && claim.path.segments
                    == [
                        PathSegment::PropertyName("credentialSchema".to_string()),
                        PathSegment::PropertyName("id".to_string()),
                    ]
        }) {
            if claim.values.is_empty() {
                signed_schema_binding.push(String::new());
            } else {
                signed_schema_binding.extend(claim.values.iter().map(|value| match value {
                    ClaimValue::String(value) => value.clone(),
                    _ => String::new(),
                }));
            }
        }
        if signed_schema_binding.is_empty() {
            schemas.extend(filter.schema_ids);
        } else {
            schemas.extend(signed_schema_binding);
        }
    }
    Ok(schemas.into_iter().collect())
}

#[cfg(test)]
mod verana_policy_test {
    use super::{verana_presentation_schema_ids, verana_resolution_enabled};
    use crate::proto::wrp_validator::model::TrustMode;
    use dcql::DcqlQuery;
    use serde_json::json;

    #[test]
    fn disabled_trust_mode_never_resolves_verana_presentation() {
        assert!(!verana_resolution_enabled(TrustMode::Disabled));
        assert!(verana_resolution_enabled(TrustMode::TrustOptional));
        assert!(verana_resolution_enabled(TrustMode::TrustMandatory));
    }

    #[test]
    fn required_signed_credential_schema_binds_q3_instead_of_the_vct_matcher() {
        let query: DcqlQuery = serde_json::from_value(json!({
            "credentials": [{
                "id": "attestation",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://issuer.example/vct/attestation"]
                },
                "claims": [{
                    "path": ["credentialSchema", "id"],
                    "values": ["https://issuer.example/vt/schemas-attestation-jsc.json"]
                }]
            }]
        }))
        .unwrap();

        assert_eq!(
            verana_presentation_schema_ids(&query).unwrap(),
            vec!["https://issuer.example/vt/schemas-attestation-jsc.json"]
        );
    }

    #[test]
    fn missing_or_optional_schema_binding_falls_back_to_the_exact_vct() {
        let query: DcqlQuery = serde_json::from_value(json!({
            "credentials": [{
                "id": "attestation",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://issuer.example/vct/attestation"]
                },
                "claims": [{
                    "path": ["credentialSchema", "id"],
                    "values": ["https://issuer.example/vt/schemas-attestation-jsc.json"],
                    "required": false
                }]
            }]
        }))
        .unwrap();

        assert_eq!(
            verana_presentation_schema_ids(&query).unwrap(),
            vec!["https://issuer.example/vct/attestation"]
        );
    }

    #[test]
    fn every_claim_set_must_bind_the_schema_or_q3_keeps_the_vct_control() {
        let query: DcqlQuery = serde_json::from_value(json!({
            "credentials": [{
                "id": "attestation",
                "format": "dc+sd-jwt",
                "meta": {
                    "vct_values": ["https://issuer.example/vct/attestation"]
                },
                "claims": [
                    {
                        "id": "schema",
                        "path": ["credentialSchema", "id"],
                        "values": ["https://issuer.example/vt/schemas-attestation-jsc.json"]
                    },
                    {
                        "id": "organization",
                        "path": ["organization"]
                    }
                ],
                "claim_sets": [["schema"], ["organization"]]
            }]
        }))
        .unwrap();

        assert_eq!(
            verana_presentation_schema_ids(&query).unwrap(),
            vec![
                "https://issuer.example/vct/attestation",
                "https://issuer.example/vt/schemas-attestation-jsc.json",
            ]
        );
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
