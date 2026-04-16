use core::str;
use std::collections::{BTreeSet, HashMap};

use dcql::DcqlQuery;
use one_dto_mapper::convert_inner;
use serde_json::json;
use shared_types::{DidValue, OrganisationId, ProofId};
use standardized_types::etsi_119_602::MultiLangString;
use standardized_types::openid4vp::PresentationFormat;
use url::Url;
use uuid::Uuid;

use super::mappers::{credential_query_matches_reg_cert_credential, decode_client_id_with_scheme};
use super::model::{
    AuthorizationRequest, AuthorizationRequestQueryParams, VerifierInfoAttestation,
};
use super::{OpenID4VPFinal1_0, encode_client_id_with_scheme};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::x509::{pem_chain_into_x5c, x5c_into_pem_chain};
use crate::model::blob::{Blob, BlobType};
use crate::model::did::KeyRole;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    WalletRelyingPartyMetadata,
};
use crate::proto::certificate_validator::{CertificateValidationOptions, ParsedCertificate};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::session_provider::SessionExt;
use crate::proto::wrp_validator;
use crate::proto::wrp_validator::error::WRPValidatorError;
use crate::proto::wrp_validator::model::AccessCertificateResult;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::credential_formatter::model::{
    CertificateDetails, IdentifierDetails, TokenVerifier,
};
use crate::provider::did_method::error::DidMethodError;
use crate::provider::signer::registration_certificate;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCVerifierAttestationPayload, OpenID4VPClientMetadata,
    OpenID4VPHolderInteractionData,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    validate_against_redirect_uris, validate_san_dns_matching_client_id,
    validate_x509_hash_matching_client_id,
};
use crate::service::error::MissingProviderError;
use crate::validator::x509::is_dns_name_matching;

impl OpenID4VPFinal1_0 {
    async fn parse_referenced_data_from_x509_san_dns_token(
        &self,
        request_token: DecomposedJwt<AuthorizationRequest>,
    ) -> Result<(AuthorizationRequest, CertificateDetails), VerificationProtocolError> {
        let x5c = request_token
            .header
            .x5c
            .ok_or(VerificationProtocolError::Failed("x5c missing".to_string()))?;

        let (client_id, _) = decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

        let pem_chain = x5c_into_pem_chain(&x5c).error_while("parsing x5c")?;

        let ParsedCertificate {
            public_key,
            attributes,
            subject_common_name,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(
                &pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .error_while("parsing PEM chain")?;

        public_key
            .signature()
            .ok_or(VerificationProtocolError::Failed(
                "Signature key missing".to_string(),
            ))?
            .public()
            .verify(
                request_token.unverified_jwt.as_bytes(),
                &request_token.signature,
            )
            .error_while("verifying signature")?;

        // x509 SAN must match client_id
        validate_san_dns_matching_client_id(&attributes, &client_id)?;

        // The response_uri must match client_id
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#section-5.7-12.2.1
        if request_token
            .payload
            .custom
            .response_uri
            .as_ref()
            .is_none_or(|response_uri| {
                !response_uri.domain().is_some_and(|response_domain| {
                    client_id == response_domain
                        || is_dns_name_matching(&format!("*.{client_id}"), response_domain)
                })
            })
        {
            return Err(VerificationProtocolError::Failed(
                "response_uri client_id mismatch".to_string(),
            ));
        }

        Ok((
            request_token.payload.custom,
            CertificateDetails {
                chain: pem_chain,
                fingerprint: attributes.fingerprint,
                expiry: attributes.not_after,
                subject_common_name,
            },
        ))
    }

    async fn parse_referenced_data_from_x509_hash_token(
        &self,
        request_token: DecomposedJwt<AuthorizationRequest>,
    ) -> Result<(AuthorizationRequest, CertificateDetails), VerificationProtocolError> {
        let x5c = request_token
            .header
            .x5c
            .ok_or(VerificationProtocolError::Failed("x5c missing".to_string()))?;

        let (client_id, _) = decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

        let pem_chain = x5c_into_pem_chain(&x5c).error_while("parsing x5c")?;

        let ParsedCertificate {
            public_key,
            attributes,
            subject_common_name,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(
                &pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .error_while("parsing PEM chain")?;

        public_key
            .signature()
            .ok_or(VerificationProtocolError::Failed(
                "Signature key missing".to_string(),
            ))?
            .public()
            .verify(
                request_token.unverified_jwt.as_bytes(),
                &request_token.signature,
            )
            .error_while("verifying signature")?;

        // client_id hash must match certificate fingerprint
        validate_x509_hash_matching_client_id(&attributes, &client_id)?;

        Ok((
            request_token.payload.custom,
            CertificateDetails {
                chain: pem_chain,
                fingerprint: attributes.fingerprint,
                expiry: attributes.not_after,
                subject_common_name,
            },
        ))
    }

    async fn parse_referenced_data_from_did_signed_token(
        &self,
        request_token: DecomposedJwt<AuthorizationRequest>,
    ) -> Result<(AuthorizationRequest, DidValue), VerificationProtocolError> {
        let (client_id, _) = decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

        let Some(kid) = request_token.header.key_id.clone() else {
            return Err(VerificationProtocolError::Failed(
                "JOSE header missing kid".to_string(),
            ));
        };

        let verifier_did = client_id
            .parse()
            .map_err(DidMethodError::DidValueError)
            .error_while("parsing verifier DID")?;

        let did_document = self
            .did_method_provider
            .resolve(&verifier_did)
            .await
            .error_while("resolving verifier DID")?;

        let (_, alg) = self
            .key_algorithm_provider
            .key_algorithm_from_jose_alg(&request_token.header.algorithm)
            .ok_or(VerificationProtocolError::Failed(format!(
                "Missing algorithm: {}",
                request_token.header.algorithm
            )))?;

        let key = did_document
            .find_verification_method(Some(&kid), Some(KeyRole::Authentication))
            .or_else(|| {
                did_document.find_verification_method(Some(&kid), Some(KeyRole::AssertionMethod))
            })
            .ok_or(VerificationProtocolError::Failed(
                "Missing key in did".to_string(),
            ))?
            .public_key_jwk
            .clone();

        alg.parse_jwk(&key)
            .error_while("parsing JWK")?
            .signature()
            .ok_or(VerificationProtocolError::Failed(
                "signature missing".to_string(),
            ))?
            .public()
            .verify(
                request_token.unverified_jwt.as_bytes(),
                &request_token.signature,
            )
            .error_while("verifying signature")?;

        Ok((request_token.payload.custom, verifier_did))
    }

    async fn parse_referenced_data_from_verifier_attestation_token(
        &self,
        request_token: DecomposedJwt<AuthorizationRequest>,
    ) -> Result<(AuthorizationRequest, Option<DidValue>), VerificationProtocolError> {
        let attestation_jwt = request_token
            .header
            .jwt
            .ok_or(VerificationProtocolError::Failed(
                "attestation JWT missing".to_string(),
            ))?;

        let key_verification: Box<dyn TokenVerifier> = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.to_owned(),
            did_method_provider: self.did_method_provider.to_owned(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.to_owned(),
        });

        /*
         * TODO(ONE-3846): this should be created by some trusted entity, not by current verifier.
         *     Key verification function should only allow trusted entity keys
         */
        let attestation_jwt = Jwt::<OpenID4VCVerifierAttestationPayload>::build_from_token(
            &attestation_jwt,
            Some(&key_verification),
            None,
        )
        .await
        .error_while("parsing attestation JWT")?;

        let (_, alg) = self
            .key_algorithm_provider
            .key_algorithm_from_jose_alg(&request_token.header.algorithm)
            .ok_or(VerificationProtocolError::Failed(format!(
                "Missing algorithm: {}",
                request_token.header.algorithm
            )))?;

        let public_key_cnf = attestation_jwt
            .payload
            .proof_of_possession_key
            .ok_or(VerificationProtocolError::Failed(
                "missing `cnf` in attestation JWT token".to_string(),
            ))?
            .jwk
            .jwk()
            .to_owned();

        alg.parse_jwk(&public_key_cnf)
            .error_while("parsing JWK")?
            .signature()
            .ok_or(VerificationProtocolError::Failed(
                "Signature key missing".to_string(),
            ))?
            .public()
            .verify(
                request_token.unverified_jwt.as_bytes(),
                &request_token.signature,
            )
            .error_while("verifying signature")?;

        validate_against_redirect_uris(
            &attestation_jwt.payload.custom.redirect_uris,
            request_token.payload.custom.redirect_uri.as_deref(),
        )?;
        validate_against_redirect_uris(
            &attestation_jwt.payload.custom.redirect_uris,
            request_token
                .payload
                .custom
                .response_uri
                .as_ref()
                .map(|url| url.as_str()),
        )?;

        let client_id_without_prefix =
            attestation_jwt
                .payload
                .subject
                .ok_or(VerificationProtocolError::Failed(
                    "missing `sub` in attestation JWT token".to_string(),
                ))?;

        Ok((
            AuthorizationRequest {
                client_id: encode_client_id_with_scheme(
                    client_id_without_prefix,
                    ClientIdScheme::VerifierAttestation,
                ),
                ..request_token.payload.custom
            },
            attestation_jwt
                .payload
                .issuer
                .map(DidValue::try_from)
                .transpose()
                .map_err(DidMethodError::DidValueError)
                .error_while("parsing verifier DID")?,
        ))
    }

    async fn retrieve_authorization_params_by_reference(
        &self,
        query_params: AuthorizationRequestQueryParams,
        url: Url,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<(AuthorizationRequest, Option<IdentifierDetails>), VerificationProtocolError> {
        let response = async {
            self.client
                .get(url.as_str())
                .header("Accept", "application/oauth-authz-req+jwt")
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("fetching authorization request")?;

        let token = String::from_utf8(response.body)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        let request_token: DecomposedJwt<AuthorizationRequest> =
            Jwt::decompose_token(&token).error_while("parsing request JWT")?;

        if let Some(audience) = &request_token.payload.audience {
            if audience.len() != 1 {
                tracing::warn!("Invalid `aud` claim, {} items", audience.len());
            } else {
                let aud = audience.first();
                if aud != Some(&"https://self-issued.me/v2".to_string()) {
                    tracing::warn!("Invalid `aud` claim: {aud:?}");
                }
            }
        } else {
            tracing::warn!("`aud` claim missing in request JWT payload");
        }

        let (_, client_id_scheme) =
            decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

        if !self
            .params
            .holder
            .supported_client_id_schemes
            .contains(&client_id_scheme)
        {
            return Err(VerificationProtocolError::InvalidRequest(format!(
                "Unsupported client_id_scheme: {client_id_scheme}"
            )));
        }

        let (referenced_params, verifier_details): (
            AuthorizationRequest,
            Option<IdentifierDetails>,
        ) = match client_id_scheme {
            ClientIdScheme::VerifierAttestation => {
                let (request, did) = self
                    .parse_referenced_data_from_verifier_attestation_token(request_token)
                    .await?;
                (request, did.map(IdentifierDetails::Did))
            }
            ClientIdScheme::RedirectUri => (request_token.payload.custom, None),
            ClientIdScheme::X509SanDns => {
                let (params, certificate) = self
                    .parse_referenced_data_from_x509_san_dns_token(request_token)
                    .await?;
                (params, Some(IdentifierDetails::Certificate(certificate)))
            }
            ClientIdScheme::X509Hash => {
                let (params, certificate) = self
                    .parse_referenced_data_from_x509_hash_token(request_token)
                    .await?;
                (params, Some(IdentifierDetails::Certificate(certificate)))
            }
            ClientIdScheme::Did => {
                let (request, did) = self
                    .parse_referenced_data_from_did_signed_token(request_token)
                    .await?;
                (request, Some(IdentifierDetails::Did(did)))
            }
        };

        // client_id from the query params must match client_id inisde the token
        if referenced_params.client_id != query_params.client_id {
            return Err(VerificationProtocolError::InvalidRequest(
                "client_id mismatch with the request token".to_string(),
            ));
        }

        if self.params.holder.trust_ecosystems_enabled {
            // check access certificate trust
            if let Some(IdentifierDetails::Certificate(access_certificate)) = &verifier_details
                && let Some(access_certificate_trust) = self
                    .handle_access_certificate(access_certificate, proof_id, organisation_id)
                    .await?
            {
                let relying_party_id = &access_certificate_trust.relying_party_id;
                let dcql_query = referenced_params.dcql_query.as_ref().ok_or(
                    VerificationProtocolError::InvalidRequest("missing dcql_query".to_string()),
                )?;

                if referenced_params.verifier_info.is_empty() {
                    let registry_url = access_certificate_trust.registry_url.as_ref().ok_or(
                        VerificationProtocolError::InvalidRequest(
                            "missing registry URL".to_string(),
                        ),
                    )?;

                    self.handle_registry_info(
                        &access_certificate_trust.relying_party_id,
                        registry_url,
                        dcql_query,
                        proof_id,
                        organisation_id,
                    )
                    .await?;
                } else {
                    // check query against registration certificates
                    self.handle_registration_certificates(
                        &referenced_params.verifier_info,
                        dcql_query,
                        relying_party_id,
                        proof_id,
                        organisation_id,
                    )
                    .await?;
                }
            }
        }

        Ok((referenced_params, verifier_details))
    }

    pub(super) async fn request_from_openid4vp_query(
        &self,
        query: &str,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<(AuthorizationRequest, Option<IdentifierDetails>), VerificationProtocolError> {
        let query_params: AuthorizationRequestQueryParams = serde_qs::from_str(query)
            .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

        let (authorization_request, verifier_details) =
            match (&query_params.request_uri, &query_params.request) {
                (Some(_), Some(_)) => {
                    return Err(VerificationProtocolError::InvalidRequest(
                        "request and request_uri cannot be set together".to_string(),
                    ));
                }
                (Some(request_uri), None) => {
                    let request_uri = Url::parse(request_uri)
                        .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

                    if !self.params.allow_insecure_http_transport && request_uri.scheme() != "https"
                    {
                        return Err(VerificationProtocolError::InvalidRequest(
                            "request_uri must use HTTPS scheme".to_string(),
                        ));
                    }

                    Ok::<_, VerificationProtocolError>(
                        self.retrieve_authorization_params_by_reference(
                            query_params,
                            request_uri,
                            proof_id,
                            organisation_id,
                        )
                        .await?,
                    )
                }
                (None, Some(request)) => {
                    let authorization_request = serde_json::from_str(request).map_err(|e| {
                        VerificationProtocolError::InvalidRequest(format!(
                            "Failed to parse request: {e}"
                        ))
                    })?;
                    Ok((authorization_request, None))
                }
                (None, None) => {
                    return Err(VerificationProtocolError::InvalidRequest(
                        "request or request_uri is required".to_string(),
                    ));
                }
            }?;
        Ok((authorization_request, verifier_details))
    }

    async fn handle_access_certificate(
        &self,
        certificate: &CertificateDetails,
        proof_id: ProofId,
        organisation_id: OrganisationId,
    ) -> Result<Option<AccessCertificateResult>, VerificationProtocolError> {
        let result = match self
            .wrp_validator
            .validate_access_certificate_trust(&certificate.chain, Some(organisation_id))
            .await
        {
            Ok(result) => result,
            Err(WRPValidatorError::TrustManagementDisabled) => {
                // trust management disabled, skipping other checks and history creation
                return Ok(None);
            }
            Err(err) => {
                return Err(err.error_while("checking access certificate trust").into());
            }
        };

        let certificate = pem_chain_into_x5c(&certificate.chain)
            .error_while("PEM chain conversion")?
            .into_iter()
            .next()
            .ok_or(VerificationProtocolError::Failed("Empty x5c".to_string()))?;

        self.store_certificate_history_event(
            HistoryAction::WrpAcReceived,
            proof_id,
            organisation_id,
            certificate,
            None,
        )
        .await?;

        Ok(Some(result))
    }

    async fn handle_registration_certificates(
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
            self.store_certificate_history_event(
                HistoryAction::WrpRcReceived,
                proof_id,
                organisation_id,
                used_reg_cert,
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

    async fn handle_registry_info(
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

        self.store_certificate_history_event(
            HistoryAction::WrpNrReceived,
            proof_id,
            organisation_id,
            info.jwt,
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

    async fn store_certificate_history_event(
        &self,
        action: HistoryAction,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        certificate_content: String,
        metadata: Option<HistoryMetadata>,
    ) -> Result<(), VerificationProtocolError> {
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
            .error_while("getting blob storage")?;

        let blob = Blob::new(certificate_content, BlobType::HistoryMetadata);

        let blob_id = blob.id;
        blob_storage
            .create(blob)
            .await
            .error_while("creating history metadata blob")?;

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
                metadata_blob_id: Some(blob_id),
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("storing history")?;

        Ok(())
    }
}

pub(super) fn validate_interaction_data(
    interaction_data: &OpenID4VPHolderInteractionData,
) -> Result<(), VerificationProtocolError> {
    if interaction_data.redirect_uri.is_some() {
        return Err(VerificationProtocolError::InvalidRequest(
            "redirect_uri must be None".to_string(),
        ));
    }

    if interaction_data.presentation_definition.is_some() {
        return Err(VerificationProtocolError::InvalidRequest(
            "presentation_definition must be None".to_string(),
        ));
    }

    if interaction_data.presentation_definition_uri.is_some() {
        return Err(VerificationProtocolError::InvalidRequest(
            "presentation_definition_uri must be None".to_string(),
        ));
    }

    let Some(dcql_query) = &interaction_data.dcql_query else {
        return Err(VerificationProtocolError::InvalidRequest(
            "dcql_query must be set".to_string(),
        ));
    };
    if let Some(credential_sets) = &dcql_query.credential_sets {
        for query_id in credential_sets
            .iter()
            .flat_map(|s| s.options.iter().flatten())
        {
            if !dcql_query.credentials.iter().any(|c| c.id == *query_id) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "invalid DCQL query: credential_set is referring to a non-existing credential query `{query_id}`"
                )));
            }
        }
    }

    let response_type = interaction_data.response_type.as_ref().ok_or(
        VerificationProtocolError::InvalidRequest("response_type is None".to_string()),
    )?;
    assert_query_param(response_type, &["vp_token"], "response_type")?;

    interaction_data
        .response_mode
        .ok_or(VerificationProtocolError::InvalidRequest(
            "response_mode is None".to_string(),
        ))?;

    let Some(OpenID4VPClientMetadata::Final1_0(client_metadata)) =
        interaction_data.client_metadata.as_ref()
    else {
        return Err(VerificationProtocolError::Failed(
            "client_metadata is None".to_string(),
        ));
    };

    let mso_mdoc = client_metadata.vp_formats_supported.get("mso_mdoc");
    let jwt_vc_json = client_metadata.vp_formats_supported.get("jwt_vc_json");
    let ldp_vc = client_metadata.vp_formats_supported.get("ldp_vc");
    let sd_jwt_vc = client_metadata.vp_formats_supported.get("dc+sd-jwt");

    if jwt_vc_json.is_none() && sd_jwt_vc.is_none() && mso_mdoc.is_none() && ldp_vc.is_none() {
        Err(VerificationProtocolError::InvalidRequest(
            "unsupported client_metadata.vp_formats_supported must contain 'jwt_vc_json', 'vc+sd-jwt', 'dc+sd-jwt', 'mso_mdoc', or 'ldp_vc'".to_string(),
        ))?;
    }

    let cose_supported = [-7, -8, -9, -19];
    let jose_supported = ["ES256".to_string(), "EdDSA".to_string()];

    /// find at least one common entry
    fn is_supported<T: Clone + Ord>(remotely_supported: &[T], locally_supported: &[T]) -> bool {
        if remotely_supported.is_empty() {
            return true; // no remotely specified means no known restrictions
        }

        let locally_supported = BTreeSet::from_iter(locally_supported);
        !locally_supported.is_disjoint(&BTreeSet::from_iter(remotely_supported))
    }

    match jwt_vc_json {
        None | Some(PresentationFormat::Empty(_)) => {}
        Some(PresentationFormat::W3CJwtAlgs(jwt_vc_json)) => {
            if !is_supported(&jwt_vc_json.alg_values, &jose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'jwt_vc_json' ({:?}) does not contain a supported algorithm",
                    jwt_vc_json.alg_values
                )));
            }
        }
        Some(_) => {
            Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported entry for 'jwt_vc_json'".to_string(),
            ))?;
        }
    };

    match ldp_vc {
        None | Some(PresentationFormat::Empty(_)) => {}
        Some(PresentationFormat::W3CLdpAlgs(ldp_vc)) => {
            if !is_supported(
                &ldp_vc.proof_type_values,
                &["DataIntegrityProof".to_string()],
            ) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'ldp_vc' ({:?}) must contain 'DataIntegrityProof' proof type",
                    ldp_vc.proof_type_values
                )));
            }

            if !is_supported(
                &ldp_vc.cryptosuite_values,
                &[
                    "bbs-2023".to_string(),
                    "ecdsa-rdfc-2019".to_string(),
                    "eddsa-rdfc-2022".to_string(),
                ],
            ) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'ldp_vc' ({:?}) does not contain a supported cryptosuite",
                    ldp_vc.cryptosuite_values
                )));
            }
        }
        Some(_) => {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported entry for 'ldp_vc'".to_string(),
            ));
        }
    }

    match sd_jwt_vc {
        None | Some(PresentationFormat::Empty(_)) => {}
        Some(PresentationFormat::SdJwtVcAlgs(sd_jwt_vc)) => {
            if !is_supported(&sd_jwt_vc.sd_jwt_alg_values, &jose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'dc+sd-jwt' ({:?}) does not contain a supported algorithm",
                    sd_jwt_vc.sd_jwt_alg_values
                )));
            }

            if !is_supported(&sd_jwt_vc.kb_jwt_alg_values, &jose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'dc+sd-jwt' ({:?}) does not contain a supported algorithm",
                    sd_jwt_vc.kb_jwt_alg_values
                )));
            }
        }
        Some(_) => {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported[\"dc+sd-jwt\"] structure".to_string(),
            ));
        }
    };

    // As per section B.3.2.3.2, ISO/IEC DTS 18013-7, an empty object is allowed
    match mso_mdoc {
        None
        | Some(PresentationFormat::Empty(_))
        // EUDI compatibility shim: allow null object and null values
        | Some(PresentationFormat::Other(serde_json::Value::Null)) => {}
         Some(PresentationFormat::Other(val)) if *val == json!({
                "issuerauth_alg_values": null,
                "deviceauth_alg_values": null
            }) => {}
        Some(PresentationFormat::MdocAlgs(mso_mdoc)) => {
            if !is_supported(&mso_mdoc.issuerauth_alg_values, &cose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'mso_mdoc' ({:?}) do not contain supported algorithms",
                    mso_mdoc.issuerauth_alg_values
                )));
            }

            if !is_supported(&mso_mdoc.deviceauth_alg_values, &cose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'mso_mdoc' ({:?}) do not contain supported algorithms",
                    mso_mdoc.deviceauth_alg_values
                )));
            }
        }
        Some(_) => {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported entry for 'mso_mdoc'".to_string(),
            ));
        }
    };

    let Some(response_uri) = interaction_data.response_uri.as_ref() else {
        return Err(VerificationProtocolError::InvalidRequest(
            "response_uri must be set".to_string(),
        ));
    };
    if interaction_data.client_id_scheme == ClientIdScheme::RedirectUri
        && interaction_data.client_id.as_str() != response_uri.as_str()
    {
        return Err(VerificationProtocolError::InvalidRequest(
            "client_id must match response_uri for client_id_scheme=redirect_uri".to_string(),
        ));
    }

    if interaction_data.nonce.is_none() {
        return Err(VerificationProtocolError::InvalidRequest(
            "nonce must be set".to_string(),
        ));
    }

    Ok(())
}

fn assert_query_param(
    value: &str,
    expected_values: &[&str],
    key: &str,
) -> Result<(), VerificationProtocolError> {
    if !expected_values.contains(&value) {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "{key} must be one of '[{}]'",
            expected_values.join(", ")
        )));
    }
    Ok(())
}

fn find_matching_intended_use(
    credential_query: &dcql::CredentialQuery,
    among_uses: &[wrp_validator::model::IntendedUse],
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
