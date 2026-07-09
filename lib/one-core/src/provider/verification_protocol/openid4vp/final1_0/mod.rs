use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use dcql::create_dcql_query;
use futures::future::BoxFuture;
use indexmap::IndexMap;
use mappers::{create_openid4vp_final1_0_authorization_request, encode_client_id_with_scheme};
use model::Params;
use one_crypto::utilities;
use one_dto_mapper::convert_inner;
use proc_macros::Provider;
use serde_json::Value;
use shared_types::TransactionDataId;
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::ResponseMode;
use time::Duration;
use url::Url;
use utils::validate_interaction_data;
use uuid::Uuid;

use super::jwe_presentation::{self, encryption_key_from_metadata};
use super::mapper::{format_to_type, unencrypted_params};
use super::mdoc::mdoc_presentation_context;
use crate::config::core_config::{
    CoreConfig, DidType, FormatType, IdentifierType, TransportType, VerificationProtocolType,
};
use crate::error::ContextWithErrorCode;
use crate::model::did::Did;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::session_provider::SessionProvider;
use crate::proto::trust_information::TrustInformationProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{CredentialToPresent, FormatPresentationCtx};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::Handover;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::openid4vp_final1_0::OID4VPFinal1_0Handover;
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::transaction_data::processed_transaction_data::ProcessedTransactionData;
use crate::provider::transaction_data::provider::TransactionDataProvider;
use crate::provider::verification_protocol::dto::{
    Feature, FormattedCredentialPresentation, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, ShareResponse,
    UpdateResponse, VerificationProtocolCapabilities,
};
use crate::provider::verification_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::verification_protocol::openid4vp::dcql::get_presentation_definition_v2;
use crate::provider::verification_protocol::openid4vp::final1_0::mappers::create_open_id_for_vp_client_metadata_final1_0;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, DcqlSubmission, HolderTxData, JwePayload, OpenID4VPDirectPostResponseDTO,
    OpenID4VPHolderInteractionData, OpenID4VPVerifierInteractionContent, ValidatedHolderTxData,
    VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, VerificationProtocolError, get_client_id_scheme,
};
use crate::provider::verification_protocol::{
    VerificationProtocol, deserialize_interaction_data, serialize_interaction_data,
};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::oid4vp_final1_0::proof_request::{
    generate_authorization_request_params_final1_0, select_key_agreement_key_from_proof,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;

pub(super) mod dcql;
pub mod mappers;
pub mod model;
#[cfg(test)]
mod test;
mod trust;
mod utils;

const DCQL_QUERY_VALUE_QUERY_PARAM_KEY: &str = "dcql_query";
const REQUEST_URI_QUERY_PARAM_KEY: &str = "request_uri";
const REQUEST_QUERY_PARAM_KEY: &str = "request";
const CLIENT_ID_SCHEME_QUERY_PARAM_KEY: &str = "client_id_scheme";
const PROXIMITY_QUERY_PARAM_KEY: &str = "key";

#[derive(Provider)]
pub(crate) struct OpenID4VPFinal1_0 {
    config_id: String,
    client: Arc<dyn HttpClient>,
    credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
    presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    session_provider: Arc<dyn SessionProvider>,
    wrp_validator: Arc<dyn WRPValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    trust_information_provider: Arc<dyn TrustInformationProvider>,
    transaction_data_provider: Arc<dyn TransactionDataProvider>,
    base_url: Option<String>,
    params: Params,
    config: Arc<CoreConfig>,
}

struct EncryptionInfo {
    verifier_key: PublicJwk,
    supported_algorithms: Vec<EncryptionAlgorithm>,
}

impl OpenID4VPFinal1_0 {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: String,
        base_url: Option<String>,
        credential_formatter_provider: Arc<dyn CredentialFormatterProvider>,
        presentation_formatter_provider: Arc<dyn PresentationFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        session_provider: Arc<dyn SessionProvider>,
        wrp_validator: Arc<dyn WRPValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        trust_information_provider: Arc<dyn TrustInformationProvider>,
        transaction_data_provider: Arc<dyn TransactionDataProvider>,
        client: Arc<dyn HttpClient>,
        params: serde_json::Value,
        config: Arc<CoreConfig>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            base_url,
            credential_formatter_provider,
            presentation_formatter_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            certificate_validator,
            credential_repository,
            credential_schema_repository,
            history_repository,
            interaction_repository,
            session_provider,
            wrp_validator,
            client,
            params,
            config,
            blob_storage_provider,
            trust_information_provider,
            transaction_data_provider,
        })
    }

    async fn encryption_info_from_metadata(
        &self,
        interaction_data: &OpenID4VPHolderInteractionData,
    ) -> Result<Option<EncryptionInfo>, VerificationProtocolError> {
        let Some(mut client_metadata) = interaction_data.client_metadata.clone() else {
            return Err(VerificationProtocolError::InvalidRequest(
                "failed to parse interaction_data".to_string(),
            ));
        };

        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-encrypted-responses
        // When a response_mode requires encryption (direct_post.jwt),
        // this MUST be present for anything other than the default single value of A128GCM.
        // Otherwise, this SHOULD be absent.
        let supported_encryption_algs = client_metadata
            .encrypted_response_enc_values_supported
            .clone()
            .unwrap_or(vec![EncryptionAlgorithm::A128GCM]);

        if client_metadata
            .jwks
            .as_ref()
            .map(|jwks| jwks.keys.is_empty())
            .unwrap_or(true)
            && let Some(ref uri) = client_metadata.jwks_uri
        {
            let jwks = async { self.client.get(uri).send().await?.error_for_status() }
                .await
                .error_while("fetching JWKs")?;

            client_metadata.jwks = jwks.json().error_while("parsing JWKs")?;
        }
        let Some(verifier_key) =
            encryption_key_from_metadata(client_metadata, self.key_algorithm_provider.as_ref())
        else {
            return Ok(None);
        };
        Ok(Some(EncryptionInfo {
            verifier_key,
            supported_algorithms: supported_encryption_algs,
        }))
    }

    async fn dcql_submission_data(
        &self,
        credential_presentations: Vec<FormattedCredentialPresentation>,
        interaction_data: &OpenID4VPHolderInteractionData,
    ) -> Result<(VpSubmissionData, Option<EncryptionInfo>), VerificationProtocolError> {
        let mut vp_token = HashMap::new();

        let response_mode =
            interaction_data
                .response_mode
                .ok_or(VerificationProtocolError::InvalidRequest(
                    "response_mode is None".to_string(),
                ))?;

        // As per https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3.1
        // the response should be encrypted only if the response type is direct_post.jwt
        let encryption_info = match response_mode {
            ResponseMode::DirectPost => None,
            ResponseMode::DirectPostJwt => Some(
                self.encryption_info_from_metadata(interaction_data)
                    .await?
                    .ok_or(VerificationProtocolError::InvalidRequest(
                        "direct_post.jwt requires encryption, but no verifier keys are available"
                            .to_string(),
                    ))?,
            ),
        };

        // Ordering of assigned transaction data matches credential_presentations
        let assigned_tx_data =
            assign_transaction_data(&credential_presentations, interaction_data)?;

        // For DCQL each credential gets a presentation individually
        for (credential_presentation, assigned_tx_data) in
            credential_presentations.into_iter().zip(assigned_tx_data)
        {
            let credential_query_id = credential_presentation.credential_query_id.clone();

            // Look up the credential query to check require_cryptographic_holder_binding
            let require_holder_binding = interaction_data
                .dcql_query
                .as_ref()
                .and_then(|query| {
                    query
                        .credentials
                        .iter()
                        .find(|cq| cq.id == credential_query_id)
                })
                .map(|cq| cq.require_cryptographic_holder_binding)
                .unwrap_or(true);

            if require_holder_binding {
                let credential_format =
                    format_to_type(&credential_presentation, &self.config).await?;
                let presentation_format = match credential_format {
                    FormatType::SdJwt => FormatType::SdJwt,
                    FormatType::SdJwtVc => FormatType::SdJwtVc,
                    FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => {
                        FormatType::JsonLdClassic
                    }
                    FormatType::Mdoc => FormatType::Mdoc,
                    FormatType::Jwt => FormatType::Jwt,
                };

                let presentation_formatter = self
                    .presentation_formatter_provider
                    .get_presentation_formatter(&presentation_format.to_string())
                    .ok_or_else(|| {
                        VerificationProtocolError::Failed("Formatter not found".to_string())
                    })?;

                let auth_fn = self.key_provider.get_signature_provider(
                    &credential_presentation.key,
                    credential_presentation.jwk_key_id,
                    self.key_algorithm_provider.clone(),
                )?;
                let mut aggregated_tx_data = None;
                for tx_data in assigned_tx_data {
                    let data = self
                        .transaction_data_provider
                        .get_transaction_data(&tx_data)?;
                    let processed = data
                        .process_transaction_data(&tx_data, credential_format)
                        .await
                        .error_while("processing transaction data")?;
                    let Some(existing) = aggregated_tx_data.as_mut() else {
                        aggregated_tx_data = Some(processed);
                        continue;
                    };
                    existing
                        .merge(processed)
                        .error_while("merging transaction data")?;
                }

                let credentials = CredentialToPresent {
                    credential_token: credential_presentation.presentation,
                    credential_format,
                };
                let formatted_presentation = presentation_formatter
                    .format_presentation(
                        vec![credentials],
                        auth_fn,
                        format_presentation_context(
                            interaction_data,
                            presentation_format,
                            self.params.use_legacy_did_client_id_scheme,
                            credential_presentation.holder_did,
                            aggregated_tx_data,
                        )?,
                    )
                    .await
                    .error_while("formatting presentation")?;

                vp_token
                    .entry(credential_query_id.to_string())
                    .and_modify(|presentations: &mut Vec<String>| {
                        presentations.push(formatted_presentation.vp_token.to_owned())
                    })
                    .or_insert(vec![formatted_presentation.vp_token]);
            } else {
                // No holder binding — send bare credential tokens without VP wrapper
                let tokens = vp_token.entry(credential_query_id.to_string()).or_default();
                tokens.push(credential_presentation.presentation);
            }
        }
        Ok((
            VpSubmissionData::Dcql(DcqlSubmission { vp_token }),
            encryption_info,
        ))
    }

    async fn handle_proof_invitation(
        &self,
        url: Url,
        organisation: Organisation,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        let query = url
            .query()
            .ok_or(VerificationProtocolError::InvalidRequest(
                "Query cannot be empty".to_string(),
            ))?;

        let proof_id = Uuid::new_v4().into();
        let mut holder_interaction_data = {
            let (authorization_request, verifier_details) = self
                .request_from_openid4vp_query(query, proof_id, organisation.id)
                .await?;

            let mut interaction_data: OpenID4VPHolderInteractionData =
                authorization_request.try_into()?;
            interaction_data.verifier_details = verifier_details;
            if let Some(predefined_metadata) = &self.params.predefined_client_metadata {
                interaction_data.client_metadata = Some(predefined_metadata.clone());
            }
            interaction_data
        };

        validate_interaction_data(&holder_interaction_data)?;
        self.process_transaction_data(&mut holder_interaction_data)?;
        let data = serialize_interaction_data(&holder_interaction_data)?;

        let Some(_) = holder_interaction_data.response_uri else {
            return Err(VerificationProtocolError::Failed(
                "response_uri is missing".to_string(),
            ));
        };

        let now = crate::clock::now_utc();
        let interaction = create_and_store_interaction(
            self.interaction_repository.as_ref(),
            data,
            Some(organisation),
        )
        .await?;
        let interaction_id = interaction.id;

        let proof = proof_from_handle_invitation(
            &proof_id,
            VerificationProtocolType::OpenId4VpFinal1_0.as_ref(),
            holder_interaction_data.redirect_uri,
            None,
            interaction,
            now,
            "HTTP",
            ProofStateEnum::Requested,
        );

        Ok(InvitationResponseDTO {
            interaction_id,
            proof,
        })
    }

    fn process_transaction_data(
        &self,
        holder_interaction_data: &mut OpenID4VPHolderInteractionData,
    ) -> Result<(), VerificationProtocolError> {
        if let HolderTxData::Unvalidated(transaction_data) =
            &holder_interaction_data.transaction_data
        {
            let mut validated_tx_data = IndexMap::with_capacity(transaction_data.len());
            let dcql_query = holder_interaction_data.dcql_query.as_ref().ok_or(
                VerificationProtocolError::InvalidRequest("missing DCQL query".to_string()),
            )?;
            for (idx, tx_data) in transaction_data.iter().enumerate() {
                let data = self
                    .transaction_data_provider
                    .get_transaction_data(tx_data)?;
                let validated = data
                    .validate_transaction_data(tx_data)
                    .error_while("validating transaction data")?;

                for credential_query_id in &validated.credential_ids {
                    let Some(query) = dcql_query
                        .credentials
                        .iter()
                        .find(|c| &c.id == credential_query_id)
                    else {
                        return Err(VerificationProtocolError::InvalidRequest(format!(
                            "Invalid transaction data at index {idx}: credential query id `{}` not found in DCQL query",
                            credential_query_id
                        )));
                    };
                    if !query.require_cryptographic_holder_binding {
                        return Err(VerificationProtocolError::InvalidRequest(format!(
                            "Invalid transaction data at index {idx}: referenced credential query `{}` does not require cryptographic holder binding",
                            credential_query_id
                        )));
                    }
                }

                validated_tx_data.insert(
                    TransactionDataId::from(Uuid::new_v4()),
                    ValidatedHolderTxData {
                        raw: tx_data.clone(),
                        credential_query_ids: convert_inner(validated.credential_ids),
                    },
                );
            }
            holder_interaction_data.transaction_data = HolderTxData::Validated(validated_tx_data);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl VerificationProtocol for OpenID4VPFinal1_0 {
    async fn retract_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        Ok(())
    }

    fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.params.url_scheme == url.scheme()
            && !query_has_key(PROXIMITY_QUERY_PARAM_KEY) // Ensure we do not match proximity URLs
            && (!query_has_key(CLIENT_ID_SCHEME_QUERY_PARAM_KEY)
            || query_has_key(DCQL_QUERY_VALUE_QUERY_PARAM_KEY)
            || query_has_key(REQUEST_URI_QUERY_PARAM_KEY)
            || query_has_key(REQUEST_QUERY_PARAM_KEY))
    }

    fn get_capabilities(&self) -> VerificationProtocolCapabilities {
        let did_methods = vec![DidType::Key, DidType::Jwk, DidType::Web, DidType::WebVh];
        let mut verifier_identifier_types = HashSet::new();
        let schemes = &self.params.verifier.supported_client_id_schemes;
        let mut features = vec![];

        if self.params.common.webhook_task.is_some() {
            features.push(Feature::SupportsWebhooks);
        }

        if [
            ClientIdScheme::Did,
            ClientIdScheme::RedirectUri,
            ClientIdScheme::VerifierAttestation,
        ]
        .iter()
        .any(|scheme| schemes.contains(scheme))
        {
            verifier_identifier_types.insert(IdentifierType::Did);
        }

        if schemes.contains(&ClientIdScheme::X509SanDns)
            || schemes.contains(&ClientIdScheme::X509Hash)
        {
            verifier_identifier_types.insert(IdentifierType::Certificate);
        }

        VerificationProtocolCapabilities {
            features,
            supported_transports: vec![TransportType::Http],
            did_methods,
            verifier_identifier_types: verifier_identifier_types.into_iter().collect(),
            supported_presentation_definition: vec![PresentationDefinitionVersion::V2],
        }
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        _transport: String,
    ) -> Result<InvitationResponseDTO, VerificationProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(VerificationProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        }

        self.handle_proof_invitation(url, organisation).await
    }

    async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), VerificationProtocolError> {
        // Rejection not supported and handled as no-op on holder side
        Ok(())
    }

    async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<FormattedCredentialPresentation>,
    ) -> Result<UpdateResponse, VerificationProtocolError> {
        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let interaction_data: OpenID4VPHolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;
        let holder_nonce = utilities::generate_alphanumeric(32);

        let (submission_data, encryption_info) = self
            .dcql_submission_data(credential_presentations, &interaction_data)
            .await?;

        let response_uri =
            interaction_data
                .response_uri
                .clone()
                .ok_or(VerificationProtocolError::Failed(
                    "response_uri is None".to_string(),
                ))?;

        let params = if let Some(EncryptionInfo {
            verifier_key,
            supported_algorithms,
        }) = encryption_info
        {
            encrypted_params(
                interaction_data,
                submission_data,
                &holder_nonce,
                verifier_key,
                supported_algorithms,
                &*self.key_algorithm_provider,
            )
            .await?
        } else {
            unencrypted_params(&submission_data, interaction_data.state.clone())?
        };

        let response = async {
            self.client
                .post(response_uri.as_str())
                .form(&params)?
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("posting submission")?;

        let response: Result<OpenID4VPDirectPostResponseDTO, _> = response.json();

        if let Ok(value) = response {
            Ok(UpdateResponse {
                update_proof: Some(UpdateProofRequest {
                    redirect_uri: Some(value.redirect_uri),
                    ..Default::default()
                }),
            })
        } else {
            Ok(UpdateResponse { update_proof: None })
        }
    }

    async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper,
        _callback: Option<BoxFuture<'static, ()>>,
        params: Option<ShareProofRequestParamsDTO>,
    ) -> Result<ShareResponse, VerificationProtocolError> {
        let interaction_id = Uuid::new_v4().into();

        let Some(base_url) = &self.base_url else {
            return Err(VerificationProtocolError::Failed("Missing base_url".into()));
        };
        let response_uri = format!("{base_url}/ssi/openid4vp/final-1.0/response");
        let nonce = utilities::generate_alphanumeric(32);

        let verifier_identifier =
            proof
                .clone()
                .verifier_identifier
                .ok_or(VerificationProtocolError::Failed(
                    "Missing verifier identifier".to_string(),
                ))?;

        let client_id_scheme = get_client_id_scheme(
            params,
            &self.params.verifier.supported_client_id_schemes,
            verifier_identifier,
        )?;

        if !self
            .params
            .verifier
            .supported_client_id_schemes
            .contains(&client_id_scheme)
        {
            return Err(VerificationProtocolError::InvalidRequest(
                "Unsupported client_id_scheme".into(),
            ));
        }

        let client_id_without_prefix = match client_id_scheme {
            ClientIdScheme::RedirectUri | ClientIdScheme::VerifierAttestation => {
                response_uri.to_owned()
            }
            ClientIdScheme::X509SanDns => {
                let base_url = Url::parse(base_url)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

                base_url
                    .domain()
                    .ok_or(VerificationProtocolError::Failed(
                        "Invalid base_url".to_string(),
                    ))?
                    .to_string()
            }
            ClientIdScheme::X509Hash => {
                let verifier_certificate = proof.verifier_certificate.as_ref().ok_or(
                    VerificationProtocolError::Failed("verifier_certificate is None".to_string()),
                )?;

                let fingerprint = hex::decode(&verifier_certificate.fingerprint)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

                Base64UrlSafeNoPadding::encode_to_string(fingerprint)?
            }
            ClientIdScheme::Did => proof
                .verifier_identifier
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "proof is missing verifier_identifier, required for did client_id_scheme"
                        .to_string(),
                ))?
                .did
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "proof is missing verifier_did, required for did client_id_scheme".to_string(),
                ))?
                .as_ref()
                .await?
                .did
                .to_string(),
        };

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Proof schema not found".to_string(),
            ))?;

        let key_agreement_key =
            select_key_agreement_key_from_proof(proof, &*self.key_algorithm_provider, &self.config)
                .await?;

        let client_metadata = create_open_id_for_vp_client_metadata_final1_0(key_agreement_key)?;
        let encryption_key = client_metadata
            .jwks
            .as_ref()
            .and_then(|jwks| jwks.keys.first())
            .cloned();

        let authorization_request = generate_authorization_request_params_final1_0(
            nonce.clone(),
            create_dcql_query(
                proof_schema,
                &format_to_type_mapper,
                &*self.credential_formatter_provider,
            )
            .await?,
            vec![],
            encode_client_id_with_scheme(
                client_id_without_prefix.clone(),
                client_id_scheme,
                self.params.use_legacy_did_client_id_scheme,
            ),
            response_uri.clone(),
            &interaction_id,
            client_metadata,
            vec![],
        )?;

        let interaction_content = OpenID4VPVerifierInteractionContent {
            nonce,
            client_id: authorization_request.client_id.clone(),
            dcql_query: authorization_request.dcql_query.clone(),
            encryption_key,
            client_id_scheme: Some(client_id_scheme),
            response_uri: Some(response_uri),
            transaction_data: vec![],
        };

        let authorization_request = create_openid4vp_final1_0_authorization_request(
            base_url,
            &self.params,
            client_id_without_prefix,
            proof,
            client_id_scheme,
            &self.key_algorithm_provider,
            &*self.key_provider,
            authorization_request,
        )
        .await?;

        let encoded_authorization_request = serde_urlencoded::to_string(authorization_request)?;

        let expires_at = self
            .params
            .verifier
            .interaction_expires_in
            .map(|interaction_expires_in| crate::clock::now_utc() + interaction_expires_in);

        Ok(ShareResponse {
            url: format!(
                "{}://?{encoded_authorization_request}",
                self.params.url_scheme
            ),
            interaction_id,
            interaction_data: Some(serialize_interaction_data(&interaction_content)?),
            expires_at,
        })
    }

    async fn holder_get_presentation_definition_v2(
        &self,
        proof: &Proof,
        context: Value,
    ) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
        let interaction_data: OpenID4VPHolderInteractionData = serde_json::from_value(context)?;

        let dcql_query = interaction_data
            .dcql_query
            .ok_or(VerificationProtocolError::Failed(
                "missing dcql_query".to_string(),
            ))?;

        get_presentation_definition_v2(
            dcql_query,
            proof,
            &*self.credential_repository,
            &*self.credential_schema_repository,
            &*self.credential_formatter_provider,
            &*self.trust_information_provider,
            &*self.wrp_validator,
            &self.config,
            interaction_data.verifier_details.as_ref(),
            &interaction_data.verifier_info,
        )
        .await
    }

    fn config_name(&self) -> &str {
        &self.config_id
    }
}

fn format_presentation_context(
    interaction_data: &OpenID4VPHolderInteractionData,
    presentation_format: FormatType,
    use_legacy_did_client_id_scheme: bool,
    holder_did: Option<Did>,
    transaction_data: Option<ProcessedTransactionData>,
) -> Result<FormatPresentationCtx, VerificationProtocolError> {
    let verifier_nonce =
        interaction_data
            .nonce
            .clone()
            .ok_or(VerificationProtocolError::Failed(
                "nonce is None".to_string(),
            ))?;
    let response_uri =
        interaction_data
            .response_uri
            .clone()
            .ok_or(VerificationProtocolError::Failed(
                "response_uri is None".to_string(),
            ))?;
    let ctx = if presentation_format == FormatType::Mdoc {
        let Some(metadata) = &interaction_data.client_metadata else {
            return Err(VerificationProtocolError::Failed(
                "missing or invalid client_metadata".to_string(),
            ));
        };

        let encryption_key = if interaction_data.response_mode == Some(ResponseMode::DirectPostJwt)
        {
            metadata
                .jwks
                .as_ref()
                .and_then(|jwks| jwks.keys.first())
                .cloned()
        } else {
            None
        };

        let handover = OID4VPFinal1_0Handover::compute(
            &encode_client_id_with_scheme(
                interaction_data.client_id.clone(),
                interaction_data.client_id_scheme,
                use_legacy_did_client_id_scheme,
            ),
            response_uri.as_str(),
            &verifier_nonce,
            encryption_key.as_ref(),
        )
        .error_while("computing handover")?;
        mdoc_presentation_context(Handover::OID4VPFinal1_0(handover), transaction_data)?
    } else {
        FormatPresentationCtx {
            nonce: Some(verifier_nonce),
            audience: Some(encode_client_id_with_scheme(
                interaction_data.client_id.clone(),
                interaction_data.client_id_scheme,
                use_legacy_did_client_id_scheme,
            )),
            holder_did: holder_did.map(|did| did.did),
            transaction_data,
            ..Default::default()
        }
    };
    Ok(ctx)
}

async fn encrypted_params(
    interaction_data: OpenID4VPHolderInteractionData,
    submission_data: VpSubmissionData,
    holder_nonce: &str,
    verifier_key: PublicJwk,
    encryption_algorithms: Vec<EncryptionAlgorithm>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<HashMap<String, String>, VerificationProtocolError> {
    let aud = interaction_data
        .response_uri
        .ok_or(VerificationProtocolError::Failed(
            "response_uri is None".to_string(),
        ))?;
    let verifier_nonce = interaction_data
        .nonce
        .ok_or(VerificationProtocolError::Failed(
            "nonce is None".to_string(),
        ))?;
    let payload = JwePayload {
        aud: Some(aud),
        exp: Some(crate::clock::now_utc() + Duration::minutes(10)),
        submission_data,
        state: interaction_data.state,
    };

    // All algorithms defined in the AuthorizationEncryptedResponseContentEncryptionAlgorithm enum are supported
    // we pick the first one
    let selected_encryption_alg =
        encryption_algorithms
            .first()
            .cloned()
            .ok_or(VerificationProtocolError::Failed(
                "metadata contains no encrypted_response_enc_values_supported entries".to_string(),
            ))?;

    let response = jwe_presentation::build_jwe(
        payload,
        verifier_key,
        holder_nonce,
        &verifier_nonce,
        selected_encryption_alg,
        key_algorithm_provider,
    )
    .await
    .map_err(VerificationProtocolError::Other)?;
    Ok(HashMap::from_iter([("response".to_owned(), response)]))
}

async fn create_and_store_interaction(
    interaction_repository: &dyn InteractionRepository,
    data: Vec<u8>,
    organisation: Option<Organisation>,
) -> Result<Interaction, VerificationProtocolError> {
    let now = crate::clock::now_utc();

    let interaction = interaction_from_handle_invitation(Some(data), now, organisation);

    interaction_repository
        .create_interaction(interaction.clone())
        .await
        .error_while("creating interaction")?;

    Ok(interaction)
}

fn assign_transaction_data(
    credential_presentations: &[FormattedCredentialPresentation],
    interaction_data: &OpenID4VPHolderInteractionData,
) -> Result<Vec<Vec<String>>, VerificationProtocolError> {
    let mut transaction_data = match &interaction_data.transaction_data {
        HolderTxData::Validated(transaction_data) => transaction_data.clone(),
        HolderTxData::Unvalidated(data) if data.is_empty() => IndexMap::new(),
        _ => {
            return Err(VerificationProtocolError::Failed(
                "unvalidated transaction data".to_string(),
            ));
        }
    };

    // Assign transaction data entries to credential presentations. Explicit
    // client selections (across all credentials) are honored first, then any
    // remaining entries are auto-assigned to the first applicable credential.
    let mut assignments: Vec<Vec<String>> = vec![Vec::new(); credential_presentations.len()];

    // explicit transaction data selections
    for (credential_presentation, assignment) in
        credential_presentations.iter().zip(assignments.iter_mut())
    {
        for tx_id in &credential_presentation.transaction_data_ids {
            let Some(tx_data) = transaction_data.shift_remove(tx_id) else {
                return Err(VerificationProtocolError::InvalidTransactionDataAssignment(
                    format!("unknown or already-selected transaction data id {tx_id}"),
                ));
            };
            if !tx_data
                .credential_query_ids
                .contains(&credential_presentation.credential_query_id)
            {
                return Err(VerificationProtocolError::InvalidTransactionDataAssignment(
                    format!(
                        "transaction data {tx_id} is not applicable to the selected credential"
                    ),
                ));
            }
            assignment.push(tx_data.raw);
        }
    }

    // auto-assign remaining transaction data entries
    for (credential_presentation, assignment) in
        credential_presentations.iter().zip(assignments.iter_mut())
    {
        let applicable_keys: Vec<TransactionDataId> = transaction_data
            .iter()
            .filter(|(_, tx)| {
                tx.credential_query_ids
                    .contains(&credential_presentation.credential_query_id)
            })
            .map(|(id, _)| *id)
            .collect();
        for key in applicable_keys {
            if let Some(tx_data) = transaction_data.shift_remove(&key) {
                assignment.push(tx_data.raw);
            }
        }
    }

    if !transaction_data.is_empty() {
        return Err(VerificationProtocolError::InvalidTransactionDataAssignment(
            format!(
                "Not all transaction data entries were assigned to a credential query id. Transaction data entries remaining: [{}]",
                &transaction_data
                    .keys()
                    .map(|k| k.to_string())
                    .collect::<Vec<String>>()
                    .join(",")
            ),
        ));
    }

    Ok(assignments)
}
