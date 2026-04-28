//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use indexmap::IndexMap;
use one_crypto::encryption::{decrypt_string, encrypt_string};
use one_crypto::utilities::generate_alphanumeric;
use one_dto_mapper::convert_inner;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use shared_types::{
    BlobId, CredentialFormat, CredentialId, CredentialSchemaId, DidValue, InteractionId,
    OrganisationId,
};
use standardized_types::jwk::PublicJwk;
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::dto::{ContinueIssuanceDTO, Features, IssuanceProtocolCapabilities};
use super::error::TxCodeError;
use super::mapper::{get_issued_credential_update, interaction_from_handle_invitation};
use super::model::{
    ContinueIssuanceResponseDTO, InvitationResponseEnum, KeyStorageSecurityLevel, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
};
use super::openid4vci_final1_0::mapper::{
    credential_config_to_holder_signing_algs_and_key_storage_security, get_credential_offer_url,
    interaction_data_to_accepted_key_storage_security, map_cryptographic_binding_methods_supported,
    map_proof_types_supported, parse_credential_issuer_params,
};
use super::openid4vci_final1_0::model::{
    ChallengeResponseDTO, EtsiIssuerInfoAttestationFormat, EtsiIssuerInfoResponseDTO,
    HolderInteractionData, OAuthAuthorizationServerMetadata, OpenID4VCIAuthorizationCodeGrant,
    OpenID4VCICredentialConfigurationData, OpenID4VCICredentialRequestDTO, OpenID4VCIFinal1Params,
    OpenID4VCIGrants, OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCINonceResponseDTO, OpenID4VCINotificationEvent, OpenID4VCINotificationRequestDTO,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO, PreparedMetadata,
};
use super::openid4vci_final1_0::proof_formatter::OpenID4VCIProofJWTFormatter;
use super::openid4vci_final1_0::service::{
    create_credential_offer, create_issuer_metadata_response, credential_configurations_supported,
    get_protocol_base_url,
};
use super::{
    HolderBindingInput, IssuanceProtocol, IssuanceProtocolError, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::clock::now_utc;
use crate::config::core_config::{CoreConfig, DidType as ConfigDidType, FormatType};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::certificate::CertificateRelations;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{Credential, CredentialRelations, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, KeyStorageSecurity, LayoutType, UpdateCredentialSchemaRequest,
};
use crate::model::did::KeyRole;
use crate::model::history::{HistoryAction, HistoryMetadata, WalletRelyingPartyMetadata};
use crate::model::holder_wallet_instance::HolderWalletInstance;
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierType};
use crate::model::identifier_trust_information::{IdentifierTrustInformation, SchemaFormat};
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::Organisation;
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::model::wallet_instance::WalletInstanceStatus;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::{
    IdentifierCreator, IdentifierRole, RemoteIdentifierRelation,
};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{DecomposedJwt, JWTPayload};
use crate::proto::key_verification::KeyVerification;
use crate::proto::session_provider::SessionProvider;
use crate::proto::wallet_unit::{HolderWalletUnitProto, IssueWalletAttestationRequest};
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::error::WRPValidatorError;
use crate::proto::wrp_validator::model::AccessCertificateResult;
use crate::provider::blob_storage_provider::{BlobStorageProvider, BlobStorageType};
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CertificateDetails, IdentifierDetails, VerificationFn,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::error::OpenIDIssuanceError;
use crate::provider::issuance_protocol::mapper::{
    autogenerate_holder_binding, generate_transaction_code,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialRequestIdentifier, OpenID4VCICredentialRequestProofs,
    OpenID4VCIFinal1CredentialOfferDTO, TokenRequestWalletAttestationRequest,
    WalletAttestationResult,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::holder_wallet_instance_repository::HolderWalletInstanceRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::credential::dto::CredentialAttestationBlobs;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::MissingProviderError;
use crate::service::oid4vci_final1_0::dto::{
    OAuthAuthorizationServerMetadataResponseDTO, OpenID4VCICredentialResponseDTO,
};
use crate::service::ssi_holder::dto::InitiateIssuanceAuthorizationDetailDTO;
use crate::util::key_selection::KeyFilter;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;
use crate::validator::key_security::match_key_security_level;
use crate::validator::validate_issuance_time;

pub(crate) mod mapper;
pub mod model;
pub mod proof_formatter;
pub mod service;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_issuance;
mod trust;
pub mod validator;

const CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY: &str = "credential_offer";
const CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY: &str = "credential_offer_uri";

pub(crate) struct OpenID4VCIFinal1_0 {
    client: Arc<dyn HttpClient>,
    metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
    credential_repository: Arc<dyn CredentialRepository>,
    key_repository: Arc<dyn KeyRepository>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
    base_url: Option<String>,
    protocol_base_url: Option<String>,
    config: Arc<CoreConfig>,
    params: OpenID4VCIFinal1Params,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    config_id: String,
    holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletInstanceRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    wrp_validator: Arc<dyn WRPValidator>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
    interaction_repository: Arc<dyn InteractionRepository>,
}

impl OpenID4VCIFinal1_0 {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
        credential_repository: Arc<dyn CredentialRepository>,
        key_repository: Arc<dyn KeyRepository>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIFinal1Params,
        config_id: String,
        holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletInstanceRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        wrp_validator: Arc<dyn WRPValidator>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Self {
        let protocol_base_url = base_url.as_ref().map(|url| get_protocol_base_url(url));
        Self {
            client,
            metadata_cache,
            credential_repository,
            key_repository,
            identifier_creator,
            credential_schema_importer,
            validity_credential_repository,
            credential_schema_repository,
            formatter_provider,
            revocation_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            base_url,
            protocol_base_url,
            config,
            params,
            blob_storage_provider,
            config_id,
            holder_wallet_unit_proto,
            holder_wallet_unit_repository,
            key_security_level_provider,
            certificate_validator,
            wrp_validator,
            history_repository,
            session_provider,
            interaction_repository,
        }
    }

    #[expect(clippy::too_many_arguments)]
    pub fn new_with_custom_protocol_base_url(
        protocol_base_url: Option<String>,
        client: Arc<dyn HttpClient>,
        metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
        credential_repository: Arc<dyn CredentialRepository>,
        key_repository: Arc<dyn KeyRepository>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIFinal1Params,
        config_id: String,
        holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletInstanceRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        wrp_validator: Arc<dyn WRPValidator>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Self {
        Self {
            client,
            metadata_cache,
            credential_repository,
            key_repository,
            identifier_creator,
            credential_schema_importer,
            validity_credential_repository,
            credential_schema_repository,
            formatter_provider,
            revocation_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            base_url,
            protocol_base_url,
            config,
            params,
            blob_storage_provider,
            config_id,
            holder_wallet_unit_proto,
            holder_wallet_unit_repository,
            key_security_level_provider,
            certificate_validator,
            wrp_validator,
            history_repository,
            session_provider,
            interaction_repository,
        }
    }

    async fn validate_credential_issuable(
        &self,
        credential_id: &CredentialId,
        latest_state: &CredentialStateEnum,
        format: &CredentialFormat,
        format_type: FormatType,
    ) -> Result<(), IssuanceProtocolError> {
        match (latest_state, format_type) {
            (CredentialStateEnum::Accepted, FormatType::Mdoc) => {
                let mdoc_validity_credential = self
                    .validity_credential_repository
                    .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                    .await
                    .error_while("getting validity credential")?
                    .ok_or_else(|| {
                        IssuanceProtocolError::Failed(format!(
                            "Missing verifiable credential for MDOC: {credential_id}"
                        ))
                    })?;

                let can_be_updated_at = mdoc_validity_credential.created_date
                    + self.mso_minimum_refresh_time(format)?;

                if can_be_updated_at > crate::clock::now_utc() {
                    return Err(IssuanceProtocolError::RefreshTooSoon);
                }
            }
            (CredentialStateEnum::Suspended, FormatType::Mdoc) => {
                return Err(IssuanceProtocolError::Suspended);
            }
            (CredentialStateEnum::Offered, _) => {}
            _ => {
                return Err(IssuanceProtocolError::InvalidRequest(
                    "invalid state".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn mso_minimum_refresh_time(
        &self,
        format: &CredentialFormat,
    ) -> Result<Duration, IssuanceProtocolError> {
        Ok(self
            .config
            .format
            .get::<mdoc_formatter::Params, _>(format)
            .map(|p| p.mso_minimum_refresh_time)
            .error_while("getting format params")?)
    }

    async fn jwk_key_id_from_identifier(
        &self,
        issuer_identifier: &Identifier,
        key: &Key,
    ) -> Result<Option<String>, IssuanceProtocolError> {
        let Some(ref did) = issuer_identifier.did else {
            return Ok(None);
        };

        let related_did_key = did
            .find_key(&key.id, &KeyFilter::role_filter(KeyRole::AssertionMethod))
            .await
            .error_while("finding related key")?;
        let issuer_jwk_key_id = did.verification_method_id(&related_did_key);

        Ok(Some(issuer_jwk_key_id))
    }

    async fn holder_fetch_token(
        &self,
        interaction_data: &HolderInteractionData,
        tx_code: Option<String>,
        wallet_attestation_request: Option<TokenRequestWalletAttestationRequest>,
    ) -> Result<OpenID4VCITokenResponseDTO, IssuanceProtocolError> {
        let token_endpoint =
            interaction_data
                .token_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "token endpoint is missing".to_string(),
                ))?;

        let grants = interaction_data
            .grants
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "grants data is missing".to_string(),
            ))?;

        let has_sent_tx_code = tx_code.is_some();

        let form = match grants {
            OpenID4VCIGrants::PreAuthorizedCode(code) => {
                OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                    pre_authorized_code: code.pre_authorized_code.to_owned(),
                    tx_code,
                }
            }
            OpenID4VCIGrants::AuthorizationCode(_) => {
                let Some(data) = &interaction_data.continue_issuance else {
                    return Err(IssuanceProtocolError::Failed(
                        "continue_issuance data is missing".to_string(),
                    ));
                };
                OpenID4VCITokenRequestDTO::AuthorizationCode {
                    authorization_code: data.authorization_code.to_owned(),
                    client_id: data.client_id.to_owned(),
                    redirect_uri: data.redirect_uri.to_owned(),
                    code_verifier: data.code_verifier.to_owned(),
                }
            }
        };

        let mut request = self
            .client
            .post(token_endpoint.as_str())
            .form(&form)
            .error_while("preparing token request")?;

        if let Some(wallet_attestation_request) = wallet_attestation_request {
            request = request
                .header(
                    "OAuth-Client-Attestation",
                    &wallet_attestation_request.wallet_attestation,
                )
                .header(
                    "OAuth-Client-Attestation-PoP",
                    &wallet_attestation_request.wallet_attestation_pop,
                );
        }

        let response = request.send().await.error_while("requesting token")?;

        if response.status.is_client_error() && has_sent_tx_code {
            #[derive(Deserialize)]
            struct ErrorResponse {
                error: OpenId4VciError,
            }

            #[derive(Deserialize)]
            #[serde(rename_all = "snake_case")]
            enum OpenId4VciError {
                InvalidGrant,
                InvalidRequest,
            }

            match serde_json::from_slice::<ErrorResponse>(&response.body).map(|r| r.error) {
                Ok(OpenId4VciError::InvalidGrant) => {
                    return Err(TxCodeError::IncorrectCode
                        .error_while("checking TX response")
                        .into());
                }
                Ok(OpenId4VciError::InvalidRequest) => {
                    return Err(TxCodeError::InvalidCodeUse
                        .error_while("checking TX response")
                        .into());
                }
                Err(_) => {}
            }
        }

        Ok(response
            .error_for_status()
            .error_while("requesting token")?
            .json()
            .error_while("requesting token")?)
    }

    async fn holder_reuse_or_refresh_token(
        &self,
        interaction_id: InteractionId,
        interaction_data: &mut HolderInteractionData,
    ) -> Result<SecretString, IssuanceProtocolError> {
        let now = crate::clock::now_utc();
        if let Some(encrypted_token) = &interaction_data.access_token {
            let token_valid = interaction_data
                .access_token_expires_at
                .map(|v| v > now)
                .unwrap_or(true);
            if token_valid {
                let access_token = decrypt_string(encrypted_token, &self.params.encryption)
                    .map_err(|err| {
                        IssuanceProtocolError::Failed(format!(
                            "failed to decrypt access token: {err}"
                        ))
                    })?;
                return Ok(access_token);
            }
        }

        // Fetch a new one
        let refresh_token = if let Some(refresh_token) = interaction_data.refresh_token.as_ref() {
            decrypt_string(refresh_token, &self.params.encryption).map_err(|err| {
                IssuanceProtocolError::Failed(format!("failed to decrypt refresh token: {err}"))
            })?
        } else {
            return Err(IssuanceProtocolError::Failed(
                "no refresh token saved".to_owned(),
            ));
        };

        if interaction_data
            .refresh_token_expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            // Expired refresh token
            return Err(IssuanceProtocolError::Failed(
                "expired refresh token".to_owned(),
            ));
        }

        let token_endpoint =
            interaction_data
                .token_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "token endpoint is missing".to_string(),
                ))?;

        let token_response: OpenID4VCITokenResponseDTO = async {
            self.client
                .post(token_endpoint)
                .form(&[
                    ("refresh_token", refresh_token.expose_secret().to_string()),
                    ("grant_type", "refresh_token".to_string()),
                ])?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("requesting token")?;

        let encrypted_access_token =
            encrypt_string(&token_response.access_token, &self.params.encryption).map_err(
                |err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
                },
            )?;
        interaction_data.access_token = Some(encrypted_access_token);
        interaction_data.access_token_expires_at =
            OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

        if let Some(new_refresh_token) = token_response.refresh_token {
            let encrypted_refresh_token =
                encrypt_string(&new_refresh_token, &self.params.encryption).map_err(|err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
                })?;
            interaction_data.refresh_token = Some(encrypted_refresh_token);
            interaction_data.access_token_expires_at = token_response
                .refresh_token_expires_in
                .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());
        }

        self.interaction_repository
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    data: Some(Some(serialize_interaction_data(&interaction_data)?)),
                },
            )
            .await
            .error_while("updating interaction")?;

        Ok(token_response.access_token)
    }

    async fn holder_fetch_nonce(
        &self,
        interaction_data: &HolderInteractionData,
    ) -> Result<String, IssuanceProtocolError> {
        let nonce_endpoint =
            interaction_data
                .nonce_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "nonce endpoint is missing".to_string(),
                ))?;

        let response: OpenID4VCINonceResponseDTO = async {
            self.client
                .post(nonce_endpoint.as_str())
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("requesting nonce")?;

        Ok(response.c_nonce)
    }

    /// Fetches a challenge from the attestation-based client authentication challenge endpoint
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-8>
    async fn holder_fetch_challenge(
        &self,
        challenge_endpoint: &str,
    ) -> Result<String, IssuanceProtocolError> {
        let response: ChallengeResponseDTO = async {
            self.client
                .get(challenge_endpoint)
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("fetching challenge")?;

        Ok(response.attestation_challenge)
    }

    /// Prepares wallet attestations (WIA/WUA) based on issuer requirements.
    async fn prepare_wallet_attestations(
        &self,
        interaction_data: &HolderInteractionData,
        key: &Key,
        organisation_id: OrganisationId,
    ) -> Result<WalletAttestationResult, IssuanceProtocolError> {
        // DEVIATION: RFC8414 specifies `client_secret_basic` as the default when
        // token_endpoint_auth_methods_supported is absent, but some issuers (e.g. swiyu) don't publish this field.
        // Treating empty/missing as `none` to avoid interop issues
        let default_auth_methods = [TokenEndpointAuthMethod::None];
        let token_endpoint_auth_methods = interaction_data
            .token_endpoint_auth_methods_supported
            .as_deref()
            .unwrap_or(&default_auth_methods);

        let wallet_attestation_supported =
            token_endpoint_auth_methods.contains(&TokenEndpointAuthMethod::AttestJwtClientAuth);

        let wallet_attestation_required = requires_wia(token_endpoint_auth_methods);

        let holder_wallet_unit = self.get_current_wallet_unit(organisation_id).await?;
        let wallet_unit_provided = holder_wallet_unit
            .as_ref()
            .is_some_and(|unit| unit.status == WalletInstanceStatus::Active);

        if wallet_attestation_required && !wallet_unit_provided {
            return Err(IssuanceProtocolError::Failed(
                "Active holder wallet unit id is required".to_string(),
            ));
        }

        let issuer_accepted_levels =
            interaction_data_to_accepted_key_storage_security(interaction_data);

        let key_storage_security_level = issuer_accepted_levels
            .map(|accepted_levels| {
                match_key_security_level(
                    &key.storage_type,
                    &accepted_levels,
                    &*self.key_security_level_provider,
                )
                .error_while("matching key security")
            })
            .transpose()?;

        if key_storage_security_level.is_some() && !wallet_unit_provided {
            return Err(IssuanceProtocolError::Failed(
                "key storage attestation requires active holder wallet unit id".to_string(),
            ));
        }

        let use_wallet_attestation =
            wallet_attestation_required || (wallet_attestation_supported && wallet_unit_provided);

        let wallet_attestations_issuance_request =
            match (use_wallet_attestation, &key_storage_security_level) {
                (true, Some(level)) => Some(IssueWalletAttestationRequest::WuaAndWia(key, *level)),
                (true, None) => Some(IssueWalletAttestationRequest::Wia),
                (false, Some(level)) => Some(IssueWalletAttestationRequest::Wua(key, *level)),
                (false, None) => None,
            };

        let wallet_attestations_issuance_response = match wallet_attestations_issuance_request {
            None => None,
            Some(request) => {
                let holder_wallet_unit_id = holder_wallet_unit
                    .as_ref()
                    .ok_or(IssuanceProtocolError::Failed(
                        "holder wallet unit is required".to_string(),
                    ))?
                    .id;

                let response = self
                    .holder_wallet_unit_proto
                    .issue_wallet_attestations(&holder_wallet_unit_id, request)
                    .await
                    .error_while("issuing attestations")?;

                Some(response)
            }
        };

        // Create WIA proof-of-possession if using WIA
        let wia_request = match (
            use_wallet_attestation,
            &wallet_attestations_issuance_response,
        ) {
            (true, Some(issuance_response)) => {
                let wia = issuance_response
                    .wia
                    .first()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Wallet attestation is required".to_string(),
                    ))?;

                // Per https://drafts.oauth.net/draft-ietf-oauth-attestation-based-client-auth/draft-ietf-oauth-attestation-based-client-auth.html#section-5
                // The WIA sub (subject) claim MUST specify client_id value of the OAuth Client.
                let wia_jwt: Jwt<()> = Jwt::build_from_token(wia, None, None)
                    .await
                    .error_while("parsing WIA JWT")?;

                let client_id = wia_jwt
                    .payload
                    .subject
                    .ok_or(IssuanceProtocolError::Failed(
                        "WIA missing subject claim".to_string(),
                    ))?;

                let challenge =
                    if let Some(challenge_endpoint) = &interaction_data.challenge_endpoint {
                        Some(self.holder_fetch_challenge(challenge_endpoint).await?)
                    } else {
                        None
                    };

                // Get the wallet unit's authentication key for signing the PoP
                let wallet_unit_auth_key = self
                    .holder_wallet_unit_proto
                    .get_authentication_key(
                        &holder_wallet_unit
                            .as_ref()
                            .ok_or(IssuanceProtocolError::Failed(
                                "holder wallet unit is required for WIA PoP".to_string(),
                            ))?
                            .id,
                    )
                    .await
                    .error_while("getting authentication key")?;

                let signed_proof = create_wallet_unit_attestation_pop(
                    &*self.key_provider,
                    self.key_algorithm_provider.clone(),
                    &wallet_unit_auth_key,
                    &interaction_data.issuer_url,
                    challenge,
                    &client_id,
                )
                .await?;

                Ok(Some(TokenRequestWalletAttestationRequest {
                    wallet_attestation: wia.to_owned(),
                    wallet_attestation_pop: signed_proof,
                }))
            }
            (true, None) => Err(IssuanceProtocolError::Failed(
                "Wallet attestation issuance failed".to_string(),
            )),
            (false, _) => Ok(None),
        }?;

        // Extract WUA proof if key attestation is required
        let key_attestations_required = key_storage_security_level.is_some();
        let wua_proof = match (
            key_attestations_required,
            &wallet_attestations_issuance_response,
        ) {
            (true, Some(issuance_response)) => {
                let wua = issuance_response
                    .wua
                    .first()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Key attestation is required".to_string(),
                    ))?;

                Ok(Some(wua.to_owned()))
            }
            (true, None) => Err(IssuanceProtocolError::Failed(
                "Key attestation is required".to_string(),
            )),
            (false, _) => Ok(None),
        }?;

        Ok(WalletAttestationResult {
            wia_request,
            wua_proof,
        })
    }

    async fn get_current_wallet_unit(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<Option<HolderWalletInstance>, IssuanceProtocolError> {
        let wallet_unit = self
            .holder_wallet_unit_repository
            .get_holder_wallet_instance_by_org_id(&organisation_id)
            .await
            .error_while("fetching wallet unit")?;
        Ok(wallet_unit)
    }

    async fn holder_process_accepted_credential(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        holder_binding: HolderBindingInput,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<UpdateResponse, IssuanceProtocolError> {
        let format_type = map_from_oidc_format_to_core_detailed(
            &interaction_data.format,
            Some(&issuer_response.credential),
        )?;

        let (format, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{format_type} formatter not found"))
            })?;

        let mut credential = formatter
            .parse_credential(
                &issuer_response.credential,
                organisation.to_owned(),
                self.verification_fn(),
            )
            .await
            .map_err(|e| IssuanceProtocolError::CredentialVerificationFailed(e.into()))?;

        validate_issuance_time(&credential.issuance_date, formatter.get_leeway())
            .error_while("validating issuance time")?;

        let schema = credential
            .schema
            .as_mut()
            .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?;

        let metadata = interaction_data.credential_metadata.as_ref();
        let metadata_display = metadata
            .and_then(|metadata| metadata.display.as_ref())
            .and_then(|display| {
                display
                    .iter()
                    .find(|display| display.locale.as_ref().is_none_or(|locale| locale == "en"))
            });

        if let Some(name) = metadata_display.map(|display| display.name.to_owned()) {
            schema.name = name;
        }
        schema.format = format;
        schema.organisation = organisation.to_owned().into();
        schema.layout_type = LayoutType::Card;
        schema.layout_properties = metadata_display.and_then(|display| display.to_owned().into());
        schema.key_storage_security = interaction_data
            .proof_types_supported
            .as_ref()
            .and_then(|map| map.get("jwt"))
            .and_then(|jwt| jwt.key_attestations_required.as_ref())
            .and_then(|att_list| {
                (!att_list.key_storage.is_empty()).then_some(&att_list.key_storage)
            })
            .and_then(|levels| convert_inner(KeyStorageSecurityLevel::select_lowest(levels)));

        let identifier_details = match credential.issuer_identifier.as_ref() {
            Some(Identifier {
                did: Some(did),
                r#type,
                ..
            }) if r#type == &IdentifierType::Did => IdentifierDetails::Did(did.did.to_owned()),
            Some(Identifier {
                certificates: Some(certificates),
                r#type,
                ..
            }) if r#type == &IdentifierType::Certificate => {
                let certificate = certificates
                    .first()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Missing certificate".to_string(),
                    ))?
                    .to_owned();
                IdentifierDetails::Certificate(CertificateDetails {
                    chain: certificate.chain,
                    fingerprint: certificate.fingerprint,
                    expiry: certificate.expiry_date,
                    subject_common_name: None,
                })
            }
            Some(Identifier {
                key: Some(key),
                r#type,
                ..
            }) if r#type == &IdentifierType::Key => {
                let key_handle = self
                    .key_algorithm_provider
                    .reconstruct_key(
                        key.key_algorithm_type()
                            .error_while("getting key algorithm tye")?,
                        &key.public_key,
                        None,
                        None,
                    )
                    .error_while("reconstructing key")?;
                IdentifierDetails::Key(key_handle.public_key_as_jwk().error_while("getting JWK")?)
            }
            _ => {
                return Err(IssuanceProtocolError::Failed(
                    "Invalid parsed issuer identifier".to_string(),
                ));
            }
        };

        let (issuer_identifer, issuer_identifier_relation) = self
            .identifier_creator
            .get_or_create_remote_identifier(
                &Some(organisation.to_owned()),
                &identifier_details,
                IdentifierRole::Issuer,
            )
            .await
            .error_while("creating issuer identifier")?;
        let issuer_certificate = if let RemoteIdentifierRelation::Certificate(certificate) =
            issuer_identifier_relation
        {
            Some(certificate)
        } else {
            None
        };

        credential.issuer_identifier = Some(issuer_identifer);
        credential.issuer_certificate = issuer_certificate;
        credential.redirect_uri = issuer_response.redirect_uri.clone();
        credential.state = CredentialStateEnum::Accepted;
        credential.holder_identifier = Some(holder_binding.identifier);
        credential.key = Some(holder_binding.key);
        credential.protocol = self.config_id.to_owned();
        credential.interaction = Some(interaction.to_owned());

        let update_credential_schema = prepare_credential_schema(
            self.credential_schema_importer.as_ref(),
            self.credential_schema_repository.as_ref(),
            schema.to_owned(),
            organisation,
            &mut credential,
        )
        .await?;

        if let Some(access_certificate) = &interaction_data.access_certificate {
            self.store_certificate_history_event(
                HistoryAction::WrpAcReceived,
                credential.id,
                organisation.id,
                access_certificate.to_owned(),
                None,
            )
            .await?;
        }

        if let (Some(registration_certificate), Some(relying_party_name)) = (
            &interaction_data.registration_certificate,
            &interaction_data.relying_party_name,
        ) {
            self.store_certificate_history_event(
                HistoryAction::WrpRcReceived,
                credential.id,
                organisation.id,
                registration_certificate.to_owned(),
                Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        name: relying_party_name.to_string(),
                        ..Default::default()
                    },
                )),
            )
            .await?;
        }

        if let (Some(national_registry_data), Some(relying_party_name)) = (
            &interaction_data.national_registry_data,
            &interaction_data.relying_party_name,
        ) {
            self.store_certificate_history_event(
                HistoryAction::WrpNrReceived,
                credential.id,
                organisation.id,
                national_registry_data.to_owned(),
                Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        name: relying_party_name.to_string(),
                        ..Default::default()
                    },
                )),
            )
            .await?;
        }

        Ok(UpdateResponse {
            result: issuer_response,
            update_credential_schema,
            update_credential: None,
            create_credential: Some(credential),
        })
    }

    async fn send_notification(
        &self,
        message: OpenID4VCINotificationRequestDTO,
        notification_endpoint: &str,
        access_token: &str,
    ) -> Result<(), IssuanceProtocolError> {
        async {
            self.client
                .post(notification_endpoint)
                .bearer_auth(access_token)
                .json(&message)?
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("sending notification")?;

        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    async fn holder_request_credential(
        &self,
        interaction_data: &HolderInteractionData,
        holder_did: Option<&DidValue>,
        holder_key: PublicJwk,
        nonce: Option<String>,
        auth_fn: AuthenticationFn,
        access_token: &str,
        key_attestation: Option<String>,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        let jwk = interaction_data
            .cryptographic_binding_methods_supported
            .as_ref()
            .and_then(|methods| {
                if let Some(holder_did) = holder_did
                    && methods
                        .iter()
                        .any(|method| &format!("did:{}", holder_did.method()) == method)
                {
                    None
                } else if methods.contains(&"jwk".to_string())
                    | methods.contains(&"cose_key".to_string())
                {
                    Some(holder_key)
                } else {
                    None
                }
            });

        let client_id = interaction_data
            .continue_issuance
            .as_ref()
            .map(|ci| ci.client_id.clone());

        // As per https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
        // the iss field in the proof JWT MUST be the client_id of the Client making the Credential request.
        // This claim MUST be omitted if the access token authorizing the issuance call was obtained from a Pre-Authorized Code
        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url.to_owned(),
            jwk,
            nonce,
            key_attestation,
            auth_fn,
            client_id,
        )
        .await
        .error_while("formatting proof")?;

        let body = OpenID4VCICredentialRequestDTO {
            credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                interaction_data.credential_configuration_id.to_owned(),
            ),
            proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![proof_jwt])),
        };

        let response: OpenID4VCICredentialResponseDTO = async {
            self.client
                .post(interaction_data.credential_endpoint.as_str())
                .bearer_auth(access_token)
                .json(&body)?
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("requesting credential")?;

        Ok(SubmitIssuerResponse {
            credential: response
                .credentials
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing credential".to_string(),
                ))?
                .first()
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing credential".to_string(),
                ))?
                .credential
                .to_owned(),
            redirect_uri: response.redirect_uri,
            notification_id: response.notification_id,
        })
    }

    async fn upsert_credential_blob(
        &self,
        credential: &Credential,
        token: &str,
    ) -> Result<BlobId, IssuanceProtocolError> {
        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
            .error_while("getting blob storage")?;

        let credential_blob_id = match credential.credential_blob_id {
            None => {
                let blob = Blob::new(token, BlobType::Credential);
                db_blob_storage
                    .create(blob.clone())
                    .await
                    .error_while("creating blob")?;
                blob.id
            }
            Some(blob_id) => {
                db_blob_storage
                    .update(
                        &blob_id,
                        UpdateBlobRequest {
                            value: Some(token.into()),
                        },
                    )
                    .await
                    .error_while("updating blob")?;
                blob_id
            }
        };
        Ok(credential_blob_id)
    }

    async fn create_holder_binding(
        &self,
        interaction_data: &HolderInteractionData,
        organisation: &Organisation,
    ) -> Result<HolderBindingInput, IssuanceProtocolError> {
        autogenerate_holder_binding(
            interaction_data
                .cryptographic_binding_methods_supported
                .as_ref(),
            interaction_data.proof_types_supported.as_ref(),
            organisation,
            self.key_provider.as_ref(),
            self.key_algorithm_provider.as_ref(),
            self.key_security_level_provider.as_ref(),
            self.did_method_provider.as_ref(),
            self.key_repository.as_ref(),
            self.identifier_creator.as_ref(),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    async fn fetch_issuer_metadata(
        &self,
        credential_issuer: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<IssuerMetadataRepresentation, IssuanceProtocolError> {
        let credential_issuer_endpoint: Url = credential_issuer.parse().map_err(|_| {
            IssuanceProtocolError::InvalidRequest(format!(
                "Invalid credential issuer url {credential_issuer}",
            ))
        })?;

        if !self.params.request_signed_metadata {
            return Ok(IssuerMetadataRepresentation::Unsigned(
                fetch_metadata_json_with_fallback(
                    self.metadata_cache.as_ref(),
                    &credential_issuer_endpoint,
                    "openid-credential-issuer",
                )
                .await?,
            ));
        }

        let jwt = fetch_metadata_jwt_with_fallback(
            self.metadata_cache.as_ref(),
            &credential_issuer_endpoint,
            "openid-credential-issuer",
        )
        .await?;

        self.validate_jwt(&jwt)
            .await
            .error_while("validating issuer metadata JWT")?;

        let Some(x5c) = jwt.header.x5c.as_ref() else {
            tracing::debug!("Issuer metadata signed via DID or JWK, skipping trust check");
            return Ok(IssuerMetadataRepresentation::Signed(jwt, None));
        };

        let access_certificate = if let Some(organsation_id) = validate_trust {
            let pem_chain = x5c_into_pem_chain(x5c).error_while("converting x5c")?;
            match self
                .wrp_validator
                .validate_access_certificate_trust(&pem_chain, Some(organsation_id))
                .await
            {
                Ok(result) => Some((result, pem_chain)),
                Err(WRPValidatorError::TrustManagementDisabled) => {
                    // trust management disabled, skipping other checks
                    None
                }
                Err(err) => {
                    return Err(err.error_while("validating access certificate").into());
                }
            }
        } else {
            None
        };

        Ok(IssuerMetadataRepresentation::Signed(
            jwt,
            access_certificate,
        ))
    }

    async fn validate_jwt<T: Debug>(
        &self,
        jwt: &DecomposedJwt<T>,
    ) -> Result<(), IssuanceProtocolError> {
        let public_key_source = jwt
            .public_key_source(None)
            .error_while("extracting public key info from JWT")?;
        jwt.verify_signature(public_key_source, &self.verification_fn())
            .await
            .error_while("verifying JWT signature")?;

        Ok(())
    }

    fn verification_fn(&self) -> VerificationFn {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        })
    }

    #[expect(clippy::too_many_arguments)]
    async fn prepare_issuance_interaction(
        &self,
        organisation: Organisation,
        token_endpoint: String,
        issuer_metadata: IssuerMetadataRepresentation,
        oauth_authorization_server_metadata: Option<OAuthAuthorizationServerMetadataResponseDTO>,
        grants: OpenID4VCIGrants,
        configuration_ids: &[String],
        continue_issuance: Option<ContinueIssuanceDTO>,
    ) -> Result<PrepareIssuanceSuccess, IssuanceProtocolError> {
        // We only support one credential at a time currently
        let configuration_id = configuration_ids.first().ok_or_else(|| {
            IssuanceProtocolError::Failed("Credential offer is missing credentials".to_string())
        })?;

        let credential_config = issuer_metadata
            .metadata()
            .credential_configurations_supported
            .get(configuration_id)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!(
                    "Credential configuration is missing for {configuration_id}"
                ))
            })?;

        let (
            access_certificate,
            registration_certificate,
            national_registry_data,
            relying_party_name,
        ) = if let IssuerMetadataRepresentation::Signed(jwt, Some(access_certificate)) =
            &issuer_metadata
        {
            let trust::TrustInfo {
                registration_certificate,
                national_registry_data,
                relying_party_name,
            } = self
                .validate_trust(
                    credential_config,
                    &jwt.payload.custom,
                    organisation.id,
                    &access_certificate.0,
                )
                .await?;

            (
                Some(access_certificate.1.to_owned()),
                registration_certificate,
                national_registry_data,
                Some(relying_party_name),
            )
        } else {
            (None, None, None, None)
        };

        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.2
        if let Some(authorization_server) = grants.authorization_server()
            && issuer_metadata
                .metadata()
                .authorization_servers
                .as_ref()
                .is_none_or(|servers| !servers.contains(authorization_server))
        {
            return Err(IssuanceProtocolError::InvalidRequest(format!(
                "Authorization server missing in issuer metadata: {authorization_server}"
            )));
        }

        let token_endpoint_auth_methods_supported = oauth_authorization_server_metadata
            .as_ref()
            .map(|oauth_metadata| oauth_metadata.token_endpoint_auth_methods_supported.clone());

        let challenge_endpoint = oauth_authorization_server_metadata
            .as_ref()
            .and_then(|oauth_metadata| oauth_metadata.challenge_endpoint.clone());

        let holder_data = HolderInteractionData {
            issuer_url: issuer_metadata.metadata().credential_issuer.clone(),
            credential_endpoint: issuer_metadata.metadata().credential_endpoint.clone(),
            notification_endpoint: issuer_metadata.metadata().notification_endpoint.to_owned(),
            nonce_endpoint: issuer_metadata.metadata().nonce_endpoint.to_owned(),
            challenge_endpoint,
            token_endpoint: Some(token_endpoint),
            grants: Some(grants),
            continue_issuance,
            access_token: None,
            access_token_expires_at: None,
            refresh_token: None,
            refresh_token_expires_at: None,
            credential_signing_alg_values_supported: credential_config
                .credential_signing_alg_values_supported
                .clone(),
            cryptographic_binding_methods_supported: credential_config
                .cryptographic_binding_methods_supported
                .clone(),
            proof_types_supported: credential_config.proof_types_supported.clone(),
            token_endpoint_auth_methods_supported,
            credential_metadata: credential_config.credential_metadata.clone(),
            credential_configuration_id: configuration_id.to_owned(),
            notification_id: None,
            protocol: self.config_id.to_owned(),
            format: credential_config.format.to_owned(),
            access_certificate,
            registration_certificate,
            national_registry_data,
            relying_party_name,
        };
        let data = serialize_interaction_data(&holder_data)?;

        let interaction = create_and_store_interaction(
            self.interaction_repository.as_ref(),
            data,
            Some(organisation),
        )
        .await?;
        let (key_algorithms, key_storage_security) =
            credential_config_to_holder_signing_algs_and_key_storage_security(
                self.key_algorithm_provider.as_ref(),
                credential_config,
            );
        Ok(PrepareIssuanceSuccess {
            interaction_id: interaction.id,
            key_storage_security,
            key_algorithms,
        })
    }

    pub(super) async fn get_etsi_issuer_info(
        &self,
        identifier: &Identifier,
        credential_schema: &CredentialSchema,
    ) -> Result<Option<Vec<EtsiIssuerInfoResponseDTO>>, IssuanceProtocolError> {
        let Some(trust_information_list) = identifier.trust_information.as_ref() else {
            return Ok(None);
        };
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
            .error_while("getting blob storage")?;

        let format_type = self
            .config
            .format
            .get_fields(&credential_schema.format)
            .error_while("getting format config")?
            .r#type;

        let valid_trust_information_list = trust_information_list
            .iter()
            .filter(|ti| ti.is_valid(now_utc()))
            .filter(|ti| ti.is_issuance_allowed_for(&credential_schema.schema_id, &format_type));

        let mut etsi_issuer_info_list = Vec::new();
        for trust_information in valid_trust_information_list {
            let certificate = blob_storage
                .get(&trust_information.blob_id)
                .await
                .error_while("getting trust information blob")?
                .ok_or(IssuanceProtocolError::TrustInformationError(
                    "Missing registration certificate".to_string(),
                ))?;

            if certificate.r#type != BlobType::RegistrationCertificate {
                return Err(IssuanceProtocolError::TrustInformationError(format!(
                    "Invalid trust information data, expected registration certificate, got {:?}",
                    certificate.r#type
                )));
            }

            etsi_issuer_info_list.push(EtsiIssuerInfoResponseDTO {
                format: EtsiIssuerInfoAttestationFormat::RegistrationCert,
                data: String::from_utf8(certificate.value)?,
                credential_ids: trust_information
                    .allowed_issuance_types
                    .iter()
                    .map(|ti| dcql::CredentialQueryId::from(ti.schema_id.as_str()))
                    .collect(),
            })
        }
        Ok(Some(etsi_issuer_info_list))
    }

    pub(super) async fn prepare_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<PreparedMetadata, IssuanceProtocolError> {
        let protocol_base_url =
            self.protocol_base_url
                .clone()
                .ok_or(IssuanceProtocolError::Failed(
                    "Host URL not specified".to_string(),
                ))?;

        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let Some(schema) = schema else {
            return Err(IssuanceProtocolError::MissingCredentialSchema(
                *credential_schema_id,
            ));
        };

        let format_type = self
            .config
            .format
            .get_fields(&schema.format)
            .error_while("getting format config")?
            .r#type;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&schema.format)
            .ok_or(MissingProviderError::Formatter(schema.format.to_string()))
            .error_while("getting formatter")?;

        let format_capabilities = formatter.get_capabilities();
        let credential_signing_alg_values_supported = format_capabilities
            .signing_key_algorithms
            .into_iter()
            .filter_map(|alg_type| {
                self.key_algorithm_provider
                    .key_algorithm_from_type(alg_type)
                    .map(|alg| alg.issuance_jose_alg_id())
            })
            .collect();

        let credential_configurations_supported: IndexMap<
            String,
            OpenID4VCICredentialConfigurationData,
        > = credential_configurations_supported(
            &format_type,
            &schema,
            map_cryptographic_binding_methods_supported(
                &self.did_method_provider.supported_method_names(),
                &format_capabilities.holder_identifier_types,
            ),
            map_proof_types_supported(
                self.key_algorithm_provider
                    .supported_verification_jose_alg_ids(),
                schema.key_storage_security.map(|x| x.into()),
            ),
            credential_signing_alg_values_supported,
        )
        .await
        .map_err(OpenIDIssuanceError::OpenID4VCI)?;
        Ok(PreparedMetadata {
            protocol_base_url,
            schema,
            credential_configurations_supported,
        })
    }
}

#[async_trait]
impl IssuanceProtocol for OpenID4VCIFinal1_0 {
    async fn holder_can_handle(&self, url: &Url) -> bool {
        if self.params.url_scheme != url.scheme() {
            return false;
        }

        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);
        if !query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
            && !query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY)
        {
            return false;
        }

        async {
            let credential_offer =
                resolve_credential_offer(self.client.as_ref(), url.to_owned()).await?;
            self.fetch_issuer_metadata(&credential_offer.credential_issuer, None)
                .await
        }
        .await
        .is_ok()
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum, IssuanceProtocolError> {
        let credential_offer = resolve_credential_offer(self.client.as_ref(), url).await?;

        let issuer_metadata = self
            .fetch_issuer_metadata(&credential_offer.credential_issuer, Some(organisation.id))
            .await?;

        let AuthorizationMetadata {
            token_endpoint,
            oauth_metadata,
            ..
        } = get_authorization_metadata(
            self.metadata_cache.as_ref(),
            issuer_metadata.metadata(),
            &credential_offer.credential_issuer,
            credential_offer.grants.authorization_server(),
        )
        .await?;

        if let OpenID4VCIGrants::AuthorizationCode(authorization_code) = credential_offer.grants {
            let params = self
                .config
                .credential_issuer
                .entities
                .iter()
                .filter(|(_, entity)| entity.enabled.unwrap_or(true))
                .filter_map(|(key, entity)| {
                    parse_credential_issuer_params(key, &entity.params).ok()
                })
                .find(|params| params.issuer == credential_offer.credential_issuer)
                .ok_or(IssuanceProtocolError::InvalidRequest(format!(
                    "No config entry for Authorization Code found, issuer: {}",
                    credential_offer.credential_issuer
                )))?;

            let credential_configuration_ids = credential_offer.credential_configuration_ids;
            if credential_configuration_ids.is_empty() {
                return Err(IssuanceProtocolError::InvalidRequest(
                    "No credential_configuration_ids provided".to_string(),
                ));
            }

            let scope = credential_configuration_ids
                .iter()
                .map(|id| {
                    issuer_metadata
                        .metadata()
                        .credential_configurations_supported
                        .get(id)
                        .and_then(|c| c.scope.clone())
                })
                .collect::<Option<Vec<String>>>();

            return Ok(InvitationResponseEnum::AuthorizationFlow {
                organisation_id: organisation.id,
                issuer: params.issuer,
                scope,
                client_id: params.client_id,
                redirect_uri,
                authorization_details: Some(
                    credential_configuration_ids
                        .into_iter()
                        .map(
                            |credential_configuration_id| InitiateIssuanceAuthorizationDetailDTO {
                                r#type: "openid_credential".to_string(),
                                credential_configuration_id,
                            },
                        )
                        .collect(),
                ),
                issuer_state: authorization_code.issuer_state,
                authorization_server: authorization_code.authorization_server,
            });
        }

        let tx_code = credential_offer.grants.tx_code().cloned();
        let requires_wallet_instance_attestation =
            requires_wia(&oauth_metadata.token_endpoint_auth_methods_supported);

        let PrepareIssuanceSuccess {
            interaction_id,
            key_storage_security,
            key_algorithms,
        } = self
            .prepare_issuance_interaction(
                organisation,
                token_endpoint,
                issuer_metadata,
                Some(oauth_metadata),
                credential_offer.grants,
                &credential_offer.credential_configuration_ids,
                None,
            )
            .await?;

        Ok(InvitationResponseEnum::Credential {
            interaction_id,
            tx_code,
            key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
        })
    }

    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse, IssuanceProtocolError> {
        let organisation =
            interaction
                .organisation
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "organisation is None".to_string(),
                ))?;

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let holder_binding = if let Some(holder_binding) = holder_binding {
            holder_binding
        } else {
            self.create_holder_binding(&interaction_data, organisation)
                .await?
        };

        let key = &holder_binding.key;

        let attestation_result = self
            .prepare_wallet_attestations(&interaction_data, key, organisation.id)
            .await?;

        let token_response = self
            .holder_fetch_token(&interaction_data, tx_code, attestation_result.wia_request)
            .await?;
        let nonce = self.holder_fetch_nonce(&interaction_data).await?;

        let encrypted_access_token =
            encrypt_string(&token_response.access_token, &self.params.encryption).map_err(
                |err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
                },
            )?;
        interaction_data.access_token = Some(encrypted_access_token);
        interaction_data.access_token_expires_at =
            OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

        // only mdoc credentials support refreshing, do not store refresh tokens otherwise
        if interaction_data.format == "mso_mdoc" {
            interaction_data.refresh_token = token_response
                .refresh_token
                .map(|token| encrypt_string(&token, &self.params.encryption))
                .transpose()
                .map_err(|err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
                })?;
            interaction_data.refresh_token_expires_at = token_response
                .refresh_token_expires_in
                .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());
        }

        let holder_jwk_key_id = if holder_binding.identifier.r#type == IdentifierType::Did {
            let did =
                holder_binding
                    .identifier
                    .did
                    .as_ref()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Missing identifier did".to_string(),
                    ))?;

            let related_key = did
                .find_key(
                    &holder_binding.key.id,
                    &KeyFilter::role_filter(KeyRole::Authentication),
                )
                .await
                .error_while("finding related key")?;

            Some(did.verification_method_id(&related_key))
        } else {
            None
        };

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, holder_jwk_key_id, self.key_algorithm_provider.clone())
            .error_while("getting signature provider")?;

        let key = self
            .key_algorithm_provider
            .reconstruct_key(
                key.key_algorithm_type()
                    .error_while("getting key algorithm type")?,
                &key.public_key,
                None,
                None,
            )
            .error_while("reconstructing key")?
            .public_key_as_jwk()
            .error_while("getting JWK")?;

        let credential_response = self
            .holder_request_credential(
                &interaction_data,
                holder_binding.identifier.did.as_ref().map(|did| &did.did),
                key,
                Some(nonce),
                auth_fn,
                token_response.access_token.expose_secret(),
                attestation_result.wua_proof,
            )
            .await?;

        let notification_id = credential_response.notification_id.to_owned();

        let result = self
            .holder_process_accepted_credential(
                credential_response,
                &interaction_data,
                holder_binding,
                organisation,
                &interaction,
            )
            .await;

        interaction_data.credential_metadata = None;
        interaction_data.notification_id = notification_id.clone();
        self.interaction_repository
            .update_interaction(
                interaction.id,
                UpdateInteractionRequest {
                    data: Some(Some(serialize_interaction_data(&interaction_data)?)),
                },
            )
            .await
            .error_while("updating interaction")?;

        if let (Some(notification_id), Some(notification_endpoint)) =
            (notification_id, interaction_data.notification_endpoint)
        {
            let notification = match &result {
                Ok(_) => OpenID4VCINotificationRequestDTO {
                    notification_id,
                    event: OpenID4VCINotificationEvent::CredentialAccepted,
                    event_description: None,
                },
                Err(err) => OpenID4VCINotificationRequestDTO {
                    notification_id,
                    event: OpenID4VCINotificationEvent::CredentialFailure,
                    event_description: Some(err.to_string()),
                },
            };

            if let Err(error) = self
                .send_notification(
                    notification,
                    notification_endpoint.as_str(),
                    token_response.access_token.expose_secret(),
                )
                .await
            {
                tracing::warn!(%error, "Notification failure");
            }
        }

        result
    }

    async fn holder_reject_credential(
        &self,
        credential: Credential,
    ) -> Result<(), IssuanceProtocolError> {
        let interaction = credential
            .interaction
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let notification_endpoint = match &interaction_data.notification_endpoint {
            Some(value) => value.clone(),
            None => {
                // if there's no notification endpoint specified by the issuer, we cannot notify the deletion
                tracing::info!("No notification_endpoint provided by issuer");
                return Ok(());
            }
        };
        let notification_id = match &interaction_data.notification_id {
            Some(value) => value.clone(),
            None => {
                tracing::info!("No notification_id saved for interaction");
                return Ok(());
            }
        };

        let access_token = self
            .holder_reuse_or_refresh_token(interaction.id, &mut interaction_data)
            .await?;

        self.send_notification(
            OpenID4VCINotificationRequestDTO {
                notification_id,
                event: OpenID4VCINotificationEvent::CredentialDeleted,
                event_description: None,
            },
            notification_endpoint.as_str(),
            access_token.expose_secret(),
        )
        .await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError> {
        let interaction_id: InteractionId = Uuid::new_v4().into();

        let mut url = Url::parse(&format!("{}://", self.params.url_scheme))
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        let mut query = url.query_pairs_mut();

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "credential schema missing".to_string(),
            ))?;

        let protocol_base_url = self
            .protocol_base_url
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing base_url".to_owned()))?;

        if self.params.credential_offer_by_value {
            let identifier_id = credential
                .issuer_identifier
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "issuer_identifier missing".to_string(),
                ))?
                .id;

            let offer = create_credential_offer(
                protocol_base_url,
                &credential.protocol,
                &interaction_id.to_string(),
                credential_schema,
                identifier_id,
            )?;

            let offer_string = serde_json::to_string(&offer)?;

            query.append_pair(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY, &offer_string);
        } else {
            let offer_url = get_credential_offer_url(protocol_base_url.to_owned(), credential)?;
            query.append_pair(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY, &offer_url);
        }
        let url = query.finish().to_string();

        let transaction_code = credential_schema
            .transaction_code
            .as_ref()
            .map(generate_transaction_code);

        let interaction_data = Some(serialize_interaction_data(
            &OpenID4VCIIssuerInteractionDataDTO {
                pre_authorized_code_used: false,
                access_token_hash: vec![],
                access_token_expires_at: None,
                refresh_token_hash: None,
                refresh_token_expires_at: None,
                notification_id: None,
                transaction_code: transaction_code.to_owned(),
            },
        )?);

        let expires_at = Some(crate::clock::now_utc() + self.params.pre_authorized_code_expires_in);

        Ok(ShareResponse {
            url,
            interaction_id,
            interaction_data,
            expires_at,
            transaction_code,
        })
    }

    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        let Some(mut credential) = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(Default::default()),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        certificates: Some(CertificateRelations {
                            key: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    issuer_certificate: Some(CertificateRelations::default()),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?
        else {
            return Err(IssuanceProtocolError::Failed(
                "Credential not found".to_string(),
            ));
        };

        credential.holder_identifier = Some(holder_identifier.clone());

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "credential_schema is None".to_string(),
            ))?
            .clone();
        let credential_state = credential.state;

        let credential_format_type = self
            .config
            .format
            .get_fields(&credential_schema.format)
            .error_while("getting format config")?
            .r#type;

        self.validate_credential_issuable(
            credential_id,
            &credential_state,
            &credential_schema.format,
            credential_format_type,
        )
        .await?;

        let revocation_method = match &credential_schema.revocation_method {
            Some(method_id) => {
                let method = self
                    .revocation_provider
                    .get_revocation_method(method_id)
                    .ok_or(IssuanceProtocolError::Failed(format!(
                        "revocation method not found: {}",
                        method_id
                    )))?;
                Some(method)
            }
            None => None,
        };

        let credential_status = match revocation_method.as_deref() {
            Some(method) => method
                .add_issued_credential(&credential)
                .await
                .error_while("adding issued credential")?
                .into_iter()
                .map(|revocation_info| revocation_info.credential_status)
                .collect(),
            None => vec![],
        };

        let key = credential
            .key
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing key".to_string()))?;

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "missing issuer identifier".to_string(),
                ))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                key,
                self.jwk_key_id_from_identifier(issuer_identifier, key)
                    .await?,
                self.key_algorithm_provider.clone(),
            )
            .error_while("getting signature provider")?;

        let redirect_uri = credential.redirect_uri.to_owned();

        let core_base_url = self.base_url.as_ref().ok_or(IssuanceProtocolError::Failed(
            "Missing core_base_url for credential issuance".to_string(),
        ))?;

        // TODO - remove organisation usage from here when moved to open core
        let credential_detail = credential_detail_response_from_model(
            credential.clone(),
            &self.config,
            None,
            CredentialAttestationBlobs::default(),
            None,
        )
        .await
        .error_while("creating credential detail")?;

        let contexts = vcdm_v2_base_context(None);

        let issuer_certificate = if let Some(cert) = credential.issuer_certificate.clone() {
            Some(cert)
        } else {
            credential
                .issuer_identifier
                .as_ref()
                .and_then(|identifier| {
                    identifier
                        .certificates
                        .as_ref()
                        .and_then(|certs| certs.first().cloned())
                })
        };

        let holder_identifier_id = holder_identifier.id;
        let credential_data = credential_data_from_credential_detail_response(
            credential_detail,
            &credential,
            issuer_certificate,
            Some(holder_identifier),
            holder_key_id,
            core_base_url,
            credential_status,
            contexts,
        )
        .error_while("getting credential data")?;

        let token = self
            .formatter_provider
            .get_credential_formatter(&credential_schema.format)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "formatter not found: {}",
                &credential_schema.format
            )))?
            .format_credential(credential_data, auth_fn)
            .await
            .error_while("formatting credential")?;

        match (credential_format_type, credential_state) {
            (FormatType::Mdoc, CredentialStateEnum::Accepted) => {
                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: crate::clock::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await
                    .error_while("inserting validity credential")?;
            }
            (FormatType::Mdoc, CredentialStateEnum::Offered) => {
                let credential_blob_id = self.upsert_credential_blob(&credential, &token).await?;

                self.credential_repository
                    .update_credential(
                        *credential_id,
                        get_issued_credential_update(credential_blob_id, holder_identifier_id),
                    )
                    .await
                    .error_while("updating credential")?;

                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: crate::clock::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await
                    .error_while("inserting validity credential")?;
            }
            _ => {
                let credential_blob_id = self.upsert_credential_blob(&credential, &token).await?;

                self.credential_repository
                    .update_credential(
                        *credential_id,
                        get_issued_credential_update(credential_blob_id, holder_identifier_id),
                    )
                    .await
                    .error_while("updating credential")?;
            }
        }

        Ok(SubmitIssuerResponse {
            credential: token,
            redirect_uri,
            notification_id: Some(generate_alphanumeric(32)),
        })
    }

    async fn holder_continue_issuance(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
    ) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError> {
        let issuer_metadata = self
            .fetch_issuer_metadata(
                &continue_issuance_dto.credential_issuer,
                Some(organisation.id),
            )
            .await?;

        let AuthorizationMetadata {
            token_endpoint,
            oauth_metadata,
            ..
        } = get_authorization_metadata(
            self.metadata_cache.as_ref(),
            issuer_metadata.metadata(),
            &continue_issuance_dto.credential_issuer,
            continue_issuance_dto.authorization_server.as_ref(),
        )
        .await?;

        let scope_to_id: HashMap<&String, &String> = issuer_metadata
            .metadata()
            .credential_configurations_supported
            .iter()
            .filter_map(|(id, c)| c.scope.as_ref().map(|s| (s, id)))
            .collect();

        let scope_credential_config_ids = continue_issuance_dto
            .scope
            .iter()
            .map(|s| {
                scope_to_id
                    .get(&s)
                    .map(|s| s.to_string())
                    .ok_or(IssuanceProtocolError::Failed(format!(
                        "Issuance requested scope doesnt exists: {s}"
                    )))
            })
            .collect::<Result<Vec<String>, IssuanceProtocolError>>()?;

        let all_credential_configuration_ids = [
            &scope_credential_config_ids[..],
            &continue_issuance_dto.credential_configuration_ids[..],
        ]
        .concat();

        let requires_wallet_instance_attestation =
            requires_wia(&oauth_metadata.token_endpoint_auth_methods_supported);

        let PrepareIssuanceSuccess {
            interaction_id,
            key_storage_security,
            key_algorithms,
        } = self
            .prepare_issuance_interaction(
                organisation,
                token_endpoint,
                issuer_metadata,
                Some(oauth_metadata),
                OpenID4VCIGrants::AuthorizationCode(OpenID4VCIAuthorizationCodeGrant {
                    issuer_state: None, // issuer state was used at the authorization request stage so it is not relevant anymore
                    authorization_server: continue_issuance_dto.authorization_server.to_owned(),
                }),
                &all_credential_configuration_ids,
                Some(continue_issuance_dto),
            )
            .await?;

        Ok(ContinueIssuanceResponseDTO {
            interaction_id,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
            protocol: self.config_id.to_owned(),
        })
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        let mut features = vec![Features::SupportsRejection];
        if self.params.common.webhook_task.is_some() {
            features.push(Features::SupportsWebhooks);
        }

        IssuanceProtocolCapabilities {
            features,
            did_methods: vec![
                ConfigDidType::Key,
                ConfigDidType::Jwk,
                ConfigDidType::Web,
                ConfigDidType::WebVh,
            ],
        }
    }

    async fn issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        issuer_identifier: &Identifier,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, IssuanceProtocolError> {
        let prepared_metadata = self.prepare_issuer_metadata(credential_schema_id).await?;
        let issuer_info = self
            .get_etsi_issuer_info(issuer_identifier, &prepared_metadata.schema)
            .await?;

        create_issuer_metadata_response(
            protocol_id,
            issuer_identifier,
            prepared_metadata,
            issuer_info,
        )
        .map_err(OpenIDIssuanceError::OpenID4VCI)
        .map_err(Into::into)
    }
}

fn requires_wia(token_endpoint_auth_methods: &[TokenEndpointAuthMethod]) -> bool {
    // See https://gitlab.procivis.ch/procivis/one/one-core/-/merge_requests/2585#note_86705
    // Some issuers advertise "public", which is not documented / defined by any specification
    // We treat it as the rfc7591 defined "none"
    let public_auth_supported = token_endpoint_auth_methods
        .contains(&TokenEndpointAuthMethod::None)
        || token_endpoint_auth_methods
            .contains(&TokenEndpointAuthMethod::Other("public".to_string()));

    token_endpoint_auth_methods.contains(&TokenEndpointAuthMethod::AttestJwtClientAuth)
        && !public_auth_supported
}

struct PrepareIssuanceSuccess {
    interaction_id: InteractionId,
    key_storage_security: Option<Vec<KeyStorageSecurity>>,
    key_algorithms: Option<Vec<String>>,
}

async fn resolve_credential_offer(
    client: &dyn HttpClient,
    invitation_url: Url,
) -> Result<OpenID4VCIFinal1CredentialOfferDTO, IssuanceProtocolError> {
    let query_pairs: HashMap<_, _> = invitation_url.query_pairs().collect();
    let credential_offer_param = query_pairs.get(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY);
    let credential_offer_reference_param =
        query_pairs.get(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY);

    if credential_offer_param.is_some() && credential_offer_reference_param.is_some() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Detected both {CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY} and {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY}"
        )));
    }

    if let Some(credential_offer) = credential_offer_param {
        Ok(serde_json::from_str(credential_offer)?)
    } else if let Some(credential_offer_reference) = credential_offer_reference_param {
        let credential_offer_url = Url::parse(credential_offer_reference).map_err(|error| {
            IssuanceProtocolError::Failed(format!("Failed decoding credential offer url {error}"))
        })?;

        Ok(async {
            client
                .get(credential_offer_url.as_str())
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("fetching offer")?)
    } else {
        Err(IssuanceProtocolError::Failed(
            "Missing credential offer param".to_string(),
        ))
    }
}

#[expect(clippy::large_enum_variant)]
enum IssuerMetadataRepresentation {
    Unsigned(OpenID4VCIIssuerMetadataResponseDTO),
    Signed(
        DecomposedJwt<OpenID4VCIIssuerMetadataResponseDTO>,
        Option<(AccessCertificateResult, String)>,
    ),
}

impl IssuerMetadataRepresentation {
    fn metadata(&self) -> &OpenID4VCIIssuerMetadataResponseDTO {
        match &self {
            Self::Unsigned(metadata) => metadata,
            Self::Signed(jwt, _) => &jwt.payload.custom,
        }
    }
}

struct AuthorizationMetadata {
    token_endpoint: String,
    oauth_metadata: OAuthAuthorizationServerMetadataResponseDTO,
}

async fn get_authorization_metadata(
    fetcher: &dyn OpenIDMetadataFetcher,
    issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
    credential_issuer: &str,
    authorization_server: Option<&String>,
) -> Result<AuthorizationMetadata, IssuanceProtocolError> {
    let authorization_server_url = get_authorization_server_url_from_issuer_metadata(
        issuer_metadata,
        credential_issuer,
        authorization_server,
    )?;

    let oauth_metadata_response: OAuthAuthorizationServerMetadata =
        fetch_metadata_json_with_fallback(
            fetcher,
            &authorization_server_url,
            "oauth-authorization-server",
        )
        .await
        .error_while("fetching authorization server metadata")?;

    let token_endpoint = oauth_metadata_response
        .token_endpoint
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "Missing token_endpoint".to_string(),
        ))?
        .to_string();

    Ok(AuthorizationMetadata {
        token_endpoint,
        oauth_metadata: oauth_metadata_response.into(),
    })
}

fn get_authorization_server_url_from_issuer_metadata(
    issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
    credential_issuer: &str,
    authorization_server_from_offer: Option<&String>,
) -> Result<Url, IssuanceProtocolError> {
    let server_url = if let Some(authorization_server_from_offer) = authorization_server_from_offer
    {
        if issuer_metadata
            .authorization_servers
            .as_ref()
            .is_none_or(|servers| !servers.contains(authorization_server_from_offer))
        {
            return Err(IssuanceProtocolError::InvalidRequest(format!(
                "Authorization server missing in issuer metadata: {authorization_server_from_offer}"
            )));
        }

        authorization_server_from_offer.to_owned()
    } else if let Some(authorization_servers) = &issuer_metadata.authorization_servers {
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.2
        // > When there are multiple entries in the array, the Wallet may be able to determine which Authorization Server to use by querying the metadata; for example, by examining the grant_types_supported values, the Wallet can filter the server to use based on the grant type it plans to use.
        // TODO (ONE-7915): try to pick correct server based on querying, until then just pick the first
        authorization_servers
            .first()
            .ok_or(IssuanceProtocolError::Failed(
                "Empty authorization servers".to_string(),
            ))?
            .to_owned()
    } else {
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.2
        // > If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server
        credential_issuer.to_string()
    };

    server_url.parse().map_err(|_| {
        IssuanceProtocolError::InvalidRequest(format!(
            "Invalid authorization_server url {server_url}",
        ))
    })
}

async fn fetch_metadata_json_with_fallback<T: DeserializeOwned>(
    fetcher: &dyn OpenIDMetadataFetcher,
    issuer_url: &Url,
    well_known_path: &str,
) -> Result<T, IssuanceProtocolError> {
    let issuer_metadata_endpoint = prepend_well_known_path(issuer_url, well_known_path);
    Ok(match fetcher.fetch_json(&issuer_metadata_endpoint).await {
        Ok(response) => response,
        Err(err) => {
            if err.error_code() == ErrorCode::BR_0347 {
                let fallback_metadata_endpoint = append_well_known(issuer_url, well_known_path)?;
                tracing::warn!(
                    "Failed to fetch from `{issuer_metadata_endpoint}`, falling back to legacy endpoint `{fallback_metadata_endpoint}`: {err}"
                );
                fetcher
                    .fetch_json(&fallback_metadata_endpoint)
                    .await
                    .error_while("fetching metadata from fallback URL")?
            } else {
                Err(err).error_while("fetching metadata")?
            }
        }
    })
}

async fn fetch_metadata_jwt_with_fallback<T: DeserializeOwned + Debug>(
    fetcher: &dyn OpenIDMetadataFetcher,
    issuer_url: &Url,
    well_known_path: &str,
) -> Result<DecomposedJwt<T>, IssuanceProtocolError> {
    let issuer_metadata_endpoint = prepend_well_known_path(issuer_url, well_known_path);
    Ok(match fetcher.fetch_jwt(&issuer_metadata_endpoint).await {
        Ok(response) => response,
        Err(err) => {
            if err.error_code() == ErrorCode::BR_0347 {
                let fallback_metadata_endpoint = append_well_known(issuer_url, well_known_path)?;
                tracing::warn!(
                    "Failed to fetch from `{issuer_metadata_endpoint}`, falling back to legacy endpoint `{fallback_metadata_endpoint}`: {err}"
                );
                fetcher
                    .fetch_jwt(&fallback_metadata_endpoint)
                    .await
                    .error_while("fetching metadata from fallback URL")?
            } else {
                Err(err).error_while("fetching metadata")?
            }
        }
    })
}

fn prepend_well_known_path(credential_issuer: &Url, well_known_path_segment: &str) -> String {
    let origin = {
        let mut url = credential_issuer.clone();
        url.set_path("");
        url.to_string()
    };
    let path = match credential_issuer.path() {
        "/" => "", // do not append trailing slash for empty path
        path => path,
    };
    format!("{origin}.well-known/{well_known_path_segment}{path}")
}

fn append_well_known(credential_issuer: &Url, path: &str) -> Result<String, IssuanceProtocolError> {
    let mut url = credential_issuer.to_owned();
    url.path_segments_mut()
        .map_err(move |_| {
            IssuanceProtocolError::Failed(format!(
                "Invalid credential_issuer URL: {credential_issuer}",
            ))
        })?
        .push(".well-known")
        .extend(path.split("/"));

    Ok(url.to_string())
}

async fn create_and_store_interaction(
    interaction_repository: &dyn InteractionRepository,
    data: Vec<u8>,
    organisation: Option<Organisation>,
) -> Result<Interaction, IssuanceProtocolError> {
    let now = crate::clock::now_utc();

    let interaction = interaction_from_handle_invitation(Some(data), now, organisation);

    interaction_repository
        .create_interaction(interaction.clone())
        .await
        .error_while("creating interaction")?;

    Ok(interaction)
}

async fn prepare_credential_schema(
    credential_schema_importer: &dyn CredentialSchemaImporter,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    credential_schema: CredentialSchema,
    organisation: &Organisation,
    credential: &mut Credential,
) -> Result<Option<UpdateCredentialSchemaRequest>, IssuanceProtocolError> {
    let stored_schema = credential_schema_repository
        .get_by_schema_id_and_organisation(&credential_schema.schema_id, organisation.id)
        .await
        .error_while("getting credential schema")?;

    if let Some(stored_schema) = stored_schema {
        prepare_credential_schema_updates(credential_schema, stored_schema, credential).await
    } else {
        match credential_schema_importer
            .import_credential_schema(credential_schema.clone())
            .await
        {
            Ok(schema) => {
                credential.schema = Some(schema);
                return Ok(None);
            }
            Err(error) if error.error_code() == ErrorCode::BR_0007 => {
                tracing::debug!("Conflicting schema detected during parsing, refetching");
            }
            Err(e) => {
                return Err(IssuanceProtocolError::Failed(e.to_string()));
            }
        };

        // refetch and try again
        let stored_schema = credential_schema_repository
            .get_by_schema_id_and_organisation(&credential_schema.schema_id, organisation.id)
            .await
            .error_while("getting credential schema")?
            .ok_or(IssuanceProtocolError::Failed(
                "Credential schema not found".to_string(),
            ))?;

        prepare_credential_schema_updates(credential_schema, stored_schema, credential).await
    }
}

async fn prepare_credential_schema_updates(
    parsed_schema: CredentialSchema,
    stored_schema: CredentialSchema,
    credential: &mut Credential,
) -> Result<Option<UpdateCredentialSchemaRequest>, IssuanceProtocolError> {
    let claims = credential
        .claims
        .as_mut()
        .ok_or(IssuanceProtocolError::Failed("Missing claims".to_string()))?;

    let stored_claim_schemas = stored_schema
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?;

    let parsed_claim_schemas = parsed_schema
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?;

    let mut new_claim_schemas = vec![];
    for parsed_claim_schema in parsed_claim_schemas {
        let stored_claim_schema = stored_claim_schemas
            .iter()
            .find(|schema| schema.key == parsed_claim_schema.key);

        if let Some(stored_claim_schema) = stored_claim_schema {
            // link all matching credential claims to the stored claim_schema
            claims
                .iter_mut()
                .filter(|claim| {
                    claim
                        .schema
                        .as_ref()
                        .is_some_and(|schema| schema.id == parsed_claim_schema.id)
                })
                .for_each(|claim| {
                    claim.schema = Some(stored_claim_schema.to_owned());
                });
        } else {
            new_claim_schemas.push(parsed_claim_schema);
        }
    }

    let id = stored_schema.id;
    credential.schema = Some(stored_schema);

    if new_claim_schemas.is_empty() {
        return Ok(None);
    }

    Ok(Some(UpdateCredentialSchemaRequest {
        id,
        revocation_method: None,
        format: None,
        claim_schemas: Some(new_claim_schemas),
        layout_type: None,
        layout_properties: None,
    }))
}

async fn create_wallet_unit_attestation_pop(
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key: &Key,
    audience: &str,
    challenge: Option<String>,
    client_id: &str,
) -> Result<String, IssuanceProtocolError> {
    #[derive(Serialize)]
    struct WalletUnitPopCustomClaims {
        #[serde(skip_serializing_if = "Option::is_none")]
        challenge: Option<String>,
    }

    let now = crate::clock::now_utc();

    let attestation_auth_fn = key_provider
        .get_attestation_signature_provider(key, None, key_algorithm_provider.clone())
        .error_while("getting attestation signature provider")?;

    let auth_fn = key_provider
        .get_signature_provider(key, None, key_algorithm_provider)
        .error_while("getting signature provider")?;

    let proof = Jwt::new(
        "oauth-client-attestation-pop+jwt".to_string(),
        auth_fn.jose_alg().error_while("getting JOSE alg")?,
        auth_fn.get_key_id(),
        None,
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::minutes(60)),
            invalid_before: Some(now),
            audience: Some(vec![audience.to_string()]),
            jwt_id: Some(Uuid::new_v4().to_string()),
            issuer: Some(client_id.to_string()),
            subject: None,
            proof_of_possession_key: None,
            custom: WalletUnitPopCustomClaims { challenge },
        },
    );

    // We first attempt to sign with the attestation auth fn
    // If that fails, we fall back to the auth fn
    // To be fixed in https://procivis.atlassian.net/browse/ONE-7501
    let signed_proof = proof.tokenize(Some(&*attestation_auth_fn)).await;

    match signed_proof {
        Ok(signed_proof) => Ok(signed_proof),
        Err(_) => Ok(proof
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating proof token")?),
    }
}

impl IdentifierTrustInformation {
    fn is_valid(&self, now: OffsetDateTime) -> bool {
        let valid_form = self.valid_from.map(|v| v <= now).unwrap_or(true);
        let valid_to = self.valid_to.map(|v| now <= v).unwrap_or(true);
        valid_form && valid_to
    }

    fn is_issuance_allowed_for(&self, schema_id: &str, format_type: &FormatType) -> bool {
        self.allowed_issuance_types
            .iter()
            .any(|sf| sf.is_allowed_for(schema_id, format_type))
    }
}

impl SchemaFormat {
    fn is_allowed_for(&self, schema_id: &str, format_type: &FormatType) -> bool {
        self.schema_id == schema_id && self.format == (*format_type).into()
    }
}
