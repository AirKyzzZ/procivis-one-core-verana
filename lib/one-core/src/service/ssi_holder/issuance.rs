use std::sync::Arc;

use futures_util::FutureExt;
use shared_types::{CredentialId, DidId, IdentifierId, InteractionId, KeyId};
use url::Url;
use uuid::Uuid;

use super::SSIHolderService;
use super::dto::{
    ContinueIssuanceResponseDTO, HandleInvitationResultDTO, InitiateIssuanceRequestDTO,
    InitiateIssuanceResponseDTO, OpenIDAuthorizationCodeFlowInteractionData,
};
use super::error::HolderServiceError;
use super::mapper::select_holder_key;
use super::validator::{
    validate_credentials_match_session_organisation, validate_holder_capabilities,
    validate_initiate_issuance_request,
};
use crate::config::core_config::{BlobStorageType, FormatType};
use crate::error::ContextWithErrorCode;
use crate::model::blob::{Blob, BlobType};
use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::{Interaction, InteractionRelations, InteractionType};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::proto::oauth_client::{OAuthAuthorizationRequest, OAuthClientProvider};
use crate::provider::blob_storage::BlobStorage;
use crate::provider::issuance_protocol::dto::{ContinueIssuanceDTO, Features};
use crate::provider::issuance_protocol::model::{CredentialWithBlob, InvitationResponseEnum};
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper::interaction_data_to_accepted_key_storage_security;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::CredentialSigningAlgValue;
use crate::provider::issuance_protocol::{
    self, HolderBindingInput, IssuanceProtocol, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::service::error::MissingProviderError;
use crate::validator::key_security::match_key_security_level;
use crate::validator::{
    throw_if_credential_state_not_eq, throw_if_org_id_not_matching_session,
    throw_if_org_not_matching_session,
};

const STATE: &str = "state";
const AUTHORIZATION_CODE: &str = "code";

impl SSIHolderService {
    pub async fn accept_credential(
        &self,
        interaction_id: InteractionId,
        did_id: Option<DidId>,
        identifier_id: Option<IdentifierId>,
        key_id: Option<KeyId>,
        tx_code: Option<String>,
    ) -> Result<CredentialId, HolderServiceError> {
        let identifier = match (did_id, identifier_id) {
            (Some(did_id), None) => Some(
                self.identifier_repository
                    .get_from_did_id(
                        did_id,
                        &IdentifierRelations {
                            organisation: Some(OrganisationRelations::default()),
                            did: Some(Default::default()),
                            key: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("getting identifier")?
                    .ok_or(HolderServiceError::MissingDid(did_id))?,
            ),
            (None, Some(identifier_id)) => Some(
                self.identifier_repository
                    .get(
                        identifier_id,
                        &IdentifierRelations {
                            organisation: Some(OrganisationRelations::default()),
                            did: Some(Default::default()),
                            key: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("getting identifier")?
                    .ok_or(HolderServiceError::MissingIdentifier(identifier_id))?,
            ),
            (None, None) => None,
            (Some(_), Some(_)) => {
                return Err(HolderServiceError::InvalidIdentifierInput(
                    "Both didId and identifierId specified".to_string(),
                ));
            }
        };

        let holder_binding_input = if let Some(identifier) = identifier {
            throw_if_org_not_matching_session(
                identifier.organisation.as_ref(),
                &*self.session_provider,
            )
            .error_while("checking session")?;

            let key = select_holder_key(&identifier, key_id).await?;
            Some(HolderBindingInput { identifier, key })
        } else {
            None
        };

        let credential_id = self
            .accept_credential_final1(interaction_id, holder_binding_input, tx_code)
            .await?;

        tracing::info!(
            "Accepted issuance of credential {credential_id} for interaction {interaction_id}"
        );
        Ok(credential_id)
    }

    /// specific handling for the final-1 protocol, credential gets created after issued
    async fn accept_credential_final1(
        &self,
        interaction_id: InteractionId,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
    ) -> Result<CredentialId, HolderServiceError> {
        let interaction = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations {
                    organisation: Some(Default::default()),
                },
                None,
            )
            .await
            .error_while("getting interaction")?
            .ok_or(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ))?;
        throw_if_org_not_matching_session(
            interaction.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("checking interaction organisation")?;

        if interaction.interaction_type != InteractionType::Issuance {
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ));
        }

        let data: issuance_protocol::openid4vci_final1_0::model::HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("parsing holder interaction data")?;

        if let Some(holder_binding) = &holder_binding
            && let Some(accepted_security_levels) =
                interaction_data_to_accepted_key_storage_security(&data)
        {
            match_key_security_level(
                &holder_binding.key.storage_type,
                &accepted_security_levels,
                &*self.key_security_level_provider,
            )
            .error_while("matching key security")?;
        }

        let format_type = match data.format.as_str() {
            "jwt_vc_json" => FormatType::Jwt,
            "dc+sd-jwt" => FormatType::SdJwtVc,
            "vc+sd-jwt" => FormatType::SdJwt,
            "mso_mdoc" => FormatType::Mdoc,
            "ldp_vc" => {
                if data
                    .credential_signing_alg_values_supported
                    .is_some_and(|values| {
                        values
                            .iter()
                            .any(|v| matches!(v, CredentialSigningAlgValue::String(alg) if alg == "ES256"))
                    })
                {
                    FormatType::JsonLdClassic
                } else {
                    FormatType::JsonLdBbsPlus
                }
            }
            _ => {
                return Err(HolderServiceError::MappingError(format!(
                    "Unknown format: {}",
                    data.format
                )));
            }
        };

        let (_, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or(MissingProviderError::FormatterType(format_type))
            .error_while("getting formatter")?;

        if let Some(holder_binding) = &holder_binding {
            validate_holder_capabilities(
                &self.config,
                holder_binding,
                &formatter.get_capabilities(),
                self.key_algorithm_provider.as_ref(),
            )?;
        }

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&data.protocol)?;

        let issuer_response = protocol
            .holder_accept_credential(interaction, holder_binding, tx_code)
            .await
            .error_while("accepting credential")?;
        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let main_credential_id = issuer_response.main_credential.credential.id;
        self.transaction_manager
            .tx(async {
                self.create_credential(issuer_response.main_credential, db_blob_storage.as_ref())
                    .await?;
                for batch_item in issuer_response.batch_items {
                    self.create_credential(batch_item, db_blob_storage.as_ref())
                        .await?;
                }
                Ok::<_, HolderServiceError>(())
            }
            .boxed())
            .await
            .error_while("creating credentials")??;
        Ok(main_credential_id)
    }

    async fn create_credential(
        &self,
        credential: CredentialWithBlob,
        db_blob_storage: &dyn BlobStorage,
    ) -> Result<(), HolderServiceError> {
        let CredentialWithBlob {
            credential,
            serialized,
        } = credential;

        let credential_blob_id = if let Some(token) = serialized {
            let blob = Blob::new(token.as_ref(), BlobType::Credential);
            let blob_id = blob.id;
            db_blob_storage
                .create(blob)
                .await
                .error_while("creating credential blob")?;
            Some(blob_id)
        } else {
            None
        };

        self.credential_repository
            .create_credential(Credential {
                state: CredentialStateEnum::Accepted,
                credential_blob_id,
                ..credential
            })
            .await
            .error_while("creating credential")?;
        Ok(())
    }

    pub async fn refresh_credentials(
        &self,
        interaction_id: InteractionId,
    ) -> Result<Vec<CredentialId>, HolderServiceError> {
        let interaction = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations {
                    organisation: Some(Default::default()),
                },
                None,
            )
            .await
            .error_while("getting interaction")?
            .ok_or(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ))?;
        throw_if_org_not_matching_session(
            interaction.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("checking interaction organisation")?;

        if interaction.interaction_type != InteractionType::Issuance {
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ));
        }

        let data: issuance_protocol::openid4vci_final1_0::model::HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("parsing holder interaction data")?;

        if data.batch_size.is_none() || data.refresh_token.is_none() {
            tracing::debug!(
                "Interaction batch: {}, refresh_token: {}",
                data.batch_size.is_some(),
                data.refresh_token.is_some()
            );
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ));
        }

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&data.protocol)?;

        let credential_ids = protocol
            .holder_refresh_credential(&interaction, None)
            .await
            .error_while("refreshing credential batch")?;

        tracing::info!(
            "Batch issued, new credentials {credential_ids:?} for interaction {interaction_id}"
        );
        Ok(credential_ids)
    }

    pub async fn reject_credential(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), HolderServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    key: Some(Default::default()),
                    schema: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credentials")?;

        if credentials.is_empty() {
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                *interaction_id,
            ));
        }
        validate_credentials_match_session_organisation(&credentials, &*self.session_provider)?;

        let credential_protocol_pairs = credentials
            .into_iter()
            .map(|credential| {
                throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Accepted)
                    .error_while("checking credential state")?;

                let protocol = self
                    .issuance_protocol_provider
                    .get_protocol(&credential.protocol)?;

                if !protocol
                    .get_capabilities()
                    .features
                    .contains(&Features::SupportsRejection)
                {
                    return Err(HolderServiceError::RejectionNotSupported);
                }

                Ok((credential, protocol))
            })
            .collect::<Result<Vec<_>, HolderServiceError>>()?;

        let mut result: Result<(), HolderServiceError> = Ok(());
        for (credential, protocol) in credential_protocol_pairs {
            if let Err(err) = self.reject_single_credential(credential, &*protocol).await {
                result = Err(err);
            };
        }

        result
    }

    async fn reject_single_credential(
        &self,
        credential: Credential,
        protocol: &dyn IssuanceProtocol,
    ) -> Result<(), HolderServiceError> {
        let credential_id = credential.id;
        protocol
            .holder_reject_credential(credential)
            .await
            .error_while("rejecting credential")?;

        self.credential_repository
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Rejected),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;

        Ok(())
    }

    pub(super) async fn handle_issuance_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        exchange: String,
        issuance_protocol: Arc<dyn IssuanceProtocol>,
        redirect_uri: Option<String>,
    ) -> Result<HandleInvitationResultDTO, HolderServiceError> {
        let result = issuance_protocol
            .holder_handle_invitation(url, organisation, redirect_uri)
            .await
            .error_while("handling invitation")?;

        match result {
            InvitationResponseEnum::Credential {
                interaction_id,
                tx_code,
                key_storage_security,
                key_algorithms,
                requires_wallet_instance_attestation,
            } => Ok(HandleInvitationResultDTO::Credential {
                interaction_id,
                tx_code,
                key_storage_security_levels: key_storage_security,
                key_algorithms,
                protocol: exchange,
                requires_wallet_instance_attestation,
            }),
            InvitationResponseEnum::AuthorizationFlow {
                organisation_id,
                issuer,
                client_id,
                redirect_uri,
                authorization_details,
                scope,
                issuer_state,
                authorization_server,
            } => {
                let InitiateIssuanceResponseDTO {
                    interaction_id,
                    url,
                } = self
                    .initiate_issuance(InitiateIssuanceRequestDTO {
                        organisation_id,
                        protocol: exchange.to_owned(),
                        issuer,
                        client_id,
                        redirect_uri,
                        scope,
                        authorization_details,
                        issuer_state,
                        authorization_server,
                    })
                    .await?;

                Ok(HandleInvitationResultDTO::AuthorizationCodeFlow {
                    interaction_id,
                    authorization_code_flow_url: url,
                    protocol: exchange,
                })
            }
        }
    }

    pub async fn initiate_issuance(
        &self,
        request: InitiateIssuanceRequestDTO,
    ) -> Result<InitiateIssuanceResponseDTO, HolderServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        validate_initiate_issuance_request(&request, &self.config)?;

        let Some(organisation) = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?
        else {
            return Err(HolderServiceError::MissingOrganisation(
                request.organisation_id,
            ));
        };

        let authorization_server = request
            .authorization_server
            .as_ref()
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-11.2.3-2.2
            // ... If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server
            .unwrap_or(&request.issuer);

        let authorization_server = Url::parse(authorization_server).map_err(|e| {
            HolderServiceError::InvalidInput(format!("Invalid authorization server: {e}"))
        })?;

        let interaction_id: InteractionId = Uuid::new_v4().into();
        let mut authorization_request = OAuthAuthorizationRequest::new(
            request.client_id.clone(),
            request.scope.as_ref().map(|s| s.join(" ")),
            Some(interaction_id.to_string()),
            request.redirect_uri.clone(),
            request
                .authorization_details
                .as_ref()
                .map(|ad| serde_json::json!(ad).to_string()),
        );
        if let Some(issuer_state) = &request.issuer_state {
            authorization_request =
                authorization_request.with_issuer_state(issuer_state.to_owned());
        }

        let authorization_response = self
            .client
            .oauth_client()
            .initiate_authorization_code_flow(authorization_server, authorization_request)
            .await
            .error_while("initiating authorization code flow")?;

        let interaction_data = OpenIDAuthorizationCodeFlowInteractionData {
            request,
            code_verifier: authorization_response.code_verifier,
        };
        // store request parameters inside interaction
        let data = serialize_interaction_data(&interaction_data)
            .error_while("storing interaction data")?;

        let now = crate::clock::now_utc();
        self.interaction_repository
            .create_interaction(Interaction {
                id: interaction_id,
                created_date: now,
                last_modified: now,
                data: Some(data),
                organisation: Some(organisation),
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
                expires_at: None,
            })
            .await
            .error_while("creating interaction")?;

        tracing::info!(
            "Initiated authorization code flow for credential issuance, created interaction {interaction_id}"
        );
        Ok(InitiateIssuanceResponseDTO {
            interaction_id,
            url: authorization_response.url.to_string(),
        })
    }

    pub async fn continue_issuance(
        &self,
        url: impl AsRef<str>,
    ) -> Result<ContinueIssuanceResponseDTO, HolderServiceError> {
        let url = Url::parse(url.as_ref()).map_err(|error| {
            HolderServiceError::InvalidInput(format!(
                "Continuation URL has invalid format: {error}"
            ))
        })?;

        let (_, state) = url.query_pairs().find(|(key, _)| key == STATE).ok_or(
            HolderServiceError::InvalidInput(
                "Continuation URL state parameter not specified".to_string(),
            ),
        )?;

        let (_, authorization_code) = url
            .query_pairs()
            .find(|(key, _)| key == AUTHORIZATION_CODE)
            .ok_or(HolderServiceError::InvalidInput(
                "Continuation URL authorization_code parameter not specified".to_string(),
            ))?;

        let interaction_id = Uuid::parse_str(state.as_ref())
            .map_err(|_| {
                HolderServiceError::InvalidInput(
                    "Continuation URL state parameter has invalid format".to_string(),
                )
            })?
            .into();

        let interaction = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations {
                    organisation: Some(Default::default()),
                },
                None,
            )
            .await
            .error_while("getting interaction")?
            .ok_or(HolderServiceError::MissingInteraction(interaction_id))?;

        throw_if_org_not_matching_session(
            interaction.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;
        let issuance: OpenIDAuthorizationCodeFlowInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("parsing holder interaction data")?;

        let organisation = interaction
            .organisation
            .ok_or(HolderServiceError::MappingError(
                "organisation missing".to_string(),
            ))?;

        if let (None, None) = (
            issuance.request.scope.as_ref(),
            issuance.request.authorization_details.as_ref(),
        ) {
            return Err(HolderServiceError::InvalidInput("Either `scope` or `authorization_details` has to be specified for credential issuance".to_string()));
        }

        let issuance_protocol::model::ContinueIssuanceResponseDTO {
            interaction_id,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
            protocol,
        } = self
            .issuance_protocol_provider
            .get_protocol(&issuance.request.protocol)?
            .holder_continue_issuance(
                ContinueIssuanceDTO {
                    credential_issuer: issuance.request.issuer,
                    authorization_code: authorization_code.to_string(),
                    client_id: issuance.request.client_id,
                    redirect_uri: issuance.request.redirect_uri,
                    scope: issuance.request.scope.unwrap_or_default(),
                    credential_configuration_ids: issuance
                        .request
                        .authorization_details
                        .unwrap_or_default()
                        .into_iter()
                        .map(|d| d.credential_configuration_id)
                        .collect(),
                    code_verifier: issuance.code_verifier,
                    authorization_server: issuance.request.authorization_server,
                },
                organisation,
            )
            .await
            .error_while("continuing issuance")?;

        tracing::info!(
            "Processed authorization code flow result for credential issuance using interaction {interaction_id}"
        );

        Ok(ContinueIssuanceResponseDTO {
            interaction_id,
            interaction_type: InteractionType::Issuance,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
            protocol,
        })
    }
}
