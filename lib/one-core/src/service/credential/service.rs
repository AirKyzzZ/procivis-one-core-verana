use one_dto_mapper::convert_inner;
use shared_types::CredentialId;
use uuid::Uuid;

use super::CredentialService;
use super::dto::{
    CreateCredentialRequestDTO, CredentialAttestationBlobs, CredentialDetailResponseDTO,
    CredentialRevocationCheckResponseDTO, DetailCredentialClaimResponseDTO,
    GetCredentialListResponseDTO, ShareCredentialResponseDTO, SuspendCredentialRequestDTO,
};
use super::error::CredentialServiceError;
use super::mapper::{
    claims_from_create_request, credential_detail_response_from_model, from_create_request,
};
use super::validator::{
    throw_if_credential_state_eq, validate_format_and_did_method_compatibility,
    validate_redirect_uri, validate_webhook_url,
};
use crate::config::validator::protocol::validate_protocol_did_compatibility;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::list_response_try_into;
use crate::model::certificate::{CertificateRelations, CertificateRole};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Credential, CredentialListIncludeEntityTypeEnum, CredentialRelations, CredentialRole,
    CredentialStateEnum, SortableCredentialColumn, UpdateCredentialRequest,
};
use crate::model::did::KeyRole;
use crate::model::identifier::{IdentifierRelations, IdentifierState, IdentifierType};
use crate::model::interaction::{InteractionRelations, InteractionType};
use crate::model::validity_credential::ValidityCredentialType;
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::issuance_protocol::model::ShareResponse;
use crate::provider::revocation::model::RevocationState;
use crate::repository::error::DataLayerError;
use crate::service::common_dto::{ListQueryDTO, TrustInformationDetailResponseDTO};
use crate::service::credential::dto::CredentialFilterParamsDTO;
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::service::error::{BusinessLogicError, MissingProviderError};
use crate::util::interactions::{add_new_interaction, clear_previous_interaction};
use crate::util::key_selection::{CertificateFilter, KeyFilter, KeySelection, SelectedKey};
use crate::validator::{
    throw_if_credential_schema_not_in_session_org, throw_if_org_id_not_matching_session,
};

impl CredentialService {
    /// Creates a credential according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential request
    pub async fn create_credential(
        &self,
        request: CreateCredentialRequestDTO,
    ) -> Result<CredentialId, CredentialServiceError> {
        let issuer_identifier = match request.issuer {
            Some(issuer_identifier_id) => self
                .identifier_repository
                .get(
                    issuer_identifier_id,
                    &IdentifierRelations {
                        did: Some(Default::default()),
                        certificates: Some(CertificateRelations {
                            key: Some(Default::default()),
                            ..Default::default()
                        }),
                        key: Some(Default::default()),
                        ..Default::default()
                    },
                )
                .await
                .error_while("getting identifier")?
                .ok_or(CredentialServiceError::MissingIdentifier(
                    issuer_identifier_id,
                ))?,
            None => {
                let issuer_did_id = request.issuer_did.ok_or(CredentialServiceError::NoIssuer)?;

                self.identifier_repository
                    .get_from_did_id(
                        issuer_did_id,
                        &IdentifierRelations {
                            did: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("getting identifier")?
                    .ok_or(CredentialServiceError::MissingDid(issuer_did_id))?
            }
        };

        let Some(schema) = self
            .credential_schema_repository
            .get_credential_schema(&request.credential_schema_id)
            .await
            .error_while("getting credential schema")?
        else {
            return Err(CredentialServiceError::MissingCredentialSchema(
                request.credential_schema_id,
            ));
        };
        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        validate_key_storage_security_supported(schema.key_storage_security, &self.config)
            .error_while("validating key storage security")?;

        let claim_schemas = schema
            .claim_schemas
            .get()
            .await
            .error_while("getting claim schemas")?;

        let formatter_capabilities = self
            .formatter_provider
            .get_credential_formatter(&schema.format)
            .ok_or(MissingProviderError::Formatter(schema.format.to_string()))
            .error_while("getting formatter")?
            .get_capabilities();

        let exchange_capabilities = self
            .protocol_provider
            .get_protocol(&request.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                request.protocol.to_owned(),
            ))
            .error_while("getting protocol")?
            .get_capabilities();

        let key_filter = KeyFilter {
            did_role: Some(KeyRole::AssertionMethod),
            algorithms: Some(formatter_capabilities.signing_key_algorithms.clone()),
            ..Default::default()
        };
        let certificate_filter = CertificateFilter::role_filter(CertificateRole::AssertionMethod);
        let selection = issuer_identifier
            .select_key(KeySelection {
                key: request.issuer_key,
                did: request.issuer_did,
                certificate: request.issuer_certificate,
                key_filter: Some(key_filter),
                certificate_filter: Some(certificate_filter),
            })
            .await
            .error_while("selecting key")?;

        let (issuer_key, issuer_certificate) = match selection {
            SelectedKey::Key(_) => {
                return Err(CredentialServiceError::InvalidIdentifierType(
                    IdentifierType::Key,
                ));
            }
            SelectedKey::Certificate { certificate, key } => {
                (key.to_owned(), Some(certificate.to_owned()))
            }
            SelectedKey::Did { did, key } => {
                validate_protocol_did_compatibility(
                    &exchange_capabilities.did_methods,
                    &did.did_method,
                    &self.config.did,
                )
                .error_while("checking did compatibility")?;
                validate_format_and_did_method_compatibility(
                    &did.did_method,
                    &formatter_capabilities,
                    &self.config,
                )?;
                (key.key.to_owned(), None)
            }
        };

        super::validator::validate_create_request(
            &request.protocol,
            &request.claim_values,
            &schema,
            &formatter_capabilities,
            &self.config,
        )
        .await?;
        validate_redirect_uri(
            &request.protocol,
            request.redirect_uri.as_deref(),
            &self.config,
        )?;
        validate_webhook_url(
            request.webhook_destination_url.as_ref(),
            &request.protocol,
            &self.config,
            self.notification_scheduler.as_ref(),
        )?;

        let credential_id = Uuid::new_v4().into();
        let claims = claims_from_create_request(
            credential_id,
            request.claim_values.clone(),
            &claim_schemas,
        )?;

        let success_log = format!(
            "Created credential {} using schema `{}` ({}) and issuer `{}` ({}): protocol `{}`",
            credential_id,
            schema.name,
            schema.id,
            issuer_identifier.name,
            issuer_identifier.id,
            request.protocol
        );
        let credential = from_create_request(
            request,
            credential_id,
            claims,
            issuer_identifier,
            issuer_certificate,
            schema,
            issuer_key,
        );

        let result = self
            .credential_repository
            .create_credential(credential)
            .await
            .error_while("creating credential")?;

        tracing::info!(message = success_log);
        Ok(result)
    }

    /// Deletes a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn delete_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    schema: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?;

        let Some(credential) = credential else {
            return Err(CredentialServiceError::NotFound(*credential_id));
        };

        let schema = credential
            .schema
            .as_ref()
            .ok_or(CredentialServiceError::MappingError(
                "credential_schema is None".to_string(),
            ))?;
        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        let is_issuer = credential.role == CredentialRole::Issuer;
        if is_issuer && let Some(method_id) = &schema.revocation_method {
            let _revocation_fields = self
                .config
                .revocation
                .get_fields(method_id)
                .error_while("getting revocation config")?;
            throw_if_credential_state_eq(&credential, CredentialStateEnum::Accepted)?;
        }

        self.credential_repository
            .delete_credential(&credential)
            .await
            .map_err(|error| match error {
                // credential not found or already deleted
                DataLayerError::RecordNotUpdated => {
                    CredentialServiceError::NotFound(*credential_id)
                }
                error => error.error_while("deleting credential").into(),
            })?;

        tracing::info!("Deleted credential {}", credential.id);
        Ok(())
    }

    /// Returns details of a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn get_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>, CredentialServiceError>
    {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(Default::default()),
                    issuer_identifier: Some(Default::default()),
                    issuer_certificate: Some(CertificateRelations::default()),
                    holder_identifier: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?;

        let credential = credential.ok_or(CredentialServiceError::NotFound(*credential_id))?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)
            .error_while("checking session")?;

        if credential.deleted_at.is_some() {
            return Err(CredentialServiceError::NotFound(*credential_id));
        }

        let mdoc_validity_credentials = match &credential.schema {
            Some(schema) if schema.format.to_string() == "MDOC" => self
                .validity_credential_repository
                .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                .await
                .error_while("getting validity credential")?,
            _ => None,
        };

        let trust_information = self
            .trust_information_provider
            .get_trust_information((*credential_id).into())
            .await
            .error_while("getting trust information")?;

        let attestation_blobs = self.get_wallet_attestation_blobs(&credential).await?;

        let response = credential_detail_response_from_model(
            credential,
            &self.config,
            mdoc_validity_credentials,
            attestation_blobs,
            trust_information,
        )
        .await?;

        Ok(response)
    }

    async fn get_wallet_attestation_blobs(
        &self,
        credential: &Credential,
    ) -> Result<CredentialAttestationBlobs, CredentialServiceError> {
        if credential.wallet_instance_attestation_blob_id.is_none()
            && credential.wallet_unit_attestation_blob_id.is_none()
        {
            return Ok(CredentialAttestationBlobs::default());
        }

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
            .error_while("getting blob storage")?;

        let wallet_instance_attestation_blob = match &credential.wallet_instance_attestation_blob_id
        {
            Some(blob_id) => Some(
                db_blob_storage
                    .get(blob_id)
                    .await
                    .error_while("getting WIA blob")?
                    .ok_or(CredentialServiceError::MappingError(
                        "wallet instance attestation blob is None".to_string(),
                    ))?,
            ),
            None => None,
        };
        let wallet_unit_attestation_blob = match &credential.wallet_unit_attestation_blob_id {
            Some(blob_id) => Some(
                db_blob_storage
                    .get(blob_id)
                    .await
                    .error_while("getting WUA blob")?
                    .ok_or(CredentialServiceError::MappingError(
                        "wallet unit attestation blob is None".to_string(),
                    ))?,
            ),
            None => None,
        };

        Ok(CredentialAttestationBlobs {
            wallet_instance_attestation_blob,
            wallet_unit_attestation_blob,
        })
    }

    /// Returns list of credentials according to query
    ///
    /// # Arguments
    ///
    /// * `filter_params` - query parameters
    pub async fn get_credential_list(
        &self,
        filter_params: ListQueryDTO<
            SortableCredentialColumn,
            CredentialFilterParamsDTO,
            CredentialListIncludeEntityTypeEnum,
        >,
    ) -> Result<GetCredentialListResponseDTO, CredentialServiceError> {
        if filter_params.filter.name.is_some()
            && filter_params.filter.search_type.is_some()
            && filter_params.filter.search_text.is_some()
        {
            return Err(BusinessLogicError::GeneralInputValidationError
                .error_while("validating credential filter")
                .into());
        }

        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let result = self
            .credential_repository
            .get_credential_list(filter_params.into())
            .await
            .error_while("getting credentials")?;

        list_response_try_into(result)
    }

    pub async fn reactivate_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialServiceError> {
        self.credential_validity_manager
            .change_credential_validity_state(credential_id, RevocationState::Valid)
            .await
            .error_while("reactivating credential")?;
        tracing::info!("Reactivated credential {credential_id}");
        Ok(())
    }

    pub async fn suspend_credential(
        &self,
        credential_id: &CredentialId,
        request: SuspendCredentialRequestDTO,
    ) -> Result<(), CredentialServiceError> {
        self.credential_validity_manager
            .change_credential_validity_state(
                credential_id,
                RevocationState::Suspended {
                    suspend_end_date: request.suspend_end_date,
                },
            )
            .await
            .error_while("suspending credential")?;
        tracing::info!("Suspended credential {credential_id}");
        Ok(())
    }

    /// Revokes credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn revoke_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialServiceError> {
        self.credential_validity_manager
            .change_credential_validity_state(credential_id, RevocationState::Revoked)
            .await
            .error_while("revoking credential")?;
        tracing::info!("Revoked credential {credential_id}");
        Ok(())
    }

    /// Checks credentials' revocation status
    ///
    /// # Arguments
    ///
    /// * `credential_ids` - credentials to check
    pub async fn check_revocation(
        &self,
        credential_ids: Vec<CredentialId>,
        force_refresh: bool,
    ) -> Result<Vec<CredentialRevocationCheckResponseDTO>, CredentialServiceError> {
        let mut result = vec![];
        for credential_id in credential_ids {
            result.push(
                self.credential_validity_manager
                    .check_holder_credential_validity(credential_id, force_refresh)
                    .await
                    .error_while("checking credential validity")?,
            );
        }
        Ok(convert_inner(result))
    }

    /// Returns URL of shared credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn share_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<ShareCredentialResponseDTO, CredentialServiceError> {
        let credential = self.get_credential_with_state(credential_id).await?;

        if credential.deleted_at.is_some() {
            return Err(CredentialServiceError::NotFound(*credential_id));
        }
        let Some(credential_schema) = credential.schema.as_ref() else {
            return Err(CredentialServiceError::MappingError(
                "Missing credential schema".to_string(),
            ));
        };
        throw_if_org_id_not_matching_session(
            credential_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        if !matches!(
            credential.state,
            CredentialStateEnum::Created
                | CredentialStateEnum::Pending
                | CredentialStateEnum::InteractionExpired
        ) {
            return Err(CredentialServiceError::InvalidState(credential.state));
        }

        let Some(issuer_identifier) = credential.issuer_identifier.as_ref() else {
            return Err(CredentialServiceError::MappingError(
                "Missing issuer identifier".to_string(),
            ));
        };

        if issuer_identifier.state != IdentifierState::Active {
            return Err(CredentialServiceError::IdentifierIsDeactivated(
                issuer_identifier.id,
            ));
        }

        let organisation = credential_schema
            .organisation
            .get()
            .await
            .error_while("getting organisation")?;

        let credential_exchange = &credential.protocol;
        let exchange = self
            .protocol_provider
            .get_protocol(credential_exchange)
            .ok_or(MissingProviderError::ExchangeProtocol(
                credential_exchange.clone(),
            ))
            .error_while("getting protocol")?;

        let ShareResponse {
            url,
            interaction_id,
            interaction_data,
            expires_at,
            transaction_code,
        } = exchange
            .issuer_share_credential(&credential)
            .await
            .error_while("sharing credential")?;

        add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            interaction_data,
            Some(organisation),
            InteractionType::Issuance,
            expires_at,
        )
        .await
        .error_while("adding interaction")?;
        self.credential_repository
            .update_credential(
                *credential_id,
                UpdateCredentialRequest {
                    state: (credential.state != CredentialStateEnum::Pending)
                        .then_some(CredentialStateEnum::Pending),
                    interaction: Some(interaction_id),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;
        clear_previous_interaction(&*self.interaction_repository, &credential.interaction)
            .await
            .error_while("clearing interaction")?;
        tracing::info!("Shared credential {credential_id}");
        Ok(ShareCredentialResponseDTO {
            url,
            expires_at,
            transaction_code,
        })
    }

    pub async fn get_trust_details(
        &self,
        id: CredentialId,
    ) -> Result<TrustInformationDetailResponseDTO, CredentialServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                &id,
                &CredentialRelations {
                    schema: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?;
        let credential = credential.ok_or(CredentialServiceError::NotFound(id))?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)
            .error_while("checking session")?;
        let Some(trust_details) = self
            .trust_information_provider
            .get_trust_detail(&id.into())
            .await
            .error_while("getting trust details")?
        else {
            return Ok(TrustInformationDetailResponseDTO {
                eudi_ecosystem: None,
            });
        };
        trust_details
            .try_into()
            .error_while("mapping trust information")
            .map_err(Into::into)
    }

    // ============ Private methods

    /// Get credential with the latest credential state
    async fn get_credential_with_state(
        &self,
        id: &CredentialId,
    ) -> Result<Credential, CredentialServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(Default::default()),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                    issuer_certificate: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?
            .ok_or(CredentialServiceError::NotFound(*id))?;

        Ok(credential)
    }
}
