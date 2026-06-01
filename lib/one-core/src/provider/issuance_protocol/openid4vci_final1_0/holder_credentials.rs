use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialFormat, CredentialId, OrganisationId, SerializedCredential};
use uuid::Uuid;

use super::model::OpenID4VCICredentialMetadataResponseDTO;
use super::{HolderInteractionData, OpenID4VCIFinal1_0, SubmitIssuerResponse};
use crate::clock::now_utc;
use crate::config::core_config::BlobStorageType;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::mapper::credential_schema_claim::add_fallback_translation;
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, CredentialType,
};
use crate::model::credential_schema::{
    CredentialSchema, LayoutType, UpdateCredentialSchemaRequest,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    TrustResolutionMetadata, TrustResolutionResult, WalletRelyingPartyMetadata,
};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::interaction::Interaction;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::identifier_creator::{IdentifierRole, RemoteIdentifierRelation};
use crate::proto::session_provider::SessionExt;
use crate::proto::wrp_validator::model::TrustMode;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::issuance_protocol::model::{CredentialWithBlob, KeyStorageSecurityLevel};
use crate::provider::issuance_protocol::openid4vci_final1_0::validator::validate_batch_consistency;
use crate::provider::issuance_protocol::{
    HolderBindingInput, IssuanceAcceptResponse, IssuanceProtocolError,
};
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::validator::validate_issuance_time;

impl OpenID4VCIFinal1_0 {
    pub(super) async fn holder_process_accepted_credentials(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        mut holder_bindings: Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<IssuanceAcceptResponse, IssuanceProtocolError> {
        let format_type = map_from_oidc_format_to_core_detailed(
            &interaction_data.format,
            issuer_response
                .credentials
                .first()
                .map(|c| c.as_ref().to_string())
                .as_ref(),
        )?;

        let (format, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{format_type} formatter not found"))
            })?;

        let mut trust_resolution = interaction_data.trust_resolution;

        let mut credentials = vec![];
        for issued_credential in issuer_response.credentials {
            let credential = self
                .prepare_issued_credential(
                    &issued_credential,
                    &mut holder_bindings,
                    organisation,
                    interaction,
                    formatter.as_ref(),
                    issuer_response.redirect_uri.as_ref(),
                )
                .await?;
            credentials.push(CredentialWithBlob {
                credential,
                serialized: Some(issued_credential),
            });
        }

        validate_batch_consistency(&credentials).await?;

        let (mut main_credential, issuer_cert) = if credentials.len() > 1 {
            let batch_item = credentials.first().ok_or(IssuanceProtocolError::Failed(
                "No credentials received".to_string(),
            ))?;
            let batch_parent = CredentialWithBlob {
                credential: Credential {
                    id: Uuid::new_v4().into(),
                    r#type: CredentialType::BatchParent,
                    credential_blob_id: None,
                    wallet_instance_attestation_blob_id: None,
                    wallet_unit_attestation_blob_id: None,
                    issuer_identifier: None,
                    issuer_certificate: None,
                    holder_identifier: None,
                    key: None,
                    ..batch_item.credential.clone()
                },
                serialized: None,
            };
            (
                batch_parent,
                batch_item.credential.issuer_certificate.clone(),
            )
        } else {
            let result = credentials.pop().ok_or(IssuanceProtocolError::Failed(
                "No credentials received".to_string(),
            ))?;
            let cert = result.credential.issuer_certificate.clone();
            (result, cert)
        };
        let main_credential_id = main_credential.credential.id;

        let schema = self
            .process_schema(
                &mut main_credential.credential,
                organisation,
                interaction_data,
                &format,
            )
            .await?;
        if !credentials.is_empty() {
            // update batch items
            credentials.iter_mut().for_each(|c| {
                self.change_to_batch_item(&mut c.credential, main_credential_id, &schema);
            });
        }

        if trust_resolution == TrustResolutionResult::Trusted
            && let Err(err) = self
                .wrp_validator
                .validate_credential_issuer(
                    issuer_cert
                        .as_ref()
                        .map(|certificate| certificate.chain.as_str()),
                    &schema,
                    organisation.id,
                )
                .await
        {
            tracing::info!(%err, "Credential issuer trust not verified");
            trust_resolution = TrustResolutionResult::Untrusted;
        }

        if let Some(access_certificate) = &interaction_data.access_certificate {
            self.store_trust_history_event(
                HistoryAction::WrpAcReceived,
                main_credential_id,
                organisation.id,
                Some(access_certificate.to_owned()),
                None,
            )
            .await?;
        }

        if let (Some(registration_certificate), Some(relying_party_name)) = (
            &interaction_data.registration_certificate,
            &interaction_data.relying_party_name,
        ) {
            self.store_trust_history_event(
                HistoryAction::WrpRcReceived,
                main_credential_id,
                organisation.id,
                Some(registration_certificate.to_owned()),
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
            self.store_trust_history_event(
                HistoryAction::WrpNrReceived,
                main_credential_id,
                organisation.id,
                Some(national_registry_data.to_owned()),
                Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        name: relying_party_name.to_string(),
                        ..Default::default()
                    },
                )),
            )
            .await?;
        }

        self.store_trust_history_event(
            HistoryAction::TrustResolved,
            main_credential_id,
            organisation.id,
            None,
            Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                result: trust_resolution,
            })),
        )
        .await?;

        // Add main credential to the front so that the batch_parent already exists when the batch_items are created.
        Ok(IssuanceAcceptResponse {
            main_credential,
            batch_items: credentials,
        })
    }

    fn change_to_batch_item(
        &self,
        credential: &mut Credential,
        parent_id: CredentialId,
        schema: &CredentialSchema,
    ) {
        credential.schema = Some(schema.clone());
        credential.r#type = CredentialType::BatchItem;
        credential.parent = Some(Related::new(parent_id, self.credential_repository.clone()));
        credential.claims = None;
        credential.interaction = None;
    }

    async fn process_schema(
        &self,
        main_credential: &mut Credential,
        organisation: &Organisation,
        interaction_data: &HolderInteractionData,
        format: &CredentialFormat,
    ) -> Result<CredentialSchema, IssuanceProtocolError> {
        let mut schema = self
            .prepare_credential_schema(interaction_data, main_credential, format, organisation)
            .await?;
        let claim_schema_update = validate_existing_and_find_new_claim_schemas(
            &mut schema,
            main_credential,
            &self.config.default_language,
            true,
        )
        .await?;
        if let Some(new_claim_schemas) = claim_schema_update {
            self.credential_schema_repository
                .update_credential_schema(UpdateCredentialSchemaRequest {
                    id: schema.id,
                    claim_schemas: Some(new_claim_schemas),
                    revocation_method: None,
                    format: None,
                    layout_type: None,
                    layout_properties: None,
                })
                .await
                .error_while("updating credential schema")?;
        }
        Ok(schema)
    }

    pub(super) async fn holder_process_refresh(
        &self,
        interaction_data: &HolderInteractionData,
        holder_bindings: Vec<HolderBindingInput>,
        response: SubmitIssuerResponse,
        organisation: &Organisation,
        updated_credential: Option<Credential>,
        interaction: &Interaction,
    ) -> Result<Vec<CredentialId>, IssuanceProtocolError> {
        if let Some(credential) = updated_credential {
            self.process_mso_refresh(
                &credential,
                response,
                organisation.id,
                interaction_data.trust_mode == TrustMode::TrustMandatory,
            )
            .await?;

            Ok(vec![credential.id])
        } else {
            self.process_batch_refresh(
                response,
                interaction_data,
                holder_bindings,
                organisation,
                interaction,
            )
            .await
        }
    }

    async fn process_mso_refresh(
        &self,
        credential: &Credential,
        mut response: SubmitIssuerResponse,
        organisation_id: OrganisationId,
        check_trust: bool,
    ) -> Result<(), IssuanceProtocolError> {
        if response.credentials.len() != 1 {
            return Err(IssuanceProtocolError::Failed(
                "Refresh with multiple credentials".to_string(),
            ));
        }
        let updated_credential =
            response
                .credentials
                .pop()
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing credential schema".to_string(),
                ))?;

        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "Missing credential schema".to_string(),
            ))?;
        let credential_schema_format = schema.format().await?;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&credential_schema_format)?;

        let extracted = formatter
            .extract_credentials(&updated_credential, Some(schema), self.verification_fn())
            .await
            .error_while("extracting credential")?;

        let issuer_certificate =
            if let IdentifierDetails::Certificate(certificate) = extracted.issuer {
                Some(certificate)
            } else {
                None
            };

        if check_trust {
            self.wrp_validator
                .validate_credential_issuer(
                    issuer_certificate
                        .as_ref()
                        .map(|certificate| certificate.chain.as_str()),
                    schema,
                    organisation_id,
                )
                .await
                .error_while("validating credential issuer trust")?;
        }

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let blob_id = credential
            .credential_blob_id
            .ok_or(IssuanceProtocolError::Failed(
                "Missing credential blob id".to_string(),
            ))?;
        db_blob_storage
            .update(
                &blob_id,
                UpdateBlobRequest {
                    value: Some(updated_credential.as_ref().into()),
                },
            )
            .await
            .error_while("updating credential blob")?;
        Ok(())
    }

    async fn process_batch_refresh(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        mut holder_bindings: Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<Vec<CredentialId>, IssuanceProtocolError> {
        let batch_parent = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction.id,
                &CredentialRelations {
                    schema: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credentials")?
            .into_iter()
            .next()
            .ok_or(IssuanceProtocolError::Failed(
                "No credentials found".to_string(),
            ))?;
        if batch_parent.r#type != CredentialType::BatchParent {
            return Err(IssuanceProtocolError::Failed(format!(
                "Expected credential {} to be of type batch parent, but founnd {:?}",
                batch_parent.id, batch_parent.r#type
            )));
        }
        let mut schema = batch_parent
            .schema
            .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?;

        let format_type = map_from_oidc_format_to_core_detailed(
            &interaction_data.format,
            issuer_response
                .credentials
                .first()
                .map(|c| c.as_ref().to_string())
                .as_ref(),
        )?;

        let (_, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{format_type} formatter not found"))
            })?;

        let mut batch_credentials = Vec::with_capacity(issuer_response.credentials.len());
        for issued_credential in issuer_response.credentials {
            let credential = self
                .prepare_issued_credential(
                    &issued_credential,
                    &mut holder_bindings,
                    organisation,
                    interaction,
                    formatter.as_ref(),
                    issuer_response.redirect_uri.as_ref(),
                )
                .await?;
            batch_credentials.push(CredentialWithBlob {
                credential,
                serialized: Some(issued_credential),
            });
        }
        validate_batch_consistency(&batch_credentials).await?;

        // as the batch is validated to be consistent, any credential in the batch is suitable for this validation
        let batch_credential = batch_credentials
            .iter_mut()
            .next()
            .ok_or(IssuanceProtocolError::Failed("empty batch".to_string()))?;
        validate_existing_and_find_new_claim_schemas(
            &mut schema,
            &mut batch_credential.credential,
            &self.config.default_language,
            false,
        )
        .await?;

        if interaction_data.trust_resolution == TrustResolutionResult::Trusted {
            let issuer_cert_chain = batch_credential
                .credential
                .issuer_certificate
                .as_ref()
                .map(|certificate| certificate.chain.as_str());
            self.validate_batch_refresh_trust(
                interaction_data,
                organisation,
                interaction,
                &schema,
                batch_parent.id,
                issuer_cert_chain,
            )
            .await?;
        }

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                action: HistoryAction::Refreshed,
                name: schema.name.to_owned(),
                source: HistorySource::Core,
                entity_id: Some(batch_parent.id.into()),
                entity_type: HistoryEntityType::Credential,
                organisation_id: Some(organisation.id),
                user: self.session_provider.session().user(),
                target: None,
                metadata: None,
                metadata_blob_id: None,
            })
            .await
            .error_while("storing history")?;

        let mut result = vec![];
        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        for batch_credential in batch_credentials {
            let CredentialWithBlob {
                mut credential,
                serialized,
            } = batch_credential;
            self.change_to_batch_item(&mut credential, batch_parent.id, &schema);

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

            let id = self
                .credential_repository
                .create_credential(Credential {
                    state: CredentialStateEnum::Accepted,
                    credential_blob_id,
                    ..credential
                })
                .await
                .error_while("creating credential")?;
            result.push(id)
        }

        Ok(result)
    }

    async fn prepare_issued_credential(
        &self,
        issued_credential: &SerializedCredential,
        holder_bindings: &mut Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
        formatter: &dyn CredentialFormatter,
        redirect_uri: Option<&String>,
    ) -> Result<Credential, IssuanceProtocolError> {
        let mut credential = formatter
            .parse_credential(
                issued_credential,
                organisation.to_owned(),
                self.verification_fn(),
            )
            .await
            .map_err(|e| IssuanceProtocolError::CredentialVerificationFailed(e.into()))?;

        validate_issuance_time(&credential.issuance_date, formatter.get_leeway())
            .error_while("validating issuance time")?;

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

        let (issuer_identifier, issuer_identifier_relation) = self
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

        credential.issuer_identifier = Some(issuer_identifier);
        credential.issuer_certificate = issuer_certificate;
        credential.redirect_uri = redirect_uri.cloned();
        credential.state = CredentialStateEnum::Accepted;
        credential.protocol = self.config_id.to_owned();
        credential.interaction = Some(interaction.to_owned());
        attach_matching_holder_binding(&mut credential, holder_bindings)?;
        Ok(credential)
    }

    async fn prepare_credential_schema(
        &self,
        interaction_data: &HolderInteractionData,
        parsed_credential: &Credential,
        format: &CredentialFormat,
        organisation: &Organisation,
    ) -> Result<CredentialSchema, IssuanceProtocolError> {
        let mut schema = parsed_credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?
            .to_owned();

        apply_issuer_metadata_to_schema(
            &mut schema,
            interaction_data.credential_metadata.as_ref(),
            &self.config.default_language,
        )
        .await?;

        let schema_id = schema.schema_id().await?;
        let now = now_utc();
        schema.formats = vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_id: schema.id,
            format: format.to_owned(),
            schema_id,
            claim_mappings: Default::default(),
        }]
        .into();
        schema.batch_size = interaction_data.batch_size.map(|size| size as _);
        schema.organisation = organisation.to_owned().into();
        schema.layout_type = LayoutType::Card;
        schema.key_storage_security = interaction_data
            .proof_types_supported
            .as_ref()
            .and_then(|map| map.get("jwt"))
            .and_then(|jwt| jwt.key_attestations_required.as_ref())
            .and_then(|att_list| {
                (!att_list.key_storage.is_empty()).then_some(&att_list.key_storage)
            })
            .and_then(|levels| convert_inner(KeyStorageSecurityLevel::select_lowest(levels)));

        let stored_schema = get_or_create_credential_schema(
            self.credential_schema_importer.as_ref(),
            self.credential_schema_repository.as_ref(),
            schema,
            organisation.id,
        )
        .await?;

        Ok(stored_schema)
    }
}
async fn get_or_create_credential_schema(
    credential_schema_importer: &dyn CredentialSchemaImporter,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    credential_schema: CredentialSchema,
    organisation_id: OrganisationId,
) -> Result<CredentialSchema, IssuanceProtocolError> {
    let parsed_schema_id = credential_schema
        .schema_id()
        .await
        .error_while("getting parsed schema_id")?;
    let parsed_format = credential_schema
        .format()
        .await
        .error_while("getting parsed format")?;
    let stored_schema = credential_schema_repository
        .get_by_schema_id_and_organisation(&parsed_schema_id, organisation_id)
        .await
        .error_while("getting credential schema")?;

    if let Some(stored_schema) = stored_schema {
        if let Some(conflicting_schema) = stored_schema
            .formats
            .get()
            .await
            .error_while("getting credential schema formats")?
            .iter()
            .find(|format| format.schema_id == parsed_schema_id && format.format != parsed_format)
        {
            return Err(IssuanceProtocolError::Failed(format!(
                "Credential schema conflict: credential schema with id {} has matching schema_id {} but different format {}",
                conflicting_schema.id, conflicting_schema.schema_id, conflicting_schema.format
            )));
        }
        Ok(stored_schema)
    } else {
        match credential_schema_importer
            .import_credential_schema(credential_schema)
            .await
        {
            Ok(schema) => {
                return Ok(schema);
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
            .get_by_schema_id_and_organisation(&parsed_schema_id, organisation_id)
            .await
            .error_while("getting credential schema")?
            .ok_or(IssuanceProtocolError::Failed(
                "Credential schema not found".to_string(),
            ))?;

        Ok(stored_schema)
    }
}

async fn validate_existing_and_find_new_claim_schemas(
    stored_schema: &mut CredentialSchema,
    credential: &mut Credential,
    default_language: &str,
    allow_new_claim_schemas: bool,
) -> Result<Option<Vec<ClaimSchema>>, IssuanceProtocolError> {
    let mut new_claim_schemas = vec![];
    let claims = credential
        .claims
        .as_mut()
        .ok_or(IssuanceProtocolError::Failed("Missing claims".to_string()))?;

    let parsed_claim_schemas = credential
        .schema
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?;

    let mut stored_claim_schemas = stored_schema.claim_schemas.as_mut().await?;
    for parsed_claim_schema in parsed_claim_schemas {
        let known_claim_schema = stored_claim_schemas
            .iter()
            .find(|schema| schema.key == parsed_claim_schema.key);

        if let Some(known_claim_schema) = known_claim_schema {
            // link all matching credential claims to the stored claim_schema
            for claim in claims.iter_mut().filter(|claim| {
                claim
                    .schema
                    .as_ref()
                    .is_some_and(|schema| schema.id == parsed_claim_schema.id)
            }) {
                let cs = claim
                    .schema
                    .as_ref()
                    .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?;
                if cs.data_type != known_claim_schema.data_type {
                    // This is just a warning because the data type detection is just a heuristic
                    tracing::warn!(
                        "detected data type mismatch on claim `{}`: expected `{}` but parsed `{}`",
                        claim.path,
                        known_claim_schema.data_type,
                        cs.data_type
                    );
                }
                claim.schema = Some(known_claim_schema.to_owned());
            }
        } else {
            new_claim_schemas.push(
                add_fallback_translation(parsed_claim_schema, default_language)
                    .await
                    .error_while("adding fallback claim translation")?,
            );
        }
    }
    if !allow_new_claim_schemas && !new_claim_schemas.is_empty() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Unknown claims found: {}",
            new_claim_schemas
                .into_iter()
                .map(|claim_schema| claim_schema.key)
                .join(", ")
        )));
    }
    stored_claim_schemas.extend(new_claim_schemas.clone());
    drop(stored_claim_schemas);
    credential.schema = Some(stored_schema.to_owned());
    if new_claim_schemas.is_empty() {
        Ok(None)
    } else {
        Ok(Some(new_claim_schemas))
    }
}

async fn apply_issuer_metadata_to_schema(
    schema: &mut CredentialSchema,
    metadata: Option<&OpenID4VCICredentialMetadataResponseDTO>,
    default_language: &str,
) -> Result<(), IssuanceProtocolError> {
    let now = now_utc();
    let all_displays = metadata.and_then(|m| m.display.as_deref()).unwrap_or(&[]);

    let metadata_display = all_displays.iter().find(|display| {
        display
            .locale
            .as_deref()
            .is_none_or(|locale| locale == default_language)
    });

    if let Some(name) = metadata_display.map(|d| d.name.to_owned()) {
        schema.name = name;
    }

    let schema_translations: Vec<LocalizedText> = all_displays
        .iter()
        .flat_map(|display| {
            let lang = display
                .locale
                .as_deref()
                .unwrap_or(default_language)
                .to_owned();
            let mut entries: Vec<LocalizedText> = vec![LocalizedText {
                entity_id: schema.id.into(),
                field: LocalizedTextField::Name,
                created_date: now,
                last_modified: now,
                lang: lang.clone(),
                value: display.name.clone(),
                entity_type: LocalizedTextEntityType::CredentialSchema,
            }];
            if let Some(description) = &display.description {
                entries.push(LocalizedText {
                    entity_id: schema.id.into(),
                    field: LocalizedTextField::Description,
                    created_date: now,
                    last_modified: now,
                    lang,
                    value: description.clone(),
                    entity_type: LocalizedTextEntityType::CredentialSchema,
                });
            }
            entries
        })
        .collect();

    if !schema_translations.is_empty() {
        schema.translations = schema_translations.into();
    }

    let metadata_claims = metadata.and_then(|m| m.claims.as_deref()).unwrap_or(&[]);

    if !metadata_claims.is_empty() {
        let claim_schemas = schema
            .claim_schemas
            .get()
            .await
            .error_while("getting claim schemas")?;

        let updated_claim_schemas = claim_schemas
            .into_iter()
            .map(|mut claim_schema| {
                if claim_schema.metadata {
                    return claim_schema;
                }
                let metadata_claim = metadata_claims
                    .iter()
                    .find(|mc| mc.path.join("/") == claim_schema.key);

                if let Some(mc) = metadata_claim {
                    let claim_translations: Vec<LocalizedText> = mc
                        .display
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .filter_map(|display| {
                            let name = display.name.as_ref()?;
                            let lang = display
                                .locale
                                .as_deref()
                                .unwrap_or(default_language)
                                .to_owned();
                            Some(LocalizedText {
                                entity_id: claim_schema.id.into(),
                                field: LocalizedTextField::Name,
                                created_date: now,
                                last_modified: now,
                                lang,
                                value: name.clone(),
                                entity_type: LocalizedTextEntityType::ClaimSchema,
                            })
                        })
                        .collect();
                    if !claim_translations.is_empty() {
                        claim_schema.translations = claim_translations.into();
                    }
                }
                claim_schema
            })
            .collect::<Vec<_>>();

        schema.claim_schemas = updated_claim_schemas.into();
    }

    schema.layout_properties = metadata_display.and_then(|display| display.to_owned().into());

    Ok(())
}

fn attach_matching_holder_binding(
    credential: &mut Credential,
    holder_bindings: &mut Vec<HolderBindingInput>,
) -> Result<(), IssuanceProtocolError> {
    let parsed_identifier =
        credential
            .holder_identifier
            .take()
            .ok_or(IssuanceProtocolError::Failed(
                "No parsed holder identifier".to_string(),
            ))?;

    let Some(position) = holder_bindings.iter().position(|holder_binding| {
        holder_binding_matching_parsed_identifier(holder_binding, &parsed_identifier)
    }) else {
        return Err(IssuanceProtocolError::Failed(
            "No matching holder identifier".to_string(),
        ));
    };

    let matching_holder_binding = holder_bindings.swap_remove(position);
    credential.holder_identifier = Some(matching_holder_binding.identifier);
    credential.key = Some(matching_holder_binding.key);

    Ok(())
}

fn holder_binding_matching_parsed_identifier(
    holder_binding: &HolderBindingInput,
    parsed_identifier: &Identifier,
) -> bool {
    match parsed_identifier.r#type {
        IdentifierType::Key => {
            let Some(parsed_key) = &parsed_identifier.key else {
                return false;
            };

            holder_binding.key.key_type == parsed_key.key_type
                && holder_binding.key.public_key == parsed_key.public_key
        }
        IdentifierType::Did => {
            let Some(parsed_did) = &parsed_identifier.did else {
                return false;
            };
            let Some(holder_binding_did) = &holder_binding.identifier.did else {
                return false;
            };

            holder_binding_did.did == parsed_did.did
        }
        IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
            // No credential format uses certificates for holder binding at this point
            tracing::warn!(
                "Invalid parsed holder binding type: {}",
                parsed_identifier.r#type
            );

            false
        }
    }
}
