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
use crate::model::blob::UpdateBlobRequest;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRelations, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, LayoutType, UpdateCredentialSchemaRequest,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::{
    HistoryAction, HistoryMetadata, TrustResolutionMetadata, TrustResolutionResult,
    WalletRelyingPartyMetadata,
};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::interaction::Interaction;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::identifier_creator::{IdentifierRole, RemoteIdentifierRelation};
use crate::proto::wrp_validator::model::TrustMode;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use crate::provider::issuance_protocol::{
    HolderBindingInput, IssuanceProtocolError, UpdateResponse,
};
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::error::MissingProviderError;
use crate::validator::validate_issuance_time;

impl OpenID4VCIFinal1_0 {
    pub(super) async fn holder_process_accepted_credentials(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        holder_bindings: Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<UpdateResponse, IssuanceProtocolError> {
        if holder_bindings.len() != issuer_response.credentials.len() {
            return Err(IssuanceProtocolError::Failed(format!(
                "Different number of credentials, requested: {}, received: {}",
                holder_bindings.len(),
                issuer_response.credentials.len()
            )));
        }

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
        let mut new_claim_schemas: Vec<ClaimSchema> = vec![];
        let mut credential_schema = None;
        for (issued_credential, holder_binding) in issuer_response.credentials.iter().zip(
            // we assume the credentials were sent in the same order as the holder binding proofs
            holder_bindings,
        ) {
            let mut credential = self
                .prepare_issued_credential(
                    issued_credential,
                    holder_binding,
                    &issuer_response,
                    organisation,
                    interaction,
                    formatter.as_ref(),
                )
                .await?;

            if credential_schema.is_none() {
                credential_schema = Some(
                    self.prepare_credential_schema(
                        interaction_data,
                        &credential,
                        &format,
                        organisation,
                    )
                    .await?,
                );
            }
            let schema = credential_schema
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?;

            if trust_resolution == TrustResolutionResult::Trusted
                && let Err(err) = self
                    .wrp_validator
                    .validate_credential_issuer(
                        credential
                            .issuer_certificate
                            .as_ref()
                            .map(|certificate| certificate.chain.as_str()),
                        schema,
                        organisation.id,
                    )
                    .await
            {
                tracing::info!(%err, "Credential issuer trust not verified");
                trust_resolution = TrustResolutionResult::Untrusted;
            }

            prepare_credential_schema_updates(
                schema,
                &mut credential,
                &mut new_claim_schemas,
                &self.config.default_language,
            )
            .await?;

            if let Some(access_certificate) = &interaction_data.access_certificate {
                self.store_trust_history_event(
                    HistoryAction::WrpAcReceived,
                    credential.id,
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
                    credential.id,
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
                    credential.id,
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
                credential.id,
                organisation.id,
                None,
                Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                    result: trust_resolution,
                })),
            )
            .await?;

            credentials.push(credential);
        }

        let update_credential_schema = if new_claim_schemas.is_empty() {
            None
        } else {
            Some(UpdateCredentialSchemaRequest {
                id: credential_schema
                    .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?
                    .id,
                revocation_method: None,
                format: None,
                claim_schemas: Some(new_claim_schemas),
                layout_type: None,
                layout_properties: None,
            })
        };

        Ok(UpdateResponse {
            result: issuer_response,
            update_credential_schema,
            credentials: Some(credentials),
        })
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
            .get_credential_formatter(&credential_schema_format)
            .ok_or_else(|| MissingProviderError::Formatter(credential_schema_format.to_string()))
            .error_while("getting credential formatter")?;

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
            .get_blob_storage(BlobStorageType::Db)
            .error_while("getting blob storage")?;

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
        holder_bindings: Vec<HolderBindingInput>,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<Vec<CredentialId>, IssuanceProtocolError> {
        if holder_bindings.len() != issuer_response.credentials.len() {
            return Err(IssuanceProtocolError::Failed(format!(
                "Different number of credentials, requested: {}, received: {}",
                holder_bindings.len(),
                issuer_response.credentials.len()
            )));
        }

        let schema = self
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
            ))?
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

        let mut trust_resolution = interaction_data.trust_resolution;

        let mut result = vec![];
        for (issued_credential, holder_binding) in issuer_response.credentials.iter().zip(
            // we assume the credentials were sent in the same order as the holder binding proofs
            holder_bindings,
        ) {
            let mut credential = self
                .prepare_issued_credential(
                    issued_credential,
                    holder_binding,
                    &issuer_response,
                    organisation,
                    interaction,
                    formatter.as_ref(),
                )
                .await?;

            if trust_resolution == TrustResolutionResult::Trusted
                && let Err(err) = self
                    .wrp_validator
                    .validate_credential_issuer(
                        credential
                            .issuer_certificate
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

            let mut new_claim_schemas = vec![];
            prepare_credential_schema_updates(
                &schema,
                &mut credential,
                &mut new_claim_schemas,
                &self.config.default_language,
            )
            .await?;
            if !new_claim_schemas.is_empty() {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Unknown claims found: {}",
                    new_claim_schemas
                        .into_iter()
                        .map(|claim_schema| claim_schema.key)
                        .join(", ")
                )));
            }

            self.store_trust_history_event(
                HistoryAction::TrustResolved,
                credential.id,
                organisation.id,
                None,
                Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                    result: trust_resolution,
                })),
            )
            .await?;

            let id = self
                .credential_repository
                .create_credential(credential)
                .await
                .error_while("creating credential")?;
            result.push(id);
        }

        Ok(result)
    }

    async fn prepare_issued_credential(
        &self,
        issued_credential: &SerializedCredential,
        holder_binding: HolderBindingInput,
        issuer_response: &SubmitIssuerResponse,
        organisation: &Organisation,
        interaction: &Interaction,
        formatter: &dyn CredentialFormatter,
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
        credential.redirect_uri = issuer_response.redirect_uri.clone();
        credential.state = CredentialStateEnum::Accepted;
        credential.holder_identifier = Some(holder_binding.identifier);
        credential.key = Some(holder_binding.key);
        credential.protocol = self.config_id.to_owned();
        credential.interaction = Some(interaction.to_owned());

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

async fn prepare_credential_schema_updates(
    stored_schema: &CredentialSchema,
    credential: &mut Credential,
    new_claim_schemas: &mut Vec<ClaimSchema>,
    default_language: &str,
) -> Result<(), IssuanceProtocolError> {
    let claims = credential
        .claims
        .as_mut()
        .ok_or(IssuanceProtocolError::Failed("Missing claims".to_string()))?;

    let stored_claim_schemas = stored_schema
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?;

    let parsed_claim_schemas = credential
        .schema
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?;

    for parsed_claim_schema in parsed_claim_schemas {
        let mut known_claim_schema = stored_claim_schemas
            .iter()
            .find(|schema| schema.key == parsed_claim_schema.key);

        if known_claim_schema.is_none() {
            known_claim_schema = new_claim_schemas
                .iter()
                .find(|schema| schema.key == parsed_claim_schema.key);
        }

        if let Some(known_claim_schema) = known_claim_schema {
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
                    claim.schema = Some(known_claim_schema.to_owned());
                });
        } else {
            new_claim_schemas.push(
                add_fallback_translation(parsed_claim_schema, default_language)
                    .await
                    .error_while("adding fallback claim translation")?,
            );
        }
    }

    credential.schema = Some(stored_schema.to_owned());

    Ok(())
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
