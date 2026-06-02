use shared_types::{CredentialFormat, CredentialSchemaId, OrganisationId};
use uuid::Uuid;

use super::CredentialSchemaService;
use super::dto::{
    CreateCredentialSchemaRequestDTO, CreateCredentialSchemaV2RequestDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaDetailV2ResponseDTO,
    CredentialSchemaFilterParamsDTO, CredentialSchemaListIncludeEntityTypeEnum,
    CredentialSchemaShareResponseDTO, GetCredentialSchemaListResponseDTO,
    GetCredentialSchemaListV2ResponseDTO, ImportCredentialSchemaRequestDTO,
    ImportCredentialSchemaV2RequestDTO,
};
use super::error::CredentialSchemaServiceError;
use super::validator::UniquenessCheckResult;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::credential_schema_claim::{
    backfill_default_translations, claim_schema_from_metadata_claim_schema,
    from_request_claim_schema,
};
use crate::model::common::GetListResponse;
use crate::model::credential_schema::SortableCredentialSchemaColumn;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::CredentialSchemaVersion;
use crate::repository::error::DataLayerError;
use crate::service::common_dto::ListQueryDTO;
use crate::service::credential_schema::dto::{
    CredentialSchemaListItemResponseDTO, CredentialSchemaListItemV2ResponseDTO,
};
use crate::service::credential_schema::mapper::{
    build_format_with_claim_mappings, from_create_request_with_id, from_create_v2_request_with_id,
    schema_to_detail_response_dto, schema_to_detail_v2_response_dto,
    to_credential_schema_list_response, to_credential_schema_list_v2_response,
    unnest_claim_schemas,
};
use crate::util::logging::quoted_opt_provider;
use crate::validator::throw_if_org_id_not_matching_session;

impl CredentialSchemaService {
    /// Creates a credential schema according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential schema request
    pub async fn create_credential_schema(
        &self,
        request: CreateCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let core_base_url = self.core_base_url.as_ref().ok_or_else(|| {
            CredentialSchemaServiceError::MappingError("Missing core base_url".to_string())
        })?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&request.format)?;
        super::validator::validate_create_request(
            &request,
            &self.config,
            &*formatter,
            &*self.revocation_method_provider,
        )?;

        self.validate_credential_schema_already_exists(
            &request.name,
            request.schema_id.iter().cloned().collect(),
            request.organisation_id,
        )
        .await?;

        super::validator::check_claims_presence_in_layout_properties(
            request.layout_properties.as_ref(),
            &request.claims,
        )?;
        super::validator::check_background_properties(request.layout_properties.as_ref())?;
        super::validator::check_logo_properties(request.layout_properties.as_ref())?;
        super::validator::validate_key_storage_security_supported(
            request.key_storage_security,
            &self.config,
        )?;

        let organisation = self.get_organisation(request.organisation_id).await?;

        let id = CredentialSchemaId::from(Uuid::new_v4());
        let schema_id = formatter
            .credential_schema_id(
                id,
                organisation.id,
                request.schema_id.as_deref(),
                core_base_url,
                CredentialSchemaVersion::V1,
                None,
            )
            .error_while("creating schemaId")?;
        let imported_source_url = format!("{core_base_url}/ssi/schema/v1/{id}");
        let mut credential_schema = from_create_request_with_id(
            id,
            request,
            organisation,
            schema_id,
            imported_source_url,
            &self.config.default_language,
        )?;

        let metadata_claims = formatter
            .get_metadata_claims()
            .into_iter()
            .map(|metadata_claim| {
                claim_schema_from_metadata_claim_schema(
                    metadata_claim,
                    credential_schema.created_date,
                )
            })
            .collect::<Vec<_>>();

        {
            let mut claim_schemas = credential_schema.claim_schemas.as_mut().await?;
            claim_schemas.extend(metadata_claims);
        }
        let credential_schema =
            backfill_default_translations(credential_schema, &self.config.default_language)
                .await
                .error_while("backfilling default translations")?;

        let success_log = format!(
            "Created credential schema `{}` ({id}): format `{:?}`, revocation method {:?}, key storage security {}",
            credential_schema.name,
            credential_schema.formats,
            credential_schema.revocation_method,
            quoted_opt_provider(&credential_schema.key_storage_security)
        );
        let schema_id = self
            .credential_schema_repository
            .create_credential_schema(credential_schema)
            .await
            .error_while("creating credential schema")?;

        tracing::info!(message = success_log);
        Ok(schema_id)
    }

    pub async fn create_credential_schema_v2(
        &self,
        request: CreateCredentialSchemaV2RequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let core_base_url = self.core_base_url.as_ref().ok_or_else(|| {
            CredentialSchemaServiceError::MappingError("Missing core base_url".to_string())
        })?;

        let schema_ids = request
            .formats
            .iter()
            .flat_map(|format| format.schema_id.clone())
            .collect();

        self.validate_credential_schema_already_exists(
            &request.name,
            schema_ids,
            request.organisation_id,
        )
        .await?;

        super::validator::validate_create_v2_request(
            &request,
            &self.config,
            &*self.formatter_provider,
        )?;

        super::validator::check_claims_presence_in_layout_properties(
            request.layout_properties.as_ref(),
            &request.claims,
        )?;
        super::validator::check_background_properties(request.layout_properties.as_ref())?;
        super::validator::check_logo_properties(request.layout_properties.as_ref())?;
        super::validator::validate_key_storage_security_supported(
            request.key_storage_security,
            &self.config,
        )?;

        let organisation = self.get_organisation(request.organisation_id).await?;

        let credential_schema_id = CredentialSchemaId::from(Uuid::new_v4());
        let now = crate::clock::now_utc();

        let flat_claims = unnest_claim_schemas(request.claims.clone());
        let claim_schemas_with_raw_mappings = flat_claims
            .into_iter()
            .map(|claim_schema_request| {
                (
                    from_request_claim_schema(now, &claim_schema_request),
                    claim_schema_request.mappings.unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();

        let mut claim_schemas: Vec<_> = claim_schemas_with_raw_mappings
            .iter()
            .map(|(cs, _)| cs.clone())
            .collect();
        let mut resolved_formats = vec![];
        for format_req in &request.formats {
            let formatter = self
                .formatter_provider
                .get_credential_formatter(&format_req.format)?;

            let schema_id = formatter
                .credential_schema_id(
                    credential_schema_id,
                    organisation.id,
                    format_req.schema_id.as_deref(),
                    core_base_url,
                    CredentialSchemaVersion::V2,
                    Some(&format_req.format),
                )
                .error_while("creating schemaId")?;

            let (schema_format, format_specific_claim_schemas) = build_format_with_claim_mappings(
                credential_schema_id,
                schema_id,
                format_req.format.clone(),
                now,
                &claim_schemas_with_raw_mappings,
                formatter.as_ref(),
            );
            resolved_formats.push(schema_format);
            claim_schemas.extend(format_specific_claim_schemas);
        }
        let resolved_format_types = resolved_formats
            .iter()
            .map(|f| f.format.clone())
            .collect::<Vec<_>>();

        let imported_source_url = format!("{core_base_url}/ssi/schema/v2/{credential_schema_id}");
        let credential_schema = from_create_v2_request_with_id(
            credential_schema_id,
            request,
            organisation,
            now,
            resolved_formats,
            claim_schemas,
            imported_source_url,
            &self.config.default_language,
        );

        let credential_schema =
            backfill_default_translations(credential_schema, &self.config.default_language)
                .await
                .error_while("backfilling default translations")?;

        let success_log = format!(
            "Created credential schema v2 `{}` ({credential_schema_id}): formats `{:?}`: key storage security {}",
            credential_schema.name,
            resolved_format_types,
            quoted_opt_provider(&credential_schema.key_storage_security)
        );

        let schema_id = self
            .credential_schema_repository
            .create_credential_schema(credential_schema)
            .await
            .error_while("creating credential schema")?;

        tracing::info!(message = success_log);
        Ok(schema_id)
    }

    async fn get_organisation(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<Organisation, CredentialSchemaServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id)
            .await
            .error_while("getting organisation")?
            .ok_or(CredentialSchemaServiceError::MissingOrganisation(
                organisation_id,
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(CredentialSchemaServiceError::OrganisationIsDeactivated(
                organisation_id,
            ));
        }
        Ok(organisation)
    }

    async fn validate_credential_schema_already_exists(
        &self,
        name: &str,
        schema_ids: Vec<String>,
        organisation_id: OrganisationId,
    ) -> Result<(), CredentialSchemaServiceError> {
        match super::validator::credential_schema_already_exists(
            &*self.credential_schema_repository,
            name,
            schema_ids,
            organisation_id,
        )
        .await?
        {
            UniquenessCheckResult::SchemaIdConflict | UniquenessCheckResult::NameConflict => {
                Err(CredentialSchemaServiceError::AlreadyExists)
            }
            UniquenessCheckResult::Ok => Ok(()),
        }
    }

    /// Deletes a credential schema
    ///
    /// # Arguments
    ///
    /// * `CredentialSchemaId` - Id of an existing credential schema
    pub async fn delete_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<(), CredentialSchemaServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?
            .ok_or(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ))?;

        throw_if_org_id_not_matching_session(
            credential_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        self.credential_schema_repository
            .delete_credential_schema(&credential_schema)
            .await
            .map_err(|error| match error {
                DataLayerError::RecordNotUpdated => {
                    CredentialSchemaServiceError::NotFound(*credential_schema_id)
                }
                error => error.error_while("deleting credential schema").into(),
            })?;

        tracing::info!(
            "Deleted credential schema `{}` ({})",
            credential_schema.name,
            credential_schema.id
        );
        Ok(())
    }

    /// Returns details of a credential schema
    ///
    /// # Arguments
    ///
    /// * `CredentialSchemaId` - Id of an existing credential schema
    pub async fn get_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<CredentialSchemaDetailResponseDTO, CredentialSchemaServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let Some(schema) = schema else {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        };

        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        if schema.deleted_at.is_some() {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        }

        schema_to_detail_response_dto(schema, &self.config).await
    }

    pub async fn get_credential_schema_v2(
        &self,
        credential_schema_id: &CredentialSchemaId,
        format: Option<&CredentialFormat>,
    ) -> Result<CredentialSchemaDetailV2ResponseDTO, CredentialSchemaServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let Some(schema) = schema else {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        };

        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        if schema.deleted_at.is_some() {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        }
        if let Some(format) = format
            && !schema
                .formats
                .as_ref()
                .await?
                .iter()
                .any(|f| f.format == *format)
        {
            return Err(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ));
        }

        schema_to_detail_v2_response_dto(schema, format).await
    }

    /// Returns list of credential schemas according to query
    ///
    /// # Arguments
    ///
    /// * `filter_params` - query parameters
    pub async fn get_credential_schema_list(
        &self,
        filter_params: ListQueryDTO<
            SortableCredentialSchemaColumn,
            CredentialSchemaFilterParamsDTO,
            CredentialSchemaListIncludeEntityTypeEnum,
        >,
    ) -> Result<GetCredentialSchemaListResponseDTO, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let include_translations = filter_params
            .include
            .as_ref()
            .is_some_and(|i| i.contains(&CredentialSchemaListIncludeEntityTypeEnum::Translations));
        let result = self
            .credential_schema_repository
            .get_credential_schema_list(filter_params.into())
            .await
            .error_while("getting credential schemas")?;

        let mut items: Vec<CredentialSchemaListItemResponseDTO> =
            Vec::with_capacity(result.values.len());
        for credential_schema in result.values {
            items.push(
                to_credential_schema_list_response(credential_schema, include_translations)
                    .await
                    .error_while("mapping credential schemas")?,
            );
        }

        Ok(GetListResponse {
            values: items,
            total_items: result.total_items,
            total_pages: result.total_pages,
        })
    }

    pub async fn get_credential_schema_list_v2(
        &self,
        filter_params: ListQueryDTO<
            SortableCredentialSchemaColumn,
            CredentialSchemaFilterParamsDTO,
            CredentialSchemaListIncludeEntityTypeEnum,
        >,
    ) -> Result<GetCredentialSchemaListV2ResponseDTO, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let result = self
            .credential_schema_repository
            .get_credential_schema_list(filter_params.into())
            .await
            .error_while("getting credential schemas")?;

        let mut items: Vec<CredentialSchemaListItemV2ResponseDTO> =
            Vec::with_capacity(result.values.len());
        for credential_schema in result.values {
            items.push(
                to_credential_schema_list_v2_response(credential_schema)
                    .await
                    .error_while("mapping credential schemas")?,
            );
        }

        Ok(GetListResponse {
            values: items,
            total_items: result.total_items,
            total_pages: result.total_pages,
        })
    }

    /// Imports a credential schema according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential schema request
    pub async fn import_credential_schema(
        &self,
        request: ImportCredentialSchemaRequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?
            .ok_or(CredentialSchemaServiceError::MissingOrganisation(
                request.organisation_id,
            ))?;

        if organisation.deactivated_at.is_some() {
            return Err(CredentialSchemaServiceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        let credential_schema = self
            .import_parser
            .parse_import_credential_schema(
                crate::proto::credential_schema::dto::ImportCredentialSchemaRequestDTO {
                    organisation,
                    schema: request.schema.into(),
                },
            )
            .error_while("parsing schema")?;

        let success_log = format!(
            "Imported credential schema `{}` ({}): format `{}`, revocation method {:?}, key storage security {}",
            credential_schema.name,
            credential_schema.id,
            credential_schema.format().await?,
            credential_schema.revocation_method,
            quoted_opt_provider(&credential_schema.key_storage_security)
        );

        let credential_schema = self
            .importer_proto
            .import_credential_schema(credential_schema)
            .await
            .error_while("importing schema")?;
        tracing::info!(message = success_log);
        Ok(credential_schema.id)
    }

    pub async fn import_credential_schema_v2(
        &self,
        request: ImportCredentialSchemaV2RequestDTO,
    ) -> Result<CredentialSchemaId, CredentialSchemaServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?
            .ok_or(CredentialSchemaServiceError::MissingOrganisation(
                request.organisation_id,
            ))?;
        if organisation.deactivated_at.is_some() {
            return Err(CredentialSchemaServiceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        let credential_schema = self
            .import_parser
            .parse_import_credential_schema_v2(
                crate::proto::credential_schema::dto::ImportCredentialSchemaV2RequestDTO {
                    organisation,
                    schema: request.schema.into(),
                },
            )
            .error_while("parsing schema")?;

        let success_log = format!(
            "Imported credential schema v2 `{}` ({}): key storage security {}",
            credential_schema.name,
            credential_schema.id,
            quoted_opt_provider(&credential_schema.key_storage_security)
        );

        let credential_schema = self
            .importer_proto
            .import_credential_schema(credential_schema)
            .await
            .error_while("importing schema")?;
        tracing::info!(message = success_log);
        Ok(credential_schema.id)
    }

    /// Creates share credential schema URL
    ///
    /// # Arguments
    ///
    /// * `credential_schema_id` - id of credential schema to share
    pub async fn share_credential_schema(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<CredentialSchemaShareResponseDTO, CredentialSchemaServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?
            .ok_or(CredentialSchemaServiceError::NotFound(
                *credential_schema_id,
            ))?;

        throw_if_org_id_not_matching_session(
            credential_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        Ok(CredentialSchemaShareResponseDTO {
            url: credential_schema.imported_source_url,
        })
    }
}
