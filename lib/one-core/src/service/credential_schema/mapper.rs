use dcql::CredentialMeta;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialSchemaId, OrganisationId};
use url::Url;
use uuid::Uuid;

use super::dto::{
    CreateCredentialSchemaRequestDTO, CreateCredentialSchemaV2RequestDTO, CredentialClaimSchemaDTO,
    CredentialClaimSchemaRequestDTO, CredentialClaimSchemaTranslationsDTO,
    CredentialClaimSchemaV2DTO, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesDTO, CredentialSchemaDcqlResponseDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaDetailV2ResponseDTO,
    CredentialSchemaFilterParamsDTO, CredentialSchemaFilterValue,
    CredentialSchemaFormatResponseDTO, CredentialSchemaListItemResponseDTO,
    CredentialSchemaListItemV2ResponseDTO, CredentialSchemaLogoPropertiesRequestDTO,
    CredentialSchemaTranslationsDTO,
};
use super::error::CredentialSchemaServiceError;
use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::mapper::credential_schema_claim::{
    claim_schema_from_metadata_claim_schema, claim_schema_to_dto, from_jwt_request_claim_schema,
    translations_to_i18n,
};
use crate::mapper::{NESTED_CLAIM_MARKER, remove_first_nesting_layer};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaExactColumn, CredentialSchemaListQuery,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::list_query::ListPagination;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::model::relation::RelatedVec;
use crate::proto::credential_schema::dto::CredentialClaimSchemaMappingDTO;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Context, Features};

pub(crate) async fn schema_to_detail_response_dto(
    value: CredentialSchema,
    config: &CoreConfig,
) -> Result<CredentialSchemaDetailResponseDTO, CredentialSchemaServiceError> {
    let formats = value.formats.get().await.error_while("getting formats")?;
    let format = formats
        .first()
        .ok_or(CredentialSchemaServiceError::MappingError(
            "Missing formats".to_string(),
        ))?;
    let dcql = map_dcql_format_meta(format, config);
    let non_metadata_claims = non_metadata_claim_schemas(&value).await?;
    let mut claim_schema_dtos = Vec::with_capacity(non_metadata_claims.len());
    for cs in non_metadata_claims {
        claim_schema_dtos.push(
            claim_schema_to_dto(cs)
                .await
                .map_err(|e| CredentialSchemaServiceError::MappingError(e.to_string()))?,
        );
    }
    let claim_schemas = renest_claim_schemas(claim_schema_dtos)?;

    Ok(CredentialSchemaDetailResponseDTO {
        translations: map_translations(&value).await?,
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        format: format.format.clone(),
        imported_source_url: value.imported_source_url,
        revocation_method: value.revocation_method,
        organisation_id: value.organisation.id(),
        claims: claim_schemas,
        key_storage_security: value.key_storage_security,
        schema_id: format.schema_id.clone(),
        layout_type: Some(value.layout_type),
        layout_properties: value.layout_properties.map(|item| item.into()),
        allow_suspension: value.allow_suspension,
        requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
        transaction_code: convert_inner(value.transaction_code),
        dcql,
    })
}

pub(crate) async fn schema_to_detail_v2_response_dto(
    value: CredentialSchema,
) -> Result<CredentialSchemaDetailV2ResponseDTO, CredentialSchemaServiceError> {
    let formats = value.formats.get().await.error_while("getting formats")?;

    let format_responses: Vec<CredentialSchemaFormatResponseDTO> = formats
        .iter()
        .map(|f| CredentialSchemaFormatResponseDTO {
            format: f.format.clone(),
            schema_id: f.schema_id.clone(),
        })
        .collect();

    let non_metadata_claim_schemas = non_metadata_claim_schemas(&value).await?;
    let mut claim_mappings_map: std::collections::HashMap<
        shared_types::ClaimSchemaId,
        Vec<CredentialClaimSchemaMappingDTO>,
    > = std::collections::HashMap::new();

    for format in &formats {
        let mappings = format
            .claim_mappings
            .get()
            .await
            .error_while("getting claim mappings")?;
        for mapping in mappings {
            claim_mappings_map
                .entry(mapping.claim_schema_id)
                .or_default()
                .push(CredentialClaimSchemaMappingDTO {
                    format: format.format.clone(),
                    technical_key: mapping.technical_key.clone(),
                    namespace: mapping.namespace.clone(),
                });
        }
    }

    let mut claim_schemas_v2 = vec![];
    for cs in non_metadata_claim_schemas {
        let mappings = claim_mappings_map.remove(&cs.id);
        let translations = cs
            .translations
            .get()
            .await
            .error_while(format!("getting translations for claim schema {}", cs.id))?;
        let dto = CredentialClaimSchemaV2DTO {
            id: cs.id,
            created_date: cs.created_date,
            last_modified: cs.last_modified,
            key: cs.key,
            datatype: cs.data_type,
            required: cs.required,
            array: cs.array,
            claims: vec![],
            mappings,
            translations: CredentialClaimSchemaTranslationsDTO {
                name: translations_to_i18n(&translations, LocalizedTextField::Name).ok_or(
                    CredentialSchemaServiceError::MappingError(format!(
                        "No translations for `name` of claim schema {}",
                        cs.id
                    )),
                )?,
            },
        };
        claim_schemas_v2.push(dto);
    }

    let claim_schemas_v2 = renest_claim_schemas_v2(claim_schemas_v2)?;

    Ok(CredentialSchemaDetailV2ResponseDTO {
        translations: map_translations(&value).await?,
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        formats: format_responses,
        imported_source_url: value.imported_source_url,
        organisation_id: value.organisation.id(),
        claims: claim_schemas_v2,
        key_storage_security: value.key_storage_security,
        layout_type: Some(value.layout_type),
        layout_properties: value.layout_properties.map(|item| item.into()),
        allow_suspension: value.allow_suspension,
        allow_revocation: value.allow_revocation,
        batch_size: value.batch_size,
        requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
        transaction_code: convert_inner(value.transaction_code),
    })
}

async fn non_metadata_claim_schemas(
    value: &CredentialSchema,
) -> Result<Vec<ClaimSchema>, CredentialSchemaServiceError> {
    Ok(value
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?
        .into_iter()
        .filter(|schema| !schema.metadata)
        .collect::<Vec<_>>())
}
fn renest_claim_schemas_v2(
    claim_schemas: Vec<CredentialClaimSchemaV2DTO>,
) -> Result<Vec<CredentialClaimSchemaV2DTO>, CredentialSchemaServiceError> {
    let mut result = vec![];

    for claim_schema in claim_schemas.iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_none() {
            result.push(claim_schema.to_owned());
        }
    }

    for mut claim_schema in claim_schemas.into_iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim_schema
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", result_schema.key))
                })
                .ok_or(CredentialSchemaServiceError::MissingParentClaimSchema {
                    claim_schema_id: claim_schema.id,
                })?;
            claim_schema.key = remove_first_nesting_layer(&claim_schema.key);
            matching_entry.claims.push(claim_schema);
        }
    }

    result
        .into_iter()
        .map(|mut claim_schema| {
            claim_schema.claims = renest_claim_schemas_v2(claim_schema.claims)?;
            Ok(claim_schema)
        })
        .collect::<Result<Vec<CredentialClaimSchemaV2DTO>, _>>()
}

fn map_dcql_format_meta(
    format: &CredentialSchemaFormat,
    config: &CoreConfig,
) -> Option<CredentialSchemaDcqlResponseDTO> {
    // Ignore failures here, as we don't want to fail the whole request if we can't map the format.
    // This would happen e.g., if a provider is renamed and the schema is still using the old name.
    let format_type = config.format.get_type(&format.format).ok()?;
    let dcql = CredentialSchemaDcqlResponseDTO {
        meta: schema_to_dcql_meta(format, &format_type),
        format: format_type.into(),
    };
    Some(dcql)
}

fn schema_to_dcql_meta(
    format: &CredentialSchemaFormat,
    format_type: &FormatType,
) -> CredentialMeta {
    match format_type {
        FormatType::SdJwtVc => CredentialMeta::SdJwtVc {
            vct_values: vec![format.schema_id.clone()],
        },
        FormatType::Mdoc => CredentialMeta::MsoMdoc {
            doctype_value: format.schema_id.clone(),
        },
        FormatType::Jwt
        | FormatType::SdJwt
        | FormatType::JsonLdClassic
        | FormatType::JsonLdBbsPlus => {
            // This is a terrible heuristic, but until proper support for JSON-LD contexts is added, this is the best we can do.
            let context = if let Ok(url) = Url::parse(&format.schema_id)
                && url.path().starts_with("/ssi/schema/v1/")
            {
                format
                    .schema_id
                    .replace("/ssi/schema/v1/", "/ssi/context/v1/")
            } else {
                format.schema_id.clone()
            };
            CredentialMeta::W3cVc {
                type_values: vec![vec![Context::CredentialsV2.to_string(), context]],
            }
        }
    }
}

pub(super) fn create_unique_name_check_request(
    name: &str,
    schema_ids: Vec<String>,
    organisation_id: OrganisationId,
) -> Result<CredentialSchemaListQuery, CredentialSchemaServiceError> {
    Ok(CredentialSchemaListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(
            CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                & (CredentialSchemaFilterValue::Name(StringMatch {
                    r#match: StringMatchType::Equals,
                    value: name.to_owned(),
                })
                .condition()
                    | CredentialSchemaFilterValue::SchemaIds(schema_ids)),
        ),
        ..Default::default()
    })
}

pub(super) fn from_create_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    schema_id: String,
    imported_source_url: String,
    default_language: &str,
) -> Result<CredentialSchema, CredentialSchemaServiceError> {
    if request.claims.is_empty() {
        return Err(CredentialSchemaServiceError::MissingClaimSchemas);
    }

    let now = crate::clock::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    Ok(CredentialSchema {
        id,
        allow_revocation: request.revocation_method.as_ref().map(|_| true),
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name.clone(),
        key_storage_security: request.key_storage_security,
        revocation_method: request.revocation_method,
        claim_schemas: claim_schemas
            .into_iter()
            .map(|claim_schema| {
                from_jwt_request_claim_schema(
                    now,
                    Uuid::new_v4().into(),
                    claim_schema.key,
                    claim_schema.datatype,
                    claim_schema.required,
                    claim_schema.array,
                )
            })
            .collect::<Vec<_>>()
            .into(),
        organisation: organisation.into(),
        layout_type: request.layout_type,
        layout_properties: request.layout_properties.map(Into::into),
        imported_source_url,
        allow_suspension: request.allow_suspension.unwrap_or_default(),
        requires_wallet_instance_attestation: request.requires_wallet_instance_attestation,
        transaction_code: convert_inner(request.transaction_code),
        batch_size: None,
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_id: id,
            format: request.format,
            schema_id,
            claim_mappings: Default::default(),
        }]
        .into(),
        translations: default_name_translation(id, request.name, now, default_language).into(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn from_create_v2_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaV2RequestDTO,
    organisation: Organisation,
    now: time::OffsetDateTime,
    formats: Vec<CredentialSchemaFormat>,
    claim_schemas: Vec<ClaimSchema>,
    imported_source_url: String,
    default_language: &str,
) -> CredentialSchema {
    CredentialSchema {
        id,
        allow_revocation: request.allow_revocation,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name.clone(),
        key_storage_security: request.key_storage_security,
        revocation_method: None,
        claim_schemas: claim_schemas.into(),
        organisation: organisation.into(),
        layout_type: request.layout_type,
        layout_properties: request.layout_properties.map(Into::into),
        imported_source_url,
        allow_suspension: request.allow_suspension.unwrap_or_default(),
        requires_wallet_instance_attestation: request.requires_wallet_instance_attestation,
        transaction_code: convert_inner(request.transaction_code),
        batch_size: request.batch_size,
        formats: formats.into(),
        translations: match request.translations {
            Some(translations) => schema_translations_from_dto(id, translations, now),
            None => default_name_translation(id, request.name, now, default_language),
        }
        .into(),
    }
}

pub(crate) fn schema_translations_from_dto(
    id: CredentialSchemaId,
    translations: CredentialSchemaTranslationsDTO,
    now: time::OffsetDateTime,
) -> Vec<LocalizedText> {
    let mut result = Vec::new();
    for (lang, value) in translations.name.0 {
        result.push(LocalizedText {
            entity_id: id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang,
            value,
            entity_type: LocalizedTextEntityType::CredentialSchema,
        });
    }
    if let Some(description) = translations.description {
        for (lang, value) in description.0 {
            result.push(LocalizedText {
                entity_id: id.into(),
                field: LocalizedTextField::Description,
                created_date: now,
                last_modified: now,
                lang,
                value,
                entity_type: LocalizedTextEntityType::CredentialSchema,
            });
        }
    }
    result
}

fn default_name_translation(
    id: CredentialSchemaId,
    name: String,
    now: time::OffsetDateTime,
    default_language: &str,
) -> Vec<LocalizedText> {
    vec![LocalizedText {
        entity_id: id.into(),
        field: LocalizedTextField::Name,
        created_date: now,
        last_modified: now,
        lang: default_language.to_string(),
        value: name,
        entity_type: LocalizedTextEntityType::CredentialSchema,
    }]
}

pub(super) fn build_format_with_claim_mappings(
    credential_schema_id: CredentialSchemaId,
    schema_id: String,
    format: shared_types::CredentialFormat,
    now: time::OffsetDateTime,
    claim_schemas_to_mappings: &[(ClaimSchema, Vec<CredentialClaimSchemaMappingDTO>)],
    formatter: &dyn CredentialFormatter,
) -> (CredentialSchemaFormat, Vec<ClaimSchema>) {
    let format_id = Uuid::new_v4().into();
    let uses_namespaces = formatter
        .get_capabilities()
        .features
        .contains(&Features::RequiresNamespaces);

    let metadata_claims_with_mappings = formatter
        .get_metadata_claims()
        .into_iter()
        .map(|metadata_claim| {
            (
                claim_schema_from_metadata_claim_schema(metadata_claim, now),
                vec![],
            )
        })
        .collect::<Vec<_>>();

    let mut mappings = vec![];
    for (claim_schema, claim_mappings) in claim_schemas_to_mappings
        .iter()
        .chain(metadata_claims_with_mappings.iter())
    {
        let mapping_for_format = claim_mappings.iter().find(|m| m.format == format);

        let technical_key = mapping_for_format
            .map(|m| m.technical_key.clone())
            .unwrap_or_else(|| claim_schema.key.clone());

        let namespace = mapping_for_format
            .and_then(|m| m.namespace.clone())
            .or_else(|| {
                if uses_namespaces {
                    Some(schema_id.clone())
                } else {
                    None
                }
            });

        mappings.push(CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_format_id: format_id,
            claim_schema_id: claim_schema.id,
            technical_key,
            namespace,
        });
    }

    (
        CredentialSchemaFormat {
            id: format_id,
            created_date: now,
            last_modified: now,
            credential_schema_id,
            format,
            schema_id,
            claim_mappings: RelatedVec::from(mappings),
        },
        metadata_claims_with_mappings
            .into_iter()
            .map(|(claim_schema, _)| claim_schema)
            .collect(),
    )
}

pub(crate) async fn to_credential_schema_list_response(
    credential_schema: CredentialSchema,
    include_translations: bool,
) -> Result<CredentialSchemaListItemResponseDTO, NestedError> {
    let format = credential_schema.format().await?.to_owned();
    let schema_id = credential_schema.schema_id().await?;
    let translations = if include_translations {
        Some(
            map_translations(&credential_schema)
                .await
                .error_while("mapping translations")?,
        )
    } else {
        None
    };
    Ok(CredentialSchemaListItemResponseDTO {
        id: credential_schema.id,
        created_date: credential_schema.created_date,
        last_modified: credential_schema.last_modified,
        deleted_at: credential_schema.deleted_at,
        name: credential_schema.name,
        format,
        revocation_method: credential_schema.revocation_method,
        key_storage_security: credential_schema.key_storage_security,
        schema_id,
        imported_source_url: credential_schema.imported_source_url,
        layout_type: Some(credential_schema.layout_type),
        layout_properties: credential_schema.layout_properties.map(|item| item.into()),
        allow_suspension: credential_schema.allow_suspension,
        requires_wallet_instance_attestation: credential_schema
            .requires_wallet_instance_attestation,
        translations,
    })
}

pub(crate) async fn to_credential_schema_list_v2_response(
    credential_schema: CredentialSchema,
) -> Result<CredentialSchemaListItemV2ResponseDTO, NestedError> {
    let formats = credential_schema
        .formats
        .get()
        .await
        .error_while("getting formats")?;

    let format_responses: Vec<CredentialSchemaFormatResponseDTO> = formats
        .iter()
        .map(|f| CredentialSchemaFormatResponseDTO {
            format: f.format.clone(),
            schema_id: f.schema_id.clone(),
        })
        .collect();

    Ok(CredentialSchemaListItemV2ResponseDTO {
        id: credential_schema.id,
        created_date: credential_schema.created_date,
        last_modified: credential_schema.last_modified,
        name: credential_schema.name,
        formats: format_responses,
        key_storage_security: credential_schema.key_storage_security,
        imported_source_url: credential_schema.imported_source_url,
        layout_type: Some(credential_schema.layout_type),
        layout_properties: credential_schema.layout_properties.map(|item| item.into()),
        allow_suspension: credential_schema.allow_suspension,
        allow_revocation: credential_schema.allow_revocation,
        batch_size: credential_schema.batch_size,
        requires_wallet_instance_attestation: credential_schema
            .requires_wallet_instance_attestation,
    })
}

async fn map_translations(
    schema: &CredentialSchema,
) -> Result<CredentialSchemaTranslationsDTO, CredentialSchemaServiceError> {
    let texts = schema
        .translations
        .get()
        .await
        .error_while("getting schema translations")?;
    Ok(CredentialSchemaTranslationsDTO {
        name: translations_to_i18n(&texts, LocalizedTextField::Name).ok_or(
            CredentialSchemaServiceError::MappingError(format!(
                "No translations for `name` of credential schema {}",
                schema.id
            )),
        )?,
        description: translations_to_i18n(&texts, LocalizedTextField::Description),
    })
}

pub(super) fn renest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaDTO>,
) -> Result<Vec<CredentialClaimSchemaDTO>, CredentialSchemaServiceError> {
    let mut result = vec![];

    // Iterate over all and copy all unnested claims to new vec
    for claim_schema in claim_schemas.iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_none() {
            result.push(claim_schema.to_owned());
        }
    }

    // Find all nested claims and move them to related entries in result vec
    for mut claim_schema in claim_schemas.into_iter() {
        if claim_schema.key.find(NESTED_CLAIM_MARKER).is_some() {
            let matching_entry = result
                .iter_mut()
                .find(|result_schema| {
                    claim_schema
                        .key
                        .starts_with(&format!("{}{NESTED_CLAIM_MARKER}", result_schema.key))
                })
                .ok_or(CredentialSchemaServiceError::MissingParentClaimSchema {
                    claim_schema_id: claim_schema.id,
                })?;
            claim_schema.key = remove_first_nesting_layer(&claim_schema.key);

            matching_entry.claims.push(claim_schema);
        }
    }

    // Repeat for all claims to nest all subclaims
    result
        .into_iter()
        .map(|mut claim_schema| {
            claim_schema.claims = renest_claim_schemas(claim_schema.claims)?;
            Ok(claim_schema)
        })
        .collect::<Result<Vec<CredentialClaimSchemaDTO>, _>>()
}

pub(super) fn unnest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    unnest_claim_schemas_inner(claim_schemas, "".to_string())
}

fn unnest_claim_schemas_inner(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
    prefix: String,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut result = vec![];

    for claim_schema in claim_schemas {
        let key = format!("{prefix}{}", claim_schema.key);

        let nested =
            unnest_claim_schemas_inner(claim_schema.claims, format!("{key}{NESTED_CLAIM_MARKER}"));

        result.push(CredentialClaimSchemaRequestDTO {
            key,
            claims: vec![],
            ..claim_schema
        });

        result.extend(nested);
    }

    result
}

impl From<CredentialSchemaLogoPropertiesRequestDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO
{
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaCodePropertiesDTO
{
    fn from(value: CredentialSchemaCodePropertiesDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO>
    for crate::proto::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO
{
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaFilterParamsDTO> for ListFilterCondition<CredentialSchemaFilterValue> {
    fn from(value: CredentialSchemaFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            CredentialSchemaFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            CredentialSchemaFilterValue::Name(StringMatch {
                r#match: get_string_match_type(CredentialSchemaExactColumn::Name),
                value: name,
            })
        });

        let schema_id = value.schema_id.map(|schema_id| {
            CredentialSchemaFilterValue::SchemaId(StringMatch {
                r#match: get_string_match_type(CredentialSchemaExactColumn::SchemaId),
                value: schema_id,
            })
        });

        let formats = value.formats.map(CredentialSchemaFilterValue::Formats);

        let key_storage_security = value
            .key_storage_security
            .map(CredentialSchemaFilterValue::KeyStorageSecurity);

        let requires_wia = value
            .requires_wallet_instance_attestation
            .map(CredentialSchemaFilterValue::RequiresWalletInstanceAttestation);

        let credential_schema_ids = value
            .credential_schema_ids
            .map(CredentialSchemaFilterValue::CredentialSchemaIds);

        let created_date_after = value.created_date_after.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let uses_batch_issuance = value
            .uses_batch_issuance
            .map(CredentialSchemaFilterValue::UsesBatchIssuance);

        let is_multiformat_schema = value
            .is_multiformat_schema
            .map(CredentialSchemaFilterValue::IsMultiformatSchema);

        let schema_ids = value.schema_ids.map(CredentialSchemaFilterValue::SchemaIds);

        organisation_id
            & name
            & schema_id
            & schema_ids
            & formats
            & key_storage_security
            & requires_wia
            & credential_schema_ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & uses_batch_issuance
            & is_multiformat_schema
    }
}
