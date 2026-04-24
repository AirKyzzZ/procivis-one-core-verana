use dcql::CredentialMeta;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialSchemaId, OrganisationId};
use url::Url;
use uuid::Uuid;

use super::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaDcqlResponseDTO, CredentialSchemaDetailResponseDTO,
    CredentialSchemaFilterParamsDTO, CredentialSchemaFilterValue,
    CredentialSchemaLogoPropertiesRequestDTO,
};
use super::error::CredentialSchemaServiceError;
use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::ContextWithErrorCode;
use crate::mapper::credential_schema_claim::from_jwt_request_claim_schema;
use crate::mapper::{NESTED_CLAIM_MARKER, remove_first_nesting_layer};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaExactColumn, CredentialSchemaListQuery,
};
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::model::Context;

pub(crate) async fn schema_to_detail_response_dto(
    value: CredentialSchema,
    config: &CoreConfig,
) -> Result<CredentialSchemaDetailResponseDTO, CredentialSchemaServiceError> {
    let dcql = map_dcql_format_meta(&value, config);
    let claim_schemas = value
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?
        .into_iter()
        .filter(|schema| !schema.metadata)
        .collect::<Vec<_>>();
    let claim_schemas = renest_claim_schemas(convert_inner(claim_schemas))?;

    Ok(CredentialSchemaDetailResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        format: value.format,
        imported_source_url: value.imported_source_url,
        revocation_method: value.revocation_method,
        organisation_id: value.organisation.id(),
        claims: claim_schemas,
        key_storage_security: value.key_storage_security,
        schema_id: value.schema_id,
        layout_type: Some(value.layout_type),
        layout_properties: value.layout_properties.map(|item| item.into()),
        allow_suspension: value.allow_suspension,
        requires_wallet_instance_attestation: value.requires_wallet_instance_attestation,
        transaction_code: convert_inner(value.transaction_code),
        dcql,
    })
}

fn map_dcql_format_meta(
    value: &CredentialSchema,
    config: &CoreConfig,
) -> Option<CredentialSchemaDcqlResponseDTO> {
    // Ignore failures here, as we don't want to fail the whole request if we can't map the format.
    // This would happen e.g., if a provider is renamed and the schema is still using the old name.
    let format_type = config.format.get_type(&value.format).ok()?;
    let dcql = CredentialSchemaDcqlResponseDTO {
        meta: schema_to_dcql_meta(value, &format_type),
        format: format_type.into(),
    };
    Some(dcql)
}

fn schema_to_dcql_meta(schema: &CredentialSchema, format_type: &FormatType) -> CredentialMeta {
    match format_type {
        FormatType::SdJwtVc => CredentialMeta::SdJwtVc {
            vct_values: vec![schema.schema_id.clone()],
        },
        FormatType::Mdoc => CredentialMeta::MsoMdoc {
            doctype_value: schema.schema_id.clone(),
        },
        FormatType::Jwt
        | FormatType::SdJwt
        | FormatType::JsonLdClassic
        | FormatType::JsonLdBbsPlus => {
            // This is a terrible heuristic, but until proper support for JSON-LD contexts is added, this is the best we can do.
            let context = if let Ok(url) = Url::parse(&schema.schema_id)
                && url.path().starts_with("/ssi/schema/v1/")
            {
                schema
                    .schema_id
                    .replace("/ssi/schema/v1/", "/ssi/context/v1/")
            } else {
                schema.schema_id.clone()
            };
            CredentialMeta::W3cVc {
                type_values: vec![vec![Context::CredentialsV2.to_string(), context]],
            }
        }
    }
}

pub(super) fn create_unique_name_check_request(
    name: &str,
    schema_id: Option<String>,
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
                    | schema_id.map(|schema_id| {
                        CredentialSchemaFilterValue::SchemaId(StringMatch {
                            r#match: StringMatchType::Equals,
                            value: schema_id,
                        })
                    })),
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
) -> Result<CredentialSchema, CredentialSchemaServiceError> {
    if request.claims.is_empty() {
        return Err(CredentialSchemaServiceError::MissingClaimSchemas);
    }

    let now = crate::clock::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    Ok(CredentialSchema {
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name,
        format: request.format,
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
        schema_id,
        allow_suspension: request.allow_suspension.unwrap_or_default(),
        requires_wallet_instance_attestation: request.requires_wallet_instance_attestation,
        transaction_code: convert_inner(request.transaction_code),
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

        organisation_id
            & name
            & schema_id
            & formats
            & key_storage_security
            & requires_wia
            & credential_schema_ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
