use std::collections::HashMap;

use shared_types::ClaimSchemaId;
use shared_types::i18n::I18nString;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::provider::credential_formatter::MetadataClaimSchema;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO, CredentialClaimSchemaTranslationsDTO,
};

pub(crate) fn claim_schema_from_metadata_claim_schema(
    metadata_claim: MetadataClaimSchema,
    now: OffsetDateTime,
) -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: metadata_claim.key.to_string(),
        business_key: None,
        data_type: metadata_claim.data_type,
        created_date: now,
        last_modified: now,
        array: metadata_claim.array,
        required: metadata_claim.required,
        metadata: true,
        // metadata claims are not translated
        translations: vec![].into(),
    }
}

pub(crate) fn from_request_claim_schema(
    now: OffsetDateTime,
    request: &CredentialClaimSchemaRequestDTO,
) -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: request.key.clone(),
        business_key: Some(request.key.clone()),
        data_type: request.datatype.clone(),
        created_date: now,
        last_modified: now,
        array: request.array.unwrap_or(false),
        metadata: false,
        required: request.required,
        translations: Default::default(),
    }
}

pub(crate) fn from_jwt_request_claim_schema(
    now: OffsetDateTime,
    id: ClaimSchemaId,
    key: String,
    datatype: String,
    required: bool,
    array: Option<bool>,
) -> ClaimSchema {
    ClaimSchema {
        id,
        key,
        business_key: None,
        data_type: datatype,
        created_date: now,
        last_modified: now,
        array: array.unwrap_or(false),
        metadata: false,
        required,
        translations: Default::default(),
    }
}

pub(crate) fn translations_to_i18n(
    texts: &[LocalizedText],
    field: LocalizedTextField,
) -> Option<I18nString> {
    let translations: HashMap<_, _> = texts
        .iter()
        .filter(|t| t.field == field)
        .map(|t| (t.lang.clone(), t.value.clone()))
        .collect();
    if translations.is_empty() {
        return None;
    }
    Some(I18nString(translations))
}

pub(crate) async fn claim_schema_to_dto(
    value: ClaimSchema,
) -> Result<CredentialClaimSchemaDTO, DataLayerError> {
    let raw = value.translations.get().await?;
    let Some(name) = translations_to_i18n(&raw, LocalizedTextField::Name) else {
        return Err(DataLayerError::MissingRequiredRelation {
            relation: "translations",
            id: value.key.to_string(),
        });
    };
    Ok(CredentialClaimSchemaDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        key: value.key,
        datatype: value.data_type,
        required: value.required,
        array: value.array,
        claims: vec![],
        translations: CredentialClaimSchemaTranslationsDTO { name },
    })
}

pub(crate) async fn backfill_default_translations(
    mut credential_schema: CredentialSchema,
    default_language: &str,
) -> Result<CredentialSchema, DataLayerError> {
    if credential_schema.translations.get().await?.is_empty() {
        credential_schema.translations = vec![LocalizedText {
            entity_id: credential_schema.id.into(),
            field: LocalizedTextField::Name,
            created_date: credential_schema.created_date,
            last_modified: credential_schema.last_modified,
            lang: default_language.to_string(),
            value: credential_schema.name.clone(),
            entity_type: LocalizedTextEntityType::CredentialSchema,
        }]
        .into()
    }

    let mut claim_schemas = vec![];
    for claim_schema in credential_schema.claim_schemas.get().await? {
        claim_schemas.push(add_fallback_translation(claim_schema, default_language).await?);
    }
    credential_schema.claim_schemas = claim_schemas.into();
    Ok(credential_schema)
}

pub(crate) async fn add_fallback_translation(
    mut claim_schema: ClaimSchema,
    default_language: &str,
) -> Result<ClaimSchema, DataLayerError> {
    if !claim_schema.metadata && claim_schema.translations.get().await?.is_empty() {
        claim_schema.translations = vec![LocalizedText {
            entity_id: claim_schema.id.into(),
            field: LocalizedTextField::Name,
            created_date: claim_schema.created_date,
            last_modified: claim_schema.last_modified,
            lang: default_language.to_string(),
            value: claim_schema
                .key
                .rsplit_once(NESTED_CLAIM_MARKER)
                .map(|(_, end)| end.to_string())
                .unwrap_or(claim_schema.key.clone()),
            entity_type: LocalizedTextEntityType::ClaimSchema,
        }]
        .into();
    }
    Ok(claim_schema)
}
