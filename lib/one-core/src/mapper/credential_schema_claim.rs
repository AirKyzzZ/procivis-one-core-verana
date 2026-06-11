use std::collections::{HashMap, VecDeque};

use shared_types::ClaimSchemaId;
use shared_types::i18n::I18nString;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::mapper::{NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER_STR};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::provider::credential_formatter::MetadataClaimSchema;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
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
    let id: ClaimSchemaId = Uuid::new_v4().into();
    let translations = match &request.translations {
        Some(t) => t
            .name
            .0
            .iter()
            .map(|(lang, value)| LocalizedText {
                entity_id: id.into(),
                field: LocalizedTextField::Name,
                created_date: now,
                last_modified: now,
                lang: lang.clone(),
                value: value.clone(),
                entity_type: LocalizedTextEntityType::ClaimSchema,
            })
            .collect::<Vec<_>>()
            .into(),
        None => Default::default(),
    };
    ClaimSchema {
        id,
        key: request.key.clone(),
        business_key: Some(request.key.clone()),
        data_type: request.datatype.clone(),
        created_date: now,
        last_modified: now,
        array: request.array.unwrap_or(false),
        metadata: false,
        required: request.required,
        translations,
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
    let raw = value.translations.as_ref().await?;
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
    {
        let mut translations = credential_schema.translations.as_mut().await?;
        if !translations
            .iter()
            .any(|t| t.lang == default_language && t.field == LocalizedTextField::Name)
        {
            translations.push(LocalizedText {
                entity_id: credential_schema.id.into(),
                field: LocalizedTextField::Name,
                created_date: credential_schema.created_date,
                last_modified: credential_schema.last_modified,
                lang: default_language.to_string(),
                value: credential_schema.name.clone(),
                entity_type: LocalizedTextEntityType::CredentialSchema,
            });
        }
    }

    let mut claim_schemas = vec![];
    for claim_schema in credential_schema.claim_schemas.as_ref().await?.to_owned() {
        claim_schemas.push(add_fallback_translation(claim_schema, default_language).await?);
    }
    credential_schema.claim_schemas = claim_schemas.into();
    Ok(credential_schema)
}

pub(crate) async fn add_fallback_translation(
    mut claim_schema: ClaimSchema,
    default_language: &str,
) -> Result<ClaimSchema, DataLayerError> {
    {
        let mut translations = claim_schema.translations.as_mut().await?;
        if !claim_schema.metadata
            && !translations
                .iter()
                .any(|t| t.lang == default_language && t.field == LocalizedTextField::Name)
        {
            translations.push(LocalizedText {
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
            });
        }
    }
    Ok(claim_schema)
}

pub(crate) fn claim_path_to_formatted_path(
    claim: &Claim,
    claim_schema: &ClaimSchema,
    claim_mapping: &CredentialSchemaFormatClaimSchema,
) -> Result<(String, bool), IssuanceProtocolError> {
    let key_segments = claim_schema
        .key
        .split(NESTED_CLAIM_MARKER)
        .collect::<Vec<&str>>();
    let technical_key_segments = claim_mapping
        .technical_key
        .split(NESTED_CLAIM_MARKER)
        .collect::<Vec<&str>>();
    let mut path_segments = claim
        .path
        .split(NESTED_CLAIM_MARKER)
        .collect::<VecDeque<&str>>();
    if key_segments.len() != technical_key_segments.len() {
        return Err(IssuanceProtocolError::Failed(format!(
            "key `{}` and technical key `{}` have different number of segments",
            claim_schema.key, claim_mapping.technical_key
        )));
    }
    let mut mapped_path = vec![];
    for (key_segment, technical_key_segment) in
        key_segments.iter().zip(technical_key_segments.iter())
    {
        map_array_indices(&mut path_segments, key_segment, &mut mapped_path)?;
        mapped_path.push(technical_key_segment);
    }
    let mut array_item = false;
    if !path_segments.is_empty() {
        // there are path segments left over, which _must_ be an array indices, so _this_ claim is an array item
        array_item = true;
        mapped_path.extend(path_segments);
    }
    if let Some(namespace) = &claim_mapping.namespace {
        mapped_path.insert(0, namespace);
    }
    Ok((mapped_path.join(NESTED_CLAIM_MARKER_STR), array_item))
}

/// Maps path segments to the mapped path until one matches the key segment.
/// The path may contain additional segments (the array indices), which are not represented in the
/// schema keys, which is why we need to do this in the first place.
fn map_array_indices<'a>(
    path_segments: &mut VecDeque<&'a str>,
    key_segment: &str,
    mapped_path: &mut Vec<&'a str>,
) -> Result<(), IssuanceProtocolError> {
    loop {
        let Some(curr_path_segment) = path_segments.pop_front() else {
            return Err(IssuanceProtocolError::Failed(format!(
                "path segment missing for key segment `{key_segment}`"
            )));
        };
        if curr_path_segment == key_segment {
            return Ok(());
        }
        mapped_path.push(curr_path_segment);
    }
}
