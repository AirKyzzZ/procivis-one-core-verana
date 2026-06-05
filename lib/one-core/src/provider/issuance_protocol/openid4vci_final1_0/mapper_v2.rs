use std::collections::VecDeque;

use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::error::ContextWithErrorCode;
use crate::mapper::{NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER_STR};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::provider::credential_formatter::mapper::vcdm_from_credential_and_published_claims;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialStatus, PublishedClaim, PublishedClaimValue,
};
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

pub(super) async fn credential_to_credential_detail_v2(
    credential: &Credential,
    credential_schema: &CredentialSchema,
    credential_schema_format: &CredentialSchemaFormat,
    config: &CoreConfig,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
) -> Result<CredentialData, IssuanceProtocolError> {
    let claims = credential
        .claims
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "missing credential claims".to_string(),
        ))?;
    let mappings = credential_schema_format.claim_mappings.as_ref().await?;
    let mut published_claims = Vec::with_capacity(claims.len());
    for claim in claims
        .iter()
        // filter out metadata
        .filter(|c| !c.schema.as_ref().is_some_and(|s| s.metadata))
        // filter out container claims
        .filter(|c| c.value.is_some())
    {
        let claim_schema = claim.schema.as_ref().ok_or(IssuanceProtocolError::Failed(
            "missing claim schema".to_string(),
        ))?;
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.claim_schema_id == claim_schema.id)
            .ok_or(IssuanceProtocolError::Failed(
                "claim mapping not found".to_string(),
            ))?;
        let published_claim = claim_to_published_claim(claim, claim_schema, mapping, config)?;
        published_claims.push(published_claim);
    }
    let vcdm = vcdm_from_credential_and_published_claims(
        credential,
        core_base_url,
        credential_status,
        vcdm_v2_base_context(None),
        published_claims.clone(),
        credential_schema,
        credential_schema_format,
        config,
    )
    .error_while("creating VCDM")?;

    let credential_data = CredentialData {
        vcdm,
        claims: published_claims,
        holder_identifier: None,
        holder_key_id: None,
        issuer_certificate: None,
    };
    Ok(credential_data)
}

fn claim_to_published_claim(
    claim: &Claim,
    claim_schema: &ClaimSchema,
    claim_mapping: &CredentialSchemaFormatClaimSchema,
    config: &CoreConfig,
) -> Result<PublishedClaim, IssuanceProtocolError> {
    let claim_value = claim
        .value
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(format!(
            "Missing value on leaf claim: {}",
            claim.id
        )))?;
    let value = match config
        .datatype
        .get_fields(&claim_schema.data_type)
        .error_while("getting datatype config")?
        .r#type
    {
        DatatypeType::Number => {
            if let Ok(number) = claim_value.parse::<i64>() {
                PublishedClaimValue::Integer(number)
            } else if let Ok(float) = claim_value.parse::<f64>() {
                PublishedClaimValue::Float(float)
            } else {
                // Fallback to empty string
                PublishedClaimValue::String(String::new())
            }
        }
        DatatypeType::Boolean => {
            if let Ok(bool) = claim_value.parse::<bool>() {
                PublishedClaimValue::Bool(bool)
            } else {
                // Fallback to empty string
                PublishedClaimValue::String(String::new())
            }
        }
        _ => PublishedClaimValue::String(claim_value.to_owned()),
    };

    // map to technical keys
    let (key, array_item) = map_path(claim, claim_schema, claim_mapping)?;
    Ok(PublishedClaim {
        key,
        value,
        datatype: Some(claim_schema.data_type.clone()),
        array_item,
    })
}

fn map_path(
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
