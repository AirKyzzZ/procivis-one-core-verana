use std::collections::HashMap;

use convert_case::{Case, Casing};
use dcql::{ClaimQuery, ClaimQueryId, CredentialFormat, CredentialQuery, DcqlQuery};

use crate::config::core_config::FormatType;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::verification_protocol::FormatMapper;
use crate::provider::verification_protocol::error::VerificationProtocolError;

pub async fn create_dcql_query(
    proof_schema: &ProofSchema,
    format_to_type_mapper: &FormatMapper,
    credential_formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<DcqlQuery, VerificationProtocolError> {
    let input_schemas =
        proof_schema
            .input_schemas
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Input schemas not found".to_string(),
            ))?;

    let mut credential_queries = Vec::with_capacity(input_schemas.len());
    for input_schema in input_schemas {
        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "Credential schema not found".to_string(),
                ))?;

        let claim_schemas =
            input_schema
                .claim_schemas
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(
                    "Claim schemas not found".to_string(),
                ))?;
        let formats = credential_schema.formats.as_ref().await?;
        let format = formats
            .first()
            .ok_or(VerificationProtocolError::Failed(format!(
                "empty formats on credential schema {}",
                credential_schema.id
            )))?;
        let mappings = format.claim_mappings.as_ref().await?;
        let mappings_by_schema_id: HashMap<_, _> = mappings
            .into_iter()
            .map(|m| (m.claim_schema_id, m))
            .collect();
        let formatter = credential_formatter_provider.get_credential_formatter(&format.format)?;

        let credential_format = format_to_type_mapper(&format.format)?;
        let dcql_format: CredentialFormat = credential_format.into();

        let schema_id = credential_schema.schema_id().await?;
        let base_credential_query = match dcql_format {
            CredentialFormat::MsoMdoc => CredentialQuery::mso_mdoc(schema_id),
            CredentialFormat::SdJwt => CredentialQuery::sd_jwt_vc(vec![schema_id]),
            CredentialFormat::LdpVc => {
                CredentialQuery::ldp_vc(w3c_credential_query_type_values(credential_schema).await?)
            }
            CredentialFormat::JwtVc => {
                CredentialQuery::jwt_vc(w3c_credential_query_type_values(credential_schema).await?)
            }
            CredentialFormat::W3cSdJwt => CredentialQuery::w3c_sd_jwt(
                w3c_credential_query_type_values(credential_schema).await?,
            ),
        };

        // Build claim queries
        let claim_queries: Vec<ClaimQuery> = claim_schemas
            .iter()
            .map(|claim_schema| {
                let mapping = mappings_by_schema_id.get(&claim_schema.schema.id);
                let claim_query_builder = ClaimQuery::builder()
                    .id(claim_schema.schema.id.to_string())
                    .path(format_dcql_path(
                        &claim_schema.schema.key,
                        formatter.user_claims_path(),
                        mapping.copied(), // resolves the first reference of the && value
                    ))
                    .required(claim_schema.required);

                // Add intent_to_retain for MDOC format
                match credential_format {
                    FormatType::Mdoc => claim_query_builder.intent_to_retain(true).build(),
                    _ => claim_query_builder.build(),
                }
            })
            .collect();

        // Build final credential query
        credential_queries.push(
            base_credential_query
                .id(credential_schema.id.to_string())
                .claims(claim_queries)
                .maybe_claim_sets(build_claim_sets(claim_schemas))
                .build(),
        )
    }

    // Build and return final DCQL query
    Ok(DcqlQuery::builder().credentials(credential_queries).build())
}

fn build_claim_sets(claim_schemas: &[ProofInputClaimSchema]) -> Option<Vec<Vec<ClaimQueryId>>> {
    let (required_claims, optional_claims): (Vec<_>, Vec<_>) =
        claim_schemas.iter().partition(|cs| cs.required);

    if optional_claims.is_empty() {
        None
    } else {
        let required_claim_ids: Vec<ClaimQueryId> = required_claims
            .iter()
            .map(|cs| ClaimQueryId::from(cs.schema.id.to_string()))
            .collect();

        let optional_claim_ids: Vec<ClaimQueryId> = optional_claims
            .iter()
            .map(|cs| ClaimQueryId::from(cs.schema.id.to_string()))
            .collect();

        Some(vec![
            [&required_claim_ids[..], &optional_claim_ids[..]].concat(),
            required_claim_ids,
        ])
    }
}

async fn w3c_credential_query_type_values(
    credential_schema: &CredentialSchema,
) -> Result<Vec<Vec<String>>, VerificationProtocolError> {
    let credential_type = credential_schema.name.to_case(Case::Pascal);
    let schema_id = credential_schema.schema_id().await?;
    Ok(vec![
        vec![
            "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
            format!("{}#{}", schema_id, credential_type),
        ],
        vec![credential_type],
    ])
}

fn format_dcql_path(
    claim_key: &str,
    mut user_claim_path: Vec<String>,
    mapping: Option<&CredentialSchemaFormatClaimSchema>,
) -> Vec<String> {
    // Note: Reaching into arrays is _not_ supported by our verifier. Hence, there is no handling for array index selectors.
    let effective_claim_key = if let Some(mapping) = mapping {
        if let Some(namespace) = &mapping.namespace {
            format!(
                "{}{NESTED_CLAIM_MARKER}{}",
                namespace, mapping.technical_key
            )
        } else {
            mapping.technical_key.clone()
        }
    } else {
        claim_key.to_string()
    };
    user_claim_path.extend(
        effective_claim_key
            .split(NESTED_CLAIM_MARKER)
            .map(str::to_string),
    );
    user_claim_path
}
