use std::collections::HashSet;

use shared_types::OrganisationId;

use super::dto::{
    CreateProofSchemaRequestDTO, ImportProofSchemaClaimSchemaDTO, ImportProofSchemaDTO,
    ProofInputSchemaRequestDTO,
};
use super::error::ProofSchemaServiceError;
use super::mapper::create_unique_name_check_request;
use crate::config::core_config::{ConfigExt, CoreConfig};
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{Features, SelectiveDisclosure};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

pub async fn proof_schema_name_already_exists(
    repository: &dyn ProofSchemaRepository,
    name: &str,
    organisation_id: OrganisationId,
) -> Result<(), ProofSchemaServiceError> {
    let proof_schemas = repository
        .get_proof_schema_list(create_unique_name_check_request(name, organisation_id)?)
        .await
        .error_while("getting proof schemas")?;
    if proof_schemas.total_items > 0 {
        return Err(ProofSchemaServiceError::AlreadyExists);
    }
    Ok(())
}

pub async fn throw_if_invalid_credential_combination(
    schemas: &[CredentialSchema],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<(), ProofSchemaServiceError> {
    if schemas.len() > 1 {
        for schema in schemas {
            let schema_format = schema.format().await?;
            let formatter = formatter_provider.get_credential_formatter(&schema_format)?;

            if !formatter
                .get_capabilities()
                .features
                .contains(&Features::SupportsCombinedPresentation)
            {
                return Err(ProofSchemaServiceError::InvalidCredentialCombination {
                    credential_format: schema_format.to_string(),
                });
            }
        }
    }

    Ok(())
}

pub fn validate_create_request(
    request: &CreateProofSchemaRequestDTO,
) -> Result<(), ProofSchemaServiceError> {
    if request.proof_input_schemas.is_empty() {
        return Err(ProofSchemaServiceError::MissingProofInputSchemas);
    }

    let mut uniq = HashSet::new();

    for proof_input in &request.proof_input_schemas {
        if proof_input.claim_schemas.is_empty() {
            return Err(ProofSchemaServiceError::MissingClaims);
        }

        // at least one claim must be required
        if !proof_input.claim_schemas.iter().any(|claim| claim.required) {
            return Err(ProofSchemaServiceError::NoRequiredClaim);
        }

        if !proof_input
            .claim_schemas
            .iter()
            .all(|claim| uniq.insert(claim.id))
        {
            return Err(ProofSchemaServiceError::DuplicitClaim);
        }
    }

    Ok(())
}

pub(super) async fn extract_claims_from_credential_schema(
    proof_inputs: &[ProofInputSchemaRequestDTO],
    schemas: &[CredentialSchema],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<Vec<ClaimSchema>, ProofSchemaServiceError> {
    let mut result = vec![];

    for proof_input in proof_inputs {
        let credential_schema = schemas
            .iter()
            .find(|schema| schema.id == proof_input.credential_schema_id)
            .ok_or_else(|| {
                ProofSchemaServiceError::MappingError("Missing credential schema".into())
            })?;

        let schema_format = credential_schema.format().await?;
        let formatter = formatter_provider.get_credential_formatter(&schema_format)?;

        let claims = credential_schema.claim_schemas.as_ref().await?;
        let arrays = collect_lists(&claims);

        for proof_claim in &proof_input.claim_schemas {
            let claim_schema = claims
                .iter()
                .find(|schema_claim| schema_claim.id == proof_claim.id)
                .ok_or(ProofSchemaServiceError::MissingClaimSchema(proof_claim.id))?;

            validate_proof_schema_nesting(claim_schema, &*formatter)?;
            validate_proof_schema_claim_not_in_array(&claim_schema.key, &arrays)?;
            result.push(claim_schema.to_owned());
        }
    }

    Ok(result)
}

fn validate_proof_schema_claim_not_in_array(
    key: &str,
    arrays: &HashSet<String>,
) -> Result<(), ProofSchemaServiceError> {
    match key.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((parent, _)) => {
            if arrays.contains(parent) {
                Err(ProofSchemaServiceError::NestedClaimInArrayRequested)
            } else {
                validate_proof_schema_claim_not_in_array(parent, arrays)
            }
        }
        None => Ok(()),
    }
}

fn collect_lists(claims: &[ClaimSchema]) -> HashSet<String> {
    claims
        .iter()
        .filter_map(|c| match c.array {
            true => Some(c.key.to_owned()),
            _ => None,
        })
        .collect()
}

pub(super) fn validate_proof_schema_nesting(
    claim_schema: &ClaimSchema,
    formatter: &dyn CredentialFormatter,
) -> Result<(), ProofSchemaServiceError> {
    let capabilities = formatter.get_capabilities();

    // Check disclosure level
    let valid_disclosure_level = match (
        capabilities
            .features
            .contains(&Features::SelectiveDisclosure),
        capabilities.selective_disclosure.first(),
    ) {
        (true, None) => false,     // Incompatible capabilities
        (false, Some(_)) => false, // Incompatible capabilities
        (false, None) => !claim_schema.key.contains('/'),
        (true, Some(SelectiveDisclosure::AnyLevel)) => true,
        (true, Some(SelectiveDisclosure::SecondLevel)) => {
            claim_schema.key.chars().filter(|&c| c == '/').count() <= 1
        }
    };

    if !valid_disclosure_level {
        return Err(ProofSchemaServiceError::IncorrectDisclosureLevel);
    }
    Ok(())
}

pub(super) fn validate_imported_proof_schema(
    schema: &ImportProofSchemaDTO,
    config: &CoreConfig,
) -> Result<(), ProofSchemaServiceError> {
    for schema in &schema.proof_input_schemas {
        let format = &schema.credential_schema.format;
        config
            .format
            .get_if_enabled(format)
            .map_err(|_| ProofSchemaServiceError::UnsupportedFormat(format.to_owned()))?;

        validate_imported_proof_schema_data_types(&schema.claim_schemas, config)?;
    }

    Ok(())
}

fn validate_imported_proof_schema_data_types(
    claim_schemas: &[ImportProofSchemaClaimSchemaDTO],
    config: &CoreConfig,
) -> Result<(), ProofSchemaServiceError> {
    for claim_schema in claim_schemas {
        let datatype = &claim_schema.data_type;
        config
            .datatype
            .get_if_enabled(datatype)
            .map_err(|_| ProofSchemaServiceError::UnsupportedDatatype(datatype.to_owned()))?;

        validate_imported_proof_schema_data_types(&claim_schema.claims, config)?;
    }

    Ok(())
}
