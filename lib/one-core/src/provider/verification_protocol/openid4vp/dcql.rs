use std::collections::{HashMap, VecDeque};

use dcql::matching::{ClaimFilter, CredentialFilter};
use dcql::{
    ClaimPath, ClaimValue, CredentialFormat, CredentialQuery, DcqlQuery, PathSegment,
    TrustedAuthority,
};
use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{ClaimId, OrganisationId};
use standardized_types::x509::KeyIdentifier;

use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaListQuery};
use crate::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::proof::Proof;
use crate::proto::openid4vp_proof_validator::validator::get_trusted_akis;
use crate::proto::trust_information::TrustInformationProvider;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::verification_protocol::dto::{
    ApplicableCredentialOrFailureHintEnum, CredentialDetailClaimExtResponseDTO,
    CredentialQueryFailureHintResponseDTO, CredentialQueryFailureReasonEnum,
    CredentialQueryResponseDTO, CredentialSetResponseDTO, PresentationDefinitionV2ResponseDTO,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::mapper::get_presentation_credentials_by_schema_id;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::service::credential::dto::{
    CredentialAttestationBlobs, CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential::mapper::{
    credential_detail_response_from_model, get_remaining_batch_item_count,
};
use crate::service::credential_schema::dto::{
    CredentialSchemaDetailResponseDTO, CredentialSchemaFilterValue,
    CredentialSchemaListIncludeEntityTypeEnum,
};
use crate::service::credential_schema::mapper::schema_to_detail_response_dto;

pub(crate) async fn get_presentation_definition_v2(
    dcql_query: DcqlQuery,
    proof: &Proof,
    credential_repository: &dyn CredentialRepository,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
    trust_information_provider: &dyn TrustInformationProvider,
    config: &CoreConfig,
) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
    let organisation = proof
        .interaction
        .as_ref()
        .and_then(|interaction| interaction.organisation.as_ref())
        .ok_or(VerificationProtocolError::Failed(
            "proof organisation missing".to_string(),
        ))?;

    let query_to_filters = dcql_query.credential_filters()?;

    let mut credential_queries = HashMap::new();
    let credential_sets = if let Some(credential_sets) = dcql_query.credential_sets {
        convert_inner(credential_sets)
    } else {
        dcql_query
            .credentials
            .iter()
            .map(|query| CredentialSetResponseDTO {
                required: true,
                options: vec![vec![query.id.to_string()]],
            })
            .collect()
    };

    for query in dcql_query.credentials {
        let credential_filters =
            query_to_filters
                .get(&query.id)
                .ok_or(VerificationProtocolError::Failed(format!(
                    "missing credential filters for credential query with id {}",
                    query.id
                )))?;

        // This is very inefficient. We would have the information here to also filter by the claims
        // required, etc. but so far this was not a problem so it is not optimized.
        let credential_candidates = fetch_credentials_for_schema_ids(
            organisation.id,
            credential_filters,
            credential_repository,
        )
        .await?;

        let mut filtered_credential_candidates = vec![];
        for credential_candidate in credential_candidates.into_iter() {
            let Some(schema) = &credential_candidate.schema else {
                continue;
            };
            let format = schema.format().await?;
            if format_matches(&query.format, &format, config) {
                filtered_credential_candidates.push(credential_candidate);
            }
        }

        if let Some(authorities) = &query.trusted_authorities {
            filter_credentials_by_trusted_authorities(
                &mut filtered_credential_candidates,
                authorities.as_slice(),
            )
            .await;
        }

        if filtered_credential_candidates.is_empty() {
            let schema_ids = credential_filters
                .iter()
                .flat_map(|filter| {
                    filter
                        .schema_ids
                        .iter()
                        .map(|schema_id| map_schema_id(filter, schema_id))
                })
                .collect::<Vec<_>>();
            let credential_schema = find_schema_by_schema_ids(
                &schema_ids,
                organisation.id,
                credential_schema_repository,
            )
            .await
            .error_while("getting credential schemas")?;
            let credential_schema = match credential_schema {
                None => None,
                Some(schema) => Some(
                    schema_to_detail_response_dto(schema, config)
                        .await
                        .error_while("converting credential schema")?,
                ),
            };
            credential_queries.insert(
                query.id.to_string(),
                failure_hint(
                    &query,
                    CredentialQueryFailureReasonEnum::NoCredential,
                    credential_schema,
                )?,
            );
            // done with this query
            continue;
        }

        let (candidates, invalid_credentials): (Vec<_>, Vec<_>) = filtered_credential_candidates
            .into_iter()
            .partition(|credential| credential.state == CredentialStateEnum::Accepted);
        if candidates.is_empty() {
            let credential_schema = match invalid_credentials
                .into_iter()
                .next()
                .and_then(|cred| cred.schema)
            {
                None => None,
                Some(schema) => Some(
                    schema_to_detail_response_dto(schema, config)
                        .await
                        .error_while("converting credential schema")?,
                ),
            };

            credential_queries.insert(
                query.id.to_string(),
                failure_hint(
                    &query,
                    CredentialQueryFailureReasonEnum::Validity,
                    credential_schema,
                )?,
            );
            // done with this query
            continue;
        }

        // if none of the candidates is applicable, use this schema for the failure hint.
        let failure_hint_schema = candidates.first().and_then(|cred| cred.schema.clone());
        let mut applicable_credentials = vec![];
        for candidate in candidates {
            let format = candidate
                .schema
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(format!(
                    "missing schema for credential {}",
                    candidate.id
                )))?
                .format()
                .await
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
            let formatter = formatter_provider.get_credential_formatter(&format)?;

            let claims = first_matching_claims(&candidate, credential_filters, &*formatter).await?;
            let Some(claims) = claims else {
                continue;
            };
            let remaining_batch_item_count =
                get_remaining_batch_item_count(&candidate, credential_repository)
                    .await
                    .error_while("getting remaining batch items")?;
            let credential_detail_dto = credential_detail_response_from_model(
                candidate,
                config,
                CredentialAttestationBlobs::default(),
                None,
                remaining_batch_item_count,
                credential_repository,
            )
            .await
            .error_while("creating credential detail")?;
            applicable_credentials.push(map_to_filtered_dto(credential_detail_dto, &claims));
        }
        if applicable_credentials.is_empty() {
            credential_queries.insert(
                query.id.to_string(),
                failure_hint(
                    &query,
                    CredentialQueryFailureReasonEnum::Constraint,
                    match failure_hint_schema {
                        None => None,
                        Some(schema) => Some(
                            schema_to_detail_response_dto(schema, config)
                                .await
                                .error_while("converting failure hint schema")?,
                        ),
                    },
                )?,
            );
        } else {
            let purpose = trust_information_provider
                .get_trust_purpose(proof.id.into(), &query.id)
                .await
                .error_while("resolving trust purpose")?;
            credential_queries.insert(
                query.id.to_string(),
                CredentialQueryResponseDTO {
                    multiple: query.multiple,
                    credential_or_failure_hint:
                        ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                            applicable_credentials,
                            purpose: purpose.map(|p| p.purpose),
                        },
                },
            );
        }
    }
    Ok(PresentationDefinitionV2ResponseDTO {
        credential_queries,
        credential_sets,
    })
}

async fn filter_credentials_by_trusted_authorities(
    credentials: &mut Vec<Credential>,
    authorities: &[TrustedAuthority],
) {
    if credentials.is_empty() {
        return;
    }

    let trusted_akis = get_trusted_akis(authorities);
    credentials.retain(|cred| credential_issuer_in_aki_list(cred, trusted_akis.as_slice()));
}

fn credential_issuer_in_aki_list(credential: &Credential, list: &[KeyIdentifier]) -> bool {
    let Some(issuer_cert) = credential.issuer_certificate.as_ref() else {
        return false;
    };

    let Ok(issuer_akis) = pem_chain_to_authority_key_identifiers(&issuer_cert.chain) else {
        return false;
    };

    for issuer_aki in issuer_akis {
        for aki in list {
            if issuer_aki == *aki {
                return true;
            }
        }
    }

    false
}

fn failure_hint(
    query: &CredentialQuery,
    reason: CredentialQueryFailureReasonEnum,
    credential_schema: Option<CredentialSchemaDetailResponseDTO>,
) -> Result<CredentialQueryResponseDTO, VerificationProtocolError> {
    Ok(CredentialQueryResponseDTO {
        multiple: query.multiple,
        credential_or_failure_hint: ApplicableCredentialOrFailureHintEnum::FailureHint {
            failure_hint: Box::new(CredentialQueryFailureHintResponseDTO {
                reason,
                credential_schema,
            }),
        },
    })
}

fn map_to_filtered_dto(
    full_dto: CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>,
    selected_claims: &[SelectedClaim],
) -> CredentialDetailResponseDTO<CredentialDetailClaimExtResponseDTO> {
    let selected_claims_by_path = selected_claims
        .iter()
        .map(|claim| (claim.path.to_owned(), claim))
        .collect::<HashMap<_, _>>();

    CredentialDetailResponseDTO {
        id: full_dto.id,
        created_date: full_dto.created_date,
        issuance_date: full_dto.issuance_date,
        revocation_date: full_dto.revocation_date,
        consumed_at: full_dto.consumed_at,
        state: full_dto.state,
        last_modified: full_dto.last_modified,
        schema: full_dto.schema,
        issuer: full_dto.issuer,
        issuer_certificate: full_dto.issuer_certificate,
        claims: full_dto
            .claims
            .into_iter()
            .filter_map(|claim| to_claim_detail_ext_filtered(claim, &selected_claims_by_path))
            .collect(),
        redirect_uri: full_dto.redirect_uri,
        role: full_dto.role,
        r#type: full_dto.r#type,
        interaction_id: full_dto.interaction_id,
        suspend_end_date: full_dto.suspend_end_date,
        mdoc_mso_validity: full_dto.mdoc_mso_validity,
        holder: full_dto.holder,
        protocol: full_dto.protocol,
        profile: full_dto.profile,
        wallet_instance_attestation: None,
        wallet_unit_attestation: None,
        webhook_destination_url: full_dto.webhook_destination_url,
        trust_information: full_dto.trust_information,
        remaining_batch_item_count: full_dto.remaining_batch_item_count,
        parent_id: full_dto.parent_id,
    }
}

fn to_claim_detail_ext_filtered(
    claim: DetailCredentialClaimResponseDTO,
    all_selected_claims: &HashMap<String, &SelectedClaim>,
) -> Option<CredentialDetailClaimExtResponseDTO> {
    // exit early if not in filter list
    let selected_claim = all_selected_claims.get(&claim.path)?;

    // value mapping
    let value = match claim.value {
        DetailCredentialClaimValueResponseDTO::Boolean(val) => {
            DetailCredentialClaimValueResponseDTO::Boolean(val)
        }
        DetailCredentialClaimValueResponseDTO::Float(val) => {
            DetailCredentialClaimValueResponseDTO::Float(val)
        }
        DetailCredentialClaimValueResponseDTO::Integer(val) => {
            DetailCredentialClaimValueResponseDTO::Integer(val)
        }
        DetailCredentialClaimValueResponseDTO::String(val) => {
            DetailCredentialClaimValueResponseDTO::String(val)
        }
        DetailCredentialClaimValueResponseDTO::Nested(children) => {
            let mapped_children = children
                .into_iter()
                .filter_map(|child| to_claim_detail_ext_filtered(child, all_selected_claims))
                .collect::<Vec<_>>();
            if mapped_children.is_empty() {
                return None;
            }
            DetailCredentialClaimValueResponseDTO::Nested(mapped_children)
        }
    };
    Some(CredentialDetailClaimExtResponseDTO {
        path: claim.path,
        schema: claim.schema,
        value,
        user_selection: selected_claim.user_selection,
        required: !selected_claim.selective_disclosure_supported
            || selected_claim.required_by_verifier,
    })
}

async fn first_matching_claims(
    credential: &Credential,
    filters: &[CredentialFilter],
    formatter: &dyn CredentialFormatter,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    for filter in filters {
        let claims = select_matching_claims(credential, filter, formatter).await?;
        let Some(claims) = claims else {
            continue;
        };
        return Ok(Some(claims));
    }
    Ok(None)
}

fn format_matches(
    dcql_format: &CredentialFormat,
    format: &shared_types::CredentialFormat,
    config: &CoreConfig,
) -> bool {
    let Some(credential_format) = config
        .format
        .get_fields(format)
        .ok()
        .map(|field| field.r#type)
    else {
        return false;
    };
    match dcql_format {
        CredentialFormat::JwtVc => credential_format == FormatType::Jwt,
        CredentialFormat::LdpVc => {
            credential_format == FormatType::JsonLdBbsPlus
                || credential_format == FormatType::JsonLdClassic
        }
        CredentialFormat::MsoMdoc => credential_format == FormatType::Mdoc,
        CredentialFormat::SdJwt => credential_format == FormatType::SdJwtVc,
        CredentialFormat::W3cSdJwt => credential_format == FormatType::SdJwt,
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct SelectedClaim {
    path: String,
    selective_disclosure_supported: bool,
    required_by_verifier: bool,
    user_selection: bool,
    metadata: bool,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum MatchedClaim {
    Selected(SelectedClaim),
    Missing {
        path: ClaimPath,
        format: CredentialFormat,
        metadata: bool,
    },
}

async fn select_matching_claims(
    credential: &Credential,
    filter: &CredentialFilter,
    formatter: &dyn CredentialFormatter,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    let claims = select_claims(credential, filter, formatter, true).await?;
    let mut result = vec![];
    for claim in claims {
        match claim {
            MatchedClaim::Missing { .. } => return Ok(None), // abort as not matching on missing required claim
            MatchedClaim::Selected(selected_claim) => result.push(selected_claim),
        }
    }
    Ok(Some(result))
}

async fn select_claims(
    credential: &Credential,
    filter: &CredentialFilter,
    formatter: &dyn CredentialFormatter,
    select_children: bool,
) -> Result<Vec<MatchedClaim>, VerificationProtocolError> {
    let Some(claims) = &credential.claims else {
        return Err(VerificationProtocolError::Failed(format!(
            "credential {} missing claims",
            credential.id
        )));
    };

    let mut selected = HashMap::new();
    // add all nonselectively disclosable claims defined from root
    {
        let root_nonselectively_disclosable: Vec<_> = claims
            .iter()
            .filter(|claim| !claim.selectively_disclosable)
            .filter(|claim| !claim.path.contains("/"))
            .collect();

        // children of the root nonselectively disclosable that are also not selectively disclosable
        let nonselectively_disclosable_children_of_root = get_nonselectively_disclosable_children(
            claims,
            root_nonselectively_disclosable
                .iter()
                .map(|claim| claim.path.as_str())
                .collect::<Vec<_>>(),
        );

        let nonselectively_disclosable = root_nonselectively_disclosable
            .iter()
            .chain(nonselectively_disclosable_children_of_root.iter());

        selected.extend(
            nonselectively_disclosable
                .map(|claim| {
                    Ok((
                        claim.path.to_owned(),
                        SelectedClaim {
                            path: claim.path.to_owned(),
                            selective_disclosure_supported: claim.selectively_disclosable,
                            required_by_verifier: false,
                            // non-selectively disclosable claims can never be de-selected by the user
                            user_selection: false,
                            metadata: claim
                                .schema
                                .as_ref()
                                .ok_or(VerificationProtocolError::Failed(format!(
                                    "missing claim schema for claim {}",
                                    claim.id
                                )))?
                                .metadata,
                        },
                    ))
                })
                .collect::<Result<Vec<_>, VerificationProtocolError>>()?,
        );
    }

    let mut missing_claims = vec![];

    let credential_claim_schemas = credential
        .schema
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(format!(
            "missing schema for credential {}",
            credential.id
        )))?
        .claim_schemas
        .get()
        .await
        .error_while("getting claim schemas")?;

    let user_claim_path = formatter.user_claims_path();
    // add claims requested by the verifier
    for claim_filter in &filter.claims {
        let matching_claims =
            get_matching_claims(claims, claim_filter, &user_claim_path, select_children)?;
        if !matching_claims.is_empty() {
            matching_claims.into_iter().try_for_each(
                |(ClaimMatchId { exact, .. }, matching_claim)| {
                    // All optional claims that were explicitly requested by the verifier
                    // should have a toggle.
                    let user_selection = exact && !claim_filter.required;
                    if let Some(claim) = selected.get_mut(&matching_claim.path) {
                        claim.required_by_verifier =
                            claim.required_by_verifier || claim_filter.required;
                        claim.user_selection = claim.user_selection || user_selection
                    } else {
                        selected.insert(
                            matching_claim.path.to_owned(),
                            SelectedClaim {
                                path: matching_claim.path.to_owned(),
                                selective_disclosure_supported: matching_claim
                                    .selectively_disclosable,
                                required_by_verifier: claim_filter.required,
                                user_selection,
                                metadata: matching_claim
                                    .schema
                                    .as_ref()
                                    .ok_or(VerificationProtocolError::Failed(format!(
                                        "missing claim schema for claim {}",
                                        matching_claim.id
                                    )))?
                                    .metadata,
                            },
                        );
                    };
                    Ok::<_, VerificationProtocolError>(())
                },
            )?;
        } else if claim_filter.required {
            // no match but claim is required --> add to missing claims (mark the credential as inapplicable)
            missing_claims.push(MatchedClaim::Missing {
                path: claim_filter.path.to_owned(),
                format: filter.format.to_owned(),
                metadata: dcql_path_matches_metadata(
                    &claim_filter.path,
                    &credential_claim_schemas,
                    &formatter.user_claims_path(),
                ),
            });
        }
    }

    let mut result: Vec<MatchedClaim> =
        selected.into_values().map(MatchedClaim::Selected).collect();

    result.extend(missing_claims);

    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ClaimMatchId {
    claim_id: ClaimId,
    // Whether it was an exact match on the DCQL path or matched transitively by other matched claims
    exact: bool,
}

fn get_matching_claims<'a>(
    claims: &'a [Claim],
    claim_filter: &ClaimFilter,
    user_claim_path: &[String],
    select_children: bool,
) -> Result<HashMap<ClaimMatchId, &'a Claim>, VerificationProtocolError> {
    let values_filter = claim_filter
        .values
        .iter()
        .map(stringify_value)
        .collect::<Vec<_>>();

    let exactly_matching_claims: Vec<_> = claims
        .iter()
        // use filter_map to propagate errors of fallible predicate
        .filter_map(|claim| {
            dcql_path_exactly_matches_claim(&claim_filter.path, claim, claims, user_claim_path)
                .map(|matches| {
                    if matches
                        && (values_filter.is_empty()
                            || claim
                                .value
                                .as_ref()
                                .is_some_and(|value| values_filter.contains(value)))
                    {
                        Some(claim)
                    } else {
                        None
                    }
                })
                .transpose()
        })
        .collect::<Result<_, _>>()?;

    if exactly_matching_claims.is_empty() {
        // no matches found, return empty result
        return Ok(HashMap::new());
    }

    let mut child_claims = HashMap::<ClaimId, &Claim>::new();
    if select_children {
        // Presentation definition v2: child claims of exactly matching claims are also selected
        exactly_matching_claims.iter().for_each(|claim| {
            let prefix = format!("{}/", claim.path);
            for claim in claims.iter().filter(|c| c.path.starts_with(&prefix)) {
                child_claims.insert(claim.id, claim);
            }
        });
    }

    // "trunk" nodes on the path from root to the filtered_claims
    // all of these are either arrays or objects
    let mut claims_towards_root = HashMap::<ClaimId, &Claim>::new();
    exactly_matching_claims.iter().try_for_each(|claim| {
        let mut current_path = claim.path.as_str();
        while let Some((parent_path, _)) = current_path.rsplit_once('/') {
            let parent_claim = claims
                .iter()
                .find(|claim| claim.path == parent_path)
                .ok_or(VerificationProtocolError::Failed(format!(
                    "Missing claim with path '{parent_path}' (parent of claim {}).",
                    claim.id
                )))?;
            claims_towards_root.insert(parent_claim.id, parent_claim);
            current_path = parent_path;
        }
        Ok::<_, VerificationProtocolError>(())
    })?;

    // branches of nodes that are not selectively disclosable
    let nonselectively_disclosable_children = get_nonselectively_disclosable_children(
        claims,
        claims_towards_root
            .values()
            .map(|claim| claim.path.as_str()),
    );

    let mut combined_set = HashMap::new();
    combined_set.extend(exactly_matching_claims.into_iter().map(|claim| {
        (
            ClaimMatchId {
                claim_id: claim.id,
                exact: true,
            },
            claim,
        )
    }));
    combined_set.extend(child_claims.into_iter().map(|(claim_id, claim)| {
        (
            ClaimMatchId {
                claim_id,
                exact: false,
            },
            claim,
        )
    }));
    combined_set.extend(claims_towards_root.into_iter().map(|(claim_id, claim)| {
        (
            ClaimMatchId {
                claim_id,
                exact: false,
            },
            claim,
        )
    }));
    combined_set.extend(
        nonselectively_disclosable_children
            .into_iter()
            .map(|claim| {
                (
                    ClaimMatchId {
                        claim_id: claim.id,
                        exact: false,
                    },
                    claim,
                )
            }),
    );
    Ok(combined_set)
}

fn get_nonselectively_disclosable_children<'a, 'b>(
    all_claims: &'a [Claim],
    of_parent_paths: impl IntoIterator<Item = &'b str>,
) -> Vec<&'a Claim> {
    let mut result = vec![];

    let mut parent_paths = VecDeque::from_iter(of_parent_paths);
    while let Some(parent_path) = parent_paths.pop_front() {
        let nonselectively_disclosable_children = all_claims
            .iter()
            .filter(|claim| !claim.selectively_disclosable)
            .filter(|claim| {
                claim
                    .path
                    .rsplit_once("/")
                    .is_some_and(|(prefix, _)| prefix == parent_path)
            });

        for child in nonselectively_disclosable_children {
            parent_paths.push_back(child.path.as_str());
            result.push(child);
        }
    }

    result
}

async fn fetch_credentials_for_schema_ids(
    organisation_id: OrganisationId,
    credential_filters: &[CredentialFilter],
    credential_repository: &dyn CredentialRepository,
) -> Result<Vec<Credential>, VerificationProtocolError> {
    let mut credentials = vec![];

    // The filters only change based on the different claim sets. So to retrieve the
    // credential schema ids, just looking at the first one is sufficient.
    let Some(filter) = credential_filters.first() else {
        return Err(VerificationProtocolError::Failed(
            "empty credential filters".to_string(),
        ));
    };

    for schema_id in &filter.schema_ids {
        let schema_id = map_schema_id(filter, schema_id);

        credentials.append(
            &mut get_presentation_credentials_by_schema_id(
                credential_repository,
                schema_id,
                organisation_id,
            )
            .await
            .error_while("getting presentation credentials for schema")?,
        );
    }
    Ok(credentials)
}

fn map_schema_id(filter: &CredentialFilter, schema_id: &str) -> String {
    match filter.format {
        CredentialFormat::JwtVc | CredentialFormat::LdpVc | CredentialFormat::W3cSdJwt => {
            schema_id
                // Make use of the fact that Procivis One issuers put the schema id into the context,
                // hence we can potentially parse it out of the supplied types.
                // Note: This will most likely fail with third party issuers. Improve the logic,
                // once we need to interop with such issuers.
                .split_once("#")
                .map(|(first, _)| first)
                .unwrap_or(schema_id)
        }
        CredentialFormat::MsoMdoc | CredentialFormat::SdJwt => schema_id,
    }
    .to_string()
}

/// Predicate that checks if the DCQL path matches the claim path exactly, as in
/// it addresses the claim directly (and not a child claim).
fn dcql_path_exactly_matches_claim(
    dcql_path: &ClaimPath,
    claim: &Claim,
    all_claims: &[Claim],
    user_claim_path: &[String],
) -> Result<bool, VerificationProtocolError> {
    let dcql_segments = if !claim
        .schema
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(format!(
            "missing schema for claim '{}'",
            claim.id
        )))?
        .metadata
    {
        adjust_dcql_path_for_user_claims(dcql_path, user_claim_path)?
    } else {
        dcql_path.segments.iter().collect()
    };
    let claim_path_segments = claim.path.split('/').collect::<Vec<_>>();
    if dcql_segments.len() != claim_path_segments.len() {
        // nesting depth mismatch -> no match
        return Ok(false);
    }

    let mut current_path = "".to_string();
    for (dcql_path_segment, claim_path_segment) in
        dcql_segments.into_iter().zip(claim.path.split('/'))
    {
        current_path = if current_path.is_empty() {
            claim_path_segment.to_string()
        } else {
            format!("{current_path}/{claim_path_segment}")
        };
        let schema = all_claims
            .iter()
            .find(|claim| claim.path == current_path)
            .and_then(|claim| claim.schema.as_ref())
            .ok_or(VerificationProtocolError::Failed(format!(
                "missing schema for claim with path '{current_path}'"
            )))?;
        match dcql_path_segment {
            PathSegment::PropertyName(name) => {
                if name != claim_path_segment {
                    // wrong property name -> no match
                    return Ok(false);
                }
            }
            PathSegment::ArrayIndex(index) => {
                if !schema.array {
                    // property is not an array -> no match
                    return Ok(false);
                }
                if index.to_string() != claim_path_segment {
                    // wrong index -> no match
                    return Ok(false);
                }
            }
            PathSegment::ArrayAll => {
                if !schema.array {
                    // property is not an array -> no match
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// Predicate that checks if the DCQL path matches a metadata claim.
fn dcql_path_matches_metadata(
    dcql_path: &ClaimPath,
    claim_schemas: &[ClaimSchema],
    user_claim_path: &[String],
) -> bool {
    let array_selector_count = dcql_path
        .segments
        .iter()
        .filter(|s| !matches!(s, PathSegment::PropertyName(_)))
        .count();
    // No currently supported metadata claim uses nested arrays, so at most one array selector must be in the DCQL path
    if array_selector_count > 1 {
        return false;
    }
    let mut segments = dcql_path.segments.iter().collect::<Vec<_>>();
    if array_selector_count == 1 {
        let Some(segment) = segments.pop() else {
            return false;
        };
        if matches!(segment, PathSegment::PropertyName(_)) {
            // In currently supported metadata paths, this needs to be the (single) array selector,
            // if any.
            return false;
        }
    }
    if user_claim_path.len() >= segments.len()
        && segments
            .iter()
            .zip(user_claim_path)
            .all(|(segment, o)| matches!(segment, PathSegment::PropertyName(name) if name == o))
    {
        // the dcql query also addresses user claims, so it is not considered metadata
        return false;
    }

    let dcql_key = segments
        .into_iter()
        .filter_map(|s| {
            if let PathSegment::PropertyName(s) = s {
                Some(s)
            } else {
                None
            }
        })
        .join("/");
    claim_schemas
        .iter()
        .filter(|cs| cs.metadata)
        .any(|cs| cs.key == dcql_key || cs.key.starts_with(&format!("{dcql_key}/")))
}

fn adjust_dcql_path_for_user_claims<'a>(
    path: &'a ClaimPath,
    user_claim_path: &[String],
) -> Result<Vec<&'a PathSegment>, VerificationProtocolError> {
    let mut segments_iter = path.segments.iter().peekable();
    for user_path_segment in user_claim_path.iter() {
        let Some(PathSegment::PropertyName(name)) = segments_iter.peek() else {
            return Err(VerificationProtocolError::Failed(format!(
                "Unsupported DCQL path: {path} matches user claim path [{}] partially",
                user_claim_path.join(", ")
            )));
        };
        if name == user_path_segment {
            segments_iter.next();
        } else {
            // mismatch, claim path is not reaching into user claims --> return original
            return Ok(path.segments.iter().collect());
        }
    }
    let result = segments_iter.collect::<Vec<_>>();
    if result.is_empty() {
        return Err(VerificationProtocolError::Failed(format!(
            "Unsupported DCQL path: {path} should be more specific than user claim path [{}]",
            user_claim_path.join(", ")
        )));
    }
    Ok(result)
}

fn stringify_value(value: &ClaimValue) -> String {
    match value {
        ClaimValue::String(string) => string.to_string(),
        ClaimValue::Integer(int) => format!("{int}"),
        ClaimValue::Boolean(bool) => format!("{bool}"),
    }
}

impl From<FormatType> for CredentialFormat {
    fn from(value: FormatType) -> Self {
        match value {
            FormatType::Jwt => CredentialFormat::JwtVc,
            FormatType::SdJwt => CredentialFormat::W3cSdJwt,
            FormatType::SdJwtVc => CredentialFormat::SdJwt,
            FormatType::JsonLdClassic => CredentialFormat::LdpVc,
            FormatType::JsonLdBbsPlus => CredentialFormat::LdpVc,
            FormatType::Mdoc => CredentialFormat::MsoMdoc,
        }
    }
}

async fn find_schema_by_schema_ids(
    schema_ids: &[String],
    organisation_id: OrganisationId,
    credential_schema_repository: &dyn CredentialSchemaRepository,
) -> Result<Option<CredentialSchema>, DataLayerError> {
    let schema_ids_filter_cond = schema_ids
        .iter()
        .map(|id| CredentialSchemaFilterValue::SchemaId(StringMatch::equals(id)))
        .fold(ListFilterCondition::default(), |acc, cond| acc | cond);
    let candidates = credential_schema_repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            sorting: None,
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                    & schema_ids_filter_cond,
            ),
            include: Some(vec![
                CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
            ]),
        })
        .await?;
    Ok(candidates.values.into_iter().next())
}
