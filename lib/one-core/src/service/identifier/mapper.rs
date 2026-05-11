use dcql::CredentialMeta;
use one_dto_mapper::{convert_inner, try_convert_inner};
use shared_types::{CredentialSchemaId, OrganisationId, ProofSchemaId};

use super::dto::{
    CertificateRolesMatchMode, CreateIdentifierDidRequestDTO, GetIdentifierListItemResponseDTO,
    GetIdentifierListResponseDTO, GetIdentifierResponseDTO, IdentifierFilterParamsDTO,
    IdentifierTrustInformationResponseDTO, IdentifierTrustInformationType,
    ResolvedTrustEntrySourceResponseDTO,
};
use super::error::IdentifierServiceError;
use crate::config::core_config::{BlobStorageType, CoreConfig};
use crate::error::ContextWithErrorCode;
use crate::model::blob::BlobType;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::identifier::{
    ExactIdentifierFilterColumn, GetIdentifierList, Identifier, IdentifierFilterValue,
    IdentifierListQuery, IdentifierType, SortableIdentifierColumn,
};
use crate::model::identifier_trust_information::{IdentifierTrustInformation, SchemaFormat};
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::model::proof_schema::{ProofInputSchemaRelations, ProofSchemaRelations};
use crate::model::trust_list_subscription::TrustListSubscription;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::signer::registration_certificate::model::Credential;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::service::certificate::mapper::certificate_to_response_dto;
use crate::service::common_dto::ListQueryDTO;
use crate::service::did::dto::CreateDidRequestDTO;
use crate::service::did::mapper::response_from_did;

pub(super) async fn identifier_to_response_dto(
    value: Identifier,
    blob_storage_provider: &dyn BlobStorageProvider,
) -> Result<GetIdentifierResponseDTO, IdentifierServiceError> {
    let organisation_id = value.organisation.map(|org| org.id);

    let mut certificates = None;
    let mut certificate_authorities = None;
    match value.r#type {
        IdentifierType::Did => {
            if value.did.is_none() {
                return Err(IdentifierServiceError::MappingError(
                    "DID is required for identifier type Did".to_string(),
                ));
            }
        }
        IdentifierType::Key => {
            if value.key.is_none() {
                return Err(IdentifierServiceError::MappingError(
                    "Key is required for identifier type Key".to_string(),
                ));
            }
        }
        IdentifierType::Certificate => {
            let mut certs = vec![];
            for certificate in value
                .certificates
                .ok_or(IdentifierServiceError::MappingError(format!(
                    "Certificates required for identifier type {}",
                    value.r#type
                )))?
            {
                certs.push(
                    certificate_to_response_dto(certificate)
                        .await
                        .error_while("converting certificate")?,
                );
            }
            certificates = Some(certs);
        }
        IdentifierType::CertificateAuthority => {
            let mut certs = vec![];
            for certificate in value
                .certificates
                .ok_or(IdentifierServiceError::MappingError(format!(
                    "Certificates required for identifier type {}",
                    value.r#type
                )))?
            {
                certs.push(
                    certificate_to_response_dto(certificate)
                        .await
                        .error_while("converting certificate")?,
                );
            }
            certificate_authorities = Some(certs);
        }
    }
    let trust_information = value
        .trust_information
        .ok_or(IdentifierServiceError::MappingError(
            "missing trust information".to_string(),
        ))?;
    let trust_information = map_trust_information(blob_storage_provider, trust_information).await?;

    let did = match value.did {
        Some(did) => Some(response_from_did(did).await.error_while("converting did")?),
        None => None,
    };
    Ok(GetIdentifierResponseDTO {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        organisation_id,
        r#type: value.r#type,
        is_remote: value.is_remote,
        state: value.state,
        did,
        key: value
            .key
            .map(TryInto::try_into)
            .transpose()
            .error_while("converting key")?,
        certificates,
        certificate_authorities,
        trust_information,
    })
}

async fn map_trust_information(
    blob_storage_provider: &dyn BlobStorageProvider,
    trust_information: Vec<IdentifierTrustInformation>,
) -> Result<Vec<IdentifierTrustInformationResponseDTO>, IdentifierServiceError> {
    let blob_storage = blob_storage_provider
        .get_blob_storage(BlobStorageType::Db)
        .error_while("getting blob storage")?;
    let mut trust_info_dtos = vec![];
    for entry in trust_information {
        let blob = blob_storage
            .get(&entry.blob_id)
            .await
            .error_while("retrieving blob")?
            .ok_or(IdentifierServiceError::MissingTrustInformationBlob(
                entry.blob_id,
            ))?;
        trust_info_dtos.push(IdentifierTrustInformationResponseDTO {
            data: std::str::from_utf8(&blob.value)
                .map_err(|e| IdentifierServiceError::MappingError(e.to_string()))?
                .to_string(),
            r#type: blob.r#type.try_into()?,
            valid_from: entry.valid_from,
            valid_to: entry.valid_to,
        })
    }
    Ok(trust_info_dtos)
}

impl TryFrom<BlobType> for IdentifierTrustInformationType {
    type Error = IdentifierServiceError;
    fn try_from(value: BlobType) -> Result<Self, Self::Error> {
        match value {
            BlobType::RegistrationCertificate => {
                Ok(IdentifierTrustInformationType::RegistrationCertificate)
            }
            t => Err(IdentifierServiceError::MappingError(format!(
                "invalid trust information blob type `{t:?}`"
            ))),
        }
    }
}

impl From<IdentifierTrustInformationType> for BlobType {
    fn from(value: IdentifierTrustInformationType) -> Self {
        match value {
            IdentifierTrustInformationType::RegistrationCertificate => {
                BlobType::RegistrationCertificate
            }
        }
    }
}

impl From<Identifier> for GetIdentifierListItemResponseDTO {
    fn from(value: Identifier) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            r#type: value.r#type,
            is_remote: value.is_remote,
            state: value.state,
            organisation_id: value.organisation.map(|org| org.id),
        }
    }
}

impl From<GetIdentifierList> for GetIdentifierListResponseDTO {
    fn from(value: GetIdentifierList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub(super) fn to_create_did_request(
    identifier_name: &str,
    request: CreateIdentifierDidRequestDTO,
    organisation_id: OrganisationId,
) -> CreateDidRequestDTO {
    CreateDidRequestDTO {
        name: request.name.unwrap_or(identifier_name.to_string()),
        organisation_id,
        did_method: request.method,
        keys: request.keys,
        params: request.params,
    }
}

impl TryFrom<TrustListSubscription> for ResolvedTrustEntrySourceResponseDTO {
    type Error = IdentifierServiceError;

    fn try_from(value: TrustListSubscription) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            role: value.role,
            reference: value.reference,
            r#type: value.r#type,
            state: value.state,
            trust_collection: value.trust_collection.map(Into::into).ok_or(
                IdentifierServiceError::MappingError("missing trust collection".to_string()),
            )?,
        })
    }
}

pub(super) async fn params_to_query(
    filter_params: ListQueryDTO<SortableIdentifierColumn, IdentifierFilterParamsDTO>,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    proof_schema_repository: &dyn ProofSchemaRepository,
    config: &CoreConfig,
) -> Result<IdentifierListQuery, IdentifierServiceError> {
    let condition = params_to_condition(
        filter_params.filter,
        credential_schema_repository,
        proof_schema_repository,
        config,
    )
    .await?;
    Ok(ListQuery {
        pagination: Some(ListPagination {
            page: filter_params.page,
            page_size: filter_params.page_size,
        }),
        sorting: filter_params.sort.map(|column| ListSorting {
            column,
            direction: filter_params.sort_direction,
        }),
        filtering: Some(condition),
        include: filter_params.include,
    })
}

pub(super) async fn params_to_condition(
    value: IdentifierFilterParamsDTO,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    proof_schema_repository: &dyn ProofSchemaRepository,
    config: &CoreConfig,
) -> Result<ListFilterCondition<IdentifierFilterValue>, IdentifierServiceError> {
    let exact = value.exact.unwrap_or_default();
    let get_string_match_type = |column| {
        if exact.contains(&column) {
            StringMatchType::Equals
        } else {
            StringMatchType::StartsWith
        }
    };

    let organisation_id = IdentifierFilterValue::OrganisationId(value.organisation_id).condition();

    let name = value.name.map(|name| {
        IdentifierFilterValue::Name(StringMatch {
            r#match: get_string_match_type(ExactIdentifierFilterColumn::Name),
            value: name,
        })
    });

    let ids = value.ids.map(IdentifierFilterValue::Ids);
    let types = value
        .types
        .map(|types| IdentifierFilterValue::Types(convert_inner(types)));
    let state = value
        .states
        .map(|states| IdentifierFilterValue::States(convert_inner(states)));
    let did_methods = value.did_methods.map(IdentifierFilterValue::DidMethods);
    let is_remote = value.is_remote.map(IdentifierFilterValue::IsRemote);
    let key_algorithms = value
        .key_algorithms
        .map(IdentifierFilterValue::KeyAlgorithms);
    let key_roles = value
        .key_roles
        .map(|key_roles| IdentifierFilterValue::KeyRoles(convert_inner(key_roles)));
    let key_storages = value.key_storages.map(IdentifierFilterValue::KeyStorages);

    let certificate_roles = value.certificate_roles.and_then(|roles| {
        let filter_values: Vec<_> = roles
            .into_iter()
            .map(|role| IdentifierFilterValue::CertificateRole(role).condition())
            .collect();
        let reduce_fn = match value.certificate_roles_match_mode {
            CertificateRolesMatchMode::All => |a, b| a & b,
            CertificateRolesMatchMode::Any => |a, b| a | b,
        };
        filter_values.into_iter().reduce(reduce_fn)
    });

    let created_date_after = value.created_date_after.map(|date| {
        IdentifierFilterValue::CreatedDate(ValueComparison {
            comparison: ComparisonType::GreaterThanOrEqual,
            value: date,
        })
    });
    let created_date_before = value.created_date_before.map(|date| {
        IdentifierFilterValue::CreatedDate(ValueComparison {
            comparison: ComparisonType::LessThanOrEqual,
            value: date,
        })
    });

    let last_modified_after = value.last_modified_after.map(|date| {
        IdentifierFilterValue::LastModified(ValueComparison {
            comparison: ComparisonType::GreaterThanOrEqual,
            value: date,
        })
    });
    let last_modified_before = value.last_modified_before.map(|date| {
        IdentifierFilterValue::LastModified(ValueComparison {
            comparison: ComparisonType::LessThanOrEqual,
            value: date,
        })
    });

    let trust_issuance_types = if let Some(credential_schema_id) = value.trust_issuance_schema_id {
        let filter_value =
            credential_schema_filter(&credential_schema_id, credential_schema_repository, config)
                .await?;
        Some(filter_value)
    } else {
        None
    };

    let trust_verification_types = if let Some(proof_schema_id) = value.trust_verification_schema_id
    {
        let filter_condition =
            proof_schema_filter(&proof_schema_id, proof_schema_repository, config).await?;
        Some(filter_condition)
    } else {
        None
    };

    Ok(organisation_id
        & name
        & ids
        & types
        & state
        & did_methods
        & is_remote
        & key_algorithms
        & key_roles
        & key_storages
        & certificate_roles
        & trust_issuance_types
        & trust_verification_types
        & created_date_after
        & created_date_before
        & last_modified_after
        & last_modified_before)
}

async fn credential_schema_filter(
    credential_schema_id: &CredentialSchemaId,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    config: &CoreConfig,
) -> Result<IdentifierFilterValue, IdentifierServiceError> {
    let schema = credential_schema_repository
        .get_credential_schema(credential_schema_id)
        .await
        .error_while("retrieving credential schema")?
        .ok_or(IdentifierServiceError::CredentialSchemaNotFound(
            *credential_schema_id,
        ))?;
    let filter_value =
        filter_value_from_credential_schema(config, schema, TrustContext::Issuance).await?;
    Ok(filter_value)
}

async fn proof_schema_filter(
    proof_schema_id: &ProofSchemaId,
    proof_schema_repository: &dyn ProofSchemaRepository,
    config: &CoreConfig,
) -> Result<ListFilterCondition<IdentifierFilterValue>, IdentifierServiceError> {
    let schema = proof_schema_repository
        .get_proof_schema(
            proof_schema_id,
            &ProofSchemaRelations {
                organisation: None,
                proof_inputs: Some(ProofInputSchemaRelations {
                    credential_schema: Some(CredentialSchemaRelations::default()),
                    ..Default::default()
                }),
            },
        )
        .await
        .error_while("retrieving proof schema")?
        .ok_or(IdentifierServiceError::ProofSchemaNotFound(
            *proof_schema_id,
        ))?;
    let mut trust_verification_types = ListFilterCondition::<IdentifierFilterValue>::default();
    for input_schema in schema
        .input_schemas
        .ok_or(IdentifierServiceError::MappingError(
            "missing input schemas".to_string(),
        ))?
    {
        let credential_schema =
            input_schema
                .credential_schema
                .ok_or(IdentifierServiceError::MappingError(
                    "missing credential schema".to_string(),
                ))?;
        let filter_value = filter_value_from_credential_schema(
            config,
            credential_schema,
            TrustContext::Verification,
        )
        .await?;
        trust_verification_types = trust_verification_types & filter_value;
    }
    Ok(trust_verification_types)
}

enum TrustContext {
    Issuance,
    Verification,
}

async fn filter_value_from_credential_schema(
    config: &CoreConfig,
    schema: CredentialSchema,
    context: TrustContext,
) -> Result<IdentifierFilterValue, IdentifierServiceError> {
    let schema_format = schema.format().await?;
    let format_type = config
        .format
        .get_type(&schema_format)
        .error_while("retrieving credential schema format")?;
    let schema_id = schema.schema_id().await?;
    let schema_format = SchemaFormat {
        format: format_type.into(),
        schema_id,
    };
    let filter_value = match context {
        TrustContext::Issuance => IdentifierFilterValue::TrustAllowedIssuanceTypes(schema_format),
        TrustContext::Verification => {
            IdentifierFilterValue::TrustAllowedVerificationTypes(schema_format)
        }
    };
    Ok(filter_value)
}

pub(super) fn map_dcql_credentials(
    credentials: Vec<Credential>,
) -> Result<Vec<SchemaFormat>, IdentifierServiceError> {
    let schema_formats: Vec<Vec<SchemaFormat>> = try_convert_inner(credentials)?;
    Ok(schema_formats.into_iter().flatten().collect())
}

impl TryFrom<Credential> for Vec<SchemaFormat> {
    type Error = IdentifierServiceError;

    fn try_from(value: Credential) -> Result<Self, Self::Error> {
        let schema_ids = match value.meta {
            CredentialMeta::MsoMdoc { doctype_value } => vec![doctype_value],
            CredentialMeta::SdJwtVc { vct_values } => vct_values,
            CredentialMeta::W3cVc { .. } => {
                return Err(IdentifierServiceError::InvalidTrustInformation(
                    "W3C credentials are not supported in trust information".to_string(),
                ));
            }
        };
        Ok(schema_ids
            .into_iter()
            .map(|c| SchemaFormat {
                format: value.format,
                schema_id: c,
            })
            .collect())
    }
}
