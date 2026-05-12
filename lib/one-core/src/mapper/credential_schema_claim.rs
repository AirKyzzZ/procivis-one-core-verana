use shared_types::ClaimSchemaId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::claim_schema::ClaimSchema;
use crate::provider::credential_formatter::MetadataClaimSchema;
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
};

pub(crate) fn claim_schema_from_metadata_claim_schema(
    metadata_claim: MetadataClaimSchema,
    now: OffsetDateTime,
) -> ClaimSchema {
    ClaimSchema {
        id: Uuid::new_v4().into(),
        key: metadata_claim.key,
        business_key: None,
        data_type: metadata_claim.data_type,
        created_date: now,
        last_modified: now,
        array: metadata_claim.array,
        required: metadata_claim.required,
        metadata: true,
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
    }
}

impl From<ClaimSchema> for CredentialClaimSchemaDTO {
    fn from(value: ClaimSchema) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.data_type,
            required: value.required,
            array: value.array,
            claims: vec![],
        }
    }
}
