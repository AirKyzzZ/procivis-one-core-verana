use proc_macros::Model;
use shared_types::{ClaimSchemaId, CredentialSchemaFormatClaimSchemaId, CredentialSchemaFormatId};
use time::OffsetDateTime;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct CredentialSchemaFormatClaimSchema {
    #[model(id)]
    pub id: CredentialSchemaFormatClaimSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential_schema_format_id: CredentialSchemaFormatId,
    pub claim_schema_id: ClaimSchemaId,
    pub technical_key: String,
    pub namespace: Option<String>,
}
