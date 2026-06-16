use shared_types::{BlobId, IdentifierId, IdentifierTrustInformationId};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct IdentifierTrustInformation {
    pub id: IdentifierTrustInformationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub valid_from: Option<OffsetDateTime>,
    pub valid_to: Option<OffsetDateTime>,
    pub intended_use: Option<String>,
    pub allowed_issuance_types: Vec<SchemaFormat>,
    pub allowed_verification_types: Vec<SchemaFormat>,
    pub identifier_id: IdentifierId,
    pub blob_id: BlobId,
    // No relations
    // * to identifier because it is included the other way around in the identifier model
    // * to blob because it is intended to eventually be made into a provider which would not
    //   necessarily store the blobs in the (same) database
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaFormat {
    pub format: String,
    pub schema_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IdentifierTrustInformationRelations {}
