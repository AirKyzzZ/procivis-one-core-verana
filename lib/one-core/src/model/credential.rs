use proc_macros::Model;
use shared_types::{
    BlobId, CertificateId, CredentialId, CredentialSchemaId, IdentifierId, InteractionId, KeyId,
    OrganisationId,
};
use strum::{Display, EnumString};
use time::OffsetDateTime;

use super::claim::{Claim, ClaimRelations};
use super::common::GetListResponse;
use super::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use super::identifier::{Identifier, IdentifierRelations};
use super::interaction::{Interaction, InteractionRelations};
use super::key::Key;
use super::list_query::ListQuery;
use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::key::KeyRelations;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Credential {
    #[model(id)]
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: Option<OffsetDateTime>,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub consumed_at: Option<OffsetDateTime>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    pub r#type: CredentialType,
    pub state: CredentialStateEnum,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub credential_blob_id: Option<BlobId>,
    pub wallet_unit_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,
    pub webhook_url: Option<String>,

    // Relations:
    pub claims: Option<Vec<Claim>>,
    pub issuer_identifier: Option<Identifier>,
    pub issuer_certificate: Option<Certificate>,
    pub holder_identifier: Option<Identifier>,
    pub schema: Option<CredentialSchema>,
    pub interaction: Option<Interaction>,
    pub key: Option<Key>,
    pub parent: Option<Related<Credential>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialRelations {
    pub claims: Option<ClaimRelations>,
    pub issuer_identifier: Option<IdentifierRelations>,
    pub issuer_certificate: Option<CertificateRelations>,
    pub holder_identifier: Option<IdentifierRelations>,
    pub schema: Option<CredentialSchemaRelations>,
    pub interaction: Option<InteractionRelations>,
    pub key: Option<KeyRelations>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display)]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
    InteractionExpired,
}

#[derive(Clone, Debug)]
pub enum SortableCredentialColumn {
    CreatedDate,
    SchemaName,
    Issuer,
    State,
}

pub type GetCredentialList = GetListResponse<Credential>;
pub type CredentialListQuery =
    ListQuery<SortableCredentialColumn, CredentialFilterValue, CredentialListIncludeEntityTypeEnum>;

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateCredentialRequest {
    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_certificate_id: Option<CertificateId>,
    pub issuance_date: Option<OffsetDateTime>,
    pub holder_identifier_id: Option<IdentifierId>,
    pub interaction: Option<InteractionId>,
    pub key: Option<KeyId>,
    pub redirect_uri: Option<Option<String>>,
    pub state: Option<CredentialStateEnum>,
    pub suspend_end_date: Clearable<Option<OffsetDateTime>>,
    pub consumed_at: Clearable<Option<OffsetDateTime>>,
    pub wallet_unit_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,

    pub claims: Option<Vec<Claim>>,
    pub credential_blob_id: Option<BlobId>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Display)]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Display)]
pub enum CredentialType {
    Single,
    BatchParent,
    BatchItem,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub enum Clearable<T> {
    ForceSet(T),
    #[default]
    DontTouch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialFilterValue {
    ClaimName(StringMatch),
    ClaimValue(StringMatch),
    CredentialSchemaName(StringMatch),
    OrganisationId(OrganisationId),
    Roles(Vec<CredentialRole>),
    CredentialIds(Vec<CredentialId>),
    ParentCredential(CredentialId),
    Consumed(bool),
    CredentialSchemaIds(Vec<CredentialSchemaId>),
    SchemaId(String),
    IssuerIds(Vec<IdentifierId>),
    States(Vec<CredentialStateEnum>),
    Types(Vec<CredentialType>),
    SuspendEndDate(ValueComparison<OffsetDateTime>),
    Profiles(Vec<String>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    IssuanceDate(ValueComparison<OffsetDateTime>),
    RevocationDate(ValueComparison<OffsetDateTime>),
    HasUnconsumedBatchItems(bool),
}

impl ListFilterValue for CredentialFilterValue {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactCredentialFilterColumn {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "camelCase")]
pub enum CredentialListIncludeEntityTypeEnum {
    LayoutProperties,
    Translations,
}
