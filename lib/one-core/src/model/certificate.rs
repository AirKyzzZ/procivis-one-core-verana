use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, OrganisationId};
use strum::{Display, EnumString};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::key::Key;
use super::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use super::list_query::ListQuery;
use super::organisation::Organisation;
use super::relation::Related;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Certificate {
    pub id: CertificateId,
    pub identifier_id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub expiry_date: OffsetDateTime,
    pub name: String,
    /// PEM chain
    pub chain: String,
    pub fingerprint: String,
    pub state: CertificateState,
    pub roles: Vec<CertificateRole>,

    pub key: Option<Related<Key>>,
    pub organisation: Option<Related<Organisation>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateRole {
    Authentication,
    AssertionMethod,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateState {
    NotYetActive,
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CertificateRelations {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateCertificateRequest {
    pub name: Option<String>,
    pub state: Option<CertificateState>,
}

#[derive(Clone, Debug)]
pub enum SortableCertificateColumn {
    Name,
    CreatedDate,
    ExpiryDate,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateFilterValue {
    Ids(Vec<CertificateId>),
    Name(StringMatch),
    Fingerprint(String),
    State(CertificateState),
    ExpiryDate(ValueComparison<OffsetDateTime>),
    OrganisationId(OrganisationId),
}

impl ListFilterValue for CertificateFilterValue {}

pub type GetCertificateList = GetListResponse<Certificate>;

pub type CertificateListQuery = ListQuery<SortableCertificateColumn, CertificateFilterValue>;
