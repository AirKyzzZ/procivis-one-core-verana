use one_dto_mapper::Into;
use serde::{Deserialize, Serialize};
use shared_types::{DidMethodId, IdentifierId, KeyId, OrganisationId};
use strum::{AsRefStr, Display};
use time::OffsetDateTime;

use super::certificate::{Certificate, CertificateRelations, CertificateRole, CertificateState};
use super::common::GetListResponse;
use super::did::{Did, DidRelations, KeyRole};
use super::key::{Key, KeyRelations};
use super::list_filter::{ListFilterValue, StringMatch};
use super::list_query::ListQuery;
use super::organisation::{Organisation, OrganisationRelations};
use crate::config;
use crate::model::identifier_trust_information::{
    IdentifierTrustInformation, IdentifierTrustInformationRelations, SchemaFormat,
};
use crate::model::list_filter::ValueComparison;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Identifier {
    pub id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: IdentifierType,
    pub is_remote: bool,
    pub state: IdentifierState,
    pub deleted_at: Option<OffsetDateTime>,

    // Relations:
    pub organisation: Option<Organisation>,
    pub did: Option<Did>,
    pub key: Option<Key>,
    pub certificates: Option<Vec<Certificate>>,
    pub trust_information: Option<Vec<IdentifierTrustInformation>>,
}

impl Identifier {
    pub(crate) fn active_certs(&self) -> Option<Vec<&Certificate>> {
        if self.r#type != IdentifierType::Certificate {
            return Some(vec![]);
        }
        self.certificates.as_ref().map(|certs| {
            certs
                .iter()
                .filter(|cert| cert.state == CertificateState::Active)
                .collect()
        })
    }
}

#[derive(Clone, Debug)]
pub enum SortableIdentifierColumn {
    Name,
    CreatedDate,
    Type,
    State,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactIdentifierFilterColumn {
    Name,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display, AsRefStr, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(config::core_config::IdentifierType)]
pub enum IdentifierType {
    Key,
    Did,
    Certificate,
    #[serde(rename = "CA")]
    CertificateAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentifierState {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct IdentifierRelations {
    pub organisation: Option<OrganisationRelations>,
    pub did: Option<DidRelations>,
    pub key: Option<KeyRelations>,
    pub certificates: Option<CertificateRelations>,
    pub trust_information: Option<IdentifierTrustInformationRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateIdentifierRequest {
    pub name: Option<String>,
    pub state: Option<IdentifierState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierFilterValue {
    Ids(Vec<IdentifierId>),
    Name(StringMatch),
    Types(Vec<IdentifierType>),
    States(Vec<IdentifierState>),
    OrganisationId(OrganisationId),
    DidMethods(Vec<DidMethodId>),
    IsRemote(bool),
    KeyAlgorithms(Vec<String>),
    KeyRoles(Vec<KeyRole>),
    KeyStorages(Vec<String>),
    KeyIds(Vec<KeyId>),
    CertificateRole(CertificateRole),
    TrustAllowedIssuanceTypes(SchemaFormat),
    TrustAllowedVerificationTypes(SchemaFormat),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for IdentifierFilterValue {}

pub type GetIdentifierList = GetListResponse<Identifier>;

pub type IdentifierListQuery = ListQuery<SortableIdentifierColumn, IdentifierFilterValue>;
