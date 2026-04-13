use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::list_query::ListQuery;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Organisation {
    pub id: OrganisationId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    pub wallet_provider_issuer: Option<IdentifierId>,
    pub parent_organisation: Option<OrganisationId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateOrganisationRequest {
    pub id: OrganisationId,
    pub name: Option<String>,
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
    pub parent_organisation: Option<Option<OrganisationId>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableOrganisationColumn {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrganisationFilterValue {
    Name(StringMatch),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    HasParentOrganisation(bool),
    ParentOrganisations(Vec<OrganisationId>),
}

impl ListFilterValue for OrganisationFilterValue {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactOrganisationFilterColumn {
    Name,
}

pub type OrganisationListQuery = ListQuery<SortableOrganisationColumn, OrganisationFilterValue>;

pub type GetOrganisationList = GetListResponse<Organisation>;
