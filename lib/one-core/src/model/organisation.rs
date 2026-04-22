use proc_macros::Model;
use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::list_filter::{ListFilterValue, ValueComparison};
use super::list_query::ListQuery;
use super::relation::Related;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Organisation {
    #[model(id)]
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    pub wallet_provider_issuer: Option<IdentifierId>,
    pub parent_organisation: Option<Related<Organisation>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateOrganisationRequest {
    pub id: OrganisationId,
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
    pub parent_organisation: Option<Option<OrganisationId>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct OrganisationRelations {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableOrganisationColumn {
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrganisationFilterValue {
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    HasParentOrganisation(bool),
    ParentOrganisations(Vec<OrganisationId>),
}

impl ListFilterValue for OrganisationFilterValue {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactOrganisationFilterColumn {}

pub type OrganisationListQuery = ListQuery<SortableOrganisationColumn, OrganisationFilterValue>;

pub type GetOrganisationList = GetListResponse<Organisation>;
