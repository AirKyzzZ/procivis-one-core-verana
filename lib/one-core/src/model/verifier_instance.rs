use shared_types::{OrganisationId, VerifierInstanceId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::organisation::Organisation;
use crate::model::relation::Related;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct VerifierInstance {
    pub id: VerifierInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub provider_type: String,
    pub provider_name: String,
    pub provider_url: String,
    pub trusted_issuer_required: bool,
    pub organisation: Related<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableVerifierInstanceColumn {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifierInstanceFilterValue {
    OrganisationIds(Vec<OrganisationId>),
}

impl ListFilterValue for VerifierInstanceFilterValue {}

pub type VerifierInstanceListQuery =
    ListQuery<SortableVerifierInstanceColumn, VerifierInstanceFilterValue>;

pub type GetVerifierInstanceList = GetListResponse<VerifierInstance>;
