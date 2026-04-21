use one_dto_mapper::Into;
use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::organisation::UpdateOrganisationRequest;
use crate::service::identifier::dto::GetIdentifierListItemResponseDTO;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateOrganisationRequestDTO {
    pub id: Option<OrganisationId>,
    pub parent_organisation: Option<OrganisationId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Into)]
#[into(UpdateOrganisationRequest)]
pub struct UpsertOrganisationRequestDTO {
    pub id: OrganisationId,
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<String>>,
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
    pub parent_organisation: Option<Option<OrganisationId>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOrganisationDetailsResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    pub wallet_provider_issuer: Option<GetIdentifierListItemResponseDTO>,
    pub parent_organisation: Option<OrganisationId>,
}

pub type OrganisationListItemResponseDTO = GetOrganisationDetailsResponseDTO;
pub type GetOrganisationListResponseDTO = GetListResponse<OrganisationListItemResponseDTO>;

#[derive(Clone, Debug, Default)]
pub struct OrganisationFilterParamsDTO {
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub has_parent_organisation: Option<bool>,
    pub parent_organisations: Option<Vec<OrganisationId>>,
}
