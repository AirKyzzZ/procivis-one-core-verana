use one_dto_mapper::Into;
use shared_types::{HolderWalletInstanceId, IdentifierId, OrganisationId, VerifierInstanceId};
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
    pub parent_organisation: Option<OrganisationId>,
    pub wallet_instance: Option<HolderWalletInstanceDetailResponseDTO>,
    pub verifier_instance: Option<VerifierInstanceDetailResponseDTO>,
    pub wallet_provider: Option<WalletProviderDetailResponseDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetOrganisationListItemResponseDTO {
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub parent_organisation: Option<OrganisationId>,
    pub wallet_provider: Option<WalletProviderDetailResponseDTO>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderWalletInstanceDetailResponseDTO {
    pub id: HolderWalletInstanceId,
    pub trusted_rp_required: bool,
    pub wallet_provider_url: String,
    pub wallet_provider_name: String,
    pub authentication_key_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierInstanceDetailResponseDTO {
    pub id: VerifierInstanceId,
    pub trusted_issuer_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletProviderDetailResponseDTO {
    pub provider_name: Option<String>,
    pub issuer: Option<GetIdentifierListItemResponseDTO>,
}

pub type GetOrganisationListResponseDTO = GetListResponse<GetOrganisationListItemResponseDTO>;

#[derive(Clone, Debug, Default)]
pub struct OrganisationFilterParamsDTO {
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub has_parent_organisation: Option<bool>,
    pub parent_organisations: Option<Vec<OrganisationId>>,
}
