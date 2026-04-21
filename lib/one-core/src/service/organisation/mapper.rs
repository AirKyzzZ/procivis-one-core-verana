use uuid::Uuid;

use crate::model::identifier::Identifier;
use crate::model::list_filter::{ComparisonType, ListFilterCondition, ValueComparison};
use crate::model::organisation::{Organisation, OrganisationFilterValue};
use crate::service::organisation::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO, OrganisationFilterParamsDTO,
    UpsertOrganisationRequestDTO, WalletInstanceDetailResponseDTO,
};

impl From<CreateOrganisationRequestDTO> for Organisation {
    fn from(request: CreateOrganisationRequestDTO) -> Self {
        let now = crate::clock::now_utc();
        let id = request.id.unwrap_or(Uuid::new_v4().into());
        Organisation {
            id,
            created_date: now,
            last_modified: now,
            deactivated_at: None,
            wallet_provider: None,
            wallet_provider_issuer: None,
            parent_organisation: request.parent_organisation,
        }
    }
}

impl From<UpsertOrganisationRequestDTO> for CreateOrganisationRequestDTO {
    fn from(request: UpsertOrganisationRequestDTO) -> Self {
        CreateOrganisationRequestDTO {
            id: Some(request.id),
            parent_organisation: request.parent_organisation.flatten(),
        }
    }
}

pub(super) fn detail_from_model(
    organisation: Organisation,
    wallet_provider_issuer: Option<Identifier>,
    wallet_instance: Option<WalletInstanceDetailResponseDTO>,
) -> GetOrganisationDetailsResponseDTO {
    GetOrganisationDetailsResponseDTO {
        id: organisation.id,
        created_date: organisation.created_date,
        last_modified: organisation.last_modified,
        deactivated_at: organisation.deactivated_at,
        wallet_provider: organisation.wallet_provider,
        wallet_provider_issuer: wallet_provider_issuer.map(Into::into),
        parent_organisation: organisation.parent_organisation,
        wallet_instance,
    }
}

impl From<OrganisationFilterParamsDTO> for ListFilterCondition<OrganisationFilterValue> {
    fn from(filter: OrganisationFilterParamsDTO) -> Self {
        let created_date_after = filter.created_date_after.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = filter.created_date_before.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = filter.last_modified_after.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = filter.last_modified_before.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let has_parent_organisation = filter
            .has_parent_organisation
            .map(OrganisationFilterValue::HasParentOrganisation);
        let parent_organisations = filter
            .parent_organisations
            .map(OrganisationFilterValue::ParentOrganisations);

        ListFilterCondition::<OrganisationFilterValue>::default()
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
            & has_parent_organisation
            & parent_organisations
    }
}
