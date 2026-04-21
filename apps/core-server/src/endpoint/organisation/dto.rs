use one_core::service::error::ServiceError;
use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO, OrganisationFilterParamsDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateOrganisationRequestDTO)]
pub(crate) struct CreateOrganisationRequestRestDTO {
    #[into(with_fn = convert_inner)]
    pub id: Option<OrganisationId>,
    /// Specify a parent organisation. Allows for re-use / inheritance of e.g. trust lists.
    /// The provided organisation must not have a parent organisation.
    #[into(with_fn = convert_inner)]
    pub parent_organisation: Option<OrganisationId>,
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpsertOrganisationRequestRestDTO {
    #[schema(value_type = bool, example = true)]
    pub deactivate: Option<bool>,
    /// Specify which configured wallet provider this organization will use
    /// to issue attestations.
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schema(example = "PROCIVIS_ONE")]
    pub wallet_provider: Option<Option<String>>,
    /// Specify which identifier to use as the attestation issuer. This can
    /// be any type of identifier but it must be backed by an ECDSA key.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
    /// Specify a parent organisation. Allows for re-use / inheritance of e.g. trust lists.
    /// The provided organisation must not have a parent organisation.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub parent_organisation: Option<Option<OrganisationId>>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateOrganisationResponseRestDTO {
    pub id: OrganisationId,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetOrganisationDetailsResponseDTO)]
pub(crate) struct GetOrganisationDetailsResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    #[from(with_fn = convert_inner)]
    pub wallet_provider_issuer: Option<GetIdentifierListItemResponseRestDTO>,
    #[schema(nullable = false)]
    pub parent_organisation: Option<OrganisationId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::organisation::SortableOrganisationColumn")]
pub(crate) enum SortableOrganisationColumnRestDTO {
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = OrganisationFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetOrganisationQuery
pub(crate) struct OrganisationFilterQueryParamsRest {
    /// Return only organisations created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only organisations created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only organisations last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only organisations last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// If true, return only organisations that have a parent organisation.
    /// If false, return only root organisations.
    #[param(inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub has_parent_organisation: Option<Boolean>,
    /// Return only organisations whose parent is one of the given organisation ids.
    #[param(rename = "parentOrganisations[]", nullable = false)]
    #[try_into(infallible)]
    pub parent_organisations: Option<Vec<OrganisationId>>,
}

pub(crate) type GetOrganisationsQuery =
    ListQueryParamsRest<OrganisationFilterQueryParamsRest, SortableOrganisationColumnRestDTO>;

pub(crate) type OrganisationListItemResponseRestDTO = GetOrganisationDetailsResponseRestDTO;
