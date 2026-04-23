use one_core::service::error::ServiceError;
use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO, OrganisationFilterParamsDTO,
    WalletInstanceDetailResponseDTO,
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
    /// Optionally assign a parent organization to share policy-level
    /// configuration, such as trust collections, across a one-level hierarchy.
    /// The provided organization must not have a parent organization.
    #[into(with_fn = convert_inner)]
    pub parent_organisation: Option<OrganisationId>,
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpsertOrganisationRequestRestDTO {
    #[schema(value_type = bool, example = true)]
    pub deactivate: Option<bool>,
    /// Specify which configured `walletProvider` this organization will use
    /// to issue attestations to wallet units.
    #[serde(default, with = "::serde_with::rust::double_option")]
    #[schema(example = "PROCIVIS_ONE")]
    pub wallet_provider: Option<Option<String>>,
    /// Specify which identifier to use as the attestation issuer. This can
    /// be any type of identifier but it must be backed by an ECDSA key.
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
    /// Optionally assign a parent organization to share policy-level
    /// configuration, such as trust collections, across a one-level hierarchy.
    /// The provided organization must not have a parent organization.
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
    /// Wallet Provider configuration used by this organization to provide
    /// wallets.
    pub wallet_provider: Option<String>,
    /// Identifier used by this organization to provide wallets.
    #[from(with_fn = convert_inner)]
    pub wallet_provider_issuer: Option<GetIdentifierListItemResponseRestDTO>,
    /// The parent organization this organization inherits policy-level
    /// configuration from, if any.
    #[schema(nullable = false)]
    pub parent_organisation: Option<OrganisationId>,
    /// Wallet registration details for this organization's Business
    /// Wallet.
    #[schema(nullable = false)]
    #[from(with_fn = convert_inner)]
    pub wallet_instance: Option<WalletInstanceResponseRestDTO>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(WalletInstanceDetailResponseDTO)]
pub(crate) struct WalletInstanceResponseRestDTO {
    pub wallet_provider_url: String,
    pub wallet_provider_name: String,
    pub authentication_key_type: String,
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
    /// Return only organizations created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only organizations created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only organizations last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only organizations last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// If true, return only organizations that have a parent organization.
    /// If false, return only root organizations.
    #[param(inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub has_parent_organisation: Option<Boolean>,
    /// Return only organizations that are children of the given
    /// organization IDs.
    #[param(rename = "parentOrganisations[]", nullable = false)]
    #[try_into(infallible)]
    pub parent_organisations: Option<Vec<OrganisationId>>,
}

pub(crate) type GetOrganisationsQuery =
    ListQueryParamsRest<OrganisationFilterQueryParamsRest, SortableOrganisationColumnRestDTO>;

pub(crate) type OrganisationListItemResponseRestDTO = GetOrganisationDetailsResponseRestDTO;
