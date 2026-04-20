use one_core::model::wallet_instance::SortableWalletInstanceColumn;
use one_core::service::error::ServiceError;
use one_core::service::wallet_provider::dto;
use one_core::service::wallet_provider::dto::WalletUnitFilterParamsDTO;
use one_core::service::wallet_unit::dto::{
    WalletInstanceOs, WalletInstanceStatus, WalletProviderType,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, convert_inner_of_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, WalletInstanceId};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::{front_time, front_time_option};

pub(crate) type ListWalletInstancesQuery =
    ListQueryParamsRest<WalletInstanceFilterQueryParamsRestDTO, SortableWalletInstanceColumnRest>;

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::GetWalletUnitListResponseDTO)]
pub(crate) struct GetWalletInstancesResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = convert_inner)]
    pub values: Vec<WalletInstanceResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::GetWalletUnitResponseDTO)]
pub(crate) struct WalletInstanceResponseRestDTO {
    pub id: WalletInstanceId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: WalletInstanceOsRestEnum,
    pub status: WalletInstanceStatusRestEnum,
    pub wallet_provider_type: WalletProviderTypeRestEnum,
    pub wallet_provider_name: String,
    #[from(with_fn = convert_inner)]
    pub authentication_key_jwk: Option<PublicJwk>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[from(WalletInstanceOs)]
#[into(WalletInstanceOs)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletInstanceOsRestEnum {
    Ios,
    Android,
    Web,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[from(WalletInstanceStatus)]
#[into(WalletInstanceStatus)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletInstanceStatusRestEnum {
    Active,
    Revoked,
    Pending,
    Unattested,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[from(WalletProviderType)]
#[into(WalletProviderType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletProviderTypeRestEnum {
    ProcivisOne,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = WalletUnitFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside ListWalletUnitsQuery
pub(crate) struct WalletInstanceFilterQueryParamsRestDTO {
    /// Return only wallet units with a name starting with this string.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Filter by specific wallet unit UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<WalletInstanceId>>,
    /// Return only wallet units with the specified status.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "status[]", inline, nullable = false)]
    pub status: Option<Vec<WalletInstanceStatusRestEnum>>,
    /// Return only wallet units with the specified operating systems.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "os[]", inline, nullable = false)]
    pub os: Option<Vec<WalletInstanceOsRestEnum>>,
    /// Return only wallet units with the specified wallet provider types.
    #[param(rename = "walletProviderType[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub wallet_provider_type: Option<Vec<String>>,
    /// Return only the wallet unit with the specified attestation.
    #[param(rename = "attestation", inline, nullable = false)]
    #[try_into(infallible)]
    pub attestation: Option<String>,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only wallet units created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only wallet units created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(SortableWalletInstanceColumn)]
#[into(SortableWalletInstanceColumn)]
pub(crate) enum SortableWalletInstanceColumnRest {
    CreatedDate,
    LastModified,
    Name,
    Status,
    Os,
}
