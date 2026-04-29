use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, WalletInstanceId};
use standardized_types::jwk::PublicJwk;
use strum::{AsRefStr, Display};
use time::OffsetDateTime;

use super::common::GetListResponse;
use super::list_query::ListQuery;
use crate::config;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::wallet_instance_attested_key::{
    WalletInstanceAttestedKey, WalletInstanceAttestedKeyRelations,
};

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct WalletInstance {
    pub id: WalletInstanceId,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub os: WalletInstanceOs,
    pub status: WalletInstanceStatus,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub authentication_key_jwk: Option<PublicJwk>,
    pub last_issuance: Option<OffsetDateTime>,
    pub nonce: Option<String>,

    // Relations:
    pub organisation: Option<Organisation>,
    pub attested_keys: Option<Vec<WalletInstanceAttestedKey>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum WalletInstanceOs {
    Ios,
    Android,
    Web,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletInstanceStatus {
    Pending,
    Active,
    Revoked,
    Unattested,
    Error,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Display, AsRefStr, Into, From,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(config::core_config::WalletProviderType)]
#[from(config::core_config::WalletProviderType)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum WalletProviderType {
    ProcivisOne,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct WalletInstanceRelations {
    pub organisation: Option<OrganisationRelations>,
    pub attested_keys: Option<WalletInstanceAttestedKeyRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableWalletInstanceColumn {
    CreatedDate,
    LastModified,
    Name,
    Status,
    Os,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletInstanceFilterValue {
    OrganisationId(OrganisationId),
    Name(StringMatch),
    Ids(Vec<WalletInstanceId>),
    Status(Vec<WalletInstanceStatus>),
    WalletProviderType(Vec<String>),
    Os(Vec<WalletInstanceOs>),
    AttestationHash(String),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for WalletInstanceFilterValue {}

pub type WalletInstanceListQuery =
    ListQuery<SortableWalletInstanceColumn, WalletInstanceFilterValue>;

pub type GetWalletInstanceList = GetListResponse<WalletInstance>;

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateWalletInstanceRequest {
    pub status: Option<WalletInstanceStatus>,
    pub last_issuance: Option<OffsetDateTime>,
    pub authentication_key_jwk: Option<PublicJwk>,
    pub attested_keys: Option<Vec<WalletInstanceAttestedKey>>,
}
