use shared_types::{HolderWalletInstanceId, WalletInstanceId};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::key::{Key, KeyRelations};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::model::wallet_instance::{WalletInstanceStatus, WalletProviderType};
use crate::model::wallet_instance_attestation::{
    WalletInstanceAttestation, WalletInstanceAttestationRelations,
};

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct HolderWalletInstance {
    pub id: HolderWalletInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub wallet_provider_url: String,
    pub provider_wallet_unit_id: WalletInstanceId,
    pub status: WalletInstanceStatus,
    pub trusted_rp_required: bool,

    // Relations:
    pub organisation: Related<Organisation>,
    pub authentication_key: Option<Key>,
    pub wallet_unit_attestations: Option<Vec<WalletInstanceAttestation>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct HolderWalletInstanceRelations {
    pub wallet_unit_attestations: Option<WalletInstanceAttestationRelations>,
    pub authentication_key: Option<KeyRelations>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct CreateHolderWalletInstanceRequest {
    pub id: HolderWalletInstanceId,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub wallet_provider_url: String,
    pub provider_wallet_unit_id: WalletInstanceId,
    pub status: WalletInstanceStatus,
    pub organisation: Organisation,
    pub authentication_key: Option<Key>,
    pub trusted_rp_required: bool,
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateHolderWalletInstanceRequest {
    pub status: Option<WalletInstanceStatus>,
    pub wallet_unit_attestations: Option<Vec<WalletInstanceAttestation>>,
    pub trusted_rp_required: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableHolderWalletInstanceColumn {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HolderWalletInstanceFilterValue {
    Status(WalletInstanceStatus),
}

impl ListFilterValue for HolderWalletInstanceFilterValue {}

pub type HolderWalletInstanceListQuery =
    ListQuery<SortableHolderWalletInstanceColumn, HolderWalletInstanceFilterValue>;

pub type GetHolderWalletInstanceList = GetListResponse<HolderWalletInstance>;
