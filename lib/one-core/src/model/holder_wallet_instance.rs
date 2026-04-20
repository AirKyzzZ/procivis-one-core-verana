use shared_types::{HolderWalletInstanceId, WalletInstanceId};
use time::OffsetDateTime;

use crate::model::key::{Key, KeyRelations};
use crate::model::organisation::{Organisation, OrganisationRelations};
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

    // Relations:
    pub organisation: Option<Organisation>,
    pub authentication_key: Option<Key>,
    pub wallet_unit_attestations: Option<Vec<WalletInstanceAttestation>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct HolderWalletInstanceRelations {
    pub wallet_unit_attestations: Option<WalletInstanceAttestationRelations>,
    pub organisation: Option<OrganisationRelations>,
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
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateHolderWalletInstanceRequest {
    pub status: Option<WalletInstanceStatus>,
    pub wallet_unit_attestations: Option<Vec<WalletInstanceAttestation>>,
}
