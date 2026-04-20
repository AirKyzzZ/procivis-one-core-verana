use serde::Serialize;
use shared_types::{HolderWalletInstanceId, OrganisationId, TrustCollectionId, WalletInstanceId};
use time::OffsetDateTime;

pub use crate::model::wallet_instance::{
    WalletInstance, WalletInstanceOs, WalletInstanceStatus, WalletProviderType,
};
use crate::service::key::dto::KeyListItemResponseDTO;
use crate::service::wallet_provider::dto::ProviderTrustCollectionDTO;

#[derive(Debug, Clone)]
pub struct HolderRegisterWalletUnitRequestDTO {
    pub organisation_id: OrganisationId,
    pub key_type: String,
    pub wallet_provider: WalletProviderDTO,
}

#[derive(Debug, Clone)]
pub struct WalletProviderDTO {
    pub r#type: WalletProviderType,
    pub url: String,
}

#[derive(Serialize)]
pub(super) struct NoncePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderWalletUnitResponseDTO {
    pub id: HolderWalletInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub provider_wallet_unit_id: WalletInstanceId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub status: WalletInstanceStatus,
    pub authentication_key: Option<KeyListItemResponseDTO>,
}

#[derive(Debug, Clone)]
pub struct HolderWalletUnitRegisterResponseDTO {
    pub id: HolderWalletInstanceId,
    pub status: WalletInstanceStatus,
}

#[derive(Debug, Clone)]
pub struct EditHolderWalletUnitRequestDTO {
    pub trust_collections: Vec<TrustCollectionId>,
}

#[derive(Debug, Clone)]
pub struct TrustCollectionsDetailResponseDTO {
    pub trust_collections: Vec<TrustCollectionInfoDTO>,
}

#[derive(Debug, Clone)]
pub struct TrustCollectionInfoDTO {
    pub selected: bool,
    pub collection: ProviderTrustCollectionDTO,
}
