use serde::Serialize;
use shared_types::{HolderWalletInstanceId, OrganisationId, TrustCollectionId, WalletInstanceId};
use time::OffsetDateTime;

pub use crate::model::wallet_instance::{
    WalletInstance, WalletInstanceOs, WalletInstanceStatus, WalletProviderType,
};
use crate::service::key::dto::KeyListItemResponseDTO;
use crate::service::wallet_provider::dto::ProviderTrustCollectionDTO;

#[derive(Debug, Clone)]
pub struct HolderRegisterWalletInstanceRequestDTO {
    pub organisation_id: OrganisationId,
    pub key_type: String,
    pub wallet_provider: WalletProviderDTO,
    pub trusted_rp_required: bool,
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
pub struct HolderWalletInstanceResponseDTO {
    pub id: HolderWalletInstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub provider_wallet_unit_id: WalletInstanceId,
    pub wallet_provider_url: String,
    pub wallet_provider_type: WalletProviderType,
    pub wallet_provider_name: String,
    pub status: WalletInstanceStatus,
    pub authentication_key: Option<KeyListItemResponseDTO>,
    pub trusted_rp_required: bool,
    pub user_nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderWalletInstanceRegisterResponseDTO {
    pub id: HolderWalletInstanceId,
    pub status: WalletInstanceStatus,
    pub user_nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderActivateWalletInstanceRequestDTO {
    pub key_type: String,
    pub user_id_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EditHolderWalletInstanceRequestDTO {
    pub trust_collections: Option<Vec<TrustCollectionId>>,
    pub trusted_rp_required: Option<bool>,
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
