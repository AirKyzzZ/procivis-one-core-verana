use one_core::model::holder_wallet_instance::{
    CreateHolderWalletInstanceRequest, HolderWalletInstance,
};
use one_core::model::wallet_instance::{WalletInstanceStatus, WalletProviderType};
use sea_orm::Set;

use crate::entity::holder_wallet_instance::{ActiveModel, Model};

impl From<Model> for HolderWalletInstance {
    fn from(value: Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            wallet_provider_type: WalletProviderType::from(value.wallet_provider_type),
            wallet_provider_name: value.wallet_provider_name,
            wallet_provider_url: value.wallet_provider_url,
            provider_wallet_unit_id: value.provider_wallet_unit_id,
            status: WalletInstanceStatus::from(value.status),
            organisation: None,
            authentication_key: None,
            wallet_unit_attestations: None,
        }
    }
}

impl From<CreateHolderWalletInstanceRequest> for ActiveModel {
    fn from(value: CreateHolderWalletInstanceRequest) -> Self {
        let now = one_core::clock::now_utc();
        Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            status: Set(value.status.into()),
            wallet_provider_name: Set(value.wallet_provider_name),
            wallet_provider_type: Set(value.wallet_provider_type.into()),
            wallet_provider_url: Set(value.wallet_provider_url),
            provider_wallet_unit_id: Set(value.provider_wallet_unit_id),
            organisation_id: Set(value.organisation.id),
            authentication_key_id: Set(value.authentication_key.map(|key| key.id)),
        }
    }
}
