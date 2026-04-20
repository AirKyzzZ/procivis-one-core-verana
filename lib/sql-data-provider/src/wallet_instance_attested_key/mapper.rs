use one_core::model::wallet_instance_attested_key::{
    WalletInstanceAttestedKey, WalletInstanceAttestedKeyUpsertRequest,
};
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::wallet_instance_attested_key::{ActiveModel, Model};

impl TryFrom<Model> for WalletInstanceAttestedKey {
    type Error = DataLayerError;

    fn try_from(value: Model) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: value.id,
            wallet_instance_id: value.wallet_instance_id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiration_date: value.expiration_date,
            public_key_jwk: serde_json::from_str(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?,
            revocation: None,
        })
    }
}

impl TryFrom<WalletInstanceAttestedKey> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: WalletInstanceAttestedKey) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            expiration_date: Set(value.expiration_date),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            wallet_instance_id: Set(value.wallet_instance_id),
            revocation_list_entry_id: Set(None),
        })
    }
}

impl TryFrom<WalletInstanceAttestedKeyUpsertRequest> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: WalletInstanceAttestedKeyUpsertRequest) -> Result<Self, DataLayerError> {
        let now = one_core::clock::now_utc();
        Ok(Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            expiration_date: Set(value.expiration_date),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            wallet_instance_id: Set(value.wallet_instance_id),
            revocation_list_entry_id: Set(None),
        })
    }
}
