use one_core::model::key::KeyRelations;
use one_core::model::organisation::OrganisationRelations;
use one_core::model::wallet_instance::{
    WalletInstance, WalletInstanceStatus as ModelWalletInstanceStatus,
};
use one_core::model::wallet_instance_attestation::WalletInstanceAttestation;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{
    HolderWalletInstanceId, KeyId, OrganisationId, WalletInstanceAttestationId, WalletInstanceId,
};
use time::OffsetDateTime;

use crate::entity::wallet_instance::{WalletInstanceStatus, WalletProviderType};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "wallet_instance_attestation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: WalletInstanceAttestationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    #[sea_orm(column_type = "Blob")]
    pub attestation: Vec<u8>,
    pub revocation_list_url: Option<String>,
    pub revocation_list_index: Option<i64>,
    pub holder_wallet_unit_id: HolderWalletInstanceId,
    pub attested_key_id: KeyId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::holder_wallet_instance::Entity",
        from = "Column::HolderWalletUnitId",
        to = "super::holder_wallet_instance::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    HolderWalletInstance,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::AttestedKeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    AttestedKey,
}

impl ActiveModelBehavior for ActiveModel {}
