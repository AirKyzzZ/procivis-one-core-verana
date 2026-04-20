use one_core::model::wallet_instance_attested_key::WalletInstanceAttestedKey;
use one_core::repository::error::DataLayerError;
use sea_orm::{
    ActiveModelBehavior, DeriveEntityModel, DerivePrimaryKey, DeriveRelation, EntityTrait,
    EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait, Set,
};
use shared_types::{RevocationListEntryId, WalletInstanceAttestedKeyId, WalletInstanceId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "wallet_instance_attested_key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: WalletInstanceAttestedKeyId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: String,
    pub wallet_instance_id: WalletInstanceId,
    pub revocation_list_entry_id: Option<RevocationListEntryId>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::wallet_instance::Entity",
        from = "Column::WalletInstanceId",
        to = "super::wallet_instance::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    WalletInstance,
    #[sea_orm(
        belongs_to = "super::revocation_list_entry::Entity",
        from = "Column::RevocationListEntryId",
        to = "super::revocation_list_entry::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    RevocationListEntry,
}

impl Related<super::wallet_instance::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WalletInstance.def()
    }
}

impl Related<super::revocation_list_entry::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationListEntry.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
