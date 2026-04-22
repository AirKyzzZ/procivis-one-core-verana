use std::str::FromStr;

use sea_orm::entity::prelude::*;
use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "organisation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: OrganisationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    pub wallet_provider_issuer: Option<IdentifierId>,
    pub parent_organisation: Option<OrganisationId>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential_schema::Entity")]
    CredentialSchema,
    #[sea_orm(has_many = "super::did::Entity")]
    Did,
    #[sea_orm(has_many = "super::proof_schema::Entity")]
    ProofSchema,
    #[sea_orm(has_many = "super::interaction::Entity")]
    Interaction,
    #[sea_orm(has_many = "super::wallet_instance::Entity")]
    WalletUnit,
    #[sea_orm(
        belongs_to = "Entity",
        from = "Column::Id",
        to = "Column::ParentOrganisation",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ChildOrganisation,
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl Related<super::did::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Did.def()
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchema.def()
    }
}

impl Related<super::interaction::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Interaction.def()
    }
}

impl Related<super::wallet_instance::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WalletUnit.def()
    }
}

impl Related<Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ChildOrganisation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
