use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::{ClaimSchemaId, CredentialSchemaFormatClaimSchemaId, CredentialSchemaFormatId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize)]
#[sea_orm(table_name = "credential_schema_format_claim_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: CredentialSchemaFormatClaimSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential_schema_format_id: CredentialSchemaFormatId,
    pub claim_schema_id: ClaimSchemaId,
    pub technical_key: String,
    pub namespace: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential_schema_format::Entity",
        from = "Column::CredentialSchemaFormatId",
        to = "super::credential_schema_format::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchemaFormat,
    #[sea_orm(
        belongs_to = "super::claim_schema::Entity",
        from = "Column::ClaimSchemaId",
        to = "super::claim_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ClaimSchema,
}

impl Related<super::credential_schema_format::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchemaFormat.def()
    }
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
