use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::text_null;

use crate::migrations::m20260417_150300_initial::{Credential, CredentialSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(text_null(Col::EmbeddedDisclosurePolicy))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(text_null(Col::EmbeddedDisclosurePolicy))
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Col {
    EmbeddedDisclosurePolicy,
}
