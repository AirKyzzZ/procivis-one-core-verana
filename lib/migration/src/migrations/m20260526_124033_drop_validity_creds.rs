use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::ValidityCredential;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ValidityCredential::Table).to_owned())
            .await
    }
}
