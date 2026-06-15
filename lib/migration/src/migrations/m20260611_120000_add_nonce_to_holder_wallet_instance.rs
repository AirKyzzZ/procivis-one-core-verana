use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_null;

use crate::migrations::m20260417_150300_initial::HolderWalletInstance;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstance::Table)
                    .add_column(string_null(HolderWalletInstanceColumn::Nonce))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstance::Table)
                    .add_column(string_null(HolderWalletInstanceColumn::UserNonce))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum HolderWalletInstanceColumn {
    Nonce,
    UserNonce,
}
