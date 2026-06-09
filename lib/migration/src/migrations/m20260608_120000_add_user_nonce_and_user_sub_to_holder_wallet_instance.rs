use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_null;

use crate::migrations::m20260417_150300_initial::HolderWalletInstance as HolderWalletInstanceInitial;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .add_column(string_null(HolderWalletInstance::UserNonce))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .add_column(string_null(HolderWalletInstance::UserSub))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum HolderWalletInstance {
    UserNonce,
    UserSub,
}
