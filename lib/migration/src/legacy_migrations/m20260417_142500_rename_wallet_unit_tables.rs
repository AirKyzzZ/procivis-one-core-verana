use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .rename_table(
                Table::rename()
                    .table(WalletUnit::Table, WalletInstance::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(WalletUnitAttestedKey::Table)
                    .rename_column(
                        WalletUnitAttestedKey::WalletUnitId,
                        WalletUnitAttestedKey::WalletInstanceId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(
                        WalletUnitAttestation::Table,
                        WalletInstanceAttestation::Table,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(
                        WalletUnitAttestedKey::Table,
                        WalletInstanceAttestedKey::Table,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(HolderWalletUnit::Table, HolderWalletInstance::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum WalletUnit {
    Table,
}
#[derive(DeriveIden)]
enum WalletInstance {
    Table,
}

#[derive(DeriveIden)]
pub(crate) enum WalletUnitAttestation {
    Table,
}
#[derive(DeriveIden)]
pub(crate) enum WalletInstanceAttestation {
    Table,
}

#[derive(DeriveIden)]
enum WalletUnitAttestedKey {
    Table,
    WalletUnitId,
    WalletInstanceId,
}
#[derive(DeriveIden)]
enum WalletInstanceAttestedKey {
    Table,
}

#[derive(DeriveIden)]
pub enum HolderWalletUnit {
    Table,
}
#[derive(DeriveIden)]
pub enum HolderWalletInstance {
    Table,
}
