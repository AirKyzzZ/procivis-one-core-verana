use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::MySql {
            // Drop the existing index (TEXT columns can't have a regular index)
            manager
                .drop_index(
                    Index::drop()
                        .table(History::Table)
                        .name("index-History-Metadata")
                        .to_owned(),
                )
                .await?;

            // Widen metadata from VARCHAR(255) to TEXT
            manager
                .alter_table(
                    Table::alter()
                        .table(History::Table)
                        .modify_column(ColumnDef::new(History::Metadata).text().null())
                        .to_owned(),
                )
                .await?;

            // Recreate index with 255-char prefix (needed for wallet unit attestation search)
            manager
                .get_connection()
                .execute_unprepared(
                    "CREATE INDEX `index-History-Metadata` ON `history` (`metadata`(255))",
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum History {
    Table,
    Metadata,
}
