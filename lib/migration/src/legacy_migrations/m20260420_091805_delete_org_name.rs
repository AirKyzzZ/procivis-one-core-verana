use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::m20250317_133346_add_org_name::Organisation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }
        manager
            .drop_index(
                Index::drop()
                    .table(Organisation::Table)
                    .name("index-Organisation-Name-Unique")
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Organisation::Table)
                    .drop_column(Organisation::Name)
                    .to_owned(),
            )
            .await
    }
}
