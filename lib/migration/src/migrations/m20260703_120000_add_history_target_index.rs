use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_HISTORY_TARGET: &str = "index-History-Target";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_HISTORY_TARGET)
                    .table(History::Table)
                    .col(History::Target)
                    .to_owned(),
            )
            .await
    }
}
