use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::RemoteEntityCache;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(RemoteEntityCache::Table)
                    .and_where(Expr::col(RemoteEntityCache::Type).eq("TRUST_LIST"))
                    .to_owned(),
            )
            .await
    }
}
