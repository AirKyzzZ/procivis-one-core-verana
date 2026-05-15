use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::{History, TrustAnchor, TrustEntity};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Prune history rows for the removed entity types — without this,
        // sea-orm's HistoryEntityType deserialization fails on legacy rows.
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(History::Table)
                    .and_where(
                        Expr::col(History::EntityType).is_in(["TRUST_ANCHOR", "TRUST_ENTITY"]),
                    )
                    .to_owned(),
            )
            .await?;

        // Drop child first (FK to trust_anchor), then parent.
        manager
            .drop_table(Table::drop().table(TrustEntity::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(TrustAnchor::Table).to_owned())
            .await?;

        Ok(())
    }
}
