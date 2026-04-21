use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::History;
use crate::m20250607_093448_history_optional_orgid::HistoryNew;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(History::Table)
                    .and_where(
                        Expr::col(HistoryNew::Action)
                            .eq("WRP_AC_RECEIVED")
                            .or(Expr::col(HistoryNew::Action).eq("WRP_RC_RECEIVED")),
                    )
                    .and_where(Expr::col(HistoryNew::Metadata).is_not_null())
                    .to_owned(),
            )
            .await
    }
}
