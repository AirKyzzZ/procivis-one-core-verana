use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::m20251112_152945_remote_entity_type::RemoteEntityCache;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .exec_stmt(
                Query::update()
                    .table(RemoteEntityCache::Table)
                    .value(
                        RemoteEntityCache::Type,
                        Expr::value("OPENID_METADATA_HOLDER"),
                    )
                    .and_where(Expr::col(RemoteEntityCache::Type).eq(Expr::val("OPENID_METADATA")))
                    .to_owned(),
            )
            .await
    }
}
