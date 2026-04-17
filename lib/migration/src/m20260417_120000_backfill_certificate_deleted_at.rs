use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        let db = manager.get_connection();

        let query = match manager.get_database_backend() {
            DatabaseBackend::Sqlite => "UPDATE certificate
                SET deleted_at = (
                    SELECT identifier.deleted_at
                    FROM identifier
                    WHERE identifier.id = certificate.identifier_id
                )
                WHERE certificate.deleted_at IS NULL
                  AND certificate.identifier_id IN (
                    SELECT id FROM identifier WHERE deleted_at IS NOT NULL
                );"
            .to_string(),
            _ => "UPDATE certificate
                JOIN identifier ON certificate.identifier_id = identifier.id
                SET certificate.deleted_at = identifier.deleted_at
                WHERE identifier.deleted_at IS NOT NULL
                  AND certificate.deleted_at IS NULL;"
                .to_string(),
        };

        db.execute_unprepared(&query).await?;

        Ok(())
    }
}
