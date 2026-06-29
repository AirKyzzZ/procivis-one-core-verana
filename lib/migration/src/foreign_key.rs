use sea_orm::{ConnectionTrait, DbBackend, DbErr};
use sea_orm_migration::SchemaManager;

pub(crate) async fn disable_foreign_key_checks(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    match manager.get_database_backend() {
        DbBackend::MySql => {
            manager
                .get_connection()
                .execute_unprepared("SET FOREIGN_KEY_CHECKS=0;")
                .await?;
        }
        DbBackend::Postgres => {
            // No-op because Postgres doesn't support disabling foreign key constraints globally.
        }
        DbBackend::Sqlite => {
            manager
                .get_connection()
                .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn enable_foreign_key_checks(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    match manager.get_database_backend() {
        DbBackend::MySql => {
            manager
                .get_connection()
                .execute_unprepared("SET FOREIGN_KEY_CHECKS=1;")
                .await?;
        }
        DbBackend::Postgres => {
            // No-op because Postgres doesn't support disabling foreign key constraints globally.
        }
        DbBackend::Sqlite => {
            manager
                .get_connection()
                .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
                .await?;
        }
    }
    Ok(())
}
