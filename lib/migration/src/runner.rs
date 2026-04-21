use sea_orm::{DatabaseBackend, TransactionError, TransactionTrait};
use sea_orm_migration::prelude::*;

use crate::datatype::HasDatabaseBackend;
use crate::{LegacyMigrator, Migrator};

/// Wraps DB migrations into a single transaction
/// to prevent problems with partially applied migrations
///
pub async fn run_migrations<'c, C>(db: C) -> Result<(), DbErr>
where
    C: IntoSchemaManagerConnection<'c> + Clone,
{
    clean_up_legacy_migrations(db.clone()).await?;
    migrations_with_runner::<Migrator>(db.into_schema_manager_connection()).await
}

async fn migrations_with_runner<T: MigratorTrait>(
    connection: SchemaManagerConnection<'_>,
) -> Result<(), DbErr> {
    match connection.get_database_backend() {
        // sea-orm-migrations runs it atomic with Postgres
        DatabaseBackend::Postgres => T::up(connection, None).await,

        // manual wrapping with transaction necessary for the others
        DatabaseBackend::MySql | DatabaseBackend::Sqlite => {
            let result = connection
                .transaction::<_, (), DbErr>(|txn| Box::pin(async move { T::up(txn, None).await }))
                .await;

            match result {
                Ok(_) => Ok(()),
                Err(TransactionError::Connection(e)) => Err(e),
                Err(TransactionError::Transaction(e)) => Err(e),
            }
        }
    }
}

async fn clean_up_legacy_migrations<'c, C>(db: C) -> Result<(), DbErr>
where
    C: IntoSchemaManagerConnection<'c> + Clone,
{
    let connection = db.clone().into_schema_manager_connection();
    LegacyMigrator::install(&connection).await?;
    let migration_models = LegacyMigrator::get_migration_models(&connection).await?;
    let applied_migrations: Vec<&str> = migration_models
        .iter()
        .map(|m| m.version.as_str())
        .collect();
    if !applied_migrations.is_empty() && applied_migrations.contains(&LEGACY_MIGRATION_MARKER) {
        // Legacy case: finish all legacy migrations and then delete the legacy migration table
        migrations_with_runner::<LegacyMigrator>(db.into_schema_manager_connection()).await?;
        let stmt = connection
            .backend()
            .build(Query::delete().from_table(LegacyMigrator::migration_table_name()));
        connection.execute(stmt).await?;
        // Clean slate now, start over with new initial migration
    }
    Ok(())
}

// Name of the old initial migration
static LEGACY_MIGRATION_MARKER: &str = "m20240110_000001_initial";
