use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::legacy_migrations::deletion::hard_delete_credential_schemas_and_related;
use crate::m20240110_000001_initial::CredentialSchema;
use crate::m20240305_081435_proof_input_schema::ProofInputSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if backend == DatabaseBackend::Postgres {
            return Ok(());
        }

        hard_delete_credential_schemas_and_related(
            manager,
            Expr::col(CredentialSchema::RevocationMethod).eq("LVVC"),
        )
        .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputSchema::Table)
                    .drop_column(ProofInputSchema::ValidityConstraint)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
