use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Pre-identifier, `history.target` stored the DID value string directly (e.g. "did:web:…", "did:key:…").
// This was later adapted to store started using `identifier.id` UUIDs, but history entries were not adapted.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE history
                SET target = (
                    SELECT identifier.id
                    FROM identifier
                    JOIN did ON did.id = identifier.did_id
                    WHERE did.did = history.target
                    LIMIT 1
                )
                WHERE entity_type IN ('CREDENTIAL', 'PROOF')
                  AND target LIKE 'did:%';
                "#,
            )
            .await?;

        Ok(())
    }
}
