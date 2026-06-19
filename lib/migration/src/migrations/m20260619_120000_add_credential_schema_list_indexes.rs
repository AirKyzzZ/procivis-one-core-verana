use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::CredentialSchema;
use crate::migrations::m20260429_120000_credential_schema_multiformat::CredentialSchemaFormat;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add CreatedDate to the index too, because it's the default sort order
        manager
            .create_index(
                Index::create()
                    .name("index-CredentialSchema-OrganisationId-DeletedAt-CreatedDate")
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::DeletedAt)
                    .col(CredentialSchema::CreatedDate)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-CredentialSchemaFormat-SchemaId-Format-CredentialSchemaId")
                    .table(CredentialSchemaFormat::Table)
                    .col(CredentialSchemaFormat::SchemaId)
                    .col(CredentialSchemaFormat::Format)
                    .col(CredentialSchemaFormat::CredentialSchemaId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
