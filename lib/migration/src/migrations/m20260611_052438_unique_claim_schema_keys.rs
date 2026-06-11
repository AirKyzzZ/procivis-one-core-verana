use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::{Claim, ClaimSchema};
use crate::migrations::m20260429_120000_credential_schema_multiformat::CredentialSchemaFormatClaimSchema;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("index-ClaimSchema-Key-CredentialSchemaId-Unique")
                    .unique()
                    .table(ClaimSchema::Table)
                    .col(ClaimSchema::Key)
                    .col(ClaimSchema::CredentialSchemaId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-ClaimSchema-Order-CredentialSchemaId-Unique")
                    .unique()
                    .table(ClaimSchema::Table)
                    .col(ClaimSchema::Order)
                    .col(ClaimSchema::CredentialSchemaId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-Claim-Path-CredentialId-Unique")
                    .unique()
                    .table(Claim::Table)
                    .col(Claim::Path)
                    .col(Claim::CredentialId)
                    .to_owned(),
            )
            .await?;

        add_nullable_unique_idx(
            CredentialSchemaFormatClaimSchema::Table,
            CredentialSchemaFormatClaimSchema::Namespace,
            "index-FormatClaimSchema-TechKey-FormatId-Namespace-Unique",
            NullableIdxOpts {
                non_nullable_columns: vec![
                    CredentialSchemaFormatClaimSchema::TechnicalKey,
                    CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId,
                ],
                null_value: Some(""),
                materialized_column_size_limit: Some(255),
                ..Default::default()
            },
            manager,
        )
        .await?;

        Ok(())
    }
}
