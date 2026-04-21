use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_INDEX_NAME: &str = "index-Certificate-Fingerprint-OrganisationId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Certificate::Table)
                    .add_column(
                        ColumnDef::new(Certificate::DeletedAt)
                            .datetime_millisecond_precision(manager)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_INDEX_NAME)
                    .table(Certificate::Table)
                    .to_owned(),
            )
            .await?;

        add_nullable_unique_idx(
            Certificate::Table,
            Certificate::DeletedAt,
            UNIQUE_INDEX_NAME,
            NullableIdxOpts {
                non_nullable_columns: vec![Certificate::Fingerprint, Certificate::OrganisationId],
                ..Default::default()
            },
            manager,
        )
        .await
    }
}

#[derive(DeriveIden)]
pub enum Certificate {
    Table,
    DeletedAt,
    Fingerprint,
    OrganisationId,
}
