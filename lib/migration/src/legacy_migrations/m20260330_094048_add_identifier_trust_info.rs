use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::uuid_char;
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250721_102954_creation_of_blob_storage::BlobStorage;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }
        manager
            .create_table(
                Table::create()
                    .table(IdentifierTrustInformation::Table)
                    .col(uuid_char(IdentifierTrustInformation::Id).primary_key())
                    .col(uuid_char(IdentifierTrustInformation::IdentifierId))
                    .col(uuid_char(IdentifierTrustInformation::BlobId))
                    .col(crate::datatype::timestamp(
                        IdentifierTrustInformation::CreatedDate,
                        manager,
                    ))
                    .col(crate::datatype::timestamp(
                        IdentifierTrustInformation::LastModified,
                        manager,
                    ))
                    .col(crate::datatype::timestamp_null(
                        IdentifierTrustInformation::ValidFrom,
                        manager,
                    ))
                    .col(crate::datatype::timestamp_null(
                        IdentifierTrustInformation::ValidTo,
                        manager,
                    ))
                    .col(string_null(IdentifierTrustInformation::IntendedUse))
                    // Length of 512 to have a bit more room for complex use cases
                    .col(string_len_null(
                        IdentifierTrustInformation::AllowedIssuanceTypes,
                        512,
                    ))
                    .col(string_len_null(
                        IdentifierTrustInformation::AllowedVerificationTypes,
                        512,
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-IdentifierTrustInformation-Identifier")
                            .from_tbl(IdentifierTrustInformation::Table)
                            .from_col(IdentifierTrustInformation::IdentifierId)
                            .to_tbl(Identifier::Table)
                            .to_col(Identifier::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-IdentifierTrustInformation-BlobStorage")
                            .from_tbl(IdentifierTrustInformation::Table)
                            .from_col(IdentifierTrustInformation::BlobId)
                            .to_tbl(BlobStorage::Table)
                            .to_col(BlobStorage::Id),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name("index-IdentifierTrustInformation-IdentifierId-BlobId-Unique")
                    .table(IdentifierTrustInformation::Table)
                    .col(IdentifierTrustInformation::IdentifierId)
                    .col(IdentifierTrustInformation::BlobId)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum IdentifierTrustInformation {
    Table,
    Id,
    IdentifierId,
    BlobId,
    CreatedDate,
    LastModified,
    ValidFrom,
    ValidTo,
    IntendedUse,
    AllowedIssuanceTypes,
    AllowedVerificationTypes,
}
