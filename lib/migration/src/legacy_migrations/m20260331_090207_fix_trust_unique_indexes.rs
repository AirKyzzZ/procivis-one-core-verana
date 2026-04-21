use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20260302_170000_trust_list_publication::TrustListPublication;
use crate::m20260302_170100_trust_entry::TrustEntry;
use crate::m20260316_143109_trust_collection_subscription::{
    TrustCollection, TrustListSubscription, UNIQUE_TRUST_COLLECTION_NAME_DEACTIVATED_AT_INDEX,
    UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_DEACTIVATED_AT_INDEX,
    UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_DEACTIVATED_AT_INDEX,
};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_TRUST_COLLECTION_NAME_ORG_DEACTIVATED_AT_INDEX: &str =
    "index-TrustCol-Name-Org-DeactivatedAt-Unique";
const UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT_INDEX: &str =
    "index-TrustListSubscription-Name-Col-DeactivatedAt-Unique";
const UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT_INDEX: &str =
    "index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique";
const UNIQUE_TRUST_PUBLICATION_NAME_ORG_DEACTIVATED_AT_INDEX: &str =
    "index-TrustPublication-Name-Org-DeactivatedAt-Unique";
const UNIQUE_TRUST_ENTRY_IDENTIFIER_PUBLICATION_INDEX: &str =
    "index-TrustEntry-IdentifierId-Publication-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        // Delete all trust entries and publications, because uniqueness is already violated
        manager
            .exec_stmt(Query::delete().from_table(TrustEntry::Table).to_owned())
            .await?;
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(TrustListPublication::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_TRUST_COLLECTION_NAME_DEACTIVATED_AT_INDEX)
                    .table(TrustCollection::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_DEACTIVATED_AT_INDEX)
                    .table(TrustListSubscription::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_DEACTIVATED_AT_INDEX)
                    .table(TrustListSubscription::Table)
                    .to_owned(),
            )
            .await?;

        add_nullable_unique_idx(
            TrustCollection::Table,
            TrustCollection::DeactivatedAt,
            UNIQUE_TRUST_COLLECTION_NAME_ORG_DEACTIVATED_AT_INDEX,
            NullableIdxOpts {
                non_nullable_columns: vec![TrustCollection::Name, TrustCollection::OrganisationId],
                ..Default::default()
            },
            manager,
        )
        .await?;
        add_nullable_unique_idx(
            TrustListSubscription::Table,
            TrustListSubscription::DeactivatedAt,
            UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT_INDEX,
            NullableIdxOpts {
                non_nullable_columns: vec![
                    TrustListSubscription::Name,
                    TrustListSubscription::TrustCollectionId,
                ],
                ..Default::default()
            },
            manager,
        )
        .await?;
        add_nullable_unique_idx(
            TrustListSubscription::Table,
            TrustListSubscription::DeactivatedAt,
            UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT_INDEX,
            NullableIdxOpts {
                non_nullable_columns: vec![
                    TrustListSubscription::Reference,
                    TrustListSubscription::TrustCollectionId,
                ],
                ..Default::default()
            },
            manager,
        )
        .await?;
        add_nullable_unique_idx(
            TrustListPublication::Table,
            TrustListPublication::DeactivatedAt,
            UNIQUE_TRUST_PUBLICATION_NAME_ORG_DEACTIVATED_AT_INDEX,
            NullableIdxOpts {
                non_nullable_columns: vec![
                    TrustListPublication::Name,
                    TrustListPublication::OrganisationId,
                ],
                ..Default::default()
            },
            manager,
        )
        .await?;
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(UNIQUE_TRUST_ENTRY_IDENTIFIER_PUBLICATION_INDEX)
                    .table(TrustEntry::Table)
                    .col(TrustEntry::IdentifierId)
                    .col(TrustEntry::TrustListPublicationId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
