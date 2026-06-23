use std::collections::HashMap;

use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::{ClaimSchema, CredentialSchema};
use crate::migrations::m20260429_120000_credential_schema_multiformat::{
    CredentialSchemaFormat, CredentialSchemaFormatClaimSchema,
};
use crate::migrations::m20260604_030754_credential_schema_v2::{
    ClaimSchemaEntry, create_claim_mappings_for_mdoc, create_claim_mappings_simple,
    migrate_mdoc_layout_props,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let missing_mappings = find_missing_mappings(manager).await?;
        tracing::debug!("Found {} missing mappings", missing_mappings.len());

        let mut schemas: HashMap<
            String, /* format_id */
            (SchemaFormat, Vec<ClaimSchemaEntry>),
        > = Default::default();
        for missing_mapping in missing_mappings {
            schemas
                .entry(missing_mapping.format_id)
                .or_insert((
                    SchemaFormat {
                        credential_schema_id: missing_mapping.credential_schema_id,
                        format: missing_mapping.format,
                        layout_properties: missing_mapping.layout_properties,
                    },
                    vec![],
                ))
                .1
                .push(ClaimSchemaEntry {
                    id: missing_mapping.claim_schema_id,
                    key: missing_mapping.key,
                    metadata: missing_mapping.metadata,
                });
        }

        tracing::debug!("Affected {} schema-formats", schemas.len());

        for (format_id, (schema, claim_schemas)) in schemas {
            migrate_schema(manager, format_id, schema, claim_schemas).await?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct SchemaFormat {
    credential_schema_id: String,
    format: String,
    layout_properties: Option<String>,
}

#[derive(FromQueryResult, Debug)]
struct SchemaFormatClaim {
    credential_schema_id: String,
    format_id: String,
    claim_schema_id: String,
    format: String,
    key: String,
    metadata: bool,
    layout_properties: Option<String>,
}

async fn find_missing_mappings(
    manager: &SchemaManager<'_>,
) -> Result<Vec<SchemaFormatClaim>, DbErr> {
    SchemaFormatClaim::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .expr_as(
                    Expr::col((CredentialSchema::Table, CredentialSchema::Id)),
                    "credential_schema_id",
                )
                .expr_as(
                    Expr::col((CredentialSchemaFormat::Table, CredentialSchemaFormat::Id)),
                    "format_id",
                )
                .expr_as(
                    Expr::col((ClaimSchema::Table, ClaimSchema::Id)),
                    "claim_schema_id",
                )
                .column((CredentialSchema::Table, CredentialSchema::LayoutProperties))
                .column((
                    CredentialSchemaFormat::Table,
                    CredentialSchemaFormat::Format,
                ))
                .column((ClaimSchema::Table, ClaimSchema::Key))
                .column((ClaimSchema::Table, ClaimSchema::Metadata))
                .from(CredentialSchema::Table)
                .inner_join(
                    CredentialSchemaFormat::Table,
                    Expr::col((CredentialSchema::Table, CredentialSchema::Id)).equals((
                        CredentialSchemaFormat::Table,
                        CredentialSchemaFormat::CredentialSchemaId,
                    )),
                )
                .inner_join(
                    ClaimSchema::Table,
                    Expr::col((CredentialSchema::Table, CredentialSchema::Id))
                        .equals((ClaimSchema::Table, ClaimSchema::CredentialSchemaId)),
                )
                .cond_where(
                    Expr::tuple([
                        Expr::col((CredentialSchemaFormat::Table, CredentialSchemaFormat::Id))
                            .into(),
                        Expr::col((ClaimSchema::Table, ClaimSchema::Id)).into(),
                    ])
                    .not_in_subquery(
                        Query::select()
                            .from(CredentialSchemaFormatClaimSchema::Table)
                            .column(CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId)
                            .column(CredentialSchemaFormatClaimSchema::ClaimSchemaId)
                            .to_owned(),
                    ),
                ),
        ),
    )
    .all(manager.get_connection())
    .await
}

async fn migrate_schema(
    manager: &SchemaManager<'_>,
    format_id: String,
    schema: SchemaFormat,
    claim_schemas: Vec<ClaimSchemaEntry>,
) -> Result<(), DbErr> {
    let is_mdoc = schema.format.starts_with("MDOC");

    // create mappings
    if is_mdoc {
        create_claim_mappings_for_mdoc(manager, claim_schemas, &format_id).await?;
    } else {
        create_claim_mappings_simple(manager, claim_schemas, &format_id).await?;
    }

    if is_mdoc && let Some(layout_properties) = schema.layout_properties {
        migrate_mdoc_layout_props(manager, layout_properties, &schema.credential_schema_id).await?;
    }

    Ok(())
}
