use sea_orm::{FromQueryResult, IntoSimpleExpr};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, text};

use crate::datatype::{timestamp, uuid_char};
use crate::migrations::m20260417_150300_initial::{ClaimSchema, CredentialSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(LocalizedText::Table)
                    .col(uuid_char(LocalizedText::EntityId))
                    .col(string(LocalizedText::Field))
                    .col(string(LocalizedText::Lang))
                    .primary_key(
                        Index::create()
                            .name("pk-LocalizedText")
                            .col(LocalizedText::EntityId)
                            .col(LocalizedText::Field)
                            .col(LocalizedText::Lang)
                            .primary(),
                    )
                    .col(timestamp(LocalizedText::CreatedDate, manager))
                    .col(timestamp(LocalizedText::LastModified, manager))
                    .col(text(LocalizedText::Value))
                    .col(string(LocalizedText::EntityType))
                    .to_owned(),
            )
            .await?;

        tracing::debug!("Adding translations to credential schemas");
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(LocalizedText::Table)
                    .columns([
                        LocalizedText::EntityId,
                        LocalizedText::Field,
                        LocalizedText::Lang,
                        LocalizedText::Value,
                        LocalizedText::EntityType,
                        LocalizedText::CreatedDate,
                        LocalizedText::LastModified,
                    ])
                    .select_from(
                        Query::select()
                            .from(CredentialSchema::Table)
                            .expr_as(Expr::col(CredentialSchema::Id), "entity_id")
                            .expr_as(Expr::val("NAME"), "field")
                            .expr_as(Expr::val("en"), "lang")
                            .expr_as(Expr::col(CredentialSchema::Name), "value")
                            .expr_as(Expr::val("CREDENTIAL_SCHEMA"), "entity_type")
                            .expr_as(Expr::current_timestamp(), "created_date")
                            .expr_as(Expr::current_timestamp(), "last_modified")
                            .to_owned(),
                    )
                    .map_err(|e| DbErr::Migration(e.to_string()))?
                    .to_owned(),
            )
            .await?;

        tracing::debug!("Adding translations to claim schemas");
        migrate_claim_schemas(manager).await?;
        Ok(())
    }
}

#[derive(FromQueryResult, Eq, PartialEq, Hash)]
struct ClaimSchemaIdKey {
    id: String,
    key: String,
}

const BATCH_SIZE: u64 = 10_000;
async fn migrate_claim_schemas(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let current_time_expr = Expr::current_timestamp();
    let mut page = 0;
    let db = manager.get_connection();
    let backend = manager.get_database_backend();
    loop {
        tracing::debug!("Adding translations to claim schemas, batch {page}");
        let claim_schemas = ClaimSchemaIdKey::find_by_statement(
            backend.build(
                Query::select()
                    .columns([ClaimSchema::Id, ClaimSchema::Key])
                    .from(ClaimSchema::Table)
                    .order_by(ClaimSchema::CreatedDate, Order::Asc)
                    .offset(page * BATCH_SIZE)
                    .limit(BATCH_SIZE),
            ),
        )
        .all(db)
        .await?;

        if claim_schemas.is_empty() {
            // done
            break;
        }

        let mut query = Query::insert()
            .into_table(LocalizedText::Table)
            .columns([
                LocalizedText::EntityId,
                LocalizedText::Field,
                LocalizedText::Lang,
                LocalizedText::Value,
                LocalizedText::EntityType,
                LocalizedText::CreatedDate,
                LocalizedText::LastModified,
            ])
            .to_owned();

        for claim_schema in claim_schemas {
            let exprs = [
                Expr::val(claim_schema.id),
                Expr::val("NAME"),
                Expr::val("en"),
                Expr::val(
                    claim_schema
                        .key
                        .rsplit_once("/")
                        .map(|(_, end)| end)
                        .unwrap_or(claim_schema.key.as_str()),
                ),
                Expr::val("CLAIM_SCHEMA"),
                current_time_expr.clone(),
                current_time_expr.clone(),
            ];
            query
                .values(exprs.into_iter().map(IntoSimpleExpr::into_simple_expr))
                .map_err(|e| DbErr::Migration(e.to_string()))?;
        }
        manager.exec_stmt(query).await?;

        page += 1;
    }
    Ok(())
}

#[derive(DeriveIden)]
enum LocalizedText {
    Table,
    CreatedDate,
    LastModified,
    Lang,
    Value,
    EntityId,
    EntityType,
    Field,
}
