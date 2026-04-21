use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Certificate::Table)
                    .add_column(ColumnDef::new(Certificate::Roles).string().null())
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::update()
                    .table(Certificate::Table)
                    .value(
                        Certificate::Roles,
                        "AUTHENTICATION,ASSERTION_METHOD".to_string(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(Clone, Iden)]
enum Certificate {
    Table,
    Roles,
}
