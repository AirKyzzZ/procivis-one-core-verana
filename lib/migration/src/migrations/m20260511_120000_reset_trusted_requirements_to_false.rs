use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::{
    HolderWalletInstance as HolderWalletInstanceInitial,
    VerifierInstance as VerifierInstanceInitial,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(HolderWalletInstanceInitial::Table)
                    .values([(HolderWalletInstance::TrustedRpRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(VerifierInstanceInitial::Table)
                    .values([(VerifierInstance::TrustedIssuerRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum HolderWalletInstance {
    TrustedRpRequired,
}

#[derive(DeriveIden)]
enum VerifierInstance {
    TrustedIssuerRequired,
}
