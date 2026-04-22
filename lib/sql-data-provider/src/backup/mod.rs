use std::sync::Arc;

use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod helpers;
mod mappers;
mod models;
pub mod repository;

pub(crate) struct BackupProvider {
    pub db: TransactionManagerImpl,
    exportable_storages: Vec<String>,
    organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;
