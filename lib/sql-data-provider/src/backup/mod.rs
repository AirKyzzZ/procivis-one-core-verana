use std::sync::Arc;

use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod helpers;
mod mappers;
mod models;
pub mod repository;

pub(crate) struct BackupProvider {
    pub db: TransactionManagerImpl,
    exportable_storages: Vec<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    key_repository: Arc<dyn KeyRepository>,
}

#[cfg(test)]
mod test;
