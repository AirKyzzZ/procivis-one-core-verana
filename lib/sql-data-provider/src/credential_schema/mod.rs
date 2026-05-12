use std::sync::Arc;

use one_core::repository::localized_text_repository::LocalizedTextRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

pub(crate) struct CredentialSchemaProvider {
    pub db: TransactionManagerImpl,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub localized_text_repository: Arc<dyn LocalizedTextRepository>,
}

#[cfg(test)]
mod test;
