use crate::transaction_context::TransactionManagerImpl;

pub(crate) mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub(crate) struct OrganisationProvider {
    pub db: TransactionManagerImpl,
}
