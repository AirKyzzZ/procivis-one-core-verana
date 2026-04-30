use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct CredentialSchemaFormatProvider {
    pub db: TransactionManagerImpl,
}
