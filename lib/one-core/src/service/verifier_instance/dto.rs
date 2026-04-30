use shared_types::{OrganisationId, TrustCollectionId, VerifierInstanceId};

pub use crate::model::wallet_instance::{
    WalletInstance, WalletInstanceOs, WalletInstanceStatus, WalletProviderType,
};

#[derive(Debug, Clone)]
pub struct RegisterVerifierInstanceRequestDTO {
    pub organisation_id: OrganisationId,
    pub verifier_provider_url: String,
    pub r#type: String,
    pub trusted_issuer_required: bool,
}

#[derive(Debug, Clone)]
pub struct RegisterVerifierInstanceResponseDTO {
    pub id: VerifierInstanceId,
}

#[derive(Debug, Clone)]
pub struct EditVerifierInstanceRequestDTO {
    pub trust_collections: Option<Vec<TrustCollectionId>>,
    pub trusted_issuer_required: Option<bool>,
}
