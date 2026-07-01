use std::collections::HashMap;

use error::TrustListSubscriberError;
use serde::Serialize;
use shared_types::IdentifierId;
use standardized_types::etsi_119_602::TrustedEntityInformation;
use standardized_types::jwk::PublicJwk;
use url::Url;

use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;

pub(crate) mod cert_index;
pub mod error;
pub(crate) mod etsi_lote;
pub(crate) mod etsi_lotl;
pub mod provider;

pub use etsi_lotl::model::TslServiceEntry;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListSubscriber: Send + Sync {
    fn get_capabilities(&self) -> TrustListSubscriberCapabilities;

    async fn validate_subscription(
        &self,
        reference: &Url,
        role: Option<TrustListRoleEnum>,
    ) -> Result<TrustListValidationSuccess, TrustListSubscriberError>;

    /// All trust entries each identifier resolves to; identifiers with no match
    /// are omitted.
    async fn resolve_entries(
        &self,
        reference: &Url,
        identifiers: &[Identifier],
    ) -> Result<HashMap<IdentifierId, Vec<TrustEntityResponse>>, TrustListSubscriberError>;

    /// All trust entries a certificate chain resolves to (empty if none).
    async fn resolve_certificate(
        &self,
        reference: &Url,
        pem_chain: &str,
    ) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError>;

    /// All trust entries a public key resolves to (empty if none).
    async fn resolve_public_key(
        &self,
        reference: &Url,
        public_key: &PublicJwk,
    ) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError>;
}

#[derive(Debug, Serialize)]
pub struct TrustListSubscriberCapabilities {
    pub roles: Vec<TrustListRoleEnum>,
    pub resolvable_identifier_types: Vec<IdentifierType>,
    pub features: Vec<Feature>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Feature {
    SupportsLocalIdentifiers,
    SupportsRemoteIdentifiers,
}

#[derive(Debug, Clone)]
pub struct TrustListValidationSuccess {
    pub role: Option<TrustListRoleEnum>,
}

/// Standard-agnostic result of resolving an identifier. `derived_role` is the
/// per-entity role (`None` → the subscription's own role applies); `metadata` is
/// the standard-specific payload, surfaced for display only.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustEntityResponse {
    pub derived_role: Option<TrustListRoleEnum>,
    pub metadata: TrustEntityMetadata,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrustEntityMetadata {
    Lote(TrustedEntityInformation),
    Tsl(etsi_lotl::model::TslServiceEntry),
}
