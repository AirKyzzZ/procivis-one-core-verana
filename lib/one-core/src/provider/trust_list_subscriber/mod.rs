use std::collections::HashMap;

use error::TrustListSubscriberError;
use serde::Serialize;
use shared_types::IdentifierId;
use standardized_types::etsi_119_602::TrustedEntityInformation;
use standardized_types::jwk::PublicJwk;
use url::Url;

use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;

pub mod error;
pub(crate) mod etsi_lote;
pub mod provider;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListSubscriber: Send + Sync {
    fn get_capabilities(&self) -> TrustListSubscriberCapabilities;

    async fn validate_subscription(
        &self,
        reference: &Url,
        role: Option<TrustListRoleEnum>,
    ) -> Result<TrustListValidationSuccess, TrustListSubscriberError>;

    async fn resolve_entries(
        &self,
        reference: &Url,
        identifiers: &[Identifier],
    ) -> Result<HashMap<IdentifierId, TrustEntityResponse>, TrustListSubscriberError>;

    async fn resolve_certificate(
        &self,
        reference: &Url,
        pem_chain: &str,
    ) -> Result<Option<TrustEntityResponse>, TrustListSubscriberError>;

    async fn resolve_public_key(
        &self,
        reference: &Url,
        public_key: &PublicJwk,
    ) -> Result<Option<TrustEntityResponse>, TrustListSubscriberError>;
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

#[derive(Debug, Clone, PartialEq)]
pub enum TrustEntityResponse {
    LOTE(TrustedEntityInformation),
}
