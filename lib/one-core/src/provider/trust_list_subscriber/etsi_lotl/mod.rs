use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_with::DurationSeconds;
use shared_types::{IdentifierId, TrustListSubscriberId};
use standardized_types::etsi_119_612::ServiceType;
use standardized_types::jwk::PublicJwk;
use url::Url;

use self::model::{PreprocessedLotl, TslServiceEntry};
use crate::error::ContextWithErrorCode;
use crate::mapper::etsi_lotl::role_for_service_type;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::caching_loader::etsi_lotl::EtsiLotlCache;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::{
    Feature, TrustEntityMetadata, TrustEntityResponse, TrustListSubscriber,
    TrustListSubscriberCapabilities, TrustListValidationSuccess,
};

pub(crate) mod model;
mod preprocessing;
pub mod resolver;

#[cfg(test)]
mod test;

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EtsiLotlParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway: time::Duration,
    #[serde(default)]
    pub trust_anchors: Vec<String>,
    #[serde(default)]
    pub delegate_subscribers: Vec<TrustListSubscriberId>,
}

pub struct EtsiLotlSubscriber {
    cache: EtsiLotlCache,
    certificate_validator: Arc<dyn CertificateValidator>,
    /// Subscribers to delegate member lists the LOTL does not resolve itself
    /// Tried in their configured `order`.
    delegates: Vec<Arc<dyn TrustListSubscriber>>,
}

impl EtsiLotlSubscriber {
    pub fn new(
        cache: EtsiLotlCache,
        certificate_validator: Arc<dyn CertificateValidator>,
        delegates: Vec<Arc<dyn TrustListSubscriber>>,
    ) -> Self {
        Self {
            cache,
            certificate_validator,
            delegates,
        }
    }

    async fn get_list(
        &self,
        reference: &Url,
    ) -> Result<PreprocessedLotl, TrustListSubscriberError> {
        let raw = self
            .cache
            .get(reference.as_str())
            .await
            .error_while("getting LoTL from cache")?;
        Ok(serde_json::from_slice(&raw)?)
    }

    /// Resolve a PEM chain to the matching trust-service entries.
    async fn find_matching_for_certificate(
        &self,
        preprocessed_lotl: &PreprocessedLotl,
        pem_chain: &str,
    ) -> Result<Vec<TslServiceEntry>, TrustListSubscriberError> {
        let indices = preprocessed_lotl
            .cert_index
            .match_chain(pem_chain, self.certificate_validator.as_ref())
            .await?;
        indices
            .into_iter()
            .map(|idx| {
                preprocessed_lotl.entries.get(idx).cloned().ok_or_else(|| {
                    TrustListSubscriberError::MappingError(format!(
                        "preprocessed LoTL entry index {idx} out of bounds. Num elements: {}",
                        preprocessed_lotl.entries.len()
                    ))
                })
            })
            .collect()
    }

    /// Resolve a PEM chain to a trust entity: local TSL match first, then a
    /// fallback over the delegate subscribers for any `delegated_member_urls`.
    async fn resolve_pem_chain(
        &self,
        index: &PreprocessedLotl,
        pem_chain: &str,
    ) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError> {
        let local: Vec<TrustEntityResponse> = self
            .find_matching_for_certificate(index, pem_chain)
            .await?
            .into_iter()
            .map(|entry| {
                let derived_role = role_for_service_type(&ServiceType::from(
                    entry.service_type_identifier.clone(),
                ));
                TrustEntityResponse {
                    derived_role,
                    metadata: TrustEntityMetadata::Tsl(entry),
                }
            })
            .collect();
        if !local.is_empty() {
            return Ok(local);
        }
        for member_url in &index.delegated_member_urls {
            let Ok(url) = Url::parse(member_url) else {
                tracing::warn!(url = %member_url, "skipping unparseable delegated member url");
                continue;
            };
            for delegate in &self.delegates {
                match delegate.resolve_certificate(&url, pem_chain).await {
                    Ok(found) if !found.is_empty() => return Ok(found),
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(url = %url, %error, "delegate failed to resolve member list")
                    }
                }
            }
        }
        Ok(Vec::new())
    }
}

#[async_trait::async_trait]
impl TrustListSubscriber for EtsiLotlSubscriber {
    fn get_capabilities(&self) -> TrustListSubscriberCapabilities {
        TrustListSubscriberCapabilities {
            // A LOTL itself carries no single role; the role is derived per
            // resolved entry from its `ServiceTypeIdentifier`.
            // Empty roles signal a roleless subscription, validated post-resolution by the consumer.
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        }
    }

    async fn validate_subscription(
        &self,
        reference: &Url,
        _role: Option<TrustListRoleEnum>,
    ) -> Result<TrustListValidationSuccess, TrustListSubscriberError> {
        self.get_list(reference).await?;
        Ok(TrustListValidationSuccess { role: None })
    }

    async fn resolve_entries(
        &self,
        reference: &Url,
        identifiers: &[Identifier],
    ) -> Result<HashMap<IdentifierId, Vec<TrustEntityResponse>>, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;
        let mut result = HashMap::new();
        for identifier in identifiers {
            let entities = find_matching_for_identifier(self, &list, identifier).await?;
            if !entities.is_empty() {
                result.insert(identifier.id, entities);
            }
        }
        Ok(result)
    }

    async fn resolve_certificate(
        &self,
        reference: &Url,
        pem_chain: &str,
    ) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;
        self.resolve_pem_chain(&list, pem_chain).await
    }

    // TODO: Double check this part,
    // per 5.5.3 "optionally, a public key value expressed as a ds:KeyValue element [4];"
    // Did not see test vectors with this case
    async fn resolve_public_key(
        &self,
        _reference: &Url,
        _public_key: &PublicJwk,
    ) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError> {
        // TS 119 612 digital identities are X.509-based; there is no public-key
        // index to resolve against.
        Ok(Vec::new())
    }
}

async fn find_matching_for_identifier(
    subscriber: &EtsiLotlSubscriber,
    index: &PreprocessedLotl,
    identifier: &Identifier,
) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError> {
    match identifier.r#type {
        r#type @ IdentifierType::Did | r#type @ IdentifierType::Key => {
            Err(TrustListSubscriberError::UnsupportedIdentifierType(r#type))
        }
        IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
            let Some(active_certs) = identifier.active_certs() else {
                return Ok(Vec::new());
            };
            if active_certs.len() > 1 {
                return Err(TrustListSubscriberError::MultipleActiveCertificates(
                    identifier.id,
                ));
            }
            let Some(active_cert) = active_certs.first() else {
                return Ok(Vec::new());
            };

            subscriber
                .resolve_pem_chain(index, &active_cert.chain)
                .await
        }
    }
}
