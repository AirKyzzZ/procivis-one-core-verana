use std::collections::HashMap;
use std::sync::Arc;

use model::{LoteEntity, PreprocessedLote};
use preprocessing::jwk_to_der_b64;
use serde::Deserialize;
use serde_with::DurationSeconds;
use shared_types::IdentifierId;
use standardized_types::jwk::PublicJwk;
use strum::Display;
use url::Url;

use crate::error::ContextWithErrorCode;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::CertificateValidator;
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::{
    Feature, TrustEntityMetadata, TrustEntityResponse, TrustListSubscriber,
    TrustListSubscriberCapabilities, TrustListValidationSuccess,
};

mod model;
mod preprocessing;
pub mod resolver;

#[cfg(test)]
mod test;

#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EtsiLoteParams {
    pub accepts: LoteContentType,
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway: time::Duration,
    /// Max depth to follow through chained `PointersToOtherLoTE`.
    #[serde(default = "default_max_pointer_depth")]
    pub max_pointer_depth: Option<usize>,
}

fn default_max_pointer_depth() -> Option<usize> {
    Some(5)
}

#[derive(Clone, Debug, Display, Deserialize)]
pub enum LoteContentType {
    #[strum(to_string = "application/xml")]
    #[serde(rename = "application/xml")]
    Xml,
    #[strum(to_string = "application/jwt")]
    #[serde(rename = "application/jwt")]
    Jwt,
}

pub struct EtsiLoteSubscriber {
    cache: EtsiLoteCache,
    certificate_validator: Arc<dyn CertificateValidator>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl EtsiLoteSubscriber {
    pub fn new(
        cache: EtsiLoteCache,
        certificate_validator: Arc<dyn CertificateValidator>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            cache,
            certificate_validator,
            key_algorithm_provider,
        }
    }

    async fn get_list(
        &self,
        reference: &Url,
    ) -> Result<PreprocessedLote, TrustListSubscriberError> {
        let raw_data = self
            .cache
            .get(reference.as_str())
            .await
            .error_while("getting LOTE from cache")?;
        Ok(serde_json::from_slice::<PreprocessedLote>(&raw_data)?)
    }
}

#[async_trait::async_trait]
impl TrustListSubscriber for EtsiLoteSubscriber {
    fn get_capabilities(&self) -> TrustListSubscriberCapabilities {
        TrustListSubscriberCapabilities {
            roles: vec![
                TrustListRoleEnum::PidProvider,
                TrustListRoleEnum::WalletProvider,
                TrustListRoleEnum::WrpAcProvider,
                TrustListRoleEnum::PubEeaProvider,
                TrustListRoleEnum::WrpRcProvider,
                TrustListRoleEnum::NationalRegistryRegistrar,
            ],
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
        role: Option<TrustListRoleEnum>,
    ) -> Result<TrustListValidationSuccess, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;
        // An aggregate of differently-typed lists is roleless; its role is then
        // re-derived per entity at resolve time, like the LoTL.
        Ok(TrustListValidationSuccess {
            role: list.role.or(role),
        })
    }

    async fn resolve_entries(
        &self,
        reference: &Url,
        identifiers: &[Identifier],
    ) -> Result<HashMap<IdentifierId, Vec<TrustEntityResponse>>, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;
        let mut result = HashMap::new();
        for identifier in identifiers {
            let entities = find_matching_for_identifier(
                identifier,
                &list,
                self.certificate_validator.as_ref(),
            )
            .await?;
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
        find_matching_for_certificate(&list, pem_chain, self.certificate_validator.as_ref()).await
    }

    async fn resolve_public_key(
        &self,
        reference: &Url,
        public_key: &PublicJwk,
    ) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError> {
        let der_64 = jwk_to_der_b64(public_key, self.key_algorithm_provider.as_ref())
            .error_while("converting JWK")?;
        let list = self.get_list(reference).await?;

        let Some(indices) = list.public_keys.get(&der_64) else {
            return Ok(Vec::new());
        };
        indices
            .iter()
            .map(|idx| entity_response(&list.trusted_entities, *idx))
            .collect()
    }
}

async fn find_matching_for_identifier(
    identifier: &Identifier,
    preprocessed_lote: &PreprocessedLote,
    certificate_validator: &dyn CertificateValidator,
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

            find_matching_for_certificate(
                preprocessed_lote,
                &active_cert.chain,
                certificate_validator,
            )
            .await
        }
    }
}

async fn find_matching_for_certificate(
    preprocessed_lote: &PreprocessedLote,
    pem_chain: &str,
    certificate_validator: &dyn CertificateValidator,
) -> Result<Vec<TrustEntityResponse>, TrustListSubscriberError> {
    let indices = preprocessed_lote
        .cert_index
        .match_chain(pem_chain, certificate_validator)
        .await?;
    indices
        .into_iter()
        .map(|idx| entity_response(&preprocessed_lote.trusted_entities, idx))
        .collect()
}

fn entity_response(
    trusted_entities: &[LoteEntity],
    idx: usize,
) -> Result<TrustEntityResponse, TrustListSubscriberError> {
    let entry = trusted_entities.get(idx).ok_or_else(|| {
        TrustListSubscriberError::MappingError(format!(
            "preprocessed LoTE index {idx} out of bounds. Num elements: {}",
            trusted_entities.len()
        ))
    })?;
    Ok(TrustEntityResponse {
        derived_role: entry.derived_role,
        metadata: TrustEntityMetadata::Lote(entry.info.clone()),
    })
}
