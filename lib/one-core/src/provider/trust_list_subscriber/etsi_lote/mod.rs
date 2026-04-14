use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use serde_with::DurationSeconds;
use shared_types::IdentifierId;
use standardized_types::etsi_119_602::TrustedEntityInformation;
use standardized_types::jwk::PublicJwk;
use strum::Display;
use url::Url;

use crate::error::ContextWithErrorCode;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::etsi_lote::model::PreprocessedLote;
use crate::provider::trust_list_subscriber::etsi_lote::preprocessing::jwk_to_der_b64;
use crate::provider::trust_list_subscriber::{
    Feature, TrustEntityResponse, TrustListSubscriber, TrustListSubscriberCapabilities,
    TrustListValidationSuccess,
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
        let list = serde_json::from_slice::<PreprocessedLote>(&raw_data)?;
        Ok(list)
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
        let role = list
            .role
            .or(role)
            .ok_or(TrustListSubscriberError::UnknownTrustListRole)?;
        Ok(TrustListValidationSuccess { role })
    }

    async fn resolve_entries(
        &self,
        reference: &Url,
        identifiers: &[Identifier],
    ) -> Result<HashMap<IdentifierId, TrustEntityResponse>, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;
        let mut result = HashMap::new();
        for identifier in identifiers {
            if let Some(entity) = find_matching_trusted_entity_for_identifier(identifier, &list)? {
                result.insert(identifier.id, TrustEntityResponse::LOTE(entity));
            }
        }
        Ok(result)
    }

    async fn resolve_certificate(
        &self,
        reference: &Url,
        pem_chain: &str,
    ) -> Result<Option<TrustEntityResponse>, TrustListSubscriberError> {
        let list = self.get_list(reference).await?;

        let ParsedCertificate { attributes, .. } = self
            .certificate_validator
            .parse_pem_chain(pem_chain, CertificateValidationOptions::no_validation())
            .await
            .error_while("parsing PEM")?;

        if let Some(result) = find_matching_for_certificate(&list, &attributes.fingerprint)? {
            return Ok(Some(TrustEntityResponse::LOTE(result)));
        };
        Ok(None)
    }

    async fn resolve_public_key(
        &self,
        reference: &Url,
        public_key: &PublicJwk,
    ) -> Result<Option<TrustEntityResponse>, TrustListSubscriberError> {
        let der_64 = jwk_to_der_b64(public_key, self.key_algorithm_provider.as_ref())
            .error_while("converting JWK")?;
        let list = self.get_list(reference).await?;

        let Some(idx) = list.public_keys.get(&der_64) else {
            return Ok(None);
        };

        Ok(Some(TrustEntityResponse::LOTE(get(
            &list.trusted_entities,
            *idx,
        )?)))
    }
}

fn find_matching_trusted_entity_for_identifier(
    identifier: &Identifier,
    preprocessed_lote: &PreprocessedLote,
) -> Result<Option<TrustedEntityInformation>, TrustListSubscriberError> {
    match identifier.r#type {
        r#type @ IdentifierType::Did | r#type @ IdentifierType::Key => {
            Err(TrustListSubscriberError::UnsupportedIdentifierType(r#type))
        }
        IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
            let Some(active_certs) = identifier.active_certs() else {
                return Ok(None);
            };
            if active_certs.len() > 1 {
                return Err(TrustListSubscriberError::MultipleActiveCertificates(
                    identifier.id,
                ));
            }
            let Some(active_cert) = active_certs.first() else {
                return Ok(None);
            };

            if let Some(result) =
                find_matching_for_certificate(preprocessed_lote, &active_cert.fingerprint)?
            {
                return Ok(Some(result));
            }

            Ok(None)
        }
    }
}

fn find_matching_for_certificate(
    preprocessed_lote: &PreprocessedLote,
    fingerprint: &str,
) -> Result<Option<TrustedEntityInformation>, TrustListSubscriberError> {
    // check fingerprint
    let Some(idx) = preprocessed_lote.certificate_fingerprints.get(fingerprint) else {
        // the certificate must be known
        return Ok(None);
    };
    get(&preprocessed_lote.trusted_entities, *idx).map(Some)
}

fn get(
    trusted_entities: &[TrustedEntityInformation],
    idx: usize,
) -> Result<TrustedEntityInformation, TrustListSubscriberError> {
    Ok(trusted_entities
        .get(idx)
        .ok_or_else(|| {
            TrustListSubscriberError::MappingError(format!(
                "preprocessed LoTE index {idx} out of bounds. Num elements: {}",
                trusted_entities.len()
            ))
        })?
        .clone())
}
