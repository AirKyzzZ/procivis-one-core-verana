use std::collections::HashMap;
use std::sync::Arc;

use model::{CertificateEntry, PreprocessedLote};
use preprocessing::jwk_to_der_b64;
use serde::Deserialize;
use serde_with::DurationSeconds;
use shared_types::IdentifierId;
use standardized_types::etsi_119_602::TrustedEntityInformation;
use standardized_types::jwk::PublicJwk;
use strum::Display;
use url::Url;

use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
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
    pub supported_pid_provider_role_schema_ids: Vec<String>,
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
    pid_provider_role_schema_ids: Vec<String>,
}

impl EtsiLoteSubscriber {
    pub fn new(
        cache: EtsiLoteCache,
        certificate_validator: Arc<dyn CertificateValidator>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        pid_provider_role_schema_ids: Vec<String>,
    ) -> Self {
        Self {
            cache,
            certificate_validator,
            key_algorithm_provider,
            pid_provider_role_schema_ids,
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
            pid_provider_role_schema_ids: self.pid_provider_role_schema_ids.to_owned(),
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
            if let Some(entity) = find_matching_trusted_entity_for_identifier(
                identifier,
                &list,
                self.certificate_validator.as_ref(),
            )
            .await?
            {
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

        if let Some(result) =
            find_matching_for_certificate(&list, pem_chain, self.certificate_validator.as_ref())
                .await?
        {
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

async fn find_matching_trusted_entity_for_identifier(
    identifier: &Identifier,
    preprocessed_lote: &PreprocessedLote,
    certificate_validator: &dyn CertificateValidator,
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

            if let Some(result) = find_matching_for_certificate(
                preprocessed_lote,
                &active_cert.chain,
                certificate_validator,
            )
            .await?
            {
                return Ok(Some(result));
            }

            Ok(None)
        }
    }
}

async fn find_matching_for_certificate(
    preprocessed_lote: &PreprocessedLote,
    pem_chain: &str,
    certificate_validator: &dyn CertificateValidator,
) -> Result<Option<TrustedEntityInformation>, TrustListSubscriberError> {
    let chain_authority_key_identifers =
        pem_chain_to_authority_key_identifiers(pem_chain).error_while("parsing PEM chain")?;

    // try matching via trusted CA SKI == input AKI
    let mut idx = if let Some(CertificateEntry {
        idx,
        pem: ca_pem_chain,
    }) = chain_authority_key_identifers
        .iter()
        .find_map(|key_identifier| {
            preprocessed_lote
                .certificate_by_subject_key_identifier
                .get(key_identifier)
        }) {
        // matching via CA hierarchy, check consistency of the whole chain
        match certificate_validator
            .validate_chain_against_ca_chain(
                pem_chain,
                ca_pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
                CertSelection::Leaf,
            )
            .await
        {
            Err(err) => {
                tracing::warn!(%err, "Trust entity found via AKI, but consistency checking failed");
                None
            }
            Ok(_) => {
                tracing::debug!(
                    "Found matching trusted certificate anchor via SKI, entry index: {idx}"
                );
                Some(*idx)
            }
        }
    } else {
        None
    };

    // fallback, try matching the leaf certificate directly via fingerprint
    if idx.is_none() {
        let ParsedCertificate { attributes, .. } = certificate_validator
            .parse_pem_chain(
                pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
            .error_while("parsing input PEM chain")?;

        if let Some(idx_by_fingerprint) = preprocessed_lote
            .certificate_fingerprints
            .get(&attributes.fingerprint)
        {
            tracing::debug!(
                "Found matching trusted certificate anchor via fingerprint, entry index: {idx_by_fingerprint}"
            );
            idx = Some(*idx_by_fingerprint);
        }
    }

    let Some(idx) = idx else {
        // no match
        return Ok(None);
    };

    get(&preprocessed_lote.trusted_entities, idx).map(Some)
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
