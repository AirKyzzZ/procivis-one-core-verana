use std::collections::HashMap;
use std::sync::Arc;

use shared_types::{CredentialSchemaId, IdentifierId};
use time::OffsetDateTime;

use crate::clock::now_utc;
use crate::config::core_config::{CacheEntityCacheType, CoreConfig};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::certificate::CertificateRole;
use crate::model::did::KeyRole;
use crate::model::identifier::Identifier;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::caching_loader::{CachingLoader, ResolveResult, Resolver};
use crate::provider::issuance_protocol::IssuanceProtocol;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIIssuerMetadataResponseDTO;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::service::oid4vci_final1_0::error::OID4VCIFinal1_0ServiceError;
use crate::util::key_selection::{
    CertificateFilter, KeyFilter, KeySelection, KeySelectionError, SelectedKey,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait CredentialIssuerMetadataFetcher: Send + Sync {
    async fn get_issuer_metadata_jwt(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        identifier: Identifier,
        service: Arc<dyn IssuanceProtocol>,
    ) -> Result<String, OID4VCIFinal1_0ServiceError>;
}

pub(crate) struct CredentialIssuerMetadataCache {
    inner: CachingLoader<OID4VCIFinal1_0ServiceError>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl CredentialIssuerMetadataCache {
    fn new(
        storage: Arc<dyn RemoteEntityStorage>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::OpenIdMetadataIssuer,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            key_provider,
            key_algorithm_provider,
        }
    }
}

#[async_trait::async_trait]
impl CredentialIssuerMetadataFetcher for CredentialIssuerMetadataCache {
    async fn get_issuer_metadata_jwt(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        identifier: Identifier,
        issuance_protocol: Arc<dyn IssuanceProtocol>,
    ) -> Result<String, OID4VCIFinal1_0ServiceError> {
        let key = encode_key(protocol_id, &identifier.id, credential_schema_id);
        let (content, _) = self
            .inner
            .get(
                key.as_str(),
                Arc::new(CredentialIssuerMetadataResolver {
                    protocol_id: protocol_id.to_string(),
                    credential_schema_id: *credential_schema_id,
                    identifier: Arc::new(identifier),
                    issuance_protocol,
                    key_provider: self.key_provider.clone(),
                    key_algorithm_provider: self.key_algorithm_provider.clone(),
                }),
                false,
            )
            .await
            .error_while("getting OpenID metadata")?;
        Ok(String::from_utf8(content)?)
    }
}

struct CredentialIssuerMetadataResolver {
    protocol_id: String,
    credential_schema_id: CredentialSchemaId,
    identifier: Arc<Identifier>,
    issuance_protocol: Arc<dyn IssuanceProtocol>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

#[async_trait::async_trait]
impl Resolver for CredentialIssuerMetadataResolver {
    type Error = OID4VCIFinal1_0ServiceError;

    async fn do_resolve(
        &self,
        _key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let issuer_metadata = self
            .issuance_protocol
            .issuer_metadata(
                &self.protocol_id,
                &self.credential_schema_id,
                &self.identifier,
            )
            .await
            .error_while("getting issuer metadata")?;
        let jwt = self
            .sign_issuer_metadata(&self.identifier, issuer_metadata)
            .await?;
        Ok(ResolveResult::NewValue {
            content: jwt.into_bytes(),
            media_type: Some("application/jwt".to_string()),
            expiry_date: None,
        })
    }
}

impl CredentialIssuerMetadataResolver {
    async fn sign_issuer_metadata(
        &self,
        issuer_identifier: &Identifier,
        issuer_metadata: OpenID4VCIIssuerMetadataResponseDTO,
    ) -> Result<String, OID4VCIFinal1_0ServiceError> {
        let signing_key = issuer_identifier
            .select_key(KeySelection {
                certificate: CertificateFilter::role_filter(CertificateRole::Authentication),
                key: KeyFilter::did_role(KeyRole::Authentication),
                ..Default::default()
            })
            .await
            .map_err(|e| match e {
                KeySelectionError::CertificateNotMatchingFilter { .. }
                | KeySelectionError::NoMatchingCertificate { .. } => {
                    OID4VCIFinal1_0ServiceError::MissingAuthenticationCapableCertificate(
                        issuer_identifier.id,
                    )
                }
                e => e.error_while("selecting signing key").into(),
            })?;

        let kid = if let SelectedKey::Did { key, did } = &signing_key {
            Some(did.verification_method_id(key))
        } else {
            None
        };

        let auth_fn = self
            .key_provider
            .get_signature_provider(signing_key.key(), kid, self.key_algorithm_provider.clone())
            .error_while("getting signature provider")?;

        let (key_info, issuer) = match signing_key {
            SelectedKey::Key(key) => {
                let key_handle = self
                    .key_provider
                    .get_key_storage(&key.storage_type)
                    .error_while("getting key storage")?
                    .key_handle(key)
                    .error_while("getting key storage")?;
                (
                    Some(JwtPublicKeyInfo::Jwk(
                        key_handle.public_key_as_jwk().error_while("getting JWK")?,
                    )),
                    None,
                )
            }
            SelectedKey::Certificate { certificate, .. } => (
                Some(JwtPublicKeyInfo::X5c(
                    pem_chain_into_x5c(&certificate.chain).error_while("parsing PEM chain")?,
                )),
                None,
            ),
            SelectedKey::Did { did, .. } => (None, Some(did.did.to_string())),
        };

        let now = now_utc();
        let issuer_metadata_jwt = Jwt::new(
            "openidvci-issuer-metadata+jwt".to_string(),
            auth_fn.jose_alg().error_while("getting JOSE algorithm")?,
            auth_fn.get_key_id(),
            key_info,
            JWTPayload {
                issued_at: Some(now),
                expires_at: None,
                invalid_before: Some(now),
                issuer,
                subject: Some(issuer_metadata.credential_issuer.to_owned()),
                audience: None,
                jwt_id: None,
                proof_of_possession_key: None,
                custom: issuer_metadata,
            },
        );
        Ok(issuer_metadata_jwt
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("tokenizing issuer metadata JWT")?)
    }
}

fn encode_key(
    protocol_id: &str,
    identifier_id: &IdentifierId,
    credential_schema_id: &CredentialSchemaId,
) -> String {
    format!("{}:{}:{}", protocol_id, identifier_id, credential_schema_id)
}

pub(crate) fn initialize_credential_issuer_metadata_cache_from_config(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
) -> Result<Arc<dyn CredentialIssuerMetadataFetcher>, anyhow::Error> {
    let config = config
        .cache_entities
        .entities
        .get("CREDENTIAL_ISSUER_METADATA")
        .cloned()
        .unwrap_or_default();

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    let cache = CredentialIssuerMetadataCache::new(
        storage,
        key_provider,
        key_algorithm_provider,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    );

    Ok(Arc::new(cache))
}
