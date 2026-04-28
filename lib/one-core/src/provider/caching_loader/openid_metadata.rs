use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use time::OffsetDateTime;
use url::Url;

use super::{CacheError, CachingLoader, ResolveResult, Resolver, ResolverError};
use crate::config::core_config::{CacheEntityCacheType, CoreConfig};
use crate::error::ContextWithErrorCode;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait OpenIDMetadataFetcher: Send + Sync {
    async fn get(&self, url: &str, accept_mime: &str) -> Result<Vec<u8>, CacheError>;
}

impl<'a> dyn OpenIDMetadataFetcher + 'a {
    pub(crate) async fn fetch_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, CacheError> {
        let content = self.get(url, "application/json").await?;
        Ok(serde_json::from_slice(&content)?)
    }

    pub(crate) async fn fetch_jwt<CustomPayload: DeserializeOwned + Debug>(
        &self,
        url: &str,
    ) -> Result<DecomposedJwt<CustomPayload>, CacheError> {
        let content = self.get(url, "application/jwt").await?;
        let jwt = String::from_utf8(content)?;
        Ok(Jwt::decompose_token(&jwt)?)
    }
}

struct OpenIDMetadataCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl OpenIDMetadataCache {
    fn new(
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::OpenIdMetadataHolder,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }
}

#[async_trait::async_trait]
impl OpenIDMetadataFetcher for OpenIDMetadataCache {
    async fn get(&self, url: &str, accept_mime: &str) -> Result<Vec<u8>, CacheError> {
        let (metadata, _) = self
            .inner
            .get(&url_to_key(url, accept_mime), self.resolver.clone(), false)
            .await
            .error_while("getting OpenID metadata")?;

        Ok(metadata)
    }
}

fn url_to_key(url: &str, accept_mime: &str) -> String {
    format!("{accept_mime};{url}")
}

fn key_to_url(key: &str) -> Option<(Url, String)> {
    let (mime, url) = key.split_once(';')?;
    Some((url.parse().ok()?, mime.to_string()))
}

struct OpenIDMetadataResolver {
    client: Arc<dyn HttpClient>,
}

impl OpenIDMetadataResolver {
    fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for OpenIDMetadataResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let (url, accept_mime) =
            key_to_url(key).ok_or(ResolverError::MappingError("invalid key".to_string()))?;

        let response = self
            .client
            .get(url.as_str())
            .header("Accept", accept_mime.as_str())
            .send()
            .await
            .error_while("downloading OpenID metadata")?
            .error_for_status()
            .error_while("downloading OpenID metadata")?;

        let media_type = response.header_get("content-type").map(|t| t.to_owned());
        let content = response.body;

        if let Some(mime) = &media_type
            && mime != &accept_mime
        {
            return Err(ResolverError::InvalidResponse(format!(
                "Unexpected Content-Type: {mime}"
            )));
        }

        if accept_mime == "application/json" {
            serde_json::from_slice::<serde_json::Value>(&content)?;
        }

        Ok(ResolveResult::NewValue {
            content,
            media_type,
            expiry_date: None,
        })
    }
}

pub(crate) fn openid_metadata_cache_from_config(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    client: Arc<dyn HttpClient>,
) -> Arc<dyn OpenIDMetadataFetcher> {
    let config = config
        .cache_entities
        .entities
        .get("OPENID_METADATA")
        .cloned()
        .unwrap_or_default();

    let storage: Arc<dyn RemoteEntityStorage> = match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    };

    Arc::new(OpenIDMetadataCache::new(
        Arc::new(OpenIDMetadataResolver::new(client)),
        storage,
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
    ))
}
