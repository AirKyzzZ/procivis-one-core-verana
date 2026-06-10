use one_dto_mapper::{From, Into};

use super::OneCore;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Deletes entries from the system cache. See
    /// [Caching](https://docs.procivis.ch/configure/caching#cached-entities)
    /// for details on cached entity types.
    #[uniffi::method]
    pub async fn delete_cache(
        &self,
        types: Option<Vec<CacheTypeBindingDTO>>,
    ) -> Result<(), BindingError> {
        let types = types.map(|vec| vec.into_iter().map(Into::into).collect());

        let core = self.use_core().await?;
        core.cache_service.prune_cache(types).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, uniffi::Enum)]
#[from("one_core::model::remote_entity_cache::CacheType")]
#[into("one_core::model::remote_entity_cache::CacheType")]
#[uniffi(name = "CacheType")]
pub enum CacheTypeBindingDTO {
    DidDocument,
    JsonLdContext,
    /// Credential status list fetched from an external source.
    StatusListCredential,
    /// Metadata for SD-JWT VC type (VCT).
    VctMetadata,
    JsonSchema,
    TrustList,
    /// X.509 certificate revocation list.
    X509Crl,
    /// Certificate revocation list used for Android key attestation.
    AndroidAttestationCrl,
    /// OpenID provider metadata fetched from holder endpoints.
    OpenIdMetadataHolder,
    /// OpenID provider metadata fetched from issuer endpoints.
    OpenIdMetadataIssuer,
    /// Metadata fetched from the registered wallet provider.
    WalletProviderMetadata,
    /// Trust collection data fetched from a remote source.
    RemoteTrustCollection,
}
