use std::fmt::Display;
use std::sync::Arc;

use shared_types::SignerId;

use super::Signer;
use crate::config::core_config::ConfigFields;
use crate::error::ContextWithErrorCode;
use crate::proto::session_provider::SessionProvider;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDecorators;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::Issuer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::validator::permissions::RequiredPermissions;

impl WithDecorators for dyn Signer {
    fn decorate(self: Arc<dyn Signer>, fields: &impl ConfigFields) -> Arc<dyn Signer> {
        if fields.enabled() {
            Arc::new(CapabilityChecked(self))
        } else {
            Arc::new(DisabledProvider::new(self))
        }
    }
}

#[async_trait::async_trait]
impl<T: Provider + Signer + Display + ?Sized> Signer for DisabledProvider<T> {
    fn get_capabilities(&self) -> SignerCapabilities {
        let mut capabilities = self.inner().get_capabilities();
        capabilities.features = vec![];
        capabilities
    }

    async fn sign(
        &self,
        _issuer: Issuer,
        _request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        self.disabled_error()
    }

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError> {
        self.inner().revocation_method()
    }

    fn config_name(&self) -> &SignerId {
        self.inner().config_name()
    }
}

/// Checks supported identifier/key type used for signing
struct CapabilityChecked(Arc<dyn Signer>);

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.0.capabilities()
    }
}

#[async_trait::async_trait]
impl Signer for CapabilityChecked {
    fn get_capabilities(&self) -> SignerCapabilities {
        self.0.get_capabilities()
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        match &issuer {
            Issuer::Identifier { identifier, .. } => {
                let identifier_types = self.0.get_capabilities().supported_identifiers;
                if !identifier_types.contains(&identifier.r#type.into()) {
                    return Err(SignerError::InvalidIssuerIdentifier(identifier.id));
                }
            }
            Issuer::Key(key) => {
                let key_algorithm = key
                    .key_algorithm_type()
                    .error_while("parsing key algorithm")?;

                let key_algorithms = self.0.get_capabilities().signing_key_algorithms;
                if !key_algorithms.contains(&key_algorithm) {
                    return Err(SignerError::UnsupportedKeyAlgorithm(key_algorithm));
                }
            }
        };

        self.0.sign(issuer, request).await
    }

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError> {
        self.0.revocation_method()
    }

    fn config_name(&self) -> &SignerId {
        self.0.config_name()
    }
}

/// Checks permissions for signing
pub(super) struct PermissionChecked {
    pub inner: Arc<dyn Signer>,
    pub session_provider: Arc<dyn SessionProvider>,
}

impl Provider for PermissionChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.inner.capabilities()
    }
}

#[async_trait::async_trait]
impl Signer for PermissionChecked {
    fn get_capabilities(&self) -> SignerCapabilities {
        self.inner.get_capabilities()
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        let permissions = self.inner.get_capabilities().sign_required_permissions;
        RequiredPermissions::at_least_one(permissions)
            .check(self.session_provider.as_ref())
            .error_while("validating signer required permissions")?;

        self.inner.sign(issuer, request).await
    }

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError> {
        self.inner.revocation_method()
    }

    fn config_name(&self) -> &SignerId {
        self.inner.config_name()
    }
}
