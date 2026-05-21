use std::fmt::Display;
use std::sync::Arc;

use shared_types::SignerId;

use super::Signer;
use crate::config::core_config::ConfigFields;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDecorators;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::Issuer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;

impl WithDecorators for dyn Signer {
    fn decorate(self: Arc<dyn Signer>, fields: &impl ConfigFields) -> Arc<dyn Signer> {
        if fields.enabled() {
            self
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

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>> {
        self.inner().revocation_method()
    }

    fn config_name(&self) -> &SignerId {
        self.inner().config_name()
    }
}
