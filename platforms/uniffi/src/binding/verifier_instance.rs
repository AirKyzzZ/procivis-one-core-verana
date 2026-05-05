use one_core::service::verifier_instance::dto::{
    RegisterVerifierInstanceRequestDTO, RegisterVerifierInstanceResponseDTO,
};
use one_dto_mapper::{From, TryInto};

use super::OneCore;
use crate::binding::wallet_unit::TrustCollectionsBindingDTO;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Registers the verifier unit with a Verifier Provider.
    #[uniffi::method]
    pub async fn register_verifier_instance(
        &self,
        request: RegisterVerifierInstanceRequestBindingDTO,
    ) -> Result<RegisterVerifierInstanceResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let response = core
            .verifier_instance_service
            .register_verifier_instance(request.try_into()?)
            .await?;
        Ok(response.into())
    }

    /// Returns trust collections curated by the Verifier Provider.
    #[uniffi::method]
    pub async fn get_verifier_instance_trust_collections(
        &self,
        id: String,
    ) -> Result<TrustCollectionsBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .verifier_instance_service
            .get_trust_collections(into_id(&id)?)
            .await?
            .into())
    }

    /// Modifies verifier unit's settings.
    #[uniffi::method]
    pub async fn update_verifier_instance(
        &self,
        id: String,
        request: EditVerifierInstanceRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        core.verifier_instance_service
            .edit_verifier_instance(into_id(&id)?, request.try_into()?)
            .await?;
        Ok(())
    }
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = RegisterVerifierInstanceRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "RegisterVerifierInstanceRequest")]
pub struct RegisterVerifierInstanceRequestBindingDTO {
    /// The verifier unit's organization.
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    /// The Verifier Provider's reference URL.
    pub verifier_provider_url: String,
    /// Reference a configured `verifierProvider` instance.
    pub r#type: String,
    /// When true, the verifier will only validate presentations of
    /// credentials issued by trusted issuers. Requires the Verifier
    /// Provider to have the `trustEcosystemsEnabled` feature flag
    /// enabled.
    pub trusted_issuer_required: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(RegisterVerifierInstanceResponseDTO)]
#[uniffi(name = "RegisterVerifierInstanceResponse")]
pub struct RegisterVerifierInstanceResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "UpdateVerifierInstanceRequest")]
pub struct EditVerifierInstanceRequestBindingDTO {
    /// The trust collections the verifier subscribes to, selected from
    /// those made available by the Verifier Provider. The verifier will
    /// evaluate trust against the lists contained in these collections.
    /// To keep subscribed collections in sync with the Verifier Provider,
    /// run the `TRUST_COLLECTION_SYNC` task.
    pub trust_collections: Option<Vec<String>>,
    /// When true, the verifier will only validate presentations of
    /// credentials issued by trusted issuers. Requires the Verifier
    /// Provider to have the `trustEcosystemsEnabled` feature flag
    /// enabled.
    pub trusted_issuer_required: Option<bool>,
}
