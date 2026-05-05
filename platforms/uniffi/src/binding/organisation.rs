use one_core::service::organisation::dto::{
    GetOrganisationDetailsResponseDTO, HolderWalletInstanceDetailResponseDTO,
    VerifierInstanceDetailResponseDTO, WalletProviderDetailResponseDTO,
};
use one_dto_mapper::{From, convert_inner};

use super::OneCore;
use super::mapper::OptionalString;
use crate::binding::identifier::GetIdentifierListItemBindingDTO;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, from_id_opt, from_timestamp_opt, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Creates an organization.
    #[uniffi::method]
    pub async fn create_organisation(
        &self,
        request: CreateOrganisationRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .organisation_service
            .create_organisation(request.try_into()?)
            .await?
            .to_string())
    }

    /// Updates or deactivates an organization if it exists, otherwise
    /// creates a new organization using the provided UUID and name.
    #[uniffi::method]
    pub async fn upsert_organisation(
        &self,
        request: UpsertOrganisationRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .organisation_service
            .upsert_organisation(request.try_into()?)
            .await?)
    }

    /// Returns details of an existing organization.
    #[uniffi::method]
    pub async fn get_organisation(
        &self,
        id: String,
    ) -> Result<GetOrganisationDetailsResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let id = into_id(&id)?;
        let response = core.organisation_service.get_organisation(&id).await?;
        Ok(response.into())
    }
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CreateOrganisationRequest")]
pub struct CreateOrganisationRequestBindingDTO {
    /// If no UUID is passed, one will be created.
    pub id: Option<String>,
    pub parent_organisation: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "UpsertOrganisationRequest")]
pub struct UpsertOrganisationRequestBindingDTO {
    /// Unique identifier of the organization to create or update.
    pub id: String,
    /// Set to `true` to deactivate the organization.
    pub deactivate: Option<bool>,
    /// Wallet Provider use only.
    pub wallet_provider: Option<OptionalString>,
    /// Wallet Provider use only.
    pub wallet_provider_issuer: Option<OptionalString>,
    /// The parent organization this organization inherits policy-level
    /// configuration from, if any.
    pub parent_organisation: Option<OptionalString>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "OrganisationDetail")]
#[from(GetOrganisationDetailsResponseDTO)]
pub struct GetOrganisationDetailsResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn = "from_timestamp_opt")]
    pub deactivated_at: Option<String>,
    /// The parent organization this organization inherits policy-level
    /// configuration from, if any.
    #[from(with_fn = "from_id_opt")]
    pub parent_organisation: Option<String>,
    #[from(with_fn = convert_inner)]
    pub wallet_provider: Option<WalletProviderDetailResponseBindingDTO>,
    /// Wallet registration details for this organization's Business
    /// Wallet.
    #[from(with_fn = convert_inner)]
    pub wallet_instance: Option<HolderWalletInstanceDetailResponseBindingDTO>,
    /// Wallet registration details for this organization's Business
    /// Wallet.
    #[from(with_fn = convert_inner)]
    pub verifier_instance: Option<VerifierInstanceDetailResponseBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "HolderWalletInstanceDetail")]
#[from(HolderWalletInstanceDetailResponseDTO)]
pub(crate) struct HolderWalletInstanceDetailResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub trusted_rp_required: bool,
    pub wallet_provider_url: String,
    pub wallet_provider_name: String,
    pub authentication_key_type: String,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "VerifierInstanceDetail")]
#[from(VerifierInstanceDetailResponseDTO)]
pub(crate) struct VerifierInstanceDetailResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    /// When true, the verifier will only validate presentations of
    /// credentials issued by trusted issuers. Requires the Verifier
    /// Provider to have the `trustEcosystemsEnabled` feature flag
    /// enabled.
    pub trusted_issuer_required: bool,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[uniffi(name = "WalletProviderDetail")]
#[from(WalletProviderDetailResponseDTO)]
pub(crate) struct WalletProviderDetailResponseBindingDTO {
    /// Wallet Provider configuration used by this organization to provide
    /// wallets.
    pub provider_name: Option<String>,
    /// Identifier used by this organization to provide wallets.
    #[from(with_fn = convert_inner)]
    pub issuer: Option<GetIdentifierListItemBindingDTO>,
}
