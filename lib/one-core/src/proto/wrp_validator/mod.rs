use error::WRPValidatorError;
use model::{
    AccessCertificateResult, FetchRegistryResult, RegistrationCertificateResult, TrustMode,
};
use shared_types::OrganisationId;
use time::Duration;
use url::Url;

use crate::model::credential_schema::CredentialSchema;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::provider::trust_list_subscriber::TrustEntityResponse;

pub(crate) mod error;
pub(crate) mod model;
pub(crate) mod validator;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait WRPValidator: Send + Sync {
    /// Validate and optionally resolve WRPAC trust information
    async fn validate_access_certificate(
        &self,
        pem_chain: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<AccessCertificateResult, WRPValidatorError>;

    async fn validate_registration_certificate(
        &self,
        wrprc_jwt: &str,
        expected_relying_party_id: &str,
        validate_trust: Option<OrganisationId>,
        leeway: Duration,
    ) -> Result<RegistrationCertificateResult, WRPValidatorError>;

    fn validate_registration_certificates_consistency(
        &self,
        first: &Payload,
        second: &Payload,
    ) -> Result<(), WRPValidatorError>;

    /// Receive registration from the WRP registry
    async fn fetch_from_registry(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        validate_trust: Option<OrganisationId>,
        leeway: Duration,
    ) -> Result<FetchRegistryResult, WRPValidatorError>;

    async fn validate_credential_issuer<'a>(
        &self,
        issuer_certificate_pem_chain: Option<&'a str>,
        credential_schema: &CredentialSchema,
        organisation_id: OrganisationId,
    ) -> Result<Option<TrustEntityResponse>, WRPValidatorError>;

    /// Decide on the current trust settings for the given wallet organisation
    async fn wallet_trust_mode(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<TrustMode, WRPValidatorError>;

    /// Decide on the current trust settings for the given verifier organisation
    async fn verifier_trust_mode(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<TrustMode, WRPValidatorError>;
}
