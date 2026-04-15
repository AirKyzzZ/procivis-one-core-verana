use error::WRPValidatorError;
use model::{AccessCertificateResult, FetchRegistryResult, RegistrationCertificateResult};
use shared_types::OrganisationId;
use time::Duration;
use url::Url;

pub(crate) mod error;
pub(crate) mod model;
pub(crate) mod validator;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait WRPValidator: Send + Sync {
    /// Validate and optionally resolve WRPAC trust information
    async fn validate_access_certificate_trust(
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

    /// Receive registration from the WRP registry
    async fn fetch_from_registry(
        &self,
        relying_party_id: &str,
        registry_url: &Url,
        validate_trust: Option<OrganisationId>,
        leeway: Duration,
    ) -> Result<FetchRegistryResult, WRPValidatorError>;
}
