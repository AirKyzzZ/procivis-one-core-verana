use error::WRPValidatorError;
use shared_types::OrganisationId;
use url::Url;

use crate::proto::jwt::model::JWTPayload;
use crate::provider::signer::registration_certificate::model::Payload;
use crate::provider::trust_list_subscriber::TrustEntityResponse;

pub(crate) mod error;
pub(crate) mod validator;

pub(crate) struct AccessCertificateResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub rp_id: String,
    #[expect(unused)]
    pub registry_url: Option<Url>,
}

pub(crate) struct RegistrationCertificateResult {
    #[expect(unused)]
    pub trust_entity: Option<TrustEntityResponse>,
    pub payload: JWTPayload<Payload>,
}

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
        expected_rp_id: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<RegistrationCertificateResult, WRPValidatorError>;
}
