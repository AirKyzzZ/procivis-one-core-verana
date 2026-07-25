use dcql::{CredentialQueryId, DcqlQuery};
use shared_types::{OrganisationId, ProofId};
use thiserror::Error;
use time::Duration;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::verana_trust::VerifierTrustProvenance;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::verification_protocol::openid4vp::final1_0::model::VerifierInfoAttestation;

mod mapper;
pub(crate) mod resolver;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait HolderTrustResolver: Send + Sync {
    /// resolve trust on holder-side during verification
    async fn resolve_verification_trust<'a>(
        &self,
        verifier_details: Option<&'a IdentifierDetails>,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        dcql_query: &DcqlQuery,
        verifier_info: &[VerifierInfoAttestation],
        leeway: Duration,
        provenance: VerifierTrustProvenance,
    ) -> Result<(), HolderTrustResolverError>;
}

#[derive(Debug, Error)]
pub(crate) enum HolderTrustResolverError {
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Query not allowed by trust ecosystem: `{0}`")]
    DisallowedQuery(CredentialQueryId),
    #[error("Interaction not allowed - untrusted")]
    Untrusted,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderTrustResolverError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Untrusted => ErrorCode::BR_0433,
            Self::DisallowedQuery(_) => ErrorCode::BR_0411,
            Self::InvalidRequest(_) => ErrorCode::BR_0085,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
