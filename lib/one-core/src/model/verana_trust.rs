use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VeranaTrustRole {
    Issuer,
    Verifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerifierTrustProvenance {
    DidSignedRequest,
    VerifierAttestation,
    RedirectUri,
    X509,
    Proximity,
}

impl VerifierTrustProvenance {
    pub(crate) fn allows_verana_positive(self) -> bool {
        self == Self::DidSignedRequest
    }
}

#[cfg(test)]
mod provenance_test {
    use super::VerifierTrustProvenance;

    #[test]
    fn only_native_did_signed_request_provenance_can_be_verana_positive() {
        assert!(VerifierTrustProvenance::DidSignedRequest.allows_verana_positive());
        for provenance in [
            VerifierTrustProvenance::VerifierAttestation,
            VerifierTrustProvenance::RedirectUri,
            VerifierTrustProvenance::X509,
            VerifierTrustProvenance::Proximity,
        ] {
            assert!(!provenance.allows_verana_positive());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VeranaTrustVerdict {
    TrustedAuthorized,
    Unauthorized,
    Untrusted,
    NonProduction,
    Mismatch,
    UnknownSchema,
    Partial,
    Unavailable,
}

impl VeranaTrustVerdict {
    pub fn is_positive(self) -> bool {
        self == Self::TrustedAuthorized
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VeranaQ1Evidence {
    pub response_did: Option<String>,
    pub trust_status: Option<String>,
    pub production: Option<bool>,
    pub evaluated_at: Option<String>,
    pub evaluated_at_block: Option<Value>,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VeranaAuthorizationEvidence {
    pub schema: String,
    pub response_did: Option<String>,
    pub response_schema: Option<String>,
    pub authorized: Option<bool>,
    pub evaluated_at: Option<String>,
    pub evaluated_at_block: Option<String>,
    pub permission: Option<Value>,
    pub fees: Option<Value>,
    pub permission_chain: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VeranaTrustSummary {
    pub resolver_url: String,
    pub role: VeranaTrustRole,
    pub verdict: VeranaTrustVerdict,
    pub did: String,
    pub schemas: Vec<String>,
    pub q1: Option<VeranaQ1Evidence>,
    pub authorizations: Vec<VeranaAuthorizationEvidence>,
    pub failure: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VeranaTrustClaim {
    pub name: String,
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VeranaTrustCredential {
    pub id: Option<String>,
    pub credential_type: Option<String>,
    pub format: Option<String>,
    pub ecs_type: Option<String>,
    pub issued_by: Option<String>,
    pub presented_by: Option<String>,
    pub claims: Vec<VeranaTrustClaim>,
    pub permission_chain: Vec<Value>,
    pub result: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VeranaTrustFullDetails {
    pub resolver_url: String,
    pub did: String,
    pub trust_status: String,
    pub production: bool,
    pub evaluated_at: Option<String>,
    pub evaluated_at_block: Option<Value>,
    pub expires_at: Option<String>,
    pub credentials: Vec<VeranaTrustCredential>,
    pub failed_credentials: Vec<Value>,
    pub dereference_errors: Vec<Value>,
}
