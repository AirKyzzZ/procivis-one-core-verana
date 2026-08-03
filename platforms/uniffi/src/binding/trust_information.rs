use std::collections::HashMap;

use one_core::model::verana_trust::{
    VeranaAuthorizationEvidence, VeranaQ1Evidence, VeranaTrustClaim, VeranaTrustCredential,
    VeranaTrustFullDetails, VeranaTrustRole, VeranaTrustSummary, VeranaTrustVerdict,
};
use one_core::provider::signer::registration_certificate::model::SupervisoryAuthority;
use one_core::service::common_dto::{
    EudiIntermediaryResponseDTO, EudiTrustInformationResponseDTO, TrustInformationDetailResponseDTO,
};
use one_dto_mapper::{From, convert_inner};

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(TrustInformationDetailResponseDTO)]
#[uniffi(name = "TrustInformationDetail")]
pub struct TrustInformationDetailResponseBindingDTO {
    /// EUDI trust information received from Access Certificates, Registration
    /// Certificates, or National Registry public APIs.
    #[from(with_fn = convert_inner)]
    pub eudi_ecosystem: Option<EudiTrustInformationResponseBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub verana: Option<VeranaTrustFullDetailsBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "VeranaTrustSummary")]
pub struct VeranaTrustSummaryBindingDTO {
    pub resolver_url: String,
    pub role: VeranaTrustRoleBindingEnum,
    pub verdict: VeranaTrustVerdictBindingEnum,
    pub did: String,
    pub production: Option<bool>,
    pub schemas: Vec<String>,
    pub q1: Option<VeranaQ1EvidenceBindingDTO>,
    pub authorizations: Vec<VeranaAuthorizationEvidenceBindingDTO>,
    pub failure: Option<String>,
}

impl From<VeranaTrustSummary> for VeranaTrustSummaryBindingDTO {
    fn from(value: VeranaTrustSummary) -> Self {
        Self {
            resolver_url: value.resolver_url,
            role: value.role.into(),
            verdict: value.verdict.into(),
            did: value.did,
            production: value.production,
            schemas: value.schemas,
            q1: value.q1.map(Into::into),
            authorizations: value.authorizations.into_iter().map(Into::into).collect(),
            failure: value.failure,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "VeranaQ1Evidence")]
pub struct VeranaQ1EvidenceBindingDTO {
    pub response_did: Option<String>,
    pub trust_status: Option<String>,
    pub production: Option<bool>,
    pub evaluated_at: Option<String>,
    pub evaluated_at_block: Option<String>,
    pub expires_at: Option<String>,
}

impl From<VeranaQ1Evidence> for VeranaQ1EvidenceBindingDTO {
    fn from(value: VeranaQ1Evidence) -> Self {
        Self {
            response_did: value.response_did,
            trust_status: value.trust_status,
            production: value.production,
            evaluated_at: value.evaluated_at,
            evaluated_at_block: value.evaluated_at_block.map(|value| value.to_string()),
            expires_at: value.expires_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "VeranaAuthorizationEvidence")]
pub struct VeranaAuthorizationEvidenceBindingDTO {
    pub schema: String,
    pub response_did: Option<String>,
    pub response_schema: Option<String>,
    pub authorized: Option<bool>,
    pub evaluated_at: Option<String>,
    pub evaluated_at_block: Option<String>,
    pub permission: Option<String>,
    pub fees: Option<String>,
    pub permission_chain: Option<String>,
}

impl From<VeranaAuthorizationEvidence> for VeranaAuthorizationEvidenceBindingDTO {
    fn from(value: VeranaAuthorizationEvidence) -> Self {
        Self {
            schema: value.schema,
            response_did: value.response_did,
            response_schema: value.response_schema,
            authorized: value.authorized,
            evaluated_at: value.evaluated_at,
            evaluated_at_block: value.evaluated_at_block,
            permission: value.permission.map(|value| value.to_string()),
            fees: value.fees.map(|value| value.to_string()),
            permission_chain: value.permission_chain.map(|value| value.to_string()),
        }
    }
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(VeranaTrustRole)]
#[uniffi(name = "VeranaTrustRole")]
pub enum VeranaTrustRoleBindingEnum {
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(VeranaTrustVerdict)]
#[uniffi(name = "VeranaTrustVerdict")]
pub enum VeranaTrustVerdictBindingEnum {
    TrustedAuthorized,
    Unauthorized,
    Untrusted,
    NonProduction,
    Mismatch,
    UnknownSchema,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "VeranaTrustFullDetails")]
pub struct VeranaTrustFullDetailsBindingDTO {
    pub resolver_url: String,
    pub did: String,
    pub trust_status: String,
    pub production: bool,
    pub evaluated_at: Option<String>,
    pub evaluated_at_block: Option<String>,
    pub expires_at: Option<String>,
    pub credentials: Vec<VeranaTrustCredentialBindingDTO>,
    pub failed_credentials: Vec<String>,
    pub dereference_errors: Vec<String>,
}

impl From<VeranaTrustFullDetails> for VeranaTrustFullDetailsBindingDTO {
    fn from(value: VeranaTrustFullDetails) -> Self {
        Self {
            resolver_url: value.resolver_url,
            did: value.did,
            trust_status: value.trust_status,
            production: value.production,
            evaluated_at: value.evaluated_at,
            evaluated_at_block: value.evaluated_at_block.map(|value| value.to_string()),
            expires_at: value.expires_at,
            credentials: value.credentials.into_iter().map(Into::into).collect(),
            failed_credentials: value
                .failed_credentials
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
            dereference_errors: value
                .dereference_errors
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(VeranaTrustCredential)]
#[uniffi(name = "VeranaTrustCredential")]
pub struct VeranaTrustCredentialBindingDTO {
    pub id: Option<String>,
    pub credential_type: Option<String>,
    pub format: Option<String>,
    pub ecs_type: Option<String>,
    pub issued_by: Option<String>,
    pub presented_by: Option<String>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<VeranaTrustClaimBindingDTO>,
    #[from(with_fn = "permission_chain_to_strings")]
    pub permission_chain: Vec<String>,
    pub result: Option<String>,
}

fn permission_chain_to_strings(values: Vec<serde_json::Value>) -> Vec<String> {
    values.into_iter().map(|value| value.to_string()).collect()
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(VeranaTrustClaim)]
#[uniffi(name = "VeranaTrustClaim")]
pub struct VeranaTrustClaimBindingDTO {
    pub name: String,
    pub value: String,
    pub value_type: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(EudiTrustInformationResponseDTO)]
#[uniffi(name = "EudiTrustInformation")]
pub struct EudiTrustInformationResponseBindingDTO {
    pub name: String,
    pub website: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
    pub identifier: String,
    pub service_description: Vec<HashMap<String, String>>,
    pub supervisory_authority: EudiSupervisoryAuthorityResponseBindingDTO,
    #[from(with_fn = convert_inner)]
    pub intermediary: Option<EudiIntermediaryResponseBindingDTO>,
    pub is_public_sector: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(SupervisoryAuthority)]
#[uniffi(name = "EudiSupervisoryAuthority")]
pub(crate) struct EudiSupervisoryAuthorityResponseBindingDTO {
    pub email: String,
    pub phone: String,
    pub uri: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(EudiIntermediaryResponseDTO)]
#[uniffi(name = "EudiIntermediary")]
pub struct EudiIntermediaryResponseBindingDTO {
    pub name: Option<String>,
    pub identifier: String,
    pub website: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
}
