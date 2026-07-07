use dcql::DcqlQuery;
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, VecSkipError, serde_as, skip_serializing_none};
use standardized_types::openid4vp::{ClientMetadata, ResponseMode};
use time::Duration;
use url::Url;

use crate::provider::verification_protocol::model::CommonParams;
use crate::provider::verification_protocol::openid4vp::mapper::deserialize_with_serde_json;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCRedirectUriParams, default_presentation_url_scheme,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde(default)]
    pub use_legacy_did_client_id_scheme: bool,
    #[serde(default)]
    pub use_request_uri: bool,

    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,

    pub holder: HolderParams,
    pub verifier: PresentationVerifierParams,
    pub redirect_uri: OpenID4VCRedirectUriParams,
    // Required to handle SWIYU verification requests that have invalid client_metadata.
    // Remove when the SWIYU provider is removed.
    pub predefined_client_metadata: Option<ClientMetadata>,

    #[serde(flatten)]
    pub common: CommonParams,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderParams {
    pub supported_client_id_schemes: Vec<ClientIdScheme>,

    #[serde(default)]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub trust_ecosystems_leeway: Duration,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationVerifierParams {
    pub supported_client_id_schemes: Vec<ClientIdScheme>,
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub interaction_expires_in: Option<Duration>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub(crate) struct AuthorizationRequestQueryParams {
    /// with client_id_scheme prefix
    pub client_id: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<ResponseMode>,
    pub response_uri: Option<String>,
    pub client_metadata: Option<String>,
    pub dcql_query: Option<String>,
    pub transaction_data: Option<Vec<String>>,

    // https://www.rfc-editor.org/rfc/rfc9101.html#name-authorization-request
    pub request: Option<String>,
    pub request_uri: Option<String>,

    pub redirect_uri: Option<String>,
}

#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub(crate) struct AuthorizationRequest {
    /// with client_id_scheme prefix
    pub client_id: String,

    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,

    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub response_mode: Option<ResponseMode>,
    #[serde(default)]
    pub response_uri: Option<Url>,

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<ClientMetadata>,

    #[serde(default)]
    pub dcql_query: Option<DcqlQuery>,

    #[serde(default)]
    pub redirect_uri: Option<String>,

    #[serde_as(as = "VecSkipError<_>")] // wallets SHOULD ignore any unrecognized or unsupported Verifier Info types
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_info: Vec<VerifierInfoAttestation>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_data: Vec<String>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct VerifierInfoAttestation {
    pub format: VerifierInfoAttestationFormat,
    pub data: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_ids: Vec<dcql::CredentialQueryId>,
}

#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq)]
pub(crate) enum VerifierInfoAttestationFormat {
    #[serde(rename = "registration_cert")]
    RegistrationCert,
}
