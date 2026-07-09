use std::collections::HashMap;

use anyhow::Context;
use dcql::{CredentialQueryId, DcqlQuery};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{InteractionId, KeyId, TransactionDataId, TransactionDataType};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::{ClientMetadata, ResponseMode};
use strum::{Display, EnumString};
use time::OffsetDateTime;
use url::Url;

use super::mapper::{deserialize_with_serde_json, unix_timestamp_option};
use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::model::VerifierInfoAttestation;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JwePayload {
    pub aud: Option<Url>,
    #[serde(default, with = "unix_timestamp_option")]
    pub exp: Option<OffsetDateTime>,
    #[serde(flatten)]
    pub submission_data: VpSubmissionData,
    pub state: Option<String>,
}

impl JwePayload {
    pub(crate) fn try_from_json(payload: &[u8]) -> anyhow::Result<Self> {
        let payload =
            serde_json::from_slice(payload).context("JWE payload deserialization failed")?;

        Ok(payload)
    }

    pub(crate) fn try_into_json(&self) -> anyhow::Result<Vec<u8>> {
        let payload = serde_json::to_vec(self).context("JWE payload serialization failed")?;
        Ok(payload)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DcqlSubmission {
    pub vp_token: HashMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DcqlSubmissionEudi {
    pub vp_token: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseSubmission {
    pub response: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum VpSubmissionData {
    Dcql(DcqlSubmission),
    DcqlEudi(DcqlSubmissionEudi),
    EncryptedResponse(ResponseSubmission),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostRequestDTO {
    #[serde(flatten)]
    pub submission_data: VpSubmissionData,
    pub state: Option<InteractionId>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenID4VPDirectPostResponseDTO {
    pub redirect_uri: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct OpenID4VPClientMetadataJwks {
    pub keys: Vec<PublicJwk>,
}

/// Interaction data used for OpenID4VP on verifier side
/// - HTTP transport generates this
///
/// Important: This structure is used to deserialize
/// also from all the other verifier interaction data structures
/// during proof submission validation
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPVerifierInteractionContent {
    pub nonce: String,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: DcqlQuery,
    /// with client_id_scheme prefix (for Final 1.0)
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub response_uri: Option<String>,
    pub encryption_key: Option<PublicJwk>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_data: Vec<TransactionDataRequest>,
}

/// Transaction data as provided at proof-request creation, turned into an OpenID4VP
/// `transaction_data` entry by the transaction data provider named by `name`
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct TransactionDataRequest {
    pub name: TransactionDataType,
    pub credential_ids: Vec<CredentialQueryId>,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub(crate) struct SubmissionRequestData {
    pub submission_data: VpSubmissionData,
    pub state: InteractionId,
    pub mdoc_generated_nonce: Option<String>,
    pub encryption_key: Option<KeyId>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProvedCredential {
    pub credential: Credential,
    pub issuer_details: IdentifierDetails,
    pub holder_details: IdentifierDetails,
}

/// Interaction data used for OpenID4VP (HTTP) on holder side
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPHolderInteractionData {
    pub response_type: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub client_id_scheme: ClientIdScheme,

    /// without client_id_scheme prefix (in case of Final 1.0)
    pub client_id: String,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<ClientMetadata>,
    pub client_metadata_uri: Option<Url>,
    pub response_mode: Option<ResponseMode>,
    pub response_uri: Option<Url>,
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: DcqlQuery,
    #[serde(default)]
    pub transaction_data: HolderTxData,

    #[serde(default, skip_serializing)]
    pub redirect_uri: Option<String>,

    #[serde(default)]
    pub verifier_details: Option<IdentifierDetails>,
    #[serde(default)]
    pub verifier_info: Vec<VerifierInfoAttestation>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
pub enum HolderTxData {
    Unvalidated(Vec<String>),
    Validated(IndexMap<TransactionDataId, ValidatedHolderTxData>),
}

impl Default for HolderTxData {
    fn default() -> Self {
        Self::Unvalidated(Vec::new())
    }
}

impl HolderTxData {
    pub fn validated(
        &self,
    ) -> Result<IndexMap<TransactionDataId, ValidatedHolderTxData>, VerificationProtocolError> {
        match self {
            HolderTxData::Validated(tx_data) => Ok(tx_data.clone()),
            HolderTxData::Unvalidated(d) if d.is_empty() => Ok(IndexMap::new()),
            HolderTxData::Unvalidated(_) => Err(VerificationProtocolError::Failed(
                "Unvalidated transaction data".to_string(),
            )),
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct ValidatedHolderTxData {
    /// Raw base64URL-encoded transaction data.
    pub raw: String,
    /// Credential ids the transaction data is for.
    pub credential_query_ids: Vec<CredentialQueryId>,
    /// Config name of the `TransactionData` provider that validated this entry.
    pub transaction_data_type: TransactionDataType,
}

// Apparently the indirection via functions is required: https://github.com/serde-rs/serde/issues/368
pub(crate) fn default_presentation_url_scheme() -> String {
    "openid4vp".to_string()
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize, Serialize, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ClientIdScheme {
    RedirectUri,
    VerifierAttestation,
    #[serde(alias = "decentralized_identifier")]
    Did,
    X509SanDns,
    X509Hash,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCRedirectUriParams {
    pub enabled: bool,
    pub allowed_schemes: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct OpenID4VCVerifierAttestationPayload {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
}
