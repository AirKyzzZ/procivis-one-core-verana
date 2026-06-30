use std::collections::HashMap;

use anyhow::Context;
use dcql::DcqlQuery;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{ClaimSchemaId, InteractionId, KeyId};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::{ClientMetadata, PresentationFormat, ResponseMode};
use strum::{Display, EnumString};
use time::OffsetDateTime;
use url::Url;

use super::mapper::{deserialize_with_serde_json, unix_timestamp_option};
use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::IdentifierDetails;
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
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: Option<DcqlQuery>,
    /// with client_id_scheme prefix (for Final 1.0)
    pub client_id: String,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub response_uri: Option<String>,
    pub encryption_key: Option<PublicJwk>,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct OpenID4VPPresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<OpenID4VPPresentationDefinitionInputDescriptor>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct OpenID4VPPresentationDefinitionInputDescriptor {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub format: HashMap<String, PresentationFormat>,
    pub constraints: OpenID4VPPresentationDefinitionConstraint,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct OpenID4VPPresentationDefinitionConstraint {
    pub fields: Vec<OpenID4VPPresentationDefinitionConstraintField>,
    #[serde(default)]
    pub limit_disclosure: Option<OpenID4VPPresentationDefinitionLimitDisclosurePreference>,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum OpenID4VPPresentationDefinitionLimitDisclosurePreference {
    Required,
    Preferred,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct OpenID4VPPresentationDefinitionConstraintField {
    pub id: Option<ClaimSchemaId>,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub path: Vec<String>,
    pub optional: Option<bool>,
    pub filter: Option<OpenID4VPPresentationDefinitionConstraintFieldFilter>,
    #[serde(default)]
    pub intent_to_retain: Option<bool>,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq)]
pub struct OpenID4VPPresentationDefinitionConstraintFieldFilter {
    pub r#type: String,
    pub r#const: String,
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
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    pub presentation_definition_uri: Option<Url>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_with_serde_json")]
    pub dcql_query: Option<DcqlQuery>,

    #[serde(default, skip_serializing)]
    pub redirect_uri: Option<String>,

    #[serde(default)]
    pub verifier_details: Option<IdentifierDetails>,
    #[serde(default)]
    pub verifier_info: Vec<VerifierInfoAttestation>,
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
