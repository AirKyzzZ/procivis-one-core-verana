use ct_codecs::{Base64, Decoder, Encoder};
use one_core::service::error::ServiceError;
use one_core::service::qes::dto::{
    QesAuthorizeRequestDTO, QesAuthorizeResponseDTO, QesSignRequestDTO, QesSignResponseDTO,
};
use one_dto_mapper::{From, TryFrom, TryInto};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use utoipa::ToSchema;

fn decode_base64(value: String) -> Result<Vec<u8>, ServiceError> {
    Base64::decode_to_vec(value.trim(), None)
        .map_err(|_| ServiceError::ValidationError("`document` is not valid base64".to_string()))
}

fn encode_base64(value: Vec<u8>) -> Result<String, ServiceError> {
    Base64::encode_to_string(value).map_err(|e| ServiceError::MappingError(e.to_string()))
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = QesAuthorizeRequestDTO, Error = ServiceError)]
pub(crate) struct QesAuthorizeRequestRestDTO {
    /// Configured document signer name (e.g. `SIGN8`).
    #[try_into(infallible)]
    pub provider: String,
    /// Base64-encoded document to be signed (e.g. a PDF with PAdES).
    #[try_into(with_fn = decode_base64)]
    pub document: String,
    /// Wallet deep link the document signer redirects to with the `code`.
    /// When omitted, the configured default is used.
    #[try_into(infallible)]
    pub redirect_uri: Option<String>,
    /// Organisation context. Optional when resolvable from STS auth.
    #[try_into(infallible)]
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(QesAuthorizeResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QesAuthorizeResponseRestDTO {
    /// Authorization URL the wallet opens to identify and authorize signing.
    pub authorization_url: String,
    /// PKCE `code_verifier` to pass back to `/api/qes/v1/sign`.
    pub code_verifier: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = QesSignRequestDTO, Error = ServiceError)]
pub(crate) struct QesSignRequestRestDTO {
    /// Configured document signer name (e.g. `SIGN8`).
    #[try_into(infallible)]
    pub provider: String,
    /// Authorization code from the document signer redirect.
    #[try_into(infallible)]
    pub code: String,
    /// `codeVerifier` returned from `/api/qes/v1/authorize`.
    #[try_into(infallible)]
    pub code_verifier: String,
    /// Base64-encoded document to be signed (the same one authorized).
    #[try_into(with_fn = decode_base64)]
    pub document: String,
    /// Wallet deep link; must match the one used at `/api/qes/v1/authorize`.
    /// When omitted, the configured default is used.
    #[try_into(infallible)]
    pub redirect_uri: Option<String>,
    /// Organisation context. Optional when resolvable from STS auth.
    #[try_into(infallible)]
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = QesSignResponseDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QesSignResponseRestDTO {
    /// Base64-encoded signed document (e.g. a PAdES PDF).
    #[try_from(with_fn = encode_base64)]
    pub signed_document: String,
}
