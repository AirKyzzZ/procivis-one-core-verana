use ct_codecs::{Base64, Decoder, Encoder};
use one_core::service::error::ServiceError;
use one_core::service::qes::dto::{
    QesAuthorizeRequestDTO, QesAuthorizeResponseDTO, QesSignRequestDTO, QesSignResponseDTO,
};
use one_dto_mapper::{From, TryFrom, TryInto};

use super::OneCore;
use crate::error::BindingError;
use crate::utils::into_id_opt;

fn decode_base64(value: String) -> Result<Vec<u8>, ServiceError> {
    Base64::decode_to_vec(value.trim(), None)
        .map_err(|_| ServiceError::ValidationError("`document` is not valid base64".to_string()))
}

fn encode_base64(value: Vec<u8>) -> Result<String, ServiceError> {
    Base64::encode_to_string(value).map_err(|e| ServiceError::MappingError(e.to_string()))
}

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Initiates the QES signing flow for a document with a configured
    /// QES provider. Returns an `authorizationUrl` for the user to
    /// authenticate with the provider, and a `codeVerifier` to be passed
    /// to the `qesSign` method on return.
    #[uniffi::method]
    pub async fn qes_authorize(
        &self,
        request: QesAuthorizeRequestBindingDTO,
    ) -> Result<QesAuthorizeResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .qes_service
            .authorize(request.try_into()?)
            .await?
            .into())
    }

    /// Completes the QES signing flow. Exchanges the authorization
    /// `code` received from the provider redirect and the `codeVerifier`
    /// from `qesAuthorize` for a signed document.
    #[uniffi::method]
    pub async fn qes_sign(
        &self,
        request: QesSignRequestBindingDTO,
    ) -> Result<QesSignResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .qes_service
            .sign(request.try_into()?)
            .await?
            .try_into()?)
    }
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = QesAuthorizeRequestDTO, Error = ServiceError)]
#[uniffi(name = "QesAuthorizeRequest")]
pub struct QesAuthorizeRequestBindingDTO {
    /// Configured document signer name (for example, `SIGN8`).
    #[try_into(infallible)]
    pub provider: String,
    /// Base64-encoded document to be signed.
    #[try_into(with_fn = decode_base64)]
    pub document: String,
    /// Wallet deep link to which the provider redirects after authorization,
    /// appending the authorization `code`. When omitted, the configured
    /// default is used.
    #[try_into(infallible)]
    pub redirect_uri: Option<String>,
    /// Organizational context. Optional when resolvable from STS auth.
    #[try_into(with_fn = into_id_opt)]
    pub organisation_id: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(QesAuthorizeResponseDTO)]
#[uniffi(name = "QesAuthorizeResponse")]
pub struct QesAuthorizeResponseBindingDTO {
    /// Authorization URL the wallet opens to identify and authorize signing.
    pub authorization_url: String,
    /// PKCE `code_verifier` to pass back to `qesSign`.
    pub code_verifier: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = QesSignRequestDTO, Error = ServiceError)]
#[uniffi(name = "QesSignRequest")]
pub struct QesSignRequestBindingDTO {
    /// Configured document signer name (for example, `SIGN8`).
    #[try_into(infallible)]
    pub provider: String,
    /// Authorization code from the document signer redirect.
    #[try_into(infallible)]
    pub code: String,
    /// `codeVerifier` returned from the `qesAuthorize` method.
    #[try_into(infallible)]
    pub code_verifier: String,
    /// Base64-encoded document to be signed. Must be identical to the
    /// document provided to `qes_authorize`.
    #[try_into(with_fn = decode_base64)]
    pub document: String,
    /// Wallet deep link. Must be identical to the one used at
    /// `qesAuthorize`. When omitted, the configured default
    /// is used.
    #[try_into(infallible)]
    pub redirect_uri: Option<String>,
    /// Organizational context. Optional when resolvable from STS auth.
    #[try_into(with_fn = into_id_opt)]
    pub organisation_id: Option<String>,
}

#[derive(Clone, Debug, TryFrom, uniffi::Record)]
#[try_from(T = QesSignResponseDTO, Error = ServiceError)]
#[uniffi(name = "QesSignResponse")]
pub struct QesSignResponseBindingDTO {
    /// Base64-encoded signed document returned by the QES provider.
    #[try_from(with_fn = encode_base64)]
    pub signed_document: String,
}
