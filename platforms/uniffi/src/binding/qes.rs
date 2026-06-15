use one_core::service::error::ServiceError;
use one_core::service::qes::dto::{
    QesAuthorizeRequestDTO, QesAuthorizeResponseDTO, QesSignRequestDTO, QesSignResponseDTO,
};
use one_dto_mapper::{From, TryInto};

use super::OneCore;
use crate::error::BindingError;
use crate::utils::into_id_opt;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
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

    #[uniffi::method]
    pub async fn qes_sign(
        &self,
        request: QesSignRequestBindingDTO,
    ) -> Result<QesSignResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core.qes_service.sign(request.try_into()?).await?.into())
    }
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = QesAuthorizeRequestDTO, Error = ServiceError)]
#[uniffi(name = "QesAuthorizeRequest")]
pub struct QesAuthorizeRequestBindingDTO {
    #[try_into(infallible)]
    pub provider: String,
    #[try_into(infallible)]
    pub document: Vec<u8>,
    #[try_into(infallible)]
    pub redirect_uri: Option<String>,
    #[try_into(with_fn = into_id_opt)]
    pub organisation_id: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(QesAuthorizeResponseDTO)]
#[uniffi(name = "QesAuthorizeResponse")]
pub struct QesAuthorizeResponseBindingDTO {
    pub authorization_url: String,
    pub code_verifier: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = QesSignRequestDTO, Error = ServiceError)]
#[uniffi(name = "QesSignRequest")]
pub struct QesSignRequestBindingDTO {
    #[try_into(infallible)]
    pub provider: String,
    #[try_into(infallible)]
    pub code: String,
    #[try_into(infallible)]
    pub code_verifier: String,
    #[try_into(infallible)]
    pub document: Vec<u8>,
    #[try_into(infallible)]
    pub redirect_uri: Option<String>,
    #[try_into(with_fn = into_id_opt)]
    pub organisation_id: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(QesSignResponseDTO)]
#[uniffi(name = "QesSignResponse")]
pub struct QesSignResponseBindingDTO {
    pub signed_document: Vec<u8>,
}
