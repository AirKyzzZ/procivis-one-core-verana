use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{HolderWalletInstanceId, Permission};

use super::dto::{
    EditHolderWalletInstanceRequestRestDTO, HolderActivateWalletInstanceRequestRestDTO,
    HolderRegisterWalletInstanceRequestRestDTO, HolderRegisterWalletInstanceResponseRestDTO,
    HolderWalletInstanceDetailRestDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::holder_wallet_instance::dto::TrustCollectionsDetailRestDTO;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::HolderWalletInstanceRegister],
    post,
    path = "/api/holder-wallet-instance/v1",
    request_body = HolderRegisterWalletInstanceRequestRestDTO,
    responses(CreatedOrErrorResponse<HolderRegisterWalletInstanceResponseRestDTO>),
    tag = "holder_wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Register with a Wallet Provider",
    description = indoc::formatdoc! {"
        Register a wallet instance with a Wallet Provider.
    "},
)]
pub(crate) async fn wallet_instance_holder_register(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<HolderRegisterWalletInstanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<HolderRegisterWalletInstanceResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .wallet_unit_service
                .holder_register(request.try_into()?)
                .await
                .error_while("registering holder wallet instance")?,
        )
    }
    .await;
    CreatedOrErrorResponse::from_result(result, state, "register wallet instance")
}

#[endpoint(
    permissions = [Permission::HolderWalletInstanceDetail],
    get,
    path = "/api/holder-wallet-instance/v1/{id}",
    responses(OkOrErrorResponse<HolderWalletInstanceDetailRestDTO>),
    params(
        ("id" = HolderWalletInstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "holder_wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve wallet registration details",
    description = "Retrieve details of a wallet instance's registration from the Wallet Provider.",
)]
pub(crate) async fn wallet_instance_holder_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletInstanceId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<HolderWalletInstanceDetailRestDTO> {
    let result = state
        .core
        .wallet_unit_service
        .holder_get_wallet_unit_details(id)
        .await
        .error_while("getting holder wallet instance")
        .map_err(ServiceError::from);

    OkOrErrorResponse::from_result_fallible(result, state, "getting holder wallet instance")
}

#[endpoint(
    permissions = [Permission::HolderWalletInstanceDetail],
    post,
    path = "/api/holder-wallet-instance/v1/{id}/status",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = HolderWalletInstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "holder_wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Check wallet status",
    description = indoc::formatdoc! {
        "Check the status of a wallet instance. Active instances return `204`. Revoked instances return an error."},
)]
pub(crate) async fn wallet_instance_holder_status(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletInstanceId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_unit_service
        .holder_wallet_unit_status(id)
        .await;

    EmptyOrErrorResponse::from_result(result, state, "holder wallet instance status check")
}

#[endpoint(
    permissions = [Permission::HolderWalletInstanceEdit],
    patch,
    path = "/api/holder-wallet-instance/v1/{id}",
    request_body = EditHolderWalletInstanceRequestRestDTO,
    responses(EmptyOrErrorResponse),
    params(
        ("id" = HolderWalletInstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "holder_wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Edit wallet settings",
    description = "Modify wallet settings.",
)]
pub(crate) async fn edit_holder_wallet_instance(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletInstanceId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<EditHolderWalletInstanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_unit_service
        .edit_holder_wallet_unit(id, request.into())
        .await;

    EmptyOrErrorResponse::from_result(result, state, "editing holder wallet instance")
}

#[endpoint(
    permissions = [Permission::HolderWalletInstanceDetail],
    get,
    path = "/api/holder-wallet-instance/v1/{id}/trust-collections",
    responses(OkOrErrorResponse<TrustCollectionsDetailRestDTO>),
    params(
        ("id" = HolderWalletInstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "holder_wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Get trust collections",
    description = "Get trust collections associated with the given holder wallet instance",
)]
pub(crate) async fn get_holder_wallet_instance_trust_collections(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletInstanceId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<TrustCollectionsDetailRestDTO> {
    let result = state
        .core
        .wallet_unit_service
        .holder_get_wallet_unit_trust_collections(id)
        .await;

    OkOrErrorResponse::from_result(
        result,
        state,
        "getting holder wallet instance trust collections",
    )
}

#[endpoint(
    permissions = [Permission::HolderWalletInstanceRegister],
    post,
    path = "/api/holder-wallet-instance/v1/{id}/activate",
    request_body = HolderActivateWalletInstanceRequestRestDTO,
    responses(EmptyOrErrorResponse),
    params(
        ("id" = HolderWalletInstanceId, Path, description = "Wallet Instance ID")
    ),
    tag = "holder_wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Activate wallet instance",
    description = indoc::formatdoc! {"
        Complete registration by activating the wallet instance with the Wallet Provider.
        Required when the Wallet Provider has user authentication configured.
    "},
)]
pub(crate) async fn holder_activate_wallet_instance(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<HolderWalletInstanceId>, ErrorResponseRestDTO>,
    WithRejection(Json(request), _): WithRejection<
        Json<HolderActivateWalletInstanceRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_unit_service
        .holder_activate(id, request.into())
        .await;

    EmptyOrErrorResponse::from_result(result, state, "activating holder wallet instance")
}
