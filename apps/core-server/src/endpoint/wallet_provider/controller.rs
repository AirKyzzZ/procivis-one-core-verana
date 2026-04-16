use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{Permission, WalletUnitId};

use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::wallet_provider::dto::{
    GetWalletInstancesResponseRestDTO, ListWalletInstancesQuery, WalletInstanceResponseRestDTO,
};
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::WalletInstanceList],
    get,
    path = "/api/wallet-instance/v1",
    params(ListWalletInstancesQuery),
    responses(OkOrErrorResponse<GetWalletInstancesResponseRestDTO>),
    tag = "wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "List wallet instances",
    description = indoc::formatdoc! {"
    Returns a list of wallet instances.
"},
)]
pub(crate) async fn get_wallet_unit_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<ListWalletInstancesQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetWalletInstancesResponseRestDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .wallet_provider_service
                .get_wallet_unit_list(query.try_into()?)
                .await
                .error_while("getting wallet instances")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting wallet instance list")
}

#[endpoint(
    permissions = [Permission::WalletInstanceDetail],
    get,
    path = "/api/wallet-instance/v1/{id}",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet instance id")
    ),
    responses(OkOrErrorResponse<WalletInstanceResponseRestDTO>),
    tag = "wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a wallet instance",
    description = "Returns details on a given wallet instance.",
)]
pub(crate) async fn get_wallet_unit_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<WalletInstanceResponseRestDTO> {
    let result = state
        .core
        .wallet_provider_service
        .get_wallet_unit(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "fetching wallet unit")
}

#[endpoint(
    permissions = [Permission::WalletInstanceRevoke],
    post,
    path = "/api/wallet-instance/v1/{id}/revoke",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet instance id")
    ),
    responses(EmptyOrErrorResponse),
    tag = "wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Revoke a wallet instance",
    description = indoc::formatdoc! {"
        Revokes a wallet instance, preventing issuance of any new attestation. If Token
        Status List is enabled for WIAs, all existing attestations are revoked as well.
    "},
)]
pub(crate) async fn revoke_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_provider_service
        .revoke_wallet_unit(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "revoking wallet instance")
}

#[endpoint(
    permissions = [Permission::WalletInstanceDelete],
    delete,
    path = "/api/wallet-instance/v1/{id}",
    params(
        ("id" = WalletUnitId, Path, description = "Wallet instance id")
    ),
    responses(EmptyOrErrorResponse),
    tag = "wallet_instance",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a wallet instance",
    description = "Permanently deletes a given wallet instance from the database, including history entries.",
)]
pub(crate) async fn remove_wallet_unit(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<WalletUnitId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .wallet_provider_service
        .delete_wallet_unit(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting wallet instance")
}
