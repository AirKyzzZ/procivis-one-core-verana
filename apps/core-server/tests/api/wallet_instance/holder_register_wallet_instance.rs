use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::api_clients::holder_wallet_instance::{
    TestHolderActivateRequest, TestHolderRegisterRequest,
};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

fn metadata_without_user_auth() -> serde_json::Value {
    json!({
        "name": "PROCIVIS_ONE",
        "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
        },
        "featureFlags": {
            "trustEcosystemsEnabled": true,
            "refreshCredentialBatchEnabled": true
        },
        "trustCollections": []
    })
}

fn metadata_with_user_auth() -> serde_json::Value {
    json!({
        "name": "PROCIVIS_ONE",
        "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
        },
        "featureFlags": {
            "trustEcosystemsEnabled": true,
            "refreshCredentialBatchEnabled": true
        },
        "trustCollections": [],
        "userAuthentication": {
            "required": true,
            "identityProvider": "https://idp.example.com",
            "clientId": "wallet-client",
            "redirectUri": "https://wallet.example.com/callback",
            "tokenValidation": {
                "aud": "wallet-client",
                "iss": "https://idp.example.com",
                "jwksUri": "https://idp.example.com/.well-known/jwks.json"
            }
        }
    })
}

fn metadata_with_optional_user_auth() -> serde_json::Value {
    json!({
        "name": "PROCIVIS_ONE",
        "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
        },
        "featureFlags": {
            "trustEcosystemsEnabled": true,
            "refreshCredentialBatchEnabled": true
        },
        "trustCollections": [],
        "userAuthentication": {
            "required": false,
            "identityProvider": "https://idp.example.com",
            "clientId": "wallet-client",
            "redirectUri": "https://wallet.example.com/callback",
            "tokenValidation": {
                "aud": "wallet-client",
                "iss": "https://idp.example.com",
                "jwksUri": "https://idp.example.com/.well-known/jwks.json"
            }
        }
    })
}

#[tokio::test]
async fn holder_register_wallet_unit_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["status"], "ACTIVE");
    assert!(resp["userNonce"].is_null());
    let history = context
        .db
        .histories
        .get_by_entity_id(&resp["id"].parse())
        .await;
    assert!(!history.values.is_empty());
}

#[tokio::test]
async fn holder_register_wallet_unit_with_user_auth_sets_pending_status() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_with_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
            "userNonce": "user-nonce-abc123",
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["status"], "PENDING");
    assert_eq!(resp["userNonce"], "user-nonce-abc123");
}

#[tokio::test]
async fn holder_register_wallet_unit_with_user_auth_skips_activation() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_with_user_auth()))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
            "userNonce": "user-nonce-abc123",
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // activate endpoint must NOT be called
    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1/activate"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["status"], "PENDING");
}

async fn register_with_user_auth(
    context: &crate::utils::context::TestContext,
    org_id: shared_types::OrganisationId,
    mock_server: &wiremock::MockServer,
    metadata: serde_json::Value,
) -> shared_types::HolderWalletInstanceId {
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
            "userNonce": "user-nonce-abc123",
        })))
        .mount(mock_server)
        .await;

    let resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org_id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;
    assert_eq!(resp.status(), 201);
    resp.json_value().await["id"].parse()
}

#[tokio::test]
async fn holder_activate_wallet_unit_successfully() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id =
        register_with_user_auth(&context, org.id, &mock_server, metadata_with_user_auth()).await;

    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/wallet-unit/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: Some("my-jwt-token".to_string()),
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn holder_activate_wallet_unit_without_user_auth_returns_error() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    // Register WITHOUT user_authentication configured
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .mount(&mock_server)
        .await;

    let register_resp = context
        .api
        .holder_wallet_instances
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;
    assert_eq!(register_resp.status(), 201);
    let wallet_unit_id: shared_types::HolderWalletInstanceId =
        register_resp.json_value().await["id"].parse();

    // metadata mock for activate call (same endpoint, returns without userAuthentication)
    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata_without_user_auth()))
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(&wallet_unit_id, TestHolderActivateRequest::default())
        .await;

    // THEN - wallet unit is Active (not Pending), so activation is rejected before user-auth check
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0450");
}

#[tokio::test]
async fn holder_activate_wallet_unit_not_found_returns_404() {
    // GIVEN
    let context = TestContext::new(None).await;
    let non_existent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &non_existent_id.into(),
            TestHolderActivateRequest::default(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn holder_activate_wallet_unit_passes_user_id_token_to_provider() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id =
        register_with_user_auth(&context, org.id, &mock_server, metadata_with_user_auth()).await;

    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/wallet-unit/v1/.*/activate",
        ))
        .and(wiremock::matchers::body_partial_json(json!({
            "userIdToken": "user-jwt-token-xyz"
        })))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: Some("user-jwt-token-xyz".to_string()),
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn holder_activate_wallet_unit_optional_auth_skips_sign_in() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id = register_with_user_auth(
        &context,
        org.id,
        &mock_server,
        metadata_with_optional_user_auth(),
    )
    .await;

    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/wallet-unit/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN - user skips sign-in (no id token) and authentication is optional
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn holder_activate_wallet_unit_required_auth_missing_token_fails_early() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let mock_server = MockServer::builder().start().await;

    let wallet_unit_id =
        register_with_user_auth(&context, org.id, &mock_server, metadata_with_user_auth()).await;

    // activate endpoint must NOT be called when the required token is missing
    Mock::given(method(Method::POST))
        .and(wiremock::matchers::path_regex(
            r"/ssi/wallet-unit/v1/.*/activate",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    // WHEN - authentication is required but no id token is supplied
    let resp = context
        .api
        .holder_wallet_instances
        .holder_activate(
            &wallet_unit_id,
            TestHolderActivateRequest {
                key_type: Some("ECDSA".to_string()),
                user_id_token: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let body = resp.json_value().await;
    assert_eq!(body["code"], "BR_0454");
}
