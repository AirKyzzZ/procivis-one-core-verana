use std::str::FromStr;

use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::IdentifierType;
use serde_json::Value;
use shared_types::DidValue;
use similar_asserts::assert_eq;

use crate::fixtures::{
    TestingDidParams, TestingIdentifierParams, create_cert_identifier, create_eddsa_key,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success_with_did_draft13() {
    test_get_sd_jwt_vc_issuer_metadata_success_with_did("OPENID4VCI_DRAFT13").await;
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success_with_did_final1() {
    test_get_sd_jwt_vc_issuer_metadata_success_with_did("OPENID4VCI_FINAL1").await;
}

async fn test_get_sd_jwt_vc_issuer_metadata_success_with_did(protocol_id: &str) {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = create_eddsa_key(&context.db.db_conn, &organisation).await;

    let did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did: Some(DidValue::from_str("did:test:123").unwrap()),
                did_type: Some(DidType::Local),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key,
                    reference: "key-1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                ..Default::default()
            },
        )
        .await;

    let schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &organisation,
            None,
            TestingCreateSchemaParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_issuer_metadata(protocol_id, identifier.id, schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json_value().await;
    assert_eq!(body["issuer"], "did:test:123");
    assert!(body["jwks_uri"].is_null());
    let jwk = &body["jwks"]["keys"][0];
    assert_eq!(jwk["alg"], "ECDH-ES");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["use"], "enc");
    assert!(!jwk["kid"].is_null());
    assert!(!jwk["x"].is_null());
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success_with_key_draft13() {
    test_get_sd_jwt_vc_issuer_metadata_success_with_key("OPENID4VCI_DRAFT13").await;
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success_with_key_final1() {
    test_get_sd_jwt_vc_issuer_metadata_success_with_key("OPENID4VCI_FINAL1").await;
}

async fn test_get_sd_jwt_vc_issuer_metadata_success_with_key(protocol_id: &str) {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = create_eddsa_key(&context.db.db_conn, &organisation).await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                key: Some(key),
                r#type: Some(IdentifierType::Key),
                ..Default::default()
            },
        )
        .await;

    let schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &organisation,
            None,
            TestingCreateSchemaParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_issuer_metadata(protocol_id, identifier.id, schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json_value().await;
    let expected_issuer = format!(
        "{}/ssi/openid4vci/{protocol_id}/{}/{}",
        context.config.app.core_base_url, identifier.id, schema.id
    );
    assert_eq!(body["issuer"], expected_issuer);
    assert!(body["jwks_uri"].is_null());
    let jwk = &body["jwks"]["keys"][0];
    assert_eq!(jwk["alg"], "ECDH-ES");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["use"], "enc");
    assert!(!jwk["kid"].is_null());
    assert!(!jwk["x"].is_null());
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success_with_certificate_draft13() {
    test_get_sd_jwt_vc_issuer_metadata_success_with_certificate("OPENID4VCI_DRAFT13").await;
}

#[tokio::test]
async fn test_get_sd_jwt_vc_issuer_metadata_success_with_certificate_final1() {
    test_get_sd_jwt_vc_issuer_metadata_success_with_certificate("OPENID4VCI_FINAL1").await;
}

async fn test_get_sd_jwt_vc_issuer_metadata_success_with_certificate(protocol_id: &str) {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let identifier = create_cert_identifier(&context, &organisation, None, None).await;

    let schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &organisation,
            None,
            TestingCreateSchemaParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_sd_jwt_vc_issuer_metadata(protocol_id, identifier.id, schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json_value().await;
    let expected_issuer = format!(
        "{}/ssi/openid4vci/{protocol_id}/{}/{}",
        context.config.app.core_base_url, identifier.id, schema.id
    );
    assert_eq!(body["issuer"], expected_issuer);
    assert!(body["jwks_uri"].is_null());
    let jwk = &body["jwks"]["keys"][0];
    assert_eq!(jwk["alg"], "ECDH-ES");
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["use"], "enc");
    assert!(!jwk["kid"].is_null());
    assert!(!jwk["x"].is_null());
}
