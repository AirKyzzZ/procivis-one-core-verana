use std::collections::HashSet;
use std::str::FromStr;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::KeyStorageSecurity;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::IdentifierType;
use one_core::model::interaction::InteractionType;
use one_core::proto::jwt::Jwt;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::macros::datetime;
use uuid::Uuid;

use crate::fixtures::interaction::{InteractionDataParams, dummy_interaction_data};
use crate::fixtures::presentation::w3c_jwt_vc;
use crate::fixtures::wallet_provider::create_wallet_unit_attestation_issuer_identifier;
use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::holder_wallet_instance::TestHolderWalletInstanceParams;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::db_clients::wallet_instances::TestWalletInstance;
use crate::utils::field_match::FieldHelpers;

async fn random_document() -> String {
    let key = Ecdsa.generate_key().unwrap();
    let multibase = key.key.public_key_as_multibase().unwrap();
    let did: DidValue = format!("did:key:{multibase}").parse().unwrap();
    w3c_jwt_vc(
        &key,
        "ES256",
        did.clone(),
        did.clone(),
        json!({"string":"value"}),
    )
    .await
}

#[tokio::test]
async fn test_issuance_accept_openid4vc() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let metadata_schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    ClaimSchema {
                        business_key: None,
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    ClaimSchema {
                        business_key: None,
                        id: metadata_schema_id.into(),
                        key: "iss".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: true,
                        required: false,
                        translations: Default::default(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        holder_did.id,
        credential.holder_identifier.unwrap().did.unwrap().id
    );
    assert_eq!(CredentialStateEnum::Accepted, credential.state);

    let claims = credential.claims.unwrap();
    let iss_claim = claims.iter().find(|claim| claim.path == "iss").unwrap();
    assert_eq!(
        iss_claim.value.as_ref().unwrap(),
        &issuer_did.did.to_string()
    );
    assert_eq!(iss_claim.selectively_disclosable, false);
    assert_eq!(iss_claim.schema.as_ref().unwrap().metadata, true);
    let payload_claim = claims.iter().find(|claim| claim.path == "string").unwrap();
    assert_eq!(payload_claim.value.as_ref().unwrap(), "string");
    assert_eq!(payload_claim.selectively_disclosable, false);
    assert_eq!(payload_claim.schema.as_ref().unwrap().metadata, false);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    assert_eq!(history.values.len(), 3); // Accepted + Issued + Trust resolved
    let actions = HashSet::from_iter(history.values.iter().map(|value| value.action));
    assert_eq!(
        actions,
        HashSet::from([
            HistoryAction::Accepted,
            HistoryAction::Issued,
            HistoryAction::TrustResolved
        ])
    );
}

#[tokio::test]
async fn test_issuance_accept_schema_name_already_exists() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let metadata_schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![
                    ClaimSchema {
                        business_key: None,
                        id: schema_id.into(),
                        key: "string".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    ClaimSchema {
                        business_key: None,
                        id: metadata_schema_id.into(),
                        key: "iss".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: datetime!(2024-10-20 12:00 +1),
                        last_modified: datetime!(2024-10-20 12:00 +1),
                        array: false,
                        metadata: true,
                        required: false,
                        translations: Default::default(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "123", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id().await.unwrap(), "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let credential_id = resp.json::<serde_json::Value>().await["id"].parse();
    let credential = context.db.credentials.get(&credential_id).await;
    let credential_schema = credential.schema.as_ref().unwrap();

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    assert_eq!(history.values.len(), 3); // Accepted + Issued + TrustResolved
    let actions = HashSet::from_iter(history.values.iter().map(|value| value.action));
    assert_eq!(
        actions,
        HashSet::from([
            HistoryAction::Accepted,
            HistoryAction::Issued,
            HistoryAction::TrustResolved
        ])
    );

    // Assert credential schema has been automatically renamed due to clash with existing schema
    // also named "test".
    assert_ne!(credential_schema.name, "test");
    assert!(credential_schema.name.starts_with("test_"));
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_issuer_invalid_signature() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    business_key: None,
                    id: schema_id.into(),
                    key: "string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: datetime!(2024-10-20 12:00 +1),
                    last_modified: datetime!(2024-10-20 12:00 +1),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let document = random_document().await;
    let (jwt_content, _sig) = document.rsplit_once(".").unwrap();
    let document_invalid_sig = format!("{jwt_content}.invalid");

    context
        .server_mock
        .ssi_credential_endpoint(
            credential_schema.id,
            "123",
            &[document_invalid_sig],
            1,
            None,
        )
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0173")
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_key_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    business_key: None,
                    id: schema_id.into(),
                    key: "string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: datetime!(2024-10-20 12:00 +1),
                    last_modified: datetime!(2024-10-20 12:00 +1),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        holder_did.id,
        credential.holder_identifier.unwrap().did.unwrap().id
    );
    assert_eq!(key.id, credential.key.unwrap().id);

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_issuance_accept_autogenerate_holder_binding() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    business_key: None,
                    id: schema_id.into(),
                    key: "string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: datetime!(2024-10-20 12:00 +1),
                    last_modified: datetime!(2024-10-20 12:00 +1),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        issuer_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_did() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
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
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            Some(Uuid::new_v4().into()),
            None,
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0024", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_unknown_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
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
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            holder_did.id,
            Some(Uuid::new_v4().into()),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wrong_key_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
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
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0330");
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_no_suitable_key_storage() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                key_storage_security: Some(KeyStorageSecurity::EnhancedBasic),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, None, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0217", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_no_key_with_auth_role() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
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
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0096", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_issuance_accept_openid4vc_wallet_storage_type_not_met() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                key_storage_security: Some(KeyStorageSecurity::High),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams::default(),
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, Some(key.id), None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0310", resp.error_code().await);
}

#[tokio::test]
async fn test_issuance_accept_openid4vc_with_tx_code() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    business_key: None,
                    id: schema_id.into(),
                    key: "string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: datetime!(2024-10-20 12:00 +1),
                    last_modified: datetime!(2024-10-20 12:00 +1),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            require_tx_code: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"string"}),
    )
    .await;
    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    let tx_code = "45454";

    context
        .server_mock
        .token_endpoint_tx_code(credential_schema.schema_id().await.unwrap(), "123", tx_code)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(interaction.id, holder_did.id, None, Some(tx_code), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        holder_did.id,
        credential.holder_identifier.unwrap().did.unwrap().id
    );

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}

#[tokio::test]
async fn test_wia_pop_iss_equals_wia_sub() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    create_wallet_unit_attestation_issuer_identifier(&context, &organisation).await;

    let holder_key_params = ecdsa_testing_params();
    let holder_public_jwk = Ecdsa
        .reconstruct_key(holder_key_params.public_key.as_ref().unwrap(), None, None)
        .unwrap()
        .public_key_as_jwk()
        .unwrap();

    let holder_auth_key = context
        .db
        .keys
        .create(&organisation, holder_key_params)
        .await;

    let wallet_unit = context
        .db
        .wallet_instances
        .create(
            organisation.clone(),
            TestWalletInstance {
                public_key: Some(holder_public_jwk),
                ..Default::default()
            },
        )
        .await;

    let holder_wallet_unit = context
        .db
        .holder_wallet_units
        .create(
            organisation.clone(),
            Some(holder_auth_key),
            TestHolderWalletInstanceParams {
                wallet_provider_url: Some(context.config.app.core_base_url.clone()),
                provider_wallet_unit_id: Some(wallet_unit.id),
                ..Default::default()
            },
        )
        .await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let issuer_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                did_type: Some(DidType::Remote),
                did: Some(format!("did:key:{multibase}").parse().unwrap()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let holder_did_key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_did_key,
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test_wia_pop",
            &organisation,
            None,
            TestingCreateSchemaParams {
                claim_schemas: Some(vec![ClaimSchema {
                    business_key: None,
                    id: schema_id.into(),
                    key: "string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: datetime!(2024-10-20 12:00 +1),
                    last_modified: datetime!(2024-10-20 12:00 +1),
                    array: false,
                    metadata: false,
                    required: true,
                    translations: Default::default(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            require_instance_attestation: true,
            ..Default::default()
        },
    );

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let jwt_credential = w3c_jwt_vc(
        &issuer_key,
        "ES256",
        issuer_did.did.clone(),
        holder_did.did.clone(),
        json!({"string":"value"}),
    )
    .await;

    context
        .server_mock
        .ssi_credential_endpoint(credential_schema.id, "123", &[jwt_credential], 1, None)
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.id, "123")
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_accept(
            interaction.id,
            holder_did.id,
            None,
            None,
            holder_wallet_unit.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let requests = context.server_mock.received_requests().await.unwrap();
    let token_request = requests
        .iter()
        .find(|r| r.url.path().contains("/token"))
        .expect("Token request not found");

    let wia_header = token_request
        .headers
        .get("oauth-client-attestation")
        .expect("OAuth-Client-Attestation header not found");
    let wia_pop_header = token_request
        .headers
        .get("oauth-client-attestation-pop")
        .expect("OAuth-Client-Attestation-PoP header not found");

    let wia =
        Jwt::<()>::decompose_token(wia_header.to_str().unwrap()).expect("Failed to parse WIA JWT");
    let wia_pop = Jwt::<()>::decompose_token(wia_pop_header.to_str().unwrap())
        .expect("Failed to parse WIA PoP JWT");

    assert_eq!(
        wia_pop.payload.issuer, wia.payload.subject,
        "WIA PoP 'iss' must equal WIA 'sub' per OAuth Attestation-Based Client Auth spec section 5.2"
    );

    assert_eq!(
        wia.payload.subject,
        Some("eudiw-abca".to_string()),
        "WIA 'sub' should be wallet_client_id from config"
    );
}
