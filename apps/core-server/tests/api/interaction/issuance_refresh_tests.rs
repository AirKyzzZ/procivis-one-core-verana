use core_server::endpoint::interaction::dto::IssuanceRefreshResponseRestDTO;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::interaction::InteractionType;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::macros::datetime;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::fixtures::interaction::{InteractionDataParams, dummy_interaction_data};
use crate::fixtures::presentation::w3c_jwt_vc;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_issuance_refresh_openid4vci_batch() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let issuer_key = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key.key.public_key_as_multibase().unwrap();
    let did: DidValue = format!("did:key:{multibase}").parse().unwrap();

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            None,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                claim_schemas: Some(
                    ["iss", "iat", "sub", "vc/type", "exp", "vc", "nbf"]
                        .iter()
                        .map(|key| ClaimSchema {
                            business_key: None,
                            id: Uuid::new_v4().into(),
                            key: key.to_string(),
                            data_type: "STRING".to_string(),
                            created_date: datetime!(2024-10-20 12:00 +1),
                            last_modified: datetime!(2024-10-20 12:00 +1),
                            array: false,
                            metadata: true,
                            required: false,
                            translations: Default::default(),
                        })
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            batch_size: Some(2),
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
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_nonce_endpoint("OPENID4VCI_FINAL1", "test-nonce", 1)
        .await;

    let credential_1 = w3c_jwt_vc(&issuer_key, "ES256", did.clone(), did.clone(), json!({})).await;
    let credential_2 = w3c_jwt_vc(&issuer_key, "ES256", did.clone(), did.clone(), json!({})).await;

    context
        .server_mock
        .ssi_credential_endpoint(
            credential_schema.id,
            "123",
            &[credential_1, credential_2],
            1,
            None,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_refresh(interaction.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: IssuanceRefreshResponseRestDTO = resp.json().await;

    // 2 newly created credentials
    assert_eq!(resp.ids.len(), 2);
    assert!(!resp.ids.contains(&credential.id));

    let credential = context.db.credentials.get(&resp.ids[0]).await;
    assert_eq!(credential.state, CredentialStateEnum::Accepted);
    assert_eq!(credential.schema.unwrap().id, credential_schema.id);
}
