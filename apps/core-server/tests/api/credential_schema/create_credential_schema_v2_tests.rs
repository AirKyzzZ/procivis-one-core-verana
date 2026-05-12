use core_server::endpoint::credential_schema::dto::{
    CredentialSchemaTransactionCodeRequestRestDTO, TransactionCodeTypeRestEnum,
};
use similar_asserts::assert_eq;

use crate::utils::api_clients::credential_schemas::{CreateSchemaV2Params, TestClaim};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

fn default_claims() -> Vec<TestClaim> {
    vec![TestClaim {
        datatype: "OBJECT".to_string(),
        key: "root".to_string(),
        required: true,
        claims: vec![TestClaim {
            datatype: "STRING".to_string(),
            key: "firstName".to_string(),
            required: true,
            claims: vec![],
            array: None,
        }],
        array: None,
    }]
}

fn jwt_format() -> serde_json::Value {
    serde_json::json!({ "format": "JWT" })
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_single_format() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;
    assert_eq!(credential_schema.name, "v2 schema");
    assert_eq!(credential_schema.organisation.id(), organisation.id);

    let formats = credential_schema.formats.get().await.unwrap();
    assert_eq!(formats.len(), 1);
    let claim_mappings = formats[0].claim_mappings.get().await.unwrap();
    assert!(claim_mappings.iter().any(|m| m.technical_key == "root"));
    assert!(
        claim_mappings
            .iter()
            .any(|m| m.technical_key == "root/firstName")
    );
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_multiple_formats() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN - JWT and MDOC produce different schema_ids (MDOC uses explicit schemaId)
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 multi-format schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                jwt_format(),
                serde_json::json!({ "format": "MDOC", "schemaId": "org.example.test" }),
            ],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let id = resp["id"].parse();
    let credential_schema = context.db.credential_schemas.get(&id).await;

    let formats = credential_schema.formats.get().await.unwrap();
    assert_eq!(formats.len(), 2);
    for format in &formats {
        let claim_mappings = format.claim_mappings.get().await.unwrap();
        assert!(claim_mappings.iter().any(|m| m.technical_key == "root"));
        assert!(
            claim_mappings
                .iter()
                .any(|m| m.technical_key == "root/firstName")
        );
    }
}

#[tokio::test]
async fn test_create_credential_schema_v2_success_with_batch_size() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 batch schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            batch_size: Some(5),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_empty_formats() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_empty_claims() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: vec![],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_duplicate_formats() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format(), jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_batch_size_too_small() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            batch_size: Some(1),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_schema_id_not_allowed_for_jwt() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JWT", "schemaId": "some-id" })],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_same_name_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_credential_schema_v2_same_name_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let organisation2 = context.db.organisations.create().await;

    // WHEN
    let resp1 = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    let resp2 = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation2.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp1.status(), 201);
    assert_eq!(resp2.status(), 201);
}

#[tokio::test]
async fn test_create_credential_schema_v2_mdoc_with_schema_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 mdoc schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![
                serde_json::json!({ "format": "MDOC", "schemaId": "org.iso.18013.5.1.mDL" }),
            ],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_duplicate_schema_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 mdoc schema 1".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "MDOC", "schemaId": "org.example.foo" })],
            claims: default_claims(),
            ..Default::default()
        })
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN - second schema with same schemaId
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 mdoc schema 2".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "MDOC", "schemaId": "org.example.foo" })],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_forbidden_claim_name() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "JSON_LD_CLASSIC" })],
            claims: vec![TestClaim {
                datatype: "OBJECT".to_string(),
                key: "root".to_string(),
                required: true,
                claims: vec![TestClaim {
                    datatype: "STRING".to_string(),
                    key: "id".to_string(),
                    required: true,
                    claims: vec![],
                    array: None,
                }],
                array: None,
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0145");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_transaction_code_length_too_big() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            transaction_code: Some(CredentialSchemaTransactionCodeRequestRestDTO {
                r#type: TransactionCodeTypeRestEnum::Numeric,
                length: 11,
                description: None,
            }),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0338");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_deactivated_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context.db.organisations.deactivate(&organisation.id).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![jwt_format()],
            claims: default_claims(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0241");
}

#[tokio::test]
async fn test_fail_create_credential_schema_v2_unsupported_data_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .create_v2(CreateSchemaV2Params {
            name: "v2 schema".into(),
            organisation_id: organisation.id.into(),
            formats: vec![serde_json::json!({ "format": "SD_JWT_VC_SWIYU", "schemaId": "ID" })],
            claims: vec![TestClaim {
                datatype: "STRING".to_string(),
                key: "firstName".to_string(),
                required: true,
                claims: vec![],
                array: Some(true),
            }],
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0245");
}
