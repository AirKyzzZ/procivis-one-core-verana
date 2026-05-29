use shared_types::CredentialFormat;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_get_json_ld_context_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let core_base_url = &context.config.app.core_base_url;

    let format: CredentialFormat = "JSON_LD_CLASSIC".into();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some(format.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}/{format}#ProcivisOneSchema2024",
            credential_schema.id
        )
    );
    assert_eq!(
        resp["@context"]["TestSchema"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}/{format}#TestSchema",
            credential_schema.id
        )
    );
    assert_eq!(
        resp["@context"]["firstName"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}/{format}#firstName",
            credential_schema.id
        )
    );
    assert_eq!(
        resp["@context"]["isOver18"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}/{format}#isOver18",
            credential_schema.id
        )
    );
}

#[tokio::test]
async fn test_get_json_ld_context_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_json_ld_context(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_json_ld_context_with_nested_claims_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let core_base_url = &context.config.app.core_base_url;

    let format: CredentialFormat = "JSON_LD_CLASSIC".into();
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some(format.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let credential_schema_id = credential_schema.id;
    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#ProcivisOneSchema2024",
        )
    );
    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@context"]["metadata"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#metadata",)
    );
    assert_eq!(
        resp["@context"]["TestSchema"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#TestSchema",)
    );
    assert_eq!(
        resp["@context"]["address"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#address",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["street"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#street",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["coordinates"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#coordinates",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["coordinates"]["@context"]["x"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#x",)
    );
    assert_eq!(
        resp["@context"]["address"]["@context"]["coordinates"]["@context"]["y"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#y",)
    );
}

#[tokio::test]
async fn test_get_json_ld_context_special_chars_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let core_base_url = &context.config.app.core_base_url;
    let format: CredentialFormat = "JSON_LD_CLASSIC".into();
    let credential_schema = context
        .db
        .credential_schemas
        .create_special_chars(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some(format.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let credential_schema_id = credential_schema.id;
    assert_eq!(
        resp["@context"]["ProcivisOneSchema2024"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#ProcivisOneSchema2024",
        )
    );
    assert_eq!(
        resp["@context"]["first name#"]["@id"],
        format!("{core_base_url}/ssi/context/v1/{credential_schema_id}/{format}#first%20name%23",)
    );
}

#[tokio::test]
async fn test_get_json_ld_context_credential_invalid_format() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_json_ld_context(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_json_ld_context_by_format_success() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let core_base_url = &context.config.app.core_base_url;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("JSON_LD_CLASSIC".into()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .ssi
        .get_json_ld_context_by_format(credential_schema.id, "JSON_LD_CLASSIC")
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["@context"]["TestSchema"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}/JSON_LD_CLASSIC#TestSchema",
            credential_schema.id
        )
    );
    assert_eq!(
        resp["@context"]["firstName"]["@id"],
        format!(
            "{core_base_url}/ssi/context/v1/{}/JSON_LD_CLASSIC#firstName",
            credential_schema.id
        )
    );
}

#[tokio::test]
async fn test_get_json_ld_context_by_format_not_found() {
    // given
    let context = TestContext::new(None).await;
    let non_existent_id = Uuid::new_v4();

    // when
    let resp = context
        .api
        .ssi
        .get_json_ld_context_by_format(non_existent_id, "JSON_LD_CLASSIC")
        .await;

    // then
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_json_ld_context_by_format_mismatch_returns_bad_request() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("JSON_LD_CLASSIC".into()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .ssi
        .get_json_ld_context_by_format(credential_schema.id, "JWT")
        .await;

    // then
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_get_json_ld_context_by_format_non_json_ld_format_returns_bad_request() {
    // given — MDOC is not a JSON-LD format
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            None,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .ssi
        .get_json_ld_context_by_format(credential_schema.id, "MDOC")
        .await;

    // then
    assert_eq!(resp.status(), 400);
}
