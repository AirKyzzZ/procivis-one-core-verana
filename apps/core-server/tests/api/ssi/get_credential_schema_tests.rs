use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "credential-schema",
            &organisation,
            Some("BITSTRINGSTATUSLIST".into()),
            Default::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_schema(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential_schema.id);
    assert_eq!(resp["claims"].as_array().unwrap().len(), 2);
    assert_eq!(resp["revocationMethod"], "BITSTRINGSTATUSLIST");
    assert_eq!(resp["organisationId"], organisation.id.to_string());
    assert_eq!(resp["layoutProperties"]["background"]["color"], "#DA2727");
    assert_eq!(resp["layoutProperties"]["primaryAttribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["secondaryAttribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["logo"]["fontColor"], "#DA2727");
    assert_eq!(
        resp["layoutProperties"]["logo"]["backgroundColor"],
        "#DA2727"
    );
    assert_eq!(resp["layoutProperties"]["pictureAttribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["code"]["attribute"], "firstName");
    assert_eq!(resp["layoutProperties"]["code"]["type"], "BARCODE");
}

#[tokio::test]
async fn test_get_credential_schema_not_found() {
    // given
    let (context, _organisation) = TestContext::new_with_organisation(None).await;
    let non_existent_id = Uuid::new_v4();

    // when
    let resp = context.api.ssi.get_credential_schema(non_existent_id).await;

    // then
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_credential_schema_deleted_returns_not_found() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, None, Default::default())
        .await;
    context
        .db
        .credential_schemas
        .delete(&credential_schema)
        .await;

    // when
    let resp = context
        .api
        .ssi
        .get_credential_schema(credential_schema.id)
        .await;

    // then
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_credential_schema_by_format_mismatch_returns_not_found() {
    // given
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("credential-schema", &organisation, None, Default::default())
        .await;

    // when — schema has JWT format, request uses MDOC
    let resp = context
        .api
        .ssi
        .get_credential_schema_by_format(credential_schema.id, "MDOC")
        .await;

    // then
    assert_eq!(resp.status(), 404);
}
