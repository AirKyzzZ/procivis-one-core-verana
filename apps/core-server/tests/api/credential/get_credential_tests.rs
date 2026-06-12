use one_core::model::blob::BlobType;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential::{CredentialRole, CredentialStateEnum, CredentialType};
use one_core::model::history::{
    HistoryAction, HistoryMetadata, TrustResolutionMetadata, TrustResolutionResult,
    WalletRelyingPartyMetadata,
};
use one_core::service::credential::dto::WalletInstanceAttestationDTO;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::{ClaimData, TestingCredentialParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    let wia_blob_value = serde_json::to_vec(&WalletInstanceAttestationDTO {
        name: "Wallet solution X by Wonderland State Department".to_string(),
        link: "https://wonderland.gov".to_string(),
        attestation: "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjE3NTY3MDc1NTcsImV4cCI6MTc1Njc5Mzk1NywibmJmIjoxNzU2NzA3NTU3LCJpc3MiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20iLCJzdWIiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vUFJPQ0lWSVNfT05FIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdtbV9IbWd3SHZPNUpWZ1lPX3k0TG9hSTRLMzVoVDlmYzByb0lkZjVpRUEifX19.0QT5ybzrQx0d0ID2xx4hzH5NUodykyju2fyo3wIu7ZSobA26gYjcMvZZstg-GcZxjguo9rEkrzdm9ZUt-44wTw".to_string(),
    }).unwrap();

    let wallet_instance_attestation_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(wia_blob_value),
            r#type: Some(BlobType::WalletInstanceAttestation),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                wallet_instance_attestation_blob_id: Some(wallet_instance_attestation_blob.id),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential.id);
    resp["schema"]["organisationId"].assert_eq(&organisation.id);
    assert_eq!(resp["schema"]["name"], "test");
    assert_eq!(resp["schema"]["translations"]["name"]["en"], "test");
    assert!(resp["revocationDate"].is_null());
    assert_eq!(resp["state"], "CREATED");
    assert_eq!(resp["role"], "ISSUER");
    assert_eq!(resp["protocol"], "OPENID4VCI_DRAFT13");
    assert_eq!(
        resp["walletInstanceAttestation"]["name"],
        "Wallet solution X by Wonderland State Department"
    );
    assert_eq!(
        resp["walletInstanceAttestation"]["link"],
        "https://wonderland.gov"
    );
    assert_eq!(
        resp["walletInstanceAttestation"]["attestation"],
        "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjE3NTY3MDc1NTcsImV4cCI6MTc1Njc5Mzk1NywibmJmIjoxNzU2NzA3NTU3LCJpc3MiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20iLCJzdWIiOiJodHRwczovL2NvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20vUFJPQ0lWSVNfT05FIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdtbV9IbWd3SHZPNUpWZ1lPX3k0TG9hSTRLMzVoVDlmYzByb0lkZjVpRUEifX19.0QT5ybzrQx0d0ID2xx4hzH5NUodykyju2fyo3wIu7ZSobA26gYjcMvZZstg-GcZxjguo9rEkrzdm9ZUt-44wTw"
    );
    assert_eq!(
        resp["claims"][0]["schema"]["translations"]["name"]["en"],
        "firstName"
    );
    assert_eq!(
        resp["claims"][1]["schema"]["translations"]["name"]["en"],
        "isOver18"
    );
}

#[tokio::test]
async fn test_get_credential_with_trust_information_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::TrustResolved),
                entity_id: Some(credential.id.into()),
                metadata: Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                    result: TrustResolutionResult::Trusted,
                })),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::WrpRcReceived),
                entity_id: Some(credential.id.into()),
                metadata: Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        name: "Test RP".to_string(),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential.id);
    assert_eq!(resp["trustInformation"]["name"], "Test RP");
    assert_eq!(resp["trustInformation"]["result"], "TRUSTED");
    assert!(!resp["trustInformation"]["receivedAt"].is_null());
}

#[tokio::test]
async fn test_get_credential_certificate_identifier_success() {
    // GIVEN
    let (context, organisation, identifier, certificate, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential.id);
    resp["schema"]["organisationId"].assert_eq(&organisation.id);
    assert_eq!(resp["schema"]["name"], "test");
    assert!(resp["revocationDate"].is_null());
    assert_eq!(resp["state"], "CREATED");
    assert_eq!(resp["role"], "ISSUER");
    assert_eq!(resp["protocol"], "OPENID4VCI_DRAFT13");
    assert_eq!(resp["issuerCertificate"]["id"], certificate.id.to_string());
    assert_eq!(
        resp["issuerCertificate"]["x509Attributes"]["subject"],
        "CN=test cert"
    );
}

#[tokio::test]
async fn test_get_credential_success_metadata() {
    // GIVEN
    let (context, org, _, identifier, _) = TestContext::new_with_did(None).await;

    let claim_schema_id = Uuid::new_v4();
    let metadata_claim_schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple test schema",
            &org,
            None,
            TestingCreateSchemaParams {
                schema_id: Some("https://example.org/foo".to_owned()),
                format: Some("SD_JWT_VC".into()),
                claim_schemas: Some(vec![
                    ClaimSchema {
                        business_key: None,
                        id: claim_schema_id.into(),
                        key: "string_claim".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        array: false,
                        metadata: false,
                        required: true,
                        translations: Default::default(),
                    },
                    ClaimSchema {
                        business_key: None,
                        id: metadata_claim_schema_id.into(),
                        key: "iss".to_string(),
                        data_type: "STRING".to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
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
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "string_claim".to_string(),
                        value: Some("test-value-first".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: metadata_claim_schema_id.into(),
                        path: "iss".to_string(),
                        value: Some("some-issuer".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&credential.id);
    assert_eq!(resp["claims"].as_array().unwrap().len(), 1);
    assert_eq!(resp["claims"][0]["path"], "string_claim".to_string());
}

#[tokio::test]
async fn test_get_credential_success_batch() {
    // GIVEN
    let (context, org, _, identifier, _) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "Simple batch schema",
            &org,
            None,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let item_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&parent_credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&parent_credential.id);
    assert_eq!(resp["type"].as_str().unwrap(), "BATCH_PARENT");
    assert!(!resp.as_object().unwrap().contains_key("parentId"));
    assert_eq!(
        resp["remainingBatchItemCount"]
            .as_number()
            .unwrap()
            .as_u64()
            .unwrap(),
        1
    );

    // WHEN
    let resp = context.api.credentials.get(&item_credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&item_credential.id);
    assert_eq!(resp["type"].as_str().unwrap(), "BATCH_ITEM");
    assert!(
        !resp
            .as_object()
            .unwrap()
            .contains_key("remainingBatchItemCount")
    );
    assert_eq!(
        resp["parentId"].as_str().unwrap(),
        parent_credential.id.to_string()
    );
}
