use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::TrustListSubscriptionState;
use serde_json::json;
use similar_asserts::assert_eq;
use url::Url;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;
use crate::utils::db_clients::verifier_instances::TestVerifierInstanceParams;

#[tokio::test]
async fn get_verifier_instance_trust_collections_empty() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "name": "verifier-name",
          "featureFlags": {
            "trustEcosystemsEnabled": true
          },
          "trustCollections": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let instance = context
        .db
        .verifier_instances
        .create(
            org,
            TestVerifierInstanceParams {
                provider_url: Some(mock_server.uri()),
                provider_type: Some("PROCIVIS_ONE".to_string()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .get_trust_collections(&instance.id)
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let trust_collections = resp["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 0);
}

#[tokio::test]
async fn get_verifier_instance_trust_collections_one_collection() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "name": "verifier-name",
          "featureFlags": {
            "trustEcosystemsEnabled": true
          },
          "trustCollections": [{
              "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
              "logo": "logo",
              "name": "collection",
              "description": [{
                  "lang": "en",
                  "value": "desc"
              }],
              "displayName": [{
                  "lang": "en",
                  "value": "name"
              }]
          }]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let instance = context
        .db
        .verifier_instances
        .create(
            org.clone(),
            TestVerifierInstanceParams {
                provider_url: Some(mock_server.uri()),
                provider_type: Some("PROCIVIS_ONE".to_string()),
                ..Default::default()
            },
        )
        .await;

    let collection = context
        .db
        .trust_collections
        .create(
            org,
            TestTrustCollectionParams {
                name: Some("collection".to_string()),
                remote_trust_collection_url: Some(Url::parse("https://provider.com").unwrap()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .get_trust_collections(&instance.id)
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let trust_collections = resp["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 1);
    assert_eq!(
        trust_collections[0],
        json!({
          "id": collection.id,
          "selected": false,
          "logo": "logo",
          "name": "collection",
          "description": [{
              "lang": "en",
              "value": "desc"
          }],
          "displayName": [{
              "lang": "en",
              "value": "name"
          }]
        })
    );
}

fn metadata_with_default_selected_collection() -> serde_json::Value {
    json!({
      "name": "verifier-name",
      "featureFlags": {
        "trustEcosystemsEnabled": true
      },
      "trustCollections": [{
          "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
          "logo": "logo",
          "name": "default-collection",
          "defaultSelected": true,
          "description": [{
              "lang": "en",
              "value": "desc"
          }],
          "displayName": [{
              "lang": "en",
              "value": "name"
          }]
      },
      {
          "id": "88a85f64-5717-4562-b3fc-2c963f66afa6",
          "logo": "logo",
          "name": "other-collection",
          "description": [{
              "lang": "en",
              "value": "desc"
          }],
          "displayName": [{
              "lang": "en",
              "value": "name"
          }]
      }]
    })
}

#[tokio::test]
async fn get_verifier_instance_trust_collections_default_selected_when_no_subscription() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_with_default_selected_collection()),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let instance = context
        .db
        .verifier_instances
        .create(
            org.clone(),
            TestVerifierInstanceParams {
                provider_url: Some(mock_server.uri()),
                provider_type: Some("PROCIVIS_ONE".to_string()),
                ..Default::default()
            },
        )
        .await;

    let default_collection = context
        .db
        .trust_collections
        .create(
            org.clone(),
            TestTrustCollectionParams {
                name: Some("default-collection".to_string()),
                remote_trust_collection_url: Some(Url::parse("https://provider.com").unwrap()),
                ..Default::default()
            },
        )
        .await;

    let other_collection = context
        .db
        .trust_collections
        .create(
            org,
            TestTrustCollectionParams {
                name: Some("other-collection".to_string()),
                remote_trust_collection_url: Some(Url::parse("https://provider.com").unwrap()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .get_trust_collections(&instance.id)
        .await;

    // then - no selection saved yet, so `selected` mirrors the provider `defaultSelected` flag
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let trust_collections = resp["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 2);
    let selected_by_id = |id| {
        trust_collections
            .iter()
            .find(|c| c["id"] == json!(id))
            .unwrap()["selected"]
            .as_bool()
            .unwrap()
    };
    assert!(selected_by_id(default_collection.id));
    assert!(!selected_by_id(other_collection.id));
}

#[tokio::test]
async fn get_verifier_instance_trust_collections_default_selected_ignored_after_user_selection() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(metadata_with_default_selected_collection()),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let instance = context
        .db
        .verifier_instances
        .create(
            org.clone(),
            TestVerifierInstanceParams {
                provider_url: Some(mock_server.uri()),
                provider_type: Some("PROCIVIS_ONE".to_string()),
                ..Default::default()
            },
        )
        .await;

    let default_collection = context
        .db
        .trust_collections
        .create(
            org.clone(),
            TestTrustCollectionParams {
                name: Some("default-collection".to_string()),
                remote_trust_collection_url: Some(Url::parse("https://provider.com").unwrap()),
                ..Default::default()
            },
        )
        .await;

    let other_collection = context
        .db
        .trust_collections
        .create(
            org,
            TestTrustCollectionParams {
                name: Some("other-collection".to_string()),
                remote_trust_collection_url: Some(Url::parse("https://provider.com").unwrap()),
                ..Default::default()
            },
        )
        .await;

    // the user selected only the non-default collection
    context
        .db
        .trust_list_subscriptions
        .create(
            "subscr",
            Some(TrustListRoleEnum::PidProvider),
            "type",
            "reference",
            TrustListSubscriptionState::Active,
            other_collection.id,
        )
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .get_trust_collections(&instance.id)
        .await;

    // then - subscriptions exist, so `defaultSelected` is ignored
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let trust_collections = resp["trustCollections"].as_array().unwrap();
    assert_eq!(trust_collections.len(), 2);
    let selected_by_id = |id| {
        trust_collections
            .iter()
            .find(|c| c["id"] == json!(id))
            .unwrap()["selected"]
            .as_bool()
            .unwrap()
    };
    assert!(!selected_by_id(default_collection.id));
    assert!(selected_by_id(other_collection.id));
}
