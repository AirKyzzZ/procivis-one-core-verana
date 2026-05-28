use std::collections::HashMap;
use std::str::FromStr;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::provider::verification_protocol::openid4vp::model::{
    OpenID4VPDraftClientMetadata, OpenID4VPPresentationDefinition,
};
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use standardized_types::openid4vp::{ClientMetadata, GenericAlgs, PresentationFormat, SdJwtVcAlgs};
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

fn openid4vci_final1_json_metadata_config() -> Option<String> {
    Some(
        indoc::indoc! {"
          issuanceProtocol:
            OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "}
        .to_string(),
    )
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value() {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let issuer_did = "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb";
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "issuer_did": issuer_did,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "namespace1/string_array/0": {"value": "foo", "value_type": "STRING"},
                "namespace1/string_array/1": {"value": "foo", "value_type": "STRING"},
                "namespace1/object_array/0/field1": {"value": "foo", "value_type": "STRING"},
                "namespace1/object_array/0/field 2": {"value": "foo", "value_type": "STRING"},
                "namespace2/Field 1": {"value": "foo", "value_type": "STRING"},
                "namespace2/array/0/N2 field1": {"value": "foo", "value_type": "STRING"},
                "namespace2/array/0/N2 array/0": {"value": "foo", "value_type": "STRING"},
                "namespace2/array/0/N2 array/1": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                          "format": "mso_mdoc",
                              "claims": {
                              "namespace1": {
                                  "string_array": {
                                    "value_type": "string[]",
                                    "mandatory": true
                                  },
                                  "object_array": [
                                  {
                                      "field1": {
                                        "value_type": "string",
                                        "mandatory": true
                                      },
                                      "field 2": {
                                        "value_type": "string",
                                        "mandatory": true
                                      }
                                  }
                                  ]
                              },
                              "namespace2": {
                                  "Field 1": {
                                    "value_type": "string",
                                    "mandatory": true
                                  },
                                  "array": [
                                    {
                                        "N2 field1": {
                                            "value_type": "string",
                                            "mandatory": true
                                        },
                                        "N2 array": {
                                            "value_type": "string[]",
                                            "mandatory": true
                                        }
                                    }
                                ]
                              }
                          },
                          "order": [
                              "namespace1~string_array",
                              "namespace1~object_array",
                              "namespace2~Field 1",
                              "namespace2~array"
                          ],
                          "display": [
                          {
                              "name": "TestNestedHell"
                          }
                          ],
                          "wallet_storage_type": "SOFTWARE",
                          "proof_types_supported": {
                            "jwt": {
                              "proof_signing_alg_values_supported": [
                                "ES256",
                                "EdDSA",
                                "EDDSA",
                                "BBS_PLUS",
                                "DILITHIUM"
                              ]
                            }
                          }
                      }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_double_layered_nested_claims()
 {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "address/location/position/x": {"value": "test_value", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "location": {
                                    "position": {
                                        "x": {
                                            "value_type": "STRING",
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "format": "vc+sd-jwt",
                }
            }}
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_optional_object_array_and_required_field()
 {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "credential_subject": {
            "keys": {
                "address/field": {"value": "xyy", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        },
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "location": {
                                    "position": {
                                        "x": {
                                            "value_type": "STRING",
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "format": "vc+sd-jwt",
                }
            }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_with_similar_prefix_keys()
 {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "credential_subject": {
            "keys": {
                "address/field": {"value": "xyy", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        },
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "location": {
                                    "position": {
                                        "x": {
                                            "value_type": "STRING",
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "format": "vc+sd-jwt",
                }
            }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_matching_succeeds() {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
        "key",
        true,
        "STRING",
        false,
    )];

    let schema_id = Uuid::new_v4();

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "MatchedSchema",
            &organisation,
            None,
            &new_claim_schemas,
            "SD_JWT_VC",
            &format!("{}/ssi/schema/v1/{}", &mock_server.uri(), schema_id),
        )
        .await;

    let credential_schema_id = credential_schema.id;
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "key": {"value": "foo", "value_type": "STRING"},
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                    {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                        "credential_definition": {
                            "type": [
                                "VerifiableCredential"
                            ],
                            "credentialSubject" : {
                                "key": {
                                    "value_type": "string",
                                }
                            }
                        },
                        "vct": "vct-schema-SD_JWT_VC",
                        "format": "vc+sd-jwt",
                    }
                }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["walletStorageType"], Value::Null);
    assert_eq!(resp["protocol"], "OPENID4VCI_FINAL1");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_id = Uuid::new_v4();
    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri())
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "field": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                {
                    format!("{}/ssi/schema/v1/{credential_schema_id}", mock_server.uri()): {
                    "wallet_storage_type": "SOFTWARE",
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "field": {
                                "value_type": "string"
                            }
                        }
                    },
                    "format": "vc+sd-jwt",
                    }
                }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/final-1.0/{credential_schema_id}/offer/{credential_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(credential_offer))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url.query_pairs_mut().append_pair(
        "credential_offer_uri",
        &format!("{credential_issuer}/offer/{credential_id}"),
    );

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_reference() {
    let mock_server = MockServer::start().await;
    let (context, organistion) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let client_metadata = serde_json::to_string(&OpenID4VPDraftClientMetadata {
        jwks: Default::default(),
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            PresentationFormat::GenericAlgList(GenericAlgs {
                alg: vec!["EdDSA".to_string()],
            }),
        )]),
        ..Default::default()
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();
    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";
    let client_metadata_uri = format!("{}/client-metadata", mock_server.uri());
    let presentation_definition_uri = format!("{}/presentation-definition", mock_server.uri());
    let query = Url::parse(&format!("openid4vp-draft20://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata_uri={client_metadata_uri}&response_mode=direct_post&response_uri={callback_url}&presentation_definition_uri={presentation_definition_uri}")).unwrap().to_string();

    Mock::given(method(Method::GET))
        .and(path("/client-metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(client_metadata, "application/json"))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path("/presentation-definition"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(presentation_definition, "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, &query)
        .await;
    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "VERIFICATION");
    assert_eq!(resp["protocol"], "OPENID4VP_DRAFT20");
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_value() {
    let (context, organistion) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let client_metadata = serde_json::to_string(&OpenID4VPDraftClientMetadata {
        jwks: Default::default(),
        vp_formats: HashMap::from([(
            "jwt_vp_json".to_string(),
            PresentationFormat::GenericAlgList(GenericAlgs {
                alg: vec!["EdDSA".to_string()],
            }),
        )]),
        ..Default::default()
    })
    .unwrap();
    let presentation_definition = serde_json::to_string(&OpenID4VPPresentationDefinition {
        id: Default::default(),
        input_descriptors: vec![],
    })
    .unwrap();
    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";
    let query = Url::parse(&format!("openid4vp-draft20://?response_type=vp_token&nonce={nonce}&client_id_scheme=redirect_uri&client_id={callback_url}&client_metadata={client_metadata}&response_mode=direct_post&response_uri={callback_url}&presentation_definition={presentation_definition}")).unwrap().to_string();

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, &query)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "VERIFICATION");
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_proof_by_value_dcql() {
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let client_metadata = ClientMetadata {
        jwks: Default::default(),
        vp_formats_supported: HashMap::from([(
            "dc+sd-jwt".to_string(),
            PresentationFormat::SdJwtVcAlgs(SdJwtVcAlgs {
                sd_jwt_alg_values: vec!["EdDSA".to_string()],
                kb_jwt_alg_values: vec!["EdDSA".to_string()],
            }),
        )]),
        ..Default::default()
    };
    let dcql_query = json!({
        "credentials": [
            {
                "id": "my_credential",
                "format": "dc+sd-jwt",
                "require_cryptographic_holder_binding": true,
                "meta": {
                    "vct_values": [
                        "https://credentials.example.com/identity_credential"
                    ]
                },
                "claims": [
                    {
                        "path": [
                            "last_name"
                        ]
                    },
                    {
                        "path": [
                            "first_name"
                        ]
                    },
                    {
                        "path": [
                            "address",
                            "street_address"
                        ]
                    }
                ]
            }
        ]
    });
    let nonce = Uuid::new_v4().to_string();
    let callback_url = "http://127.0.0.1/callback";
    let client_id = format!("redirect_uri:{callback_url}");
    let auth_request = json!({
        "client_id": client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "client_metadata": client_metadata,
        "nonce": nonce,
        "dcql_query": dcql_query,
        "response_uri": callback_url,
    });

    // unsigned JWT — redirect_uri client_id_scheme skips signature verification
    let header = json!({ "alg": "none", "typ": "oauth-authz-req+jwt" });
    let header_b64 =
        Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&header).unwrap()).unwrap();
    let payload_b64 =
        Base64UrlSafeNoPadding::encode_to_string(serde_json::to_vec(&auth_request).unwrap())
            .unwrap();
    let request_jwt = format!("{header_b64}.{payload_b64}.");

    let mut query = Url::parse(&format!("openid4vp://?client_id={client_id}")).unwrap();
    query.query_pairs_mut().append_pair("request", &request_jwt);

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, query.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "VERIFICATION");
}

#[tokio::test]
async fn test_handle_invitation_mdoc() {
    let mock_server = MockServer::start().await;
    let (context, organistion) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );

    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "custom-doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported":
                {
                    "custom-doctype":
                    {
                        "claims": {
                            "first.namespace": {
                                "field": {
                                    "value_type": "string",
                                    "mandatory": true
                                },
                                "string_array": {
                                    "value_type": "string[]"
                                },
                                "object_array": [
                                    {
                                        "field1": {
                                            "value_type": "string",
                                            "mandatory": true
                                        },
                                        "field2": {
                                            "value_type": "string",
                                            "mandatory": false
                                        },
                                    }
                                ]
                            },
                            "company": {
                                "address": {
                                    "streetName": {
                                        "value_type": "string"
                                    },
                                    "streetNumber": {
                                        "value_type": "number"
                                    },
                                    "order": ["streetName", "streetNumber"]
                                }
                            }
                        },
                        "format": "mso_mdoc",
                        "doctype": "custom-doctype",
                        "order": ["first.namespace~field", "company~address"]
                    }
                }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["walletStorageType"], Value::Null);
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_tx_code_passed() {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740",
                "tx_code":{"input_mode":"numeric","length":5,"description":"code"}
            }
        },
        "credential_subject": {
            "keys": {
                "namespace2/Field 1": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                          "format": "mso_mdoc",
                              "claims": {
                              "namespace2": {
                                  "Field 1": {
                                    "value_type": "string",
                                    "mandatory": true
                                  }
                              }
                          },
                          "order": [
                              "namespace2~Field 1",
                          ],
                          "display": [
                          {
                              "name": "TestNestedHell"
                          }
                          ],
                          "wallet_storage_type": "SOFTWARE"
                      }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
    let code = &resp["txCode"];
    assert_eq!(code["input_mode"], "numeric");
    assert_eq!(code["length"], 5);
    assert_eq!(code["description"], "code");
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_issuance_offer_by_value_no_subject() {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                          "format": "mso_mdoc",
                              "claims": {
                              "namespace1": {
                                  "string_array": {
                                    "value_type": "string[]",
                                    "mandatory": true
                                  },
                                  "object_array": [
                                  {
                                      "field1": {
                                        "value_type": "string",
                                        "mandatory": true
                                      },
                                      "field 2": {
                                        "value_type": "string",
                                        "mandatory": true
                                      }
                                  }
                                  ]
                              },
                              "namespace2": {
                                  "Field 1": {
                                    "value_type": "string",
                                    "mandatory": true
                                  },
                                  "array": [
                                    {
                                        "N2 field1": {
                                            "value_type": "string",
                                            "mandatory": true
                                        },
                                        "N2 array": {
                                            "value_type": "string[]",
                                            "mandatory": true
                                        }
                                    }
                                ]
                              }
                          },
                          "order": [
                              "namespace1~string_array",
                              "namespace1~object_array",
                              "namespace2~Field 1",
                              "namespace2~array"
                          ],
                          "display": [
                          {
                              "name": "TestNestedHell"
                          }
                          ],
                          "wallet_storage_type": "SOFTWARE"
                      }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["requiresWalletInstanceAttestation"], false);
}

#[tokio::test]
async fn test_handle_invitation_external_sd_jwt_vc() {
    let mock_server = MockServer::start().await;
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );

    let vct = format!("{}/education_credential", mock_server.uri());

    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "https://betelgeuse.example.com/education_credential"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740",
                "tx_code":{
                    "input_mode": "numeric",
                    "length": 5,
                    "description": "code"
                }
            }
        }
    });

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "https://betelgeuse.example.com/education_credential": {
                        "format": "vc+sd-jwt",
                        "display": [
                            {
                              "name": "TestNestedHell",
                              "logo": {
                                    "uri": "https://university.example.edu/public/logo.png",
                                    "alt_text": "a square logo of a university"
                              },
                              "locale": "en-US",
                              "background_color": "#12107c",
                              "text_color": "#FFFFFF"
                            }
                        ],
                        "vct": vct,
                        "claims": {
                            "name": {
                              "display": [
                                {
                                  "name": "The name of the student",
                                  "locale": "en-US"
                                }
                              ]
                            }
                        }
                    }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_endpoint = format!("{credential_issuer}/token");

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "authorization_endpoint": format!("{credential_issuer}/authorize"),
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": credential_issuer,
                "jwks_uri": format!("{credential_issuer}/jwks"),
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": token_endpoint
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp.get("interactionId").is_some());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    assert_eq!(resp["walletStorageType"], Value::Null);
}

#[tokio::test]
async fn test_handle_invitation_fails_deactivated_organisation() {
    // GIVEN
    let (context, organisation) =
        TestContext::new_with_organisation(openid4vci_final1_json_metadata_config()).await;
    context.db.organisations.deactivate(&organisation.id).await;

    // WHEN
    let credential_offer = json!({
        "credential_issuer": "https://betelgeuse.example.com/education_credential",
        "credential_configuration_ids": [
            "https://betelgeuse.example.com/education_credential"
        ],
    });

    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}

#[tokio::test]
async fn test_handle_invitation_authorization_code() {
    let mock_server = MockServer::start().await;

    let issuer = mock_server.uri();

    let additional_config = Some(indoc::formatdoc! {"
            credentialIssuer:
              EUDI:
                params:
                  public:
                    issuer: {issuer}
            issuanceProtocol:
              OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "});
    let (context, organisation) = TestContext::new_with_organisation(additional_config).await;

    let authorization_endpoint = "https://authorization.com/authorize";
    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": issuer,
                "authorization_endpoint": authorization_endpoint,
                "token_endpoint": format!("{issuer}/token"),
            }
        )))
        .expect(2)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{issuer}/credential"),
                "credential_issuer": issuer,
                "credential_configurations_supported": {
                    "test": {
                        "format": "vc+sd-jwt",
                        "vct": "vct",
                    }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let credential_offer = json!({
        "credential_issuer": issuer,
        "credential_configuration_ids": [
            "config-id"
        ],
        "grants": {
            "authorization_code": {}
        }
    });

    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_str())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp["interactionId"].is_string());
    let authorization_code_flow_url = resp["authorizationCodeFlowUrl"].as_str().unwrap();

    assert!(authorization_code_flow_url.starts_with(authorization_endpoint));
    assert!(authorization_code_flow_url.contains("client_id=eudiw-abca"));
    assert!(authorization_code_flow_url.contains("authorization_details="));
    assert!(
        authorization_code_flow_url.contains("%22credential_configuration_id%22%3A%22config-id%22")
    );
    assert!(authorization_code_flow_url.contains("%22type%22%3A%22openid_credential%22"));
}

#[tokio::test]
async fn test_handle_invitation_authorization_code_issuer_state() {
    let mock_server = MockServer::start().await;

    let issuer = mock_server.uri();

    let additional_config = Some(indoc::formatdoc! {"
            credentialIssuer:
              EUDI:
                params:
                  public:
                    issuer: {issuer}
            issuanceProtocol:
              OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "});
    let (context, organistion) = TestContext::new_with_organisation(additional_config).await;

    let authorization_endpoint = "https://authorization.com/authorize";
    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": issuer,
                "authorization_endpoint": authorization_endpoint,
                "token_endpoint": format!("{issuer}/token"),
            }
        )))
        .expect(2)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{issuer}/credential"),
                "credential_issuer": issuer,
                "credential_configurations_supported": {
                    "test": {
                        "format": "vc+sd-jwt",
                        "vct": "vct",
                    }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let credential_offer = json!({
        "credential_issuer": issuer,
        "credential_configuration_ids": [
            "config-id"
        ],
        "grants": {
            "authorization_code": {
                "issuer_state": "test-state"
            }
        }
    });

    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, credential_offer_url.as_str())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp["interactionId"].is_string());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    let authorization_code_flow_url = resp["authorizationCodeFlowUrl"].as_str().unwrap();

    assert!(authorization_code_flow_url.starts_with(authorization_endpoint));
    assert!(authorization_code_flow_url.contains("issuer_state=test-state"));
}

#[tokio::test]
async fn test_handle_invitation_authorization_code_authorization_server() {
    let mock_issuer_server = MockServer::start().await;
    let mock_authorization_server = MockServer::start().await;

    let issuer_server_uri = mock_issuer_server.uri();
    let authorization_server_uri = mock_authorization_server.uri();

    let additional_config = Some(indoc::formatdoc! {"
            credentialIssuer:
              EUDI:
                params:
                  public:
                    issuer: {issuer_server_uri}
            issuanceProtocol:
              OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "});
    let (context, organistion) = TestContext::new_with_organisation(additional_config).await;

    let authorization_endpoint = "https://authorization.com/authorize";
    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": authorization_server_uri,
                "authorization_endpoint": authorization_endpoint,
                "token_endpoint": format!("{authorization_server_uri}/token"),
            }
        )))
        .expect(2)
        .mount(&mock_authorization_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_issuer": issuer_server_uri,
                "authorization_servers": ["https://another.server.com", authorization_server_uri],
                "credential_endpoint": format!("{issuer_server_uri}/credential"),
                "credential_configurations_supported": {}
            }
        )))
        .expect(1)
        .mount(&mock_issuer_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": issuer_server_uri,
                "token_endpoint": "https://token.server.com"
            }
        )))
        .mount(&mock_issuer_server)
        .await;

    let credential_offer = json!({
        "credential_issuer": issuer_server_uri,
        "credential_configuration_ids": [
            "config-id"
        ],
        "grants": {
            "authorization_code": {
                "authorization_server": authorization_server_uri
            }
        }
    });

    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, credential_offer_url.as_str())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    assert!(resp["interactionId"].is_string());
    assert_eq!(resp["interactionType"], "ISSUANCE");
    let authorization_code_flow_url = resp["authorizationCodeFlowUrl"].as_str().unwrap();
    assert!(authorization_code_flow_url.starts_with(authorization_endpoint));
}

#[tokio::test]
async fn test_handle_invitation_fails_authorization_code_authorization_server_not_in_issuer_metadata()
 {
    let mock_issuer_server = MockServer::start().await;

    let issuer_server_uri = mock_issuer_server.uri();

    let additional_config = Some(indoc::formatdoc! {"
            credentialIssuer:
              EUDI:
                params:
                  public:
                    issuer: {issuer_server_uri}
            issuanceProtocol:
              OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "});
    let (context, organistion) = TestContext::new_with_organisation(additional_config).await;

    Mock::given(method(Method::GET))
        .and(path("/.well-known/openid-credential-issuer"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_issuer": issuer_server_uri,
                "authorization_servers": ["https://another.server.com"],
                "credential_endpoint": format!("{issuer_server_uri}/credential"),
                "credential_configurations_supported": {}
            }
        )))
        .expect(1)
        .mount(&mock_issuer_server)
        .await;

    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": issuer_server_uri,
                "token_endpoint": "https://token.server.com"
            }
        )))
        .mount(&mock_issuer_server)
        .await;

    let credential_offer = json!({
        "credential_issuer": issuer_server_uri,
        "credential_configuration_ids": [
            "config-id"
        ],
        "grants": {
            "authorization_code": {
                "authorization_server": "https://some.server.com"
            }
        }
    });

    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    // WHEN
    let resp = context
        .api
        .interactions
        .handle_invitation(organistion.id, credential_offer_url.as_str())
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0085");
}

#[tokio::test]
async fn test_handle_invitation_endpoint_for_openid4vc_final1_0_with_oauth_authorization_server_metadata()
 {
    let mock_server = MockServer::start().await;

    let additional_config = Some(indoc::formatdoc! {"
            issuanceProtocol:
              OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "});
    let (context, organisation) = TestContext::new_with_organisation(additional_config).await;

    context
        .db
        .holder_wallet_units
        .create(organisation.clone(), None, Default::default())
        .await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        },
        "credential_subject": {
            "keys": {
                "namespace1/string_array/0": {"value": "foo", "value_type": "STRING"},
            },
            "wallet_storage_type": "SOFTWARE"
        }
    });

    // Mock issuer metadata endpoint
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                          "format": "mso_mdoc",
                              "claims": {
                              "namespace1": {
                                  "string_array": {
                                    "value_type": "string[]",
                                    "mandatory": true
                                  }
                              }
                          },
                          "order": [
                              "namespace1~string_array",
                          ],
                          "display": [
                          {
                              "name": "TestSchema"
                          }
                          ],
                          "wallet_storage_type": "SOFTWARE"
                      }
              }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Mock OIDC configuration endpoint
    let token_endpoint = format!("{credential_issuer}/token");

    // Mock OAuth authorization server metadata endpoint
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": credential_issuer,
                "token_endpoint": token_endpoint,
                "response_types_supported": ["code"],
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"],
                "client_attestation_signing_alg_values_supported": ["ES256"],
                "client_attestation_pop_signing_alg_values_supported": ["ES256"]
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 201);

    let resp = resp.json_value().await;
    let interaction_id: Uuid = resp["interactionId"].parse();
    let interaction = context.db.interactions.get(interaction_id).await.unwrap();

    // Verify that the interaction was created and contains the OAuth authorization server metadata
    let interaction_data: serde_json::Value =
        serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();

    // Verify that token_endpoint_auth_methods_supported was stored in the interaction data
    assert!(
        interaction_data
            .get("token_endpoint_auth_methods_supported")
            .is_some()
    );
    let auth_methods = interaction_data["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert_eq!(auth_methods.len(), 1);
    assert_eq!(auth_methods[0], "attest_jwt_client_auth");
}

#[tokio::test]
async fn test_handle_invitation_openid4vc_final1_wua_required_fails_no_wallet_instance() {
    let mock_server = MockServer::start().await;

    let additional_config = Some(indoc::formatdoc! {"
            issuanceProtocol:
              OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "});
    let (context, organisation) = TestContext::new_with_organisation(additional_config).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    // Mock issuer metadata endpoint
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                        "format": "mso_mdoc",
                            "claims": {
                            "namespace1": {
                                "string_array": {
                                  "value_type": "string[]",
                                  "mandatory": true
                                }
                            }
                        }
                    }
                }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Mock OAuth authorization server metadata endpoint
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": credential_issuer,
                "token_endpoint": format!("{credential_issuer}/token"),
                "response_types_supported": ["code"],
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"],
                "client_attestation_signing_alg_values_supported": ["ES256"],
                "client_attestation_pop_signing_alg_values_supported": ["ES256"]
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0081");
}

#[tokio::test]
async fn test_handle_invitation_openid4vc_final1_wua_required_fails_no_compatible_storage() {
    let mock_server = MockServer::start().await;

    let additional_config = Some(indoc::formatdoc! {"
            issuanceProtocol:
              OPENID4VCI_FINAL1:
                params:
                  public:
                    requestSignedMetadata: false
        "});
    let (context, organisation) = TestContext::new_with_organisation(additional_config).await;

    let credential_schema_id = Uuid::new_v4();
    let credential_issuer = format!(
        "{}/ssi/openid4vci/final-1.0/{credential_schema_id}",
        mock_server.uri()
    );
    let credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids": [
            "doctype"
        ],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "78db97c3-dbda-4bb2-a17c-b971ae7d6740"
            }
        }
    });

    // Mock issuer metadata endpoint
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .and(header("Accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
                "credential_configurations_supported": {
                    "doctype": {
                        "format": "mso_mdoc",
                        "claims": {
                            "namespace1": {
                                "string_array": {
                                  "value_type": "string[]",
                                  "mandatory": true
                                }
                            }
                        },
                        "proof_types_supported": {
                            "jwt": {
                              "proof_signing_alg_values_supported": [
                                "ES256",
                                "EdDSA"
                              ],
                              "key_attestations_required": {
                                "key_storage": ["iso_18045_high"]
                              }
                            }
                        }
                    }
                }
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Mock OAuth authorization server metadata endpoint
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": credential_issuer,
                "token_endpoint": format!("{credential_issuer}/token"),
                "response_types_supported": ["code"],
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "token_endpoint_auth_methods_supported": ["none"]
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let credential_offer = serde_json::to_string(&credential_offer).unwrap();
    let mut credential_offer_url: Url = "openid-credential-offer://".parse().unwrap();
    credential_offer_url
        .query_pairs_mut()
        .append_pair("credential_offer", &credential_offer);

    let resp = context
        .api
        .interactions
        .handle_invitation(organisation.id, credential_offer_url.as_ref())
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0225");
}
