use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Value, json};
use time::Duration;

use super::{VeranaTrustResolver, VeranaTrustRole, VeranaTrustVerdict};
use crate::proto::http_client::{
    Error, Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};

const RESOLVER: &str = "https://resolver.example";
const DID: &str = "did:web:trusted.example";
const SCHEMA_A: &str = "https://issuer.example/schema/a";
const SCHEMA_B: &str = "https://issuer.example/schema/b";

fn http_client(
    handler: impl Fn(&str) -> Result<(u16, Value, HashMap<String, String>), Error>
    + Send
    + Sync
    + 'static,
) -> MockHttpClient {
    let handler = Arc::new(handler);
    let mut client = MockHttpClient::new();
    client.expect_get().returning(move |url| {
        let outcome = handler(url);
        let request_url = url.to_string();
        let mut request_client = MockHttpClient::new();
        request_client
            .expect_send()
            .return_once(move |_, _, _, method, timeout| {
                let (status, body, headers) = outcome?;
                Ok(Response {
                    body: serde_json::to_vec(&body).unwrap(),
                    headers,
                    status: StatusCode(status),
                    request: Request {
                        body: None,
                        headers: Default::default(),
                        method,
                        url: request_url,
                        timeout,
                    },
                })
            });
        RequestBuilder::new(Arc::new(request_client), Method::Get, url)
    });
    client
}

fn raw_http_client(body: &'static [u8]) -> MockHttpClient {
    let mut client = MockHttpClient::new();
    client.expect_get().returning(move |url| {
        let request_url = url.to_string();
        let body = body.to_vec();
        let mut request_client = MockHttpClient::new();
        request_client
            .expect_send()
            .return_once(move |_, _, _, method, timeout| {
                Ok(Response {
                    body,
                    headers: Default::default(),
                    status: StatusCode(200),
                    request: Request {
                        body: None,
                        headers: Default::default(),
                        method,
                        url: request_url,
                        timeout,
                    },
                })
            });
        RequestBuilder::new(Arc::new(request_client), Method::Get, url)
    });
    client
}

fn q1(did: &str, status: &str, production: bool) -> Value {
    json!({
        "did": did,
        "trustStatus": status,
        "production": production,
        "evaluatedAt": "2026-07-22T12:00:00Z",
        "evaluatedAtBlock": 42,
        "expiresAt": "2026-07-23T12:00:00Z"
    })
}

fn authorization(did: &str, schema: &str, authorized: bool) -> Value {
    json!({
        "did": did,
        "vtjscId": schema,
        "authorized": authorized,
        "evaluatedAt": "2026-07-22T12:00:00Z",
        "permission": { "type": "ISSUER" },
        "fees": {},
        "permissionChain": []
    })
}

fn resolver(client: MockHttpClient) -> VeranaTrustResolver {
    VeranaTrustResolver::new(RESOLVER.to_string(), Duration::seconds(5), Arc::new(client)).unwrap()
}

#[tokio::test]
async fn trusted_production_and_every_issuer_schema_authorized_is_positive() {
    let client = http_client(|url| {
        if url.contains("/v1/trust/resolve") {
            return Ok((200, q1(DID, "TRUSTED", true), Default::default()));
        }
        let schema = if url.contains("schema%2Fb") {
            SCHEMA_B
        } else {
            SCHEMA_A
        };
        Ok((
            200,
            authorization(DID, schema, true),
            HashMap::from([("X-Evaluated-At-Block".to_string(), "43".to_string())]),
        ))
    });

    let summary = resolver(client)
        .resolve_summary(
            VeranaTrustRole::Issuer,
            DID,
            vec![
                SCHEMA_B.to_string(),
                SCHEMA_A.to_string(),
                SCHEMA_A.to_string(),
            ],
        )
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
    assert_eq!(summary.production, Some(true));
    assert_eq!(summary.schemas, vec![SCHEMA_A, SCHEMA_B]);
    assert_eq!(summary.authorizations.len(), 2);
}

#[tokio::test]
async fn trusted_production_verifier_authorization_is_positive() {
    let client = http_client(|url| {
        let body = if url.contains("/v1/trust/resolve") {
            q1(DID, "TRUSTED", true)
        } else if url.contains("/v1/trust/") {
            assert!(url.contains("/v1/trust/verifier-authorization"));
            authorization(DID, SCHEMA_A, true)
        } else {
            json!({})
        };
        Ok((200, body, Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Verifier, DID, vec![SCHEMA_A.to_string()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
}

#[tokio::test]
async fn one_unauthorized_schema_makes_multi_schema_result_non_positive() {
    let client = http_client(|url| {
        if url.contains("/v1/trust/resolve") {
            return Ok((200, q1(DID, "TRUSTED", true), Default::default()));
        }
        let (schema, authorized) = if url.contains("schema%2Fb") {
            (SCHEMA_B, false)
        } else {
            (SCHEMA_A, true)
        };
        Ok((
            200,
            authorization(DID, schema, authorized),
            Default::default(),
        ))
    });

    let summary = resolver(client)
        .resolve_summary(
            VeranaTrustRole::Issuer,
            DID,
            vec![SCHEMA_A.to_string(), SCHEMA_B.to_string()],
        )
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::Unauthorized);
}

#[tokio::test]
async fn every_distinct_schema_is_attempted_when_one_authorization_is_unavailable() {
    let requested_schemas = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_schemas = requested_schemas.clone();
    let client = http_client(move |url| {
        if url.contains("/v1/trust/resolve") {
            return Ok((200, q1(DID, "TRUSTED", true), Default::default()));
        }
        if !url.contains("/v1/trust/issuer-authorization") {
            return Ok((200, json!({}), Default::default()));
        }
        if url.contains("schema%2Fa") {
            observed_schemas.lock().unwrap().push(SCHEMA_A);
            return Err(Error::Timeout);
        }
        observed_schemas.lock().unwrap().push(SCHEMA_B);
        Ok((200, authorization(DID, SCHEMA_B, true), Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(
            VeranaTrustRole::Issuer,
            DID,
            vec![SCHEMA_A.to_string(), SCHEMA_B.to_string()],
        )
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::Unavailable);
    assert_eq!(
        requested_schemas.lock().unwrap().as_slice(),
        &[SCHEMA_A, SCHEMA_B]
    );
    assert_eq!(summary.authorizations.len(), 2);
}

#[tokio::test]
async fn untrusted_and_incomplete_q1_are_distinct_non_positive_states() {
    for (body, expected) in [
        (q1(DID, "UNTRUSTED", true), VeranaTrustVerdict::Untrusted),
        (q1(DID, "UNTRUSTED", false), VeranaTrustVerdict::Untrusted),
        (
            json!({ "did": DID, "trustStatus": "TRUSTED" }),
            VeranaTrustVerdict::Partial,
        ),
    ] {
        let client = http_client(move |_| Ok((200, body.clone(), Default::default())));
        let summary = resolver(client)
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
            .await;
        assert_eq!(summary.verdict, expected);
        assert_ne!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
    }
}

#[tokio::test]
async fn trusted_non_production_still_runs_authorization_and_carries_the_flag() {
    let client = http_client(|url| {
        let body = if url.contains("/v1/trust/resolve") {
            q1(DID, "TRUSTED", false)
        } else {
            authorization(DID, SCHEMA_A, true)
        };
        Ok((200, body, Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
    assert_eq!(summary.production, Some(false));
    assert_eq!(summary.authorizations.len(), 1);
}

#[tokio::test]
async fn trusted_non_production_unauthorized_evidence_is_unauthorized() {
    let client = http_client(|url| {
        let body = if url.contains("/v1/trust/resolve") {
            q1(DID, "TRUSTED", false)
        } else {
            authorization(DID, SCHEMA_A, false)
        };
        Ok((200, body, Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::Unauthorized);
    assert_eq!(summary.production, Some(false));
}

#[tokio::test]
async fn vpr_schema_reference_is_reduced_to_the_numeric_schema_id() {
    const VPR_VCT: &str = "vpr:verana:vna-testnet-1/cs/v1/js/12345678";
    let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = queries.clone();
    let client = http_client(move |url| {
        if url.contains("/v1/trust/resolve") {
            return Ok((200, q1(DID, "TRUSTED", true), Default::default()));
        }
        observed.lock().unwrap().push(url.to_string());
        Ok((200, authorization(DID, "12345678", true), Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![VPR_VCT.to_string()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
    let queries = queries.lock().unwrap();
    assert_eq!(queries.len(), 1);
    assert!(queries[0].contains("vtjscId=12345678"));
    assert_eq!(summary.authorizations[0].schema, VPR_VCT);
    assert_eq!(
        summary.authorizations[0].response_schema.as_deref(),
        Some("12345678")
    );
}

#[tokio::test]
async fn https_vct_resolves_through_the_vtjsc_to_the_vpr_schema_id() {
    const VCT: &str = "https://issuer.example/vct/service";
    const VTJSC: &str = "https://issuer.example/vt/schema-jsc.json";
    let client = http_client(move |url| {
        if url.contains("/v1/trust/resolve") {
            return Ok((200, q1(DID, "TRUSTED", true), Default::default()));
        }
        if url == VCT {
            return Ok((
                200,
                json!({ "relatedJsonSchemaCredentialId": VTJSC }),
                Default::default(),
            ));
        }
        if url == VTJSC {
            return Ok((
                200,
                json!({
                    "credentialSubject": {
                        "jsonSchema": { "$id": "vpr:verana:vna-testnet-1/cs/v1/js/42" }
                    }
                }),
                Default::default(),
            ));
        }
        assert!(url.contains("/v1/trust/issuer-authorization"));
        assert!(url.contains("vtjscId=42"));
        Ok((200, authorization(DID, "42", true), Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![VCT.to_string()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
    assert_eq!(summary.authorizations[0].schema, VCT);
    assert_eq!(
        summary.authorizations[0].response_schema.as_deref(),
        Some("42")
    );
}

#[tokio::test]
async fn vtjsc_ref_and_subject_id_pointers_also_yield_the_schema_id() {
    const VCT: &str = "https://issuer.example/vct/service";
    const VTJSC: &str = "https://issuer.example/vt/schema-jsc.json";
    for subject in [
        json!({ "jsonSchema": { "$ref": "vpr:verana:devnet/cs/v1/js/7" } }),
        json!({ "jsonSchema": {}, "id": "vpr:verana:devnet/cs/v1/js/7" }),
    ] {
        let client = http_client(move |url| {
            if url.contains("/v1/trust/resolve") {
                return Ok((200, q1(DID, "TRUSTED", true), Default::default()));
            }
            if url == VCT {
                return Ok((
                    200,
                    json!({ "relatedJsonSchemaCredentialId": VTJSC }),
                    Default::default(),
                ));
            }
            if url == VTJSC {
                return Ok((
                    200,
                    json!({ "credentialSubject": subject.clone() }),
                    Default::default(),
                ));
            }
            assert!(url.contains("vtjscId=7"));
            Ok((200, authorization(DID, "7", true), Default::default()))
        });

        let summary = resolver(client)
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![VCT.to_string()])
            .await;

        assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
    }
}

#[tokio::test]
async fn vtjsc_chain_failure_fails_closed_to_the_raw_schema_value() {
    const VCT: &str = "https://issuer.example/vct/service";
    let client = http_client(move |url| {
        if url.contains("/v1/trust/resolve") {
            return Ok((200, q1(DID, "TRUSTED", true), Default::default()));
        }
        if url == VCT {
            return Ok((500, json!({}), Default::default()));
        }
        assert!(url.contains("/v1/trust/issuer-authorization"));
        assert!(url.contains("vtjscId=https%3A%2F%2Fissuer.example%2Fvct%2Fservice"));
        Ok((200, authorization(DID, VCT, true), Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![VCT.to_string()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
    assert_eq!(
        summary.authorizations[0].response_schema.as_deref(),
        Some(VCT)
    );
}

#[tokio::test]
async fn pending_terminated_revoked_or_slashed_permission_is_not_a_grant() {
    for permission in [
        json!({ "type": "ISSUER", "vp_state": "PENDING" }),
        json!({ "type": "ISSUER", "vp_state": "TERMINATED" }),
        json!({ "type": "ISSUER", "revoked": "2026-07-01T00:00:00Z" }),
        json!({ "type": "ISSUER", "slashed": "2026-07-01T00:00:00Z" }),
    ] {
        let client = http_client(move |url| {
            let body = if url.contains("/v1/trust/resolve") {
                q1(DID, "TRUSTED", true)
            } else {
                let mut body = authorization(DID, SCHEMA_A, true);
                body["permission"] = permission.clone();
                body
            };
            Ok((200, body, Default::default()))
        });

        let summary = resolver(client)
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
            .await;

        assert_eq!(summary.verdict, VeranaTrustVerdict::Unauthorized);
        assert_eq!(summary.authorizations[0].authorized, Some(true));
    }
}

#[tokio::test]
async fn validated_permission_state_keeps_the_grant() {
    let client = http_client(|url| {
        let body = if url.contains("/v1/trust/resolve") {
            q1(DID, "TRUSTED", true)
        } else {
            let mut body = authorization(DID, SCHEMA_A, true);
            body["permission"] = json!({ "type": "ISSUER", "vp_state": "VALIDATED" });
            body
        };
        Ok((200, body, Default::default()))
    });

    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
}

#[tokio::test]
async fn exact_did_and_schema_mismatches_are_non_positive() {
    for mismatch_q1 in [true, false] {
        let client = http_client(move |url| {
            let body = if url.contains("/v1/trust/resolve") {
                q1(
                    if mismatch_q1 {
                        "did:web:other.example"
                    } else {
                        DID
                    },
                    "TRUSTED",
                    true,
                )
            } else {
                authorization(DID, if mismatch_q1 { SCHEMA_A } else { SCHEMA_B }, true)
            };
            Ok((200, body, Default::default()))
        });
        let summary = resolver(client)
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
            .await;
        assert_eq!(summary.verdict, VeranaTrustVerdict::Mismatch);
    }
}

#[tokio::test]
async fn blank_or_missing_schema_never_calls_authorization_and_is_non_positive() {
    let client = http_client(|url| {
        assert!(url.contains("/v1/trust/resolve"));
        Ok((200, q1(DID, "TRUSTED", true), Default::default()))
    });
    let summary = resolver(client)
        .resolve_summary(
            VeranaTrustRole::Issuer,
            DID,
            vec!["  ".to_string(), "".to_string()],
        )
        .await;
    assert_eq!(summary.verdict, VeranaTrustVerdict::UnknownSchema);
}

#[tokio::test]
async fn whitespace_is_rejected_instead_of_normalizing_the_signed_schema() {
    let client = http_client(|url| {
        assert!(url.contains("/v1/trust/resolve"));
        Ok((200, q1(DID, "TRUSTED", true), Default::default()))
    });
    let signed_schema = format!(" {SCHEMA_A} ");
    let summary = resolver(client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![signed_schema.clone()])
        .await;

    assert_eq!(summary.verdict, VeranaTrustVerdict::UnknownSchema);
    assert_eq!(summary.schemas, vec![signed_schema]);
    assert!(summary.authorizations.is_empty());
}

#[tokio::test]
async fn malformed_non_success_timeout_and_network_fail_closed() {
    assert_eq!(
        resolver(raw_http_client(b"{"))
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
            .await
            .verdict,
        VeranaTrustVerdict::Unavailable
    );

    let malformed = http_client(|_| Ok((200, json!({"did": DID}), Default::default())));
    assert_eq!(
        resolver(malformed)
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
            .await
            .verdict,
        VeranaTrustVerdict::Partial
    );

    let partial_authorization = http_client(|url| {
        let body = if url.contains("/v1/trust/resolve") {
            q1(DID, "TRUSTED", true)
        } else {
            json!({ "did": DID, "vtjscId": SCHEMA_A })
        };
        Ok((200, body, Default::default()))
    });
    assert_eq!(
        resolver(partial_authorization)
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
            .await
            .verdict,
        VeranaTrustVerdict::Partial
    );

    let non_success = http_client(|_| Ok((503, json!({}), Default::default())));
    assert_eq!(
        resolver(non_success)
            .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
            .await
            .verdict,
        VeranaTrustVerdict::Unavailable
    );

    for error in [Error::Timeout, Error::InvalidHost("offline".to_string())] {
        let error = Arc::new(std::sync::Mutex::new(Some(error)));
        let client = http_client(move |_| Err(error.lock().unwrap().take().unwrap()));
        assert_eq!(
            resolver(client)
                .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
                .await
                .verdict,
            VeranaTrustVerdict::Unavailable
        );
    }
}

#[tokio::test]
async fn full_detail_mismatch_or_failure_never_upgrades_validated_summary() {
    let summary_client = http_client(|url| {
        let body = if url.contains("/v1/trust/resolve") {
            q1(DID, "TRUSTED", true)
        } else {
            authorization(DID, SCHEMA_A, true)
        };
        Ok((200, body, Default::default()))
    });
    let summary = resolver(summary_client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
        .await;
    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);

    let mismatch_client = http_client(|_| {
        Ok((
            200,
            json!({
                "did": "did:web:other.example",
                "trustStatus": "TRUSTED",
                "production": true,
                "credentials": [],
                "failedCredentials": [],
                "dereferenceErrors": []
            }),
            Default::default(),
        ))
    });
    assert!(
        resolver(mismatch_client)
            .resolve_full(&summary)
            .await
            .is_err()
    );
    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);

    let failure_client = http_client(|_| Ok((500, json!({}), Default::default())));
    assert!(
        resolver(failure_client)
            .resolve_full(&summary)
            .await
            .is_err()
    );
    assert_eq!(summary.verdict, VeranaTrustVerdict::TrustedAuthorized);
}

#[tokio::test]
async fn full_detail_maps_typed_claims_permission_chain_and_resolver_evidence() {
    let summary_client = http_client(|url| {
        let body = if url.contains("/v1/trust/resolve") {
            q1(DID, "TRUSTED", true)
        } else {
            authorization(DID, SCHEMA_A, true)
        };
        Ok((200, body, Default::default()))
    });
    let summary = resolver(summary_client)
        .resolve_summary(VeranaTrustRole::Issuer, DID, vec![SCHEMA_A.to_string()])
        .await;

    let full_client = http_client(|url| {
        assert!(url.contains("detail=full"));
        Ok((
            200,
            json!({
                "did": DID,
                "trustStatus": "TRUSTED",
                "production": true,
                "evaluatedAt": "2026-07-22T12:00:00Z",
                "evaluatedAtBlock": 44,
                "expiresAt": "2026-07-23T12:00:00Z",
                "credentials": [{
                    "id": "urn:credential:1",
                    "type": "VerifiableCredential",
                    "format": "jwt_vc_json",
                    "ecsType": "ECS-ORG",
                    "issuedBy": "did:web:authority.example",
                    "presentedBy": DID,
                    "claims": {"name": "Trusted issuer", "level": 3},
                    "permissionChain": [{"did": "did:web:authority.example"}],
                    "result": "VALID"
                }],
                "failedCredentials": [],
                "dereferenceErrors": []
            }),
            Default::default(),
        ))
    });
    let full = resolver(full_client).resolve_full(&summary).await.unwrap();
    assert_eq!(full.credentials.len(), 1);
    assert_eq!(full.credentials[0].claims[0].name, "level");
    assert_eq!(full.credentials[0].claims[0].value_type, "number");
    assert_eq!(full.credentials[0].claims[1].name, "name");
    assert_eq!(full.credentials[0].permission_chain.len(), 1);
}
