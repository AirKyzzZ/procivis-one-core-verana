use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_verification_protocol_capabilities() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let draft20 = &resp["verificationProtocol"]["OPENID4VP_DRAFT20"]["capabilities"];
    assert_eq!(draft20["features"], json!(["SUPPORTS_WEBHOOKS"]));
    assert_eq!(draft20["supportedTransports"], json!(["HTTP"]));
    assert_eq!(draft20["didMethods"], json!(["KEY", "JWK", "WEB", "WEBVH"]));

    let mdoc = &resp["verificationProtocol"]["MDOC_OPENID4VP"]["capabilities"];
    assert_eq!(mdoc["features"], json!(["SUPPORTS_WEBHOOKS"]));
    assert_eq!(mdoc["supportedTransports"], json!(["HTTP"]));
    assert_eq!(mdoc["didMethods"], json!(["KEY", "JWK", "WEB", "WEBVH"]));

    let haip = &resp["verificationProtocol"]["OPENID4VP_FINAL1_HAIP"];
    assert_eq!(
        haip["params"]["verifier"]["supportedClientIdSchemes"],
        json!(["x509_hash"])
    );
    assert_eq!(
        haip["params"]["holder"]["supportedClientIdSchemes"],
        json!(["x509_hash"])
    );
    assert_eq!(
        haip["capabilities"]["verifierIdentifierTypes"],
        json!(["CERTIFICATE"])
    );
}
