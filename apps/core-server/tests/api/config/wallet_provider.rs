use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_wallet_provider_config_without_user_authentication() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["walletProvider"]["PROCIVIS_ONE"]["params"]["userAuthentication"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn test_wallet_provider_config_with_user_authentication() {
    // GIVEN
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
          params:
            public:
              userAuthentication:
                required: true
                identityProvider: https://idp.example.com/realm/test
                clientId: my-client
                redirectUri: myapp://callback
                tokenValidation:
                  aud: my-client
                  iss: https://idp.example.com/realm/test
                  jwksUri: https://idp.example.com/realm/test/protocol/openid-connect/certs
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["walletProvider"]["PROCIVIS_ONE"]["params"]["userAuthentication"],
        serde_json::json!({
            "required": true,
            "identityProvider": "https://idp.example.com/realm/test",
            "clientId": "my-client",
            "redirectUri": "myapp://callback",
            "tokenValidation": {
                "aud": "my-client",
                "iss": "https://idp.example.com/realm/test",
                "jwksUri": "https://idp.example.com/realm/test/protocol/openid-connect/certs"
            }
        })
    );
}
