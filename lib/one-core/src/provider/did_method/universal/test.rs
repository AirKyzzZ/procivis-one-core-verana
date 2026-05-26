use std::sync::Arc;

use serde_json::json;
use similar_asserts::assert_eq;

use crate::proto::http_client::MockHttpClient;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::model::Operation;
use crate::provider::did_method::universal::UniversalDidMethod;

#[test]
fn test_get_capabilities() {
    let provider = UniversalDidMethod::new(
        "uni".into(),
        json!({
            "resolverUrl": "",
            "supportedMethodNames": ["ion"],
        }),
        Arc::new(MockHttpClient::new()),
    )
    .unwrap();

    assert_eq!(
        vec![Operation::RESOLVE],
        provider.get_capabilities().operations
    );
    assert_eq!(provider.get_capabilities().method_names, vec!["ion"]);
}
