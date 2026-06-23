use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_category_enum_datatype_is_present_in_config() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["datatype"]["EAA_CATEGORY"]["type"], "ENUM");
    assert_eq!(
        resp["datatype"]["EAA_CATEGORY"]["params"]["values"],
        json!([
            { "value": "urn:etsi:esi:eaa:eu:pub", "display": "datatype.category.public" },
            { "value": "urn:etsi:esi:eaa:eu:qualified", "display": "datatype.category.qualified" }
        ])
    );
}
