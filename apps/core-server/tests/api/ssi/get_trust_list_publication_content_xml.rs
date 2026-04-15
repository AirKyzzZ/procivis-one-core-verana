use core_server::endpoint::trust_list_publication::dto::{
    TrustEntryStateRestEnum, TrustListRoleRestEnum,
};
use core_server::extractor::Accept;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::create_cert_identifier;
use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

const XML_PUBLISHER_CONFIG: &str = r#"
trustListPublisher:
  LOTE_PUBLISHER:
    type: ETSI_LOTE
    order: 1
    display: "trustListPublisher.etsiLote"
    params:
      public:
        refreshIntervalSeconds: 86400
        contentType: "application/xml"
"#;

fn xml_accept() -> Accept {
    Accept::from("application/xml".parse::<mime::Mime>().unwrap())
}

#[tokio::test]
async fn test_get_trust_list_publication_xml_success() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(Some(XML_PUBLISHER_CONFIG.to_string())).await;

    let create_resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "test_xml_trust_list",
            role: TrustListRoleRestEnum::PubEeaProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let publication_id = create_resp.json_value().await["id"].parse::<Uuid>().into();

    // when
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(publication_id, xml_accept())
        .await;

    // then
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/xml"
    );

    let body = resp.text().await;
    assert!(body.starts_with("<?xml"));
    assert!(body.contains("<ListOfTrustedEntities"));
    assert!(body.contains("<ds:Signature"));
    assert!(body.contains("<xades:SignedProperties"));
    assert!(body.contains("<ds:X509Certificate>"));
}

#[tokio::test]
async fn test_get_trust_list_publication_xml_with_entries() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(Some(XML_PUBLISHER_CONFIG.to_string())).await;
    let identifier2 =
        create_cert_identifier(&context, &organisation, Default::default(), None).await;

    let create_resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "test_xml_with_entries",
            role: TrustListRoleRestEnum::PubEeaProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let publication_id = create_resp.json_value().await["id"].parse::<Uuid>().into();

    let entry_1_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            publication_id,
            identifier.id,
            Some(serde_json::json!({
                 "entity": {
                    "name": [{ "lang": "en", "value": "XML Entity #1"}]
                }
            })),
        )
        .await;
    assert_eq!(entry_1_resp.status(), 201);

    let entry_2_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            publication_id,
            identifier2.id,
            Some(serde_json::json!({
                "entity": {
                    "name": [{ "lang": "en", "value": "XML Entity #2"}]
                }
            })),
        )
        .await;
    assert_eq!(entry_2_resp.status(), 201);

    // when
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(publication_id, xml_accept())
        .await;

    // then
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/xml"
    );

    let body = resp.text().await;
    let doc = roxmltree::Document::parse(&body).expect("valid XML");
    let root = doc.root_element();
    assert_eq!(root.tag_name().name(), "ListOfTrustedEntities");

    // LoTESequenceNumber: create(1) + entry1(2) + entry2(3)
    let seq = root
        .descendants()
        .find(|n| n.tag_name().name() == "LoTESequenceNumber")
        .unwrap();
    assert_eq!(seq.text().unwrap(), "3");

    // SchemeName > Name
    let scheme_name = root
        .descendants()
        .find(|n| {
            n.tag_name().name() == "Name"
                && n.parent().map(|p| p.tag_name().name()) == Some("SchemeName")
        })
        .unwrap();
    assert!(
        scheme_name
            .text()
            .unwrap()
            .contains("test_xml_with_entries")
    );

    // Two TrustedEntity elements
    let entities: Vec<_> = root
        .descendants()
        .filter(|n| n.tag_name().name() == "TrustedEntity")
        .collect();
    assert_eq!(entities.len(), 2);

    // XAdES signature present
    assert!(
        root.descendants()
            .any(|n| n.tag_name().name() == "Signature")
    );
}

#[tokio::test]
async fn test_get_trust_list_publication_xml_with_suspended_entries() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(Some(XML_PUBLISHER_CONFIG.to_string())).await;
    let identifier2 =
        create_cert_identifier(&context, &organisation, Default::default(), None).await;

    let create_resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "test_xml_suspended",
            role: TrustListRoleRestEnum::PubEeaProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let publication_id = create_resp.json_value().await["id"].parse::<Uuid>().into();

    let active_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            publication_id,
            identifier.id,
            Some(serde_json::json!({
                 "entity": {
                    "name": [{ "lang": "en", "value": "Active XML Entity"}]
                }
            })),
        )
        .await;
    assert_eq!(active_resp.status(), 201);

    let suspended_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            publication_id,
            identifier2.id,
            Some(serde_json::json!({
                 "entity": {
                    "name": [{ "lang": "en", "value": "Suspended XML Entity"}]
                }
            })),
        )
        .await;
    assert_eq!(suspended_resp.status(), 201);
    let suspended_entry_id = suspended_resp.json_value().await["id"]
        .parse::<Uuid>()
        .into();

    let update_resp = context
        .api
        .trust_list_publication
        .update_trust_entry(
            publication_id,
            suspended_entry_id,
            Some(TrustEntryStateRestEnum::Suspended),
            None,
        )
        .await;
    assert_eq!(update_resp.status(), 204);

    // when
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(publication_id, xml_accept())
        .await;

    // then
    assert_eq!(resp.status(), 200);

    let body = resp.text().await;
    let doc = roxmltree::Document::parse(&body).expect("valid XML");
    let root = doc.root_element();

    // LoTESequenceNumber: create(1) + entry1(2) + entry2(3) + suspend(4)
    let seq = root
        .descendants()
        .find(|n| n.tag_name().name() == "LoTESequenceNumber")
        .unwrap();
    assert_eq!(seq.text().unwrap(), "4");

    // Only one TrustedEntity (suspended entry excluded from content)
    let entities: Vec<_> = root
        .descendants()
        .filter(|n| n.tag_name().name() == "TrustedEntity")
        .collect();
    assert_eq!(entities.len(), 1);

    // Active entity present
    let te_name = entities[0]
        .descendants()
        .find(|n| {
            n.tag_name().name() == "Name"
                && n.parent().map(|p| p.tag_name().name()) == Some("TEName")
        })
        .unwrap();
    assert!(te_name.text().unwrap().contains("Active XML Entity"));
}

#[tokio::test]
async fn test_get_trust_list_publication_xml_rejects_jwt_accept_header() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(Some(XML_PUBLISHER_CONFIG.to_string())).await;

    let create_resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "test_xml_reject_jwt",
            role: TrustListRoleRestEnum::PubEeaProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let publication_id = create_resp.json_value().await["id"].parse::<Uuid>().into();

    // when - request JWT but publisher is XML
    let accept = Accept::from("application/jwt".parse::<mime::Mime>().unwrap());
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(publication_id, accept)
        .await;

    // then
    assert_eq!(resp.status(), 406);
}
