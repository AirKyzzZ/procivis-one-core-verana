use similar_asserts::assert_eq;

use crate::etsi_119_612::xml::*;
use crate::etsi_119_612::{MIME_TSL_XML, ServiceType, TslType};

// https://trustedlist.serviceproviders.eudiw.dev/LOTL/01.xml
const LOTL: &str = include_str!("../../../tests/fixtures/eudiw_lotl.xml");
// https://trustedlist.serviceproviders.eudiw.dev/TL/EU/01.xml
const MEMBER: &str = include_str!("../../../tests/fixtures/eudiw_member_tsl.xml");

#[test]
fn parses_lotl_root_and_pointers() {
    let parsed: TrustServiceStatusList = quick_xml::de::from_str(LOTL).unwrap();
    assert_eq!(parsed.scheme_information.tsl_type, TslType::ListOfLists);
    assert_eq!(parsed.scheme_information.list_issue_date_time.year(), 2026);

    let pointers = parsed
        .scheme_information
        .pointers_to_other_tsl
        .expect("LOTL must carry pointers");
    assert!(!pointers.pointers.is_empty());
    for p in &pointers.pointers {
        assert!(!p.tsl_location.is_empty());
        assert!(!p.service_digital_identities.identities.is_empty());
    }

    let first_mime = pointers
        .pointers
        .iter()
        .flat_map(|p| p.additional_information.iter())
        .flat_map(|ai| ai.other_information.iter())
        .find_map(|oi| oi.mime_type.as_deref())
        .expect("at least one pointer must carry a MimeType");
    assert_eq!(first_mime, MIME_TSL_XML);
}

#[test]
fn parses_member_tsl_services() {
    let parsed: TrustServiceStatusList = quick_xml::de::from_str(MEMBER).unwrap();
    assert_eq!(parsed.scheme_information.tsl_type, TslType::Generic);
    let providers = parsed
        .trust_service_provider_list
        .expect("EUgeneric list must carry providers");
    let found_eaa_q = providers
        .providers
        .iter()
        .flat_map(|p| &p.tsp_services.services)
        .any(|svc| svc.service_information.service_type_identifier == ServiceType::EaaQ);
    assert!(
        found_eaa_q,
        "expected at least one EAA/Q service in member TSL"
    );
}
