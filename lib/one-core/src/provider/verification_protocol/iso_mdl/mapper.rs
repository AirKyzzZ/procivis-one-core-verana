use dcql::{
    ClaimPath, ClaimQuery, CredentialFormat, CredentialQuery, DcqlQuery, MsoMdocMeta, PathSegment,
};

use super::common::DeviceRequest;

pub(super) fn device_request_to_dcql_query(device_request: &DeviceRequest) -> DcqlQuery {
    let mut credentials = Vec::with_capacity(device_request.doc_requests.len());
    for doc_request in &device_request.doc_requests {
        let request = doc_request.items_request.inner();
        let mut claims = vec![];
        for (namespace, elements) in &request.name_spaces {
            for (element, intent_to_retain) in elements {
                claims.push(ClaimQuery {
                    id: None,
                    path: ClaimPath {
                        segments: vec![
                            PathSegment::PropertyName(namespace.to_owned()),
                            PathSegment::PropertyName(element.to_owned()),
                        ],
                    },
                    values: None,
                    required: Some(false),
                    intent_to_retain: Some(*intent_to_retain),
                });
            }
        }

        let doctype_value = request.doc_type.to_owned();
        credentials.push(CredentialQuery {
            id: doctype_value.to_owned().into(),
            format: CredentialFormat::MsoMdoc(MsoMdocMeta { doctype_value }),
            claims: Some(claims),
            claim_sets: None,
            trusted_authorities: None,
            multiple: false,
            require_cryptographic_holder_binding: true,
        });
    }

    DcqlQuery {
        credentials,
        credential_sets: None,
    }
}
